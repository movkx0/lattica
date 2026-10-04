//! Candidate-only cubic opening reduction. One matrix upload feeds all of its
//! opening points; reduced vectors stay on the device across matrices of the
//! same height. Only the final three-column FRI inputs are downloaded.
//!
//! This first consumer still reads host-backed LDEs. It is not a claim that the
//! whole prover is resident, nor a replacement for whole-job resource admission.
use super::{allocation, Allocation, Engine, ENGINE};
use crate::block_v2::profile::Challenge;
use crate::config::Val;
use ocl::Event;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use std::collections::BTreeMap;
use std::time::Instant;

mod compact;

const MAX_MATRICES: usize = 256;
const MAX_WIDTH: usize = 4096;
const MAX_POINTS: usize = 32;
const MAX_OUTPUT_BYTES: usize = 1 << 30;

pub(crate) struct OpeningTerm<'a> {
    pub inverse_denominators: &'a [Challenge],
    pub alpha_offset: Challenge,
    pub opened: Challenge,
}

pub(crate) struct OpeningMatrix<'a> {
    /// Physical bit-reversed rows, exactly as committed by the input MMCS.
    pub values: &'a [Val],
    pub width: usize,
    pub height: usize,
    pub terms: Vec<OpeningTerm<'a>>,
}

#[derive(Debug)]
struct Plan {
    heights: Vec<usize>,
    rows: usize,
    input_words: usize,
    denominator_words: usize,
    weight_words: usize,
    term_words: usize,
    total_bytes: usize,
}

impl Plan {
    fn new(
        inputs: &[OpeningMatrix<'_>],
        tile_bytes: usize,
        max_alloc: usize,
    ) -> Result<Self, String> {
        if inputs.is_empty() || inputs.len() > MAX_MATRICES {
            return Err("opening reduction matrix count".into());
        }
        let mut heights = BTreeMap::new();
        let (mut width, mut points) = (0, 0);
        for input in inputs {
            if input.width == 0 || input.width > MAX_WIDTH || input.values.len() % input.width != 0
            {
                return Err("opening reduction matrix shape".into());
            }
            let height = input.height;
            if input.values.len() / input.width < (height >> crate::block_v2::profile::LOG_BLOWUP)
                || height < 2
                || !height.is_power_of_two()
                || height > (1 << 31)
            {
                return Err("opening reduction matrix height".into());
            }
            if input.terms.is_empty()
                || input.terms.len() > MAX_POINTS
                || input
                    .terms
                    .iter()
                    .any(|term| term.inverse_denominators.len() < height)
            {
                return Err("opening reduction point dimensions".into());
            }
            heights.insert(height, ());
            width = width.max(input.width);
            points = points.max(input.terms.len());
        }
        let output_bytes = heights.keys().try_fold(0usize, |sum, height| {
            let bytes = height.checked_mul(24).ok_or("opening output overflow")?;
            if bytes > max_alloc {
                return Err("opening output allocation limit");
            }
            sum.checked_add(bytes).ok_or("opening output overflow")
        })?;
        if output_bytes > MAX_OUTPUT_BYTES {
            return Err("opening reduction output allowance".into());
        }
        // Input, denominators and download staging share this finite host/device
        // tile allowance. No per-point copy of the wide input matrix is made.
        let row_words = width + 3 * points + 3;
        let rows = (tile_bytes.min(max_alloc) / 8 / row_words).min(65536);
        if rows == 0 {
            return Err("opening reduction tile allowance".into());
        }
        let input_words = rows * width;
        let denominator_words = rows * points * 3;
        let weight_words = width * 3;
        let term_words = points * 6;
        let workspace = [input_words, denominator_words, weight_words, term_words];
        if workspace.iter().any(|words| words * 8 > max_alloc) {
            return Err("opening reduction workspace allocation limit".into());
        }
        Ok(Self {
            heights: heights.into_keys().collect(),
            rows,
            input_words,
            denominator_words,
            weight_words,
            term_words,
            total_bytes: output_bytes + workspace.iter().sum::<usize>() * 8,
        })
    }
}

pub(super) const KERNEL_SRC: &str = r#"
// Candidate extension basis: X^3 = X + 1, not the binomial cubic basis.
inline void opening_cubic_mul(ulong a[3], ulong b[3], ulong out[3]) {
    ulong c3 = gl_add(gl_mul(a[1], b[2]), gl_mul(a[2], b[1]));
    ulong c4 = gl_mul(a[2], b[2]);
    out[0] = gl_add(gl_mul(a[0], b[0]), c3);
    out[1] = gl_add(gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0])), gl_add(c3, c4));
    out[2] = gl_add(gl_add(gl_add(gl_mul(a[0], b[2]), gl_mul(a[1], b[1])), gl_mul(a[2], b[0])), c4);
}
__kernel void opening_reduce(__global const ulong *input,
    __global const ulong *weights, __global const ulong *denominators,
    __global const ulong *terms, __global ulong *output,
    uint row0, uint rows, uint width, uint points) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong compressed[3] = {0, 0, 0};
    for (uint col = 0; col < width; ++col) {
        ulong value = input[row * (size_t)width + col];
        for (uint k = 0; k < 3; ++k)
            compressed[k] = gl_add(compressed[k], gl_mul(value, weights[3 * (size_t)col + k]));
    }
    ulong sum[3] = {0, 0, 0};
    for (uint point = 0; point < points; ++point) {
        ulong offset[3], delta[3], inverse[3], product[3], scaled[3];
        for (uint k = 0; k < 3; ++k) {
            offset[k] = terms[6 * point + k];
            delta[k] = gl_sub(terms[6 * point + 3 + k], compressed[k]);
            inverse[k] = denominators[(row * (size_t)points + point) * 3 + k];
        }
        opening_cubic_mul(delta, inverse, product);
        opening_cubic_mul(offset, product, scaled);
        for (uint k = 0; k < 3; ++k) sum[k] = gl_add(sum[k], scaled[k]);
    }
    for (uint k = 0; k < 3; ++k) {
        size_t at = ((size_t)row0 + row) * 3 + k;
        output[at] = gl_canon(gl_add(output[at], sum[k]));
    }
}
// Low-coset inputs are physically bit-reversed. Emit natural-order cubic
// coefficients so the existing inverse/forward NTT can extend their polynomial.
__kernel void opening_compress_low(__global const ulong *input,
    __global const ulong *weights, __global ulong *output,
    uint row0, uint rows, uint width, uint log_low_height) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong sum[3] = {0, 0, 0};
    for (uint col = 0; col < width; ++col)
        for (uint k = 0; k < 3; ++k)
            sum[k] = gl_add(sum[k], gl_mul(input[row * (size_t)width + col],
                                         weights[3 * (size_t)col + k]));
    size_t at = (size_t)brev(row0 + (uint)row, log_low_height) * 3;
    for (uint k = 0; k < 3; ++k) output[at + k] = gl_canon(sum[k]);
}
__kernel void opening_reduce_compact(__global const ulong *compressed,
    __global const ulong *denominators, __global const ulong *terms,
    __global ulong *output, uint row0, uint rows, uint points) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    size_t at = ((size_t)row0 + row) * 3;
    ulong sum[3] = {0, 0, 0};
    for (uint point = 0; point < points; ++point) {
        ulong offset[3], delta[3], inverse[3], product[3], scaled[3];
        for (uint k = 0; k < 3; ++k) {
            offset[k] = terms[6 * point + k];
            delta[k] = gl_sub(terms[6 * point + 3 + k], compressed[at + k]);
            inverse[k] = denominators[(row * (size_t)points + point) * 3 + k];
        }
        opening_cubic_mul(delta, inverse, product);
        opening_cubic_mul(offset, product, scaled);
        for (uint k = 0; k < 3; ++k) sum[k] = gl_add(sum[k], scaled[k]);
    }
    for (uint k = 0; k < 3; ++k)
        output[at + k] = gl_canon(gl_add(output[at + k], sum[k]));
}
"#;

fn append_challenge(words: &mut Vec<u64>, value: Challenge) {
    words.extend(
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&value)
            .iter()
            .map(PrimeField64::as_canonical_u64),
    );
}

/// Returns FRI inputs in descending height order, matching upstream PCS order.
/// Admission/allocation failure never silently switches backend.
pub(crate) fn reduce(
    inputs: &[OpeningMatrix<'_>],
    alpha: Challenge,
) -> Result<Vec<Vec<Challenge>>, String> {
    let mut guard = ENGINE
        .get()
        .ok_or("opening reduction requires GPU engine")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = guard.as_mut().ok_or("GPU engine shut down")?;
    engine.reduce_openings(inputs, alpha)
}

/// PCS-only entry: every column must have degree < height / 2^log_blowup.
/// Call only after observing opened values and sampling alpha. Arbitrary row
/// vectors must use `reduce`; this optimization does not validate low degree.
pub(crate) fn reduce_lde(
    inputs: &[OpeningMatrix<'_>],
    alpha: Challenge,
    log_blowup: usize,
) -> Result<Vec<Vec<Challenge>>, String> {
    if !super::switch("LATTICA_V2_GPU_OPENING_COMPACT")? {
        return reduce(inputs, alpha);
    }
    let mut guard = ENGINE
        .get()
        .ok_or("opening reduction requires GPU engine")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    guard
        .as_mut()
        .ok_or("GPU engine shut down")?
        .reduce_openings_low_degree(inputs, alpha, log_blowup)
}

impl Engine {
    pub(super) fn reduce_openings_low_degree(
        &mut self,
        inputs: &[OpeningMatrix<'_>],
        alpha: Challenge,
        log_blowup: usize,
    ) -> Result<Vec<Vec<Challenge>>, String> {
        self.compact_openings(inputs, alpha, log_blowup)
    }

    /// Blocking writes finish before this already-reserved mapping is reused.
    /// The caller's queue fence also drains all pending work on error/unwind.
    fn upload_opening_pinned(
        &mut self,
        destination: &Allocation,
        words: usize,
        mut fill: impl FnMut(usize, &mut [u64]),
    ) -> Result<(), String> {
        let capacity = self.staging.first().map_or(0, |slot| slot.map.len());
        if capacity == 0 || words == 0 || words > destination.buffer.len() {
            return Err("opening pinned upload dimensions".into());
        }
        for offset in (0..words).step_by(capacity) {
            let count = capacity.min(words - offset);
            let marshal = Instant::now();
            fill(offset, &mut self.staging[0].map[..count]);
            self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
            let mut event = Event::empty();
            let upload = Instant::now();
            // BufferWriteCmd is blocking by default. No mutable host access or
            // later chunk may race this DMA; no new staging allocation is made.
            destination
                .buffer
                .write(&self.staging[0].map[..count])
                .offset(offset)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.opening_upload_api_ns += upload.elapsed().as_nanos();
            self.stats.opening_upload_device_ns +=
                self.timeline.record("opening_upload", &event)?;
            self.stats.opening_pinned_uploaded_bytes += (count * 8) as u64;
            self.stats.opening_pinned_upload_chunks += 1;
        }
        Ok(())
    }

    pub(super) fn reduce_openings(
        &mut self,
        inputs: &[OpeningMatrix<'_>],
        alpha: Challenge,
    ) -> Result<Vec<Vec<Challenge>>, String> {
        let pinned_uploads = super::switch("LATTICA_V2_GPU_OPENING_PINNED")?;
        self.reduce_openings_with_upload(inputs, alpha, pinned_uploads)
    }

    fn reduce_openings_with_upload(
        &mut self,
        inputs: &[OpeningMatrix<'_>],
        alpha: Challenge,
        pinned_uploads: bool,
    ) -> Result<Vec<Vec<Challenge>>, String> {
        let started = Instant::now();
        if inputs
            .iter()
            .any(|i| i.width.checked_mul(i.height) != Some(i.values.len()))
        {
            return Err("full opening reduction requires full matrices".into());
        }
        let plan = Plan::new(inputs, self.limits.tile_bytes, self.max_alloc)?;
        let old_workspace = self.workspace.as_ref().map_or(0, |w| w.bytes());
        let live = self
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live;
        let retained_live = live
            .checked_sub(old_workspace)
            .ok_or("opening accounting underflow")?;
        if retained_live
            .checked_add(plan.total_bytes)
            .ok_or("opening accounting overflow")?
            > self.limits.managed_bytes
        {
            return Err("opening reduction aggregate GPU allowance".into());
        }
        self.fence().finish()?;
        self.workspace = None;
        let alloc = |words| {
            allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                words,
                ocl::flags::MEM_READ_WRITE,
            )
        };
        let outputs = plan
            .heights
            .iter()
            .map(|height| alloc(height * 3))
            .collect::<Result<Vec<_>, _>>()?;
        let input_buffer = alloc(plan.input_words)?;
        let denominator_buffer = alloc(plan.denominator_words)?;
        let weight_buffer = alloc(plan.weight_words)?;
        let term_buffer = alloc(plan.term_words)?;
        let mut input_words = Vec::with_capacity(if pinned_uploads { 0 } else { plan.input_words });
        let mut denominator_words = Vec::with_capacity(if pinned_uploads {
            0
        } else {
            plan.denominator_words
        });
        let mut weight_words = Vec::with_capacity(plan.weight_words);
        let mut term_words = Vec::with_capacity(plan.term_words);
        let mut download = vec![0u64; plan.rows * 3];
        // Declared last: every error/unwind drains before any referenced host or
        // device allocation can be released, including after a successful enqueue.
        let fence = self.fence();
        for output in &outputs {
            output
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        for input in inputs {
            let height = input.height;
            let output_index = plan.heights.binary_search(&height).unwrap();
            let marshal = Instant::now();
            weight_words.clear();
            for weight in alpha.powers().take(input.width) {
                append_challenge(&mut weight_words, weight);
            }
            term_words.clear();
            for term in &input.terms {
                append_challenge(&mut term_words, term.alpha_offset);
                append_challenge(&mut term_words, term.opened);
            }
            self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
            let (mut weights_event, mut terms_event) = (Event::empty(), Event::empty());
            let upload = Instant::now();
            weight_buffer
                .buffer
                .write(&weight_words)
                .enew(&mut weights_event)
                .enq()
                .map_err(|e| e.to_string())?;
            term_buffer
                .buffer
                .write(&term_words)
                .enew(&mut terms_event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.opening_upload_api_ns += upload.elapsed().as_nanos();
            self.stats.opening_upload_device_ns +=
                self.timeline.record("opening_upload", &weights_event)?
                    + self.timeline.record("opening_upload", &terms_event)?;
            self.stats.opening_uploaded_bytes +=
                ((weight_words.len() + term_words.len()) * 8) as u64;
            for row0 in (0..height).step_by(plan.rows) {
                let rows = plan.rows.min(height - row0);
                if pinned_uploads {
                    let values = &input.values[row0 * input.width..(row0 + rows) * input.width];
                    self.upload_opening_pinned(&input_buffer, values.len(), |offset, target| {
                        let source = &values[offset..offset + target.len()];
                        for (word, value) in target.iter_mut().zip(source) {
                            *word = value.as_canonical_u64();
                        }
                    })?;
                    let mut coefficients = (row0..row0 + rows).flat_map(|row| {
                        input.terms.iter().flat_map(move |term| {
                            <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(
                                &term.inverse_denominators[row],
                            )
                            .iter()
                            .map(PrimeField64::as_canonical_u64)
                        })
                    });
                    self.upload_opening_pinned(
                        &denominator_buffer,
                        rows * input.terms.len() * 3,
                        |_, target| {
                            for word in target {
                                *word = coefficients.next().expect("admitted cubic dimensions");
                            }
                        },
                    )?;
                } else {
                    let marshal = Instant::now();
                    input_words.clear();
                    input_words.extend(
                        input.values[row0 * input.width..(row0 + rows) * input.width]
                            .iter()
                            .map(PrimeField64::as_canonical_u64),
                    );
                    denominator_words.clear();
                    for row in row0..row0 + rows {
                        for term in &input.terms {
                            append_challenge(
                                &mut denominator_words,
                                term.inverse_denominators[row],
                            );
                        }
                    }
                    self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
                    let (mut input_event, mut denominator_event) = (Event::empty(), Event::empty());
                    let upload = Instant::now();
                    input_buffer
                        .buffer
                        .write(&input_words)
                        .enew(&mut input_event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                    denominator_buffer
                        .buffer
                        .write(&denominator_words)
                        .enew(&mut denominator_event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                    self.stats.opening_upload_api_ns += upload.elapsed().as_nanos();
                    self.stats.opening_upload_device_ns +=
                        self.timeline.record("opening_upload", &input_event)?
                            + self.timeline.record("opening_upload", &denominator_event)?;
                }
                self.stats.opening_uploaded_bytes +=
                    ((rows * input.width + rows * input.terms.len() * 3) * 8) as u64;
                let mut event = Event::empty();
                // SAFETY: checked rectangular matrices, finite tiles, disjoint
                // input/output buffers, and a queue fence owning their lifetimes.
                let build = Instant::now();
                let kernel = self
                    .pq
                    .kernel_builder("opening_reduce")
                    .arg(&input_buffer.buffer)
                    .arg(&weight_buffer.buffer)
                    .arg(&denominator_buffer.buffer)
                    .arg(&term_buffer.buffer)
                    .arg(&outputs[output_index].buffer)
                    .arg(row0 as u32)
                    .arg(rows as u32)
                    .arg(input.width as u32)
                    .arg(input.terms.len() as u32)
                    .global_work_size(rows)
                    .build()
                    .map_err(|e| e.to_string())?;
                self.stats.opening_kernel_build_ns += build.elapsed().as_nanos();
                let enqueue = Instant::now();
                unsafe {
                    let command = kernel.cmd().enew(&mut event);
                    #[cfg(test)]
                    let command = if let Some(gate) = &self.opening_gate {
                        command.ewait(gate)
                    } else {
                        command
                    };
                    command.enq().map_err(|e| e.to_string())?;
                }
                self.stats.opening_kernel_enqueue_ns += enqueue.elapsed().as_nanos();
                #[cfg(test)]
                if let Some(unwind) = self.fail_opening_after_enqueue.take() {
                    self.injected_event = Some(event.clone());
                    if let Some(notify) = self.opening_submitted.take() {
                        let _ = notify.send(());
                    }
                    if unwind {
                        panic!("injected opening unwind after enqueue");
                    }
                    return Err("injected opening error after enqueue".into());
                }
                let wait = Instant::now();
                self.stats.opening_kernel_ns += self.timeline.record("opening_reduce", &event)?;
                self.stats.opening_kernel_wait_ns += wait.elapsed().as_nanos();
                self.stats.opening_tiles += 1;
            }
        }
        let mut result = Vec::with_capacity(outputs.len());
        for (height, output) in plan.heights.iter().zip(&outputs).rev() {
            let mut values = Vec::with_capacity(*height);
            for row0 in (0..*height).step_by(plan.rows) {
                let rows = plan.rows.min(height - row0);
                let mut event = Event::empty();
                let readback = Instant::now();
                output
                    .buffer
                    .read(&mut download[..rows * 3])
                    .offset(row0 * 3)
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.stats.opening_download_api_ns += readback.elapsed().as_nanos();
                self.stats.opening_download_device_ns +=
                    self.timeline.record("opening_download", &event)?;
                let decode = Instant::now();
                for words in download[..rows * 3].chunks_exact(3) {
                    let coefficients = [
                        Val::from_u64(words[0]),
                        Val::from_u64(words[1]),
                        Val::from_u64(words[2]),
                    ];
                    values.push(Challenge::from_basis_coefficients_slice(&coefficients).unwrap());
                }
                self.stats.opening_decode_ns += decode.elapsed().as_nanos();
                self.stats.opening_downloaded_bytes += (rows * 24) as u64;
            }
            result.push(values);
        }
        fence.finish()?;
        self.stats.opening_calls += 1;
        self.stats.opening_wall_ns += started.elapsed().as_nanos();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an OpenCL GPU and a serial <=3 GiB service"]
    fn gpu_opening_reduction_matches_cpu_all_points_and_unequal_heights() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 64 << 20,
                tile_bytes: 64 << 10,
                staging_bytes: 32 << 10,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let extension = |a, b, c| {
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(a),
                Val::from_u64(b),
                Val::from_u64(c),
            ])
            .unwrap()
        };
        let alpha = extension(2, 3, 4);
        let shapes = [(256, 7), (512, 17), (512, 257)];
        let matrices: Vec<Vec<Val>> = shapes
            .iter()
            .enumerate()
            .map(|(i, (h, w))| {
                (0..h * w)
                    .map(|j| Val::from_u64(u64::MAX - (j * 41 + i * 17) as u64))
                    .collect()
            })
            .collect();
        let denominators: Vec<Vec<Challenge>> = (0..3)
            .map(|i| {
                (0..512)
                    .map(|j| extension(j + 1, j * 7 + i, u64::MAX - j - i))
                    .collect()
            })
            .collect();
        let inputs: Vec<_> = shapes
            .iter()
            .enumerate()
            .map(|(i, (_, width))| OpeningMatrix {
                values: &matrices[i],
                width: *width,
                height: matrices[i].len() / (*width),
                terms: (0..=i)
                    .map(|j| OpeningTerm {
                        inverse_denominators: &denominators[j],
                        alpha_offset: extension(i as u64 + 3, j as u64 + 4, 5),
                        opened: extension(j as u64 + 13, 17, i as u64 + 19),
                    })
                    .collect(),
            })
            .collect();
        let mut expected = BTreeMap::<usize, Vec<Challenge>>::new();
        for input in &inputs {
            let height = input.height;
            let output = expected
                .entry(height)
                .or_insert_with(|| vec![Challenge::ZERO; height]);
            for (row, values) in input.values.chunks_exact(input.width).enumerate() {
                let compressed = values
                    .iter()
                    .zip(alpha.powers())
                    .fold(Challenge::ZERO, |sum, (value, weight)| {
                        sum + weight * *value
                    });
                for term in &input.terms {
                    output[row] += term.alpha_offset
                        * (term.opened - compressed)
                        * term.inverse_denominators[row];
                }
            }
        }
        let before = super::super::report("opening reduction before").unwrap();
        let actual = reduce(&inputs, alpha).unwrap();
        assert_eq!(actual, expected.into_values().rev().collect::<Vec<_>>());
        let after = super::super::report("opening reduction after").unwrap();
        assert_eq!(after.opening_calls - before.opening_calls, 1);
        assert!(after.opening_tiles - before.opening_tiles > 3);
        assert_eq!(
            after.opening_downloaded_bytes - before.opening_downloaded_bytes,
            (256 + 512) * 24
        );
        let uploaded: usize = inputs
            .iter()
            .map(|input| {
                input.values.len() * 8
                    + input.width * 24
                    + input.terms.len() * 48
                    + input.values.len() / input.width * input.terms.len() * 24
            })
            .sum();
        assert_eq!(
            after.opening_uploaded_bytes - before.opening_uploaded_bytes,
            uploaded as u64
        );
        assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
        assert!(after.opening_marshal_ns > before.opening_marshal_ns);
        assert!(after.opening_upload_api_ns > before.opening_upload_api_ns);
        assert!(after.opening_upload_device_ns > before.opening_upload_device_ns);
        assert!(after.opening_kernel_build_ns > before.opening_kernel_build_ns);
        assert!(after.opening_kernel_enqueue_ns > before.opening_kernel_enqueue_ns);
        assert!(after.opening_kernel_wait_ns > before.opening_kernel_wait_ns);
        assert!(after.opening_download_api_ns > before.opening_download_api_ns);
        assert!(after.opening_download_device_ns > before.opening_download_device_ns);
        assert!(after.opening_decode_ns > before.opening_decode_ns);
        // Host/API and device intervals overlap; their sum is not wall time.

        // Simulate an occupied aggregate allowance without allocating a large
        // matrix or weakening admission. Failure must precede any new allocation.
        let lease = {
            let guard = ENGINE.get().unwrap().lock().unwrap();
            let e = guard.as_ref().unwrap();
            let live = e.accounting.lock().unwrap().live;
            super::super::reserve(
                &e.accounting,
                e.limits.managed_bytes - live,
                e.limits.managed_bytes,
            )
            .unwrap()
        };
        let allocations = super::super::report("opening admission before")
            .unwrap()
            .allocations;
        assert!(reduce(&inputs, alpha).is_err());
        assert_eq!(
            super::super::report("opening admission after")
                .unwrap()
                .allocations,
            allocations
        );
        drop(lease);
        assert_eq!(reduce(&inputs, alpha).unwrap(), actual);
    }

    #[test]
    #[ignore = "requires an OpenCL GPU and a serial <=3 GiB service"]
    fn gpu_opening_pinned_partial_chunks_match_pageable_and_cpu_without_extra_allocations() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 16 << 20,
                tile_bytes: 64 << 10,
                // Deliberately splits rows, cubic coefficients and final chunks.
                staging_bytes: 127 * 8,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let height = 128;
        let width = 7;
        let values: Vec<_> = (0..height * width)
            .map(|i| Val::from_u64(u64::MAX - i as u64))
            .collect();
        let denominators: Vec<_> = (0..height)
            .map(|row| Challenge::from_u64(row as u64 + 1))
            .collect();
        let alpha = Challenge::from_basis_coefficients_slice(&[
            Val::from_u64(2),
            Val::from_u64(3),
            Val::from_u64(4),
        ])
        .unwrap();
        let input = OpeningMatrix {
            values: &values,
            width,
            height: values.len() / (width),
            terms: vec![
                OpeningTerm {
                    inverse_denominators: &denominators,
                    alpha_offset: Challenge::from_u64(3),
                    opened: Challenge::from_u64(11),
                },
                OpeningTerm {
                    inverse_denominators: &denominators,
                    alpha_offset: alpha,
                    opened: Challenge::from_u64(13),
                },
            ],
        };
        let expected: Vec<_> = values
            .chunks_exact(width)
            .enumerate()
            .map(|(row, values)| {
                let compressed = values
                    .iter()
                    .zip(alpha.powers())
                    .fold(Challenge::ZERO, |sum, (value, weight)| {
                        sum + weight * *value
                    });
                input.terms.iter().fold(Challenge::ZERO, |sum, term| {
                    sum + term.alpha_offset
                        * (term.opened - compressed)
                        * term.inverse_denominators[row]
                })
            })
            .collect();
        let mut guard = ENGINE.get().unwrap().lock().unwrap();
        let engine = guard.as_mut().unwrap();
        let mut allocation_counts = Vec::new();
        // Return to pageable after pinned to detect dirty staging/workspace reuse.
        for pinned in [false, true, false] {
            let before = engine.snapshot();
            let actual = engine
                .reduce_openings_with_upload(std::slice::from_ref(&input), alpha, pinned)
                .unwrap();
            let after = engine.snapshot();
            assert_eq!(actual, vec![expected.clone()]);
            assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
            allocation_counts.push(after.allocations - before.allocations);
            assert_eq!(
                after.opening_pinned_uploaded_bytes - before.opening_pinned_uploaded_bytes,
                if pinned {
                    (values.len() * 8 + height * input.terms.len() * 24) as u64
                } else {
                    0
                }
            );
            assert_eq!(
                after.opening_pinned_upload_chunks > before.opening_pinned_upload_chunks,
                pinned
            );
            if pinned {
                assert!(
                    after.opening_pinned_upload_chunks - before.opening_pinned_upload_chunks
                        > after.opening_tiles - before.opening_tiles
                );
            }
        }
        assert!(allocation_counts.windows(2).all(|pair| pair[0] == pair[1]));
        let destination = allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            8,
            ocl::flags::MEM_READ_WRITE,
        )
        .unwrap();
        for words in [0, 9] {
            assert!(engine
                .upload_opening_pinned(&destination, words, |_, _| panic!(
                    "must reject before fill"
                ))
                .is_err());
        }
    }

    #[test]
    #[ignore = "requires LATTICA_V2_OPENING_PROFILE=1, an OpenCL GPU and a serial <=3 GiB service"]
    fn gpu_opening_large_input_reports_host_device_costs_with_closed_form_reference() {
        assert_eq!(
            std::env::var("LATTICA_V2_OPENING_PROFILE").as_deref(),
            Ok("1"),
            "explicit bounded diagnostic opt-in required"
        );
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 128 << 20,
                tile_bytes: 32 << 20,
                staging_bytes: 16 << 20,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let extension = |a, b, c| {
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(a),
                Val::from_u64(b),
                Val::from_u64(c),
            ])
            .unwrap()
        };
        let height = 1usize << 20;
        let width = 200usize;
        let alpha = extension(2, 3, 4);
        let row_scale = Val::from_u64(u64::MAX - 917);
        let column_scale = Val::from_u64(Val::ORDER_U64 / 2 + 17);
        let constant = Val::from_u64(u64::MAX - 13);
        let columns: Vec<_> = (0..width)
            .map(|column| column_scale * Val::from_usize(column))
            .collect();
        let prepare = Instant::now();
        // Exact capacity avoids geometric growth temporarily doubling this
        // 1.5625 GiB allocation under the diagnostic's 3 GiB cgroup limit.
        let mut values = Vec::with_capacity(height * width);
        for row in 0..height {
            let base = constant + row_scale * Val::from_usize(row);
            values.extend(columns.iter().map(|column| base + *column));
        }
        // Supplied public reduction coefficients, not denominators sampled
        // from a real FRI transcript. This diagnoses an arithmetic component.
        let denominators: Vec<Vec<Challenge>> = (0..2)
            .map(|point| {
                (0..height)
                    .map(|row| extension(row as u64 + 1, 7 + point, u64::MAX - point))
                    .collect()
            })
            .collect();
        let input = OpeningMatrix {
            values: &values,
            width,
            height: values.len() / (width),
            terms: (0..2)
                .map(|point| OpeningTerm {
                    inverse_denominators: &denominators[point],
                    alpha_offset: extension(point as u64 + 3, 4, 5),
                    opened: extension(point as u64 + 13, 17, 19),
                })
                .collect(),
        };
        // For M[row,col] = base(row) + column(col), the compression is
        // base(row) * sum(alpha^col) + sum(alpha^col * column(col)). This
        // independent closed form checks every row without another wide scan.
        let (weight_sum, column_sum) = alpha.powers().zip(&columns).fold(
            (Challenge::ZERO, Challenge::ZERO),
            |(weights, weighted_columns), (weight, column)| {
                (weights + weight, weighted_columns + weight * *column)
            },
        );
        let prepare_ns = prepare.elapsed().as_nanos();
        let before = super::super::report("large opening diagnostic before").unwrap();
        let measured = Instant::now();
        let actual = reduce(std::slice::from_ref(&input), alpha).unwrap();
        let measured_ns = measured.elapsed().as_nanos();
        let after = super::super::report("large opening diagnostic after").unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].len(), height);
        let verify = Instant::now();
        for (row, actual_row) in actual[0].iter().enumerate() {
            let base = constant + row_scale * Val::from_usize(row);
            let compressed = weight_sum * base + column_sum;
            let expected = input.terms.iter().fold(Challenge::ZERO, |sum, term| {
                sum + term.alpha_offset
                    * (term.opened - compressed)
                    * term.inverse_denominators[row]
            });
            assert_eq!(*actual_row, expected, "opening row {row}");
        }
        let verify_ns = verify.elapsed().as_nanos();
        let expected_upload_bytes = values.len() * 8
            + width * 24
            + input.terms.len() * 48
            + height * input.terms.len() * 24;
        assert_eq!(after.opening_calls - before.opening_calls, 1);
        assert!(after.opening_tiles - before.opening_tiles > 1);
        assert_eq!(
            after.opening_uploaded_bytes - before.opening_uploaded_bytes,
            expected_upload_bytes as u64
        );
        assert_eq!(
            after.opening_downloaded_bytes - before.opening_downloaded_bytes,
            (height * 24) as u64
        );
        assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
        assert!(after.managed_peak_bytes <= 128 << 20);
        let pinned_uploads = super::super::switch("LATTICA_V2_GPU_OPENING_PINNED").unwrap();
        assert_eq!(
            after.opening_pinned_uploaded_bytes - before.opening_pinned_uploaded_bytes,
            if pinned_uploads {
                (values.len() * 8 + height * input.terms.len() * 24) as u64
            } else {
                0
            }
        );
        assert_eq!(
            after.opening_pinned_upload_chunks > before.opening_pinned_upload_chunks,
            pinned_uploads
        );
        println!(
            "opening_large_input=PASS pinned_uploads={pinned_uploads} height={height} width={width} input_bytes={} checked_rows={height} prepare_ns={prepare_ns} reduce_ns={measured_ns} reference_ns={verify_ns} isolated_component=true full_proof=false production_ready=false timings=nonadditive",
            values.len() * std::mem::size_of::<Val>()
        );
    }

    #[test]
    fn opening_plan_bounds_every_matrix_point_and_workspace() {
        let values = vec![Val::ONE; 256 * 7];
        let denominators = vec![Challenge::ONE; 256];
        let mut input = OpeningMatrix {
            values: &values,
            width: 7,
            height: values.len() / (7),
            terms: vec![OpeningTerm {
                inverse_denominators: &denominators,
                alpha_offset: Challenge::ONE,
                opened: Challenge::ZERO,
            }],
        };
        let plan = Plan::new(std::slice::from_ref(&input), 4096, 1 << 20).unwrap();
        assert_eq!(plan.heights, [256]);
        assert!(plan.rows > 0 && plan.rows < 256);
        assert!(plan.total_bytes <= 256 * 24 + 4096 + 7 * 24 + 48);
        assert!(Plan::new(&[], 4096, 1 << 20).is_err());
        assert!(Plan::new(std::slice::from_ref(&input), 1, 1 << 20).is_err());
        assert!(Plan::new(std::slice::from_ref(&input), 4096, 4096).is_err());
        input.terms[0].inverse_denominators = &denominators[..255];
        assert!(Plan::new(std::slice::from_ref(&input), 4096, 1 << 20).is_err());
        input.terms.clear();
        assert!(Plan::new(std::slice::from_ref(&input), 4096, 1 << 20).is_err());
        input.width = 0;
        assert!(Plan::new(std::slice::from_ref(&input), 4096, 1 << 20).is_err());
    }
}
