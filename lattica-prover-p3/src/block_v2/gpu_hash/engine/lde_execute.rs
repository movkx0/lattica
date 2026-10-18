//! Experimental, synchronous coset-LDE -> resident commitment execution.
//! This is a research seam, not a PCS replacement. Inputs and explicit salts
//! belong to one proof attempt. Returned matrices are physical bit-reversed LDEs.
//! Every device allocation uses the existing engine's accounting and lease.
use super::{
    allocation,
    lde_plan::{InputShape, LdeCommitPlan, LdeRetention},
    lde_readback::HostReadback,
    plan_slots, retained_layout, Allocation, Engine, RetainedTree, ENGINE,
};
use crate::block_v2::compute;
use crate::config::Val;
use compute::{Buffer, Event};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::*;
use std::time::Instant;

pub(super) const KERNEL_SRC: &str = r#"
// Absorb an uninterrupted column stream. A tile or matrix boundary is NOT a
// sponge boundary; only every fourth word permutes. The final partial block is
// permuted once by lde_leaf_finalize, preserving the padding-free CPU sponge.
__kernel void lde_absorb(__global const ulong *input, __global ulong *states,
    uint row0, uint rows, uint width, uint rate_offset,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong s[8];
    size_t state_base = ((size_t)row0 + row) * 8;
    for (uint k = 0; k < 8; ++k) s[k] = states[state_base + k];
    uint at = rate_offset;
    for (uint col = 0; col < width; ++col) {
        s[at++] = input[row * (size_t)width + col];
        if (at == 4) { perm8(s, rci, rcp, rcf, diag); at = 0; }
    }
    for (uint k = 0; k < 8; ++k) states[state_base + k] = s[k];
}
__kernel void lde_leaf_finalize(__global const ulong *states, __global ulong *leaves,
    uint height, uint rate_offset, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0);
    if (row >= height) return;
    ulong s[8];
    for (uint k = 0; k < 8; ++k) s[k] = states[row * 8 + k];
    if (rate_offset != 0) perm8(s, rci, rcp, rcf, diag);
    for (uint k = 0; k < 4; ++k) leaves[row * 4 + k] = gl_canon(s[k]);
}
// IDFT already multiplied coefficient i by (generator / domain_shift)^i.
// This applies the same balanced hiding polynomial as CPU fused_ldes.
__kernel void quotient_mask(__global ulong *coefficients, __global const ulong *masks,
    uint height, uint width, ulong generator, ulong ratio_h) {
    size_t index = get_global_id(0);
    size_t elements = (size_t)height * width;
    if (index >= elements) return;
    ulong masked = gl_mul(masks[index], gl_pow(generator, (ulong)(index / width)));
    coefficients[index] = gl_sub(coefficients[index], masked);
    coefficients[elements + index] = gl_mul(ratio_h, masked);
}
"#;

/// Natural-order evaluations and per-output-row salts. The caller must supply
/// fresh proof-attempt randomness; this API neither generates nor caches it.
#[derive(Clone, Copy)]
pub struct LdeInput<'a> {
    pub evaluations: &'a RowMajorMatrix<Val>,
    pub salts: &'a RowMajorMatrix<Val>,
    pub added_bits: usize,
    pub shift: Val,
}

#[derive(Clone, Copy)]
enum CommitSource<'a> {
    Trace(&'a super::device::TraceCommitInput),
    Evaluations(&'a super::device::EvaluationInput),
    Host {
        evaluations: &'a RowMajorMatrix<Val>,
        shift: Val,
    },
    Quotient {
        input: &'a super::device::QuotientCommitInput,
        chunk: usize,
    },
}

struct CommitInput<'a> {
    source: CommitSource<'a>,
    salts: SaltInput<'a>,
    shape: InputShape,
}

#[derive(Clone, Copy)]
pub(crate) enum SaltInput<'a> {
    Host(&'a RowMajorMatrix<Val>),
    Device(&'a super::device::DeviceMatrix),
    Replay(&'a super::device::ReplaySalts),
}
impl SaltInput<'_> {
    fn validate(
        self,
        height: usize,
        session: Option<&super::device::DeviceSession>,
        engine: &Engine,
    ) -> Result<(), String> {
        match self {
            Self::Host(matrix)
                if matrix.width == 4 && height.checked_mul(4) == Some(matrix.values.len()) =>
            {
                Ok(())
            }
            Self::Host(_) => Err("commitment salts must cover every output row".into()),
            Self::Replay(recipe) => {
                recipe.check_session(session.ok_or("replay salts require an owning session")?)?;
                recipe.check_engine(engine)?;
                let spec = recipe.spec();
                if spec.rows() != height
                    || spec.columns() != 4
                    || spec.extension() != super::device::Extension::Base
                    || spec.order() != super::device::RowOrder::BitReversed
                    || spec.shift() != 1
                {
                    return Err("replay salt geometry does not match committed rows".into());
                }
                Ok(())
            }
            Self::Device(matrix) => {
                matrix.check_session(session.ok_or("device salts require an owning session")?)?;
                matrix.check_engine(engine)?;
                let spec = matrix.spec();
                if spec.rows() != height
                    || spec.columns() != 4
                    || spec.extension() != super::device::Extension::Base
                    || spec.order() != super::device::RowOrder::BitReversed
                    || spec.shift() != 1
                {
                    return Err("device salt geometry does not match committed rows".into());
                }
                Ok(())
            }
        }
    }
}

/// Host readback remains explicit until quotient/opening consumers move to the
/// device. Neither the allocation plan nor this output measures whole-job RSS.
pub struct LdeCommitOutput {
    pub matrices: Vec<RowMajorMatrix<Val>>,
    pub(crate) prefixes: Vec<super::super::prefix_storage::PrefixMatrix>,
    pub plan: LdeCommitPlan,
    pub(crate) tree: RetainedTree,
    pub(crate) device_matrices: Vec<super::device::DeviceMatrix>,
    cap_height: usize,
}
impl LdeCommitOutput {
    pub fn cap(&self) -> &[[Val; 4]] {
        self.tree.cap()
    }
    pub fn open(&self, index: usize) -> Result<Vec<[Val; 4]>, String> {
        self.tree.open(index, self.cap_height)
    }
}

fn validate_inputs(inputs: &[LdeInput<'_>]) -> Result<Vec<InputShape>, String> {
    inputs
        .iter()
        .map(|input| {
            let matrix = input.evaluations;
            if matrix.width == 0 || matrix.values.len() % matrix.width != 0 {
                return Err("LDE input matrix storage is not rectangular".into());
            }
            let height = matrix.values.len() / matrix.width;
            if height < 2
                || !height.is_power_of_two()
                || input.added_bits >= 32
                || input.shift == Val::ZERO
            {
                return Err("LDE input transform domain is invalid".into());
            }
            let output_height = height
                .checked_mul(
                    1usize
                        .checked_shl(input.added_bits as u32)
                        .ok_or("LDE output overflow")?,
                )
                .ok_or("LDE output overflow")?;
            if input.salts.width != 4
                || output_height.checked_mul(4) != Some(input.salts.values.len())
            {
                return Err("LDE salts must be exactly four words per output row".into());
            }
            Ok(InputShape {
                height,
                width: matrix.width,
                added_bits: input.added_bits,
            })
        })
        .collect()
}

/// Holds the engine mutex from fresh planning through reservations, kernels and
/// drain. Existing retained trees stay live and count against the same budget.
pub fn coset_lde_commit(
    inputs: &[LdeInput<'_>],
    cap_height: usize,
    host_output_budget_bytes: usize,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    slot.as_mut()
        .ok_or("GPU hashing shut down")?
        .coset_lde_commit(inputs, cap_height, host_output_budget_bytes)
}

/// Commit quotient chunks after CPU generation of the balanced hiding masks.
/// Inputs and masks belong to this attempt; the device never draws randomness.

/// Kernel scheduling shared with the existing tiled-NTT arithmetic, without
/// borrowing that module's separate context or allocator.
fn ntt_groups(
    height: usize,
    width: usize,
    max_column_bits: usize,
    tile_log2: usize,
) -> Result<Vec<(usize, usize, usize)>, String> {
    if height < 2
        || !height.is_power_of_two()
        || height > u32::MAX as usize
        || width == 0
        || width > u32::MAX as usize
        || !(3..=4).contains(&max_column_bits)
        || !(10..=12).contains(&tile_log2)
    {
        return Err("unsupported resident NTT geometry".into());
    }
    let log_h = height.trailing_zeros() as usize;
    let log_c = width
        .checked_next_power_of_two()
        .ok_or("NTT column overflow")?
        .trailing_zeros()
        .min(max_column_bits as u32) as usize;
    let cap = (tile_log2 - log_c).min(log_h);
    let groups = log_h.div_ceil(cap);
    let (base, extra) = (log_h / groups, log_h % groups);
    let mut stage = 0;
    Ok((0..groups)
        .map(|group| {
            let count = base + usize::from(group < extra);
            let item = (stage, count, log_c);
            stage += count;
            item
        })
        .collect())
}

/// The last NTT store may also retain canonical rows without a scatter pass.
/// This destination is a separate allocation, and each output cell has one writer.
#[derive(Clone, Copy)]
pub(super) struct NttPrefix<'a> {
    buffer: &'a Buffer<u64>,
    width: usize,
    first: usize,
    height: usize,
}

pub(super) struct TransformBuffers {
    a: Allocation,
    b: Allocation,
    sponge: Allocation,
    forward: Allocation,
    inverse: Allocation,
}

impl TransformBuffers {
    pub(super) fn bytes(&self) -> usize {
        [&self.a, &self.b, &self.sponge, &self.forward, &self.inverse]
            .into_iter()
            .map(|a| a.buffer.len() * 8)
            .sum()
    }

    fn matches(&self, plan: &LdeCommitPlan) -> bool {
        self.a.buffer.len() * 8 == plan.transform_buffer_bytes
            && self.b.buffer.len() * 8 == plan.transform_buffer_bytes
            && self.sponge.buffer.len() * 8 == plan.sponge_state_bytes
            && self.forward.buffer.len() * 16 == plan.twiddle_bytes
            && self.inverse.buffer.len() * 16 == plan.twiddle_bytes
    }
}

impl Engine {
    pub(super) fn lde_upload_rows(
        &mut self,
        buffer: &Buffer<u64>,
        rows: usize,
        width: usize,
        fill: impl Fn(usize, &mut [u64]) + Sync,
    ) -> Result<(), String> {
        let started = Instant::now();
        let chunk_rows = self.staging[0].map.len() / width;
        if chunk_rows == 0 || rows.checked_mul(width).is_none_or(|n| n > buffer.len()) {
            return Err("resident LDE upload bounds".into());
        }
        for row0 in (0..rows).step_by(chunk_rows) {
            let count = chunk_rows.min(rows - row0);
            let marshal = Instant::now();
            self.staging[0].map[..count * width]
                .par_chunks_mut(width)
                .enumerate()
                .for_each(|(i, dst)| fill(row0 + i, dst));
            self.stats.marshal_ns += marshal.elapsed().as_nanos();
            let transfer = Instant::now();
            let mut event = Event::empty();
            buffer
                .write(&self.staging[0].map[..count * width])
                .offset(row0 * width)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
            self.stats.upload_device_ns += self.timeline.record("lde_upload", &event)?;
            self.stats.uploaded_bytes += (count * width * 8) as u64;
        }
        self.stats.upload_and_marshal_ns += started.elapsed().as_nanos();
        Ok(())
    }

    fn lde_read_columns(
        &mut self,
        buffer: &Buffer<u64>,
        output: &mut impl super::lde_readback::ColumnReadback,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        let started = Instant::now();
        let height = output.height();
        if columns == 0 {
            return Err("resident LDE readback columns must be nonzero".into());
        }
        let chunk_rows = self.staging[0].map.len() / columns;
        if chunk_rows == 0 || height.checked_mul(columns).is_none_or(|n| n > buffer.len()) {
            return Err("resident LDE readback bounds".into());
        }
        for row0 in (0..height).step_by(chunk_rows) {
            let count = chunk_rows.min(height - row0);
            let transfer = Instant::now();
            let mut event = Event::empty();
            buffer
                .read(&mut self.staging[0].map[..count * columns])
                .offset(row0 * columns)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.download_wall_ns += transfer.elapsed().as_nanos();
            self.stats.download_device_ns += self.timeline.record("lde_download", &event)?;
            let decode = Instant::now();
            output.append_rows(
                first,
                columns,
                row0,
                &self.staging[0].map[..count * columns],
            )?;
            self.stats.decode_ns += decode.elapsed().as_nanos();
            if output.uses_parallel_decode(count * columns) {
                self.stats.lde_parallel_decode_bytes += (count * columns * 8) as u64;
                self.stats.lde_parallel_decode_chunks += 1;
            }
            self.stats.downloaded_bytes += (count * columns * 8) as u64;
            self.stats.lde_host_output_bytes += (count * columns * 8) as u64;
        }
        self.stats.download_and_decode_ns += started.elapsed().as_nanos();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn lde_ntt(
        &mut self,
        src: &Buffer<u64>,
        dst: &Buffer<u64>,
        roots: &Buffer<u64>,
        inverse: bool,
        height: usize,
        width: usize,
        post_c: u64,
        post_b: u64,
        canonical: bool,
        bit_reversed: bool,
        opening: bool,
        prefix: Option<NttPrefix<'_>>,
    ) -> Result<bool, String> {
        #[cfg(feature = "gpu-metal")]
        let tile_log2 = self.pq.ntt_tile_log2();
        #[cfg(feature = "gpu")]
        let tile_log2 = 12;
        let log_h = height.trailing_zeros() as usize;
        #[cfg(feature = "gpu")]
        let max_column_bits =
            crate::gpu::ntt_cache::max_column_bits(self.pq.device(), log_h, width);
        #[cfg(feature = "gpu-metal")]
        let max_column_bits = 4;
        let groups = ntt_groups(height, width, max_column_bits, tile_log2)?;
        if height
            .checked_mul(width)
            .is_none_or(|n| n > src.len() || n > dst.len())
            || roots.len() < log_h
        {
            return Err("resident NTT buffer bounds".into());
        }
        if let Some(p) = prefix {
            if !bit_reversed
                || !canonical
                || p.height > height
                || p.width > u32::MAX as usize
                || p.first.checked_add(width).is_none_or(|n| n > p.width)
                || p.height
                    .checked_mul(p.width)
                    .is_none_or(|n| n > p.buffer.len())
            {
                return Err("NTT prefix bounds or canonical layout".into());
            }
        }
        #[cfg(feature = "gpu-metal")]
        let tables = self.pq.ntt_tables(roots, inverse, height, post_c, post_b)?;
        #[cfg(feature = "gpu")]
        {
            let _ = inverse;
            if prefix.is_some() {
                return Err("fused NTT prefix stores require Metal".into());
            }
        }
        let mut in_dst = true;
        for (group, &(stage, count, log_c)) in groups.iter().enumerate() {
            let last = group + 1 == groups.len();
            let (input, output) = match (group == 0, last && bit_reversed) {
                (true, _) => (src, dst),
                (false, true) => (dst, src),
                (false, false) => (dst, dst),
            };
            if last {
                in_dst = std::ptr::eq(output, dst);
            }
            let local_elements = 1usize << (count + log_c);
            #[cfg(feature = "gpu-metal")]
            let max_group = self.pq.workgroup();
            #[cfg(feature = "gpu")]
            let max_group = 256;
            let workgroup = (local_elements / 2).clamp(32, max_group);
            let workgroups = (height >> count) * width.div_ceil(1 << log_c);
            let mut event = Event::empty();
            #[cfg(feature = "gpu")]
            let power_words = crate::gpu::ntt_cache::power_words(
                count,
                log_c,
                last && (post_c != 1 || post_b != 1),
            );
            #[cfg(feature = "gpu-metal")]
            let power_words: Option<usize> = None;
            #[cfg(feature = "gpu")]
            let kernel_name = if power_words.is_some() {
                if self.nvidia_shuffle && self.tuning.ntt_powers(height, width) {
                    "ntt_tile_cached_tuned"
                } else { "ntt_tile_cached" }
            } else {
                "ntt_tile"
            };
            #[cfg(feature = "gpu-metal")]
            let kernel_name = match (tables.is_some(), last && prefix.is_some()) {
                (true, true) => "ntt_tile_cached_prefix",
                (false, true) => "ntt_tile_prefix",
                (true, false) => "ntt_tile_cached",
                (false, false) => "ntt_tile",
            };
            // SAFETY: whole independent columns, bounded u32 row/column indexing,
            // <=32 KiB total local storage and distinct permutation buffers.
            unsafe {
                // OpenCL mutates its builder; the Metal wrapper consumes it.
                #[cfg(feature = "gpu")]
                let mut builder = self.pq.kernel_builder(kernel_name);
                #[cfg(feature = "gpu-metal")]
                let builder = self.pq.kernel_builder(kernel_name);
                let builder = builder
                    .arg(input)
                    .arg(output)
                    .arg(width as u32)
                    .arg(height as u32)
                    .arg(stage as u32)
                    .arg(count as u32)
                    .arg(log_c as u32)
                    .arg(u32::from(group == 0))
                    .arg(log_h as u32)
                    .arg(u32::from(last && canonical))
                    .arg(u32::from(last && bit_reversed))
                    .arg(if last { post_c } else { 1 })
                    .arg(if last { post_b } else { 1 })
                    .arg(roots);
                #[cfg(feature = "gpu-metal")]
                let builder = if let Some(tables) = &tables {
                    builder.arg(tables)
                } else {
                    builder
                };
                #[cfg(feature = "gpu-metal")]
                let builder = if let Some(p) = prefix.filter(|_| last) {
                    builder
                        .arg(p.buffer)
                        .arg(p.width as u32)
                        .arg(p.first as u32)
                        .arg(p.height as u32)
                } else {
                    builder
                };
                let builder = builder
                    .arg_local::<u64>(local_elements)
                    .global_work_size(workgroups * workgroup)
                    .local_work_size(workgroup);
                #[cfg(feature = "gpu")]
                if let Some(words) = power_words {
                    builder.arg_local::<u64>(words);
                }
                let kernel = builder.build().map_err(|e| e.to_string())?;
                let command = kernel.cmd().enew(&mut event);
                #[cfg(test)]
                let command = if let Some(gate) = self.lde_gate.as_ref() {
                    command.ewait(gate)
                } else {
                    command
                };
                command.enq().map_err(|e| e.to_string())?;
            }
            #[cfg(test)]
            if let Some(unwind) = self.fail_lde_after_enqueue.take() {
                self.injected_event = Some(event.clone());
                if let Some(notify) = self.lde_submitted.take() {
                    use compute::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
                    assert!(!matches!(
                        event.info(EventInfo::CommandExecutionStatus).unwrap(),
                        EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
                    ));
                    notify.send(()).unwrap();
                }
                if unwind {
                    panic!("injected unwind after resident NTT enqueue");
                }
                return Err("injected error after resident NTT enqueue".into());
            }
            self.stats.lde_transform_ns += self
                .timeline
                .record(if opening { "opening_ntt" } else { "lde_ntt" }, &event)?;
        }
        Ok(in_dst)
    }

    pub(super) fn lde_absorb(
        &mut self,
        input: &Buffer<u64>,
        sponge: &Buffer<u64>,
        row0: usize,
        rows: usize,
        columns: usize,
        rate_offset: usize,
    ) -> Result<(), String> {
        if rate_offset >= 4
            || columns == 0
            || rows.checked_mul(columns).is_none_or(|n| n > input.len())
            || row0
                .checked_add(rows)
                .and_then(|n| n.checked_mul(8))
                .is_none_or(|n| n > sponge.len())
        {
            return Err("resident sponge bounds".into());
        }
        let mut event = Event::empty();
        // SAFETY: each work item owns one bounded eight-word row state.
        unsafe {
            self.commitment_builder("lde_absorb", rows)?
                .arg(input)
                .arg(sponge)
                .arg(row0 as u32)
                .arg(rows as u32)
                .arg(columns as u32)
                .arg(rate_offset as u32)
                .arg(&self.constants[0].buffer)
                .arg(&self.constants[1].buffer)
                .arg(&self.constants[2].buffer)
                .arg(&self.constants[3].buffer)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = self.timeline.record("lde_absorb", &event)?;
        self.stats.lde_sponge_ns += ns;
        self.stats.leaf_kernel_ns += ns;
        Ok(())
    }

    pub(super) fn coset_lde_commit(
        &mut self,
        inputs: &[LdeInput<'_>],
        cap_height: usize,
        host_budget: usize,
    ) -> Result<LdeCommitOutput, String> {
        self.coset_lde_commit_with_masks(inputs, None, cap_height, host_budget, 0)
    }

    fn coset_lde_commit_with_masks(
        &mut self,
        inputs: &[LdeInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
        retention_bits: usize,
    ) -> Result<LdeCommitOutput, String> {
        self.coset_lde_commit_with_capture(
            inputs,
            masks,
            cap_height,
            host_budget,
            LdeRetention::HostPrefix(retention_bits),
            None,
        )
    }

    fn coset_lde_commit_with_capture(
        &mut self,
        inputs: &[LdeInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
        retention: LdeRetention,
        capture: Option<&super::device::DeviceSession>,
    ) -> Result<LdeCommitOutput, String> {
        let shapes = validate_inputs(inputs)?;
        if let Some(masks) = masks {
            if masks.len() != inputs.len()
                || masks.iter().zip(inputs).any(|(mask, input)| {
                    mask.width != input.evaluations.width
                        || mask.values.len() != input.evaluations.values.len()
                        || input.added_bits != crate::block_v2::profile::LOG_BLOWUP + 1
                })
            {
                return Err("quotient mask dimensions or hiding blowup mismatch".into());
            }
        }
        let prepared: Vec<_> = inputs
            .iter()
            .zip(shapes)
            .map(|(input, shape)| CommitInput {
                source: CommitSource::Host {
                    evaluations: input.evaluations,
                    shift: input.shift,
                },
                salts: SaltInput::Host(input.salts),
                shape,
            })
            .collect();
        self.commit_inputs(
            &prepared,
            masks,
            cap_height,
            host_budget,
            retention,
            capture,
        )
    }

    fn commit_inputs(
        &mut self,
        inputs: &[CommitInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
        retention: LdeRetention,
        capture: Option<&super::device::DeviceSession>,
    ) -> Result<LdeCommitOutput, String> {
        if let Some(session) = capture {
            session.observe_engine(self, |engine| {
                engine.commit_inputs_inner(
                    inputs,
                    masks,
                    cap_height,
                    host_budget,
                    retention,
                    capture,
                    false,
                )
            })
        } else {
            self.commit_inputs_inner(
                inputs,
                masks,
                cap_height,
                host_budget,
                retention,
                capture,
                false,
            )
        }
    }

    fn coset_lde_commit_public(
        &mut self,
        inputs: &[LdeInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
        retention_bits: usize,
        public_preprocessing: bool,
    ) -> Result<LdeCommitOutput, String> {
        if !public_preprocessing {
            return self.coset_lde_commit_with_masks(
                inputs,
                masks,
                cap_height,
                host_budget,
                retention_bits,
            );
        }
        if masks.is_some() {
            return Err("public preprocessing cannot use private masks".into());
        }
        let shapes = validate_inputs(inputs)?;
        let prepared: Vec<_> = inputs
            .iter()
            .zip(shapes)
            .map(|(input, shape)| CommitInput {
                source: CommitSource::Host {
                    evaluations: input.evaluations,
                    shift: input.shift,
                },
                salts: SaltInput::Host(input.salts),
                shape,
            })
            .collect();
        self.commit_inputs_inner(
            &prepared,
            None,
            cap_height,
            host_budget,
            LdeRetention::HostPrefix(retention_bits),
            None,
            true,
        )
    }

    fn commit_inputs_inner(
        &mut self,
        inputs: &[CommitInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
        retention: LdeRetention,
        capture: Option<&super::device::DeviceSession>,
        public_preprocessing: bool,
    ) -> Result<LdeCommitOutput, String> {
        let retention_bits = match retention {
            LdeRetention::HostPrefix(bits) => bits,
            LdeRetention::DeviceOnly => 0,
        };
        let started = Instant::now();
        let shapes: Vec<_> = inputs.iter().map(|input| input.shape).collect();
        let masked = masks.is_some()
            || inputs
                .iter()
                .any(|input| matches!(input.source, CommitSource::Quotient { .. }));
        super::validate_device_retention(&shapes, retention, capture.map(|_| usize::from(masked)))?;
        if capture.is_some() && !cfg!(feature = "gpu") {
            return Err("owned LDE capture requires an OpenCL transform".into());
        }
        let parallel_readback = super::switch("LATTICA_V2_GPU_PARALLEL_READBACK")?;
        if !self.retain_trees {
            return Err("resident LDE requires retained commitments".into());
        }
        let live = self
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live
            .checked_sub(
                self.lde_workspace
                    .as_ref()
                    .map_or(0, TransformBuffers::bytes),
            )
            .ok_or("cached LDE accounting underflow")?;
        let old_workspace = self.workspace.as_ref().map_or(0, super::Workspace::bytes);
        let execution_limits = self.lde_limits(&shapes)?;
        let capture_shapes = super::device_capture_shapes(&shapes, usize::from(masked))?;
        let device_specs = if capture.is_some() {
            super::device::capture_specs(&capture_shapes)?
        } else {
            Vec::new()
        };
        let device_bytes = if capture.is_some() {
            super::device_capture_bytes(&capture_shapes, self.max_alloc)?
        } else {
            0
        };
        let replay_bytes = inputs.iter().try_fold(0usize, |peak, input| {
            Ok::<_, String>(peak.max(match input.salts {
                SaltInput::Replay(recipe) => recipe.workspace_bytes(self)?,
                _ => 0,
            }))
        })?;
        let mut plan = LdeCommitPlan::new_with_retention(
            &shapes,
            cap_height,
            execution_limits,
            self.max_alloc,
            self.mode.slots(),
            live.checked_add(device_bytes)
                .and_then(|bytes| bytes.checked_add(replay_bytes))
                .ok_or("owned LDE capture budget overflow")?,
            old_workspace,
            host_budget,
            retention,
            super::lde_readback::ReadbackLayout::from_env()?,
        )?;
        plan.device_output_bytes = device_bytes;
        let height = plan.output_height();
        for input in inputs {
            input.salts.validate(height, capture, self)?;
        }
        // Admission telemetry only: this snapshot does not attest to completed
        // arithmetic. Transform tiles consume spare assigned memory, so the
        // fixed/live terms must be preserved when deriving worker phase plans.
        eprintln!(
            "bounded_gpu_lde_plan {}",
            serde_json::json!({
                "schema": "lattica-lde-plan-v1",
                "managed_cap_bytes": self.limits.managed_bytes,
                "max_allocation_bytes": self.max_alloc,
                "inputs": shapes.iter().map(|s| serde_json::json!({
                    "rows": s.height, "columns": s.width, "added_bits": s.added_bits,
                })).collect::<Vec<_>>(),
                "output_rows": height,
                "live_without_transform_bytes": live,
                "replaced_hash_workspace_bytes": old_workspace,
                "owned_output_bytes": device_bytes,
                "replay_workspace_bytes": replay_bytes,
                "hash_workspace_bytes": plan.hash_workspace_bytes,
                "retained_tree_bytes": plan.retained_tree_bytes,
                "sponge_state_bytes": plan.sponge_state_bytes,
                "twiddle_bytes": plan.twiddle_bytes,
                "query_reserve_bytes": plan.query_reserve_bytes,
                "fixed_bytes": plan.predicted_managed_peak_bytes - 2 * plan.transform_buffer_bytes,
                "columns_per_tile": plan.columns_per_tile(),
                "transform_buffer_bytes": plan.transform_buffer_bytes,
                "predicted_managed_peak_bytes": plan.predicted_managed_peak_bytes,
                "predicted_host_peak_bytes": plan.predicted_host_peak_bytes,
                "host_output_payload_bytes": plan.host_output_bytes,
                "host_output_backing_bytes": plan.host_output_backing_bytes,
                "host_reorder_payload_bytes": plan.host_reorder_workspace_bytes,
                "host_reorder_backing_bytes": plan.host_reorder_backing_bytes,
                "host_budget_bytes": host_budget,
            })
        );
        eprintln!(
            "bounded_lde_readback_layout layout={:?} retention={:?} matrices={} output_bytes={} reorder_workspace_bytes={}",
            plan.readback_layout,
            plan.retention,
            shapes.len(),
            plan.host_output_bytes,
            plan.host_reorder_workspace_bytes,
        );
        if masked {
            if masks.is_none()
                && inputs
                    .iter()
                    .all(|input| matches!(input.source, CommitSource::Quotient { .. }))
            {
                plan.validate_quotient_batch_storage(inputs.len())?;
            } else {
                plan.validate_quotient_storage()?;
            }
            eprintln!(
                "bounded_quotient_storage_plan matrices={} height={height} heap_output_bytes={} reorder_workspace_bytes={} host_peak_allowance_bytes={} caller_host_budget_bytes={host_budget}",
                shapes.len(),
                plan.host_output_bytes,
                plan.host_reorder_workspace_bytes,
                plan.predicted_host_peak_bytes,
            );
        }
        let width = shapes
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.width)?.checked_add(4))
            .ok_or("resident LDE row width overflow")?;
        let hash_plan = plan_slots(
            height,
            width,
            execution_limits,
            self.max_alloc,
            self.mode.slots(),
        )?;
        let layout = retained_layout(height, cap_height, self.max_alloc)?;
        self.fence().finish()?;
        // The planner subtracts only this replaceable workspace. Force exact
        // replacement even if a larger old workspace would otherwise fit.
        let cached = self.lde_workspace.take().filter(|c| c.matches(&plan));
        let reused = cached.is_some();
        self.workspace = None;
        self.workspace(hash_plan)?;
        let alloc = |bytes| {
            allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                bytes / 8,
                compute::flags::MEM_READ_WRITE,
            )
        };
        let buffers = match cached {
            Some(buffers) => buffers,
            None => TransformBuffers {
                a: alloc(plan.transform_buffer_bytes)?,
                b: alloc(plan.transform_buffer_bytes)?,
                sponge: alloc(plan.sponge_state_bytes)?,
                forward: alloc(plan.twiddle_bytes / 2)?,
                inverse: alloc(plan.twiddle_bytes / 2)?,
            },
        };
        let mut storage = alloc(plan.retained_tree_bytes)?;
        storage._lease.mark_retained()?;
        let device_matrices = if let Some(session) = capture {
            device_specs
                .into_iter()
                .map(|spec| session.allocate(self, spec))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        // Must outlive all pending operations and drop BEFORE any owned buffer
        // above, on normal return, device error, or unwind.
        let fence = self.fence();
        let mut prefixes = Vec::new();
        let mut matrices = Vec::with_capacity(shapes.len());
        buffers
            .sponge
            .buffer
            .cmd()
            .fill(0u64, None)
            .enq()
            .map_err(|e| e.to_string())?;
        let log_height = height.trailing_zeros() as usize;
        self.lde_upload_rows(&buffers.forward.buffer, log_height, 1, |row, dst| {
            dst[0] = super::fri_fold::root((row + 1) as u32);
        })?;
        self.lde_upload_rows(&buffers.inverse.buffer, log_height, 1, |row, dst| {
            // Immutable, compile-time roots shared with owned transforms. Do
            // not invert roots on the CPU during a device-owned proof.
            dst[0] = super::fri_fold::inverse_root((row + 1) as u32);
        })?;
        for (matrix_index, input) in inputs.iter().enumerate() {
            let shape = shapes[matrix_index];
            #[cfg(feature = "gpu-metal")]
            let shared = if crate::metal_compute::resident::enabled() && retention_bits > 0 {
                Some(crate::metal_compute::resident::SharedWords::new(
                    self.pq.queue(),
                    plan.retained_height() * shape.width,
                )?)
            } else {
                None
            };
            #[cfg(not(feature = "gpu-metal"))]
            let shared: Option<()> = None;
            let mut public_readback = if public_preprocessing
                && retention_bits > 0
                && std::env::var_os(crate::block_v2::worker_memory::env_name(
                    "SHARED_PREPROCESSING_DIR",
                ))
                .is_some()
            {
                if masks.is_some()
                    || shared.is_some()
                    || plan.readback_layout != super::lde_readback::ReadbackLayout::Direct
                {
                    return Err(
                        "shared public preprocessing requires direct host readback without masks"
                            .into(),
                    );
                }
                let (CommitSource::Host { evaluations, shift }, SaltInput::Host(salts)) =
                    (input.source, input.salts)
                else {
                    return Err("shared preprocessing requires public host inputs".into());
                };
                let public_input = LdeInput {
                    evaluations,
                    salts,
                    shift,
                    added_bits: input.shape.added_bits,
                };
                super::super::shared_preprocessing::SharedReadback::for_public_input(
                    &public_input,
                    plan.retained_height(),
                    plan.columns_per_tile(),
                )?
            } else {
                None
            };
            let public_mapped = public_readback.is_some();
            let mut readback =
                if retention == LdeRetention::DeviceOnly || shared.is_some() || public_mapped {
                    None
                } else {
                    Some(
                        HostReadback::with_layout(
                            plan.retained_height(),
                            shape.width,
                            plan.columns_per_tile(),
                            if masked {
                                super::lde_readback::OutputStorage::QuotientHeap
                            } else {
                                super::lde_readback::OutputStorage::Global
                            },
                            plan.readback_layout,
                        )?
                        .with_parallel_decode(parallel_readback),
                    )
                };
            for tile in plan.tiles().filter(|t| t.matrix == matrix_index) {
                buffers
                    .b
                    .buffer
                    .cmd()
                    .fill(0u64, Some(tile.output_elements))
                    .enq()
                    .map_err(|e| e.to_string())?;
                let (normalization, transform_shift) = match input.source {
                    CommitSource::Evaluations(owned) => {
                        owned.load_columns(
                            self,
                            &buffers.a.buffer,
                            tile.first_column,
                            tile.columns,
                        )?;
                        (1, 1)
                    }
                    CommitSource::Trace(owned) => {
                        owned.load_columns(
                            self,
                            &buffers.a.buffer,
                            tile.first_column,
                            tile.columns,
                        )?;
                        (1, 1)
                    }
                    CommitSource::Host { evaluations, shift } => {
                        self.lde_upload_rows(
                            &buffers.a.buffer,
                            shape.height,
                            tile.columns,
                            |row, dst| {
                                for (out, value) in dst.iter_mut().zip(
                                    &evaluations.values[row * shape.width + tile.first_column..],
                                ) {
                                    *out = value.as_canonical_u64();
                                }
                            },
                        )?;
                        (
                            Val::from_usize(shape.height).inverse().as_canonical_u64(),
                            shift.as_canonical_u64(),
                        )
                    }
                    CommitSource::Quotient {
                        input: owned,
                        chunk,
                    } => {
                        owned.load_columns(
                            self,
                            &buffers.a.buffer,
                            chunk,
                            tile.first_column,
                            tile.columns,
                        )?;
                        (1, 1)
                    }
                };
                self.lde_ntt(
                    &buffers.a.buffer,
                    &buffers.b.buffer,
                    &buffers.inverse.buffer,
                    true,
                    shape.height,
                    tile.columns,
                    normalization,
                    transform_shift,
                    false,
                    false,
                    false,
                    None,
                )?;
                if let Some(masks) = masks {
                    let CommitSource::Host {
                        shift: host_shift, ..
                    } = input.source
                    else {
                        return Err(
                            "host masks cannot be combined with owned quotient inputs".into()
                        );
                    };
                    let mask = &masks[matrix_index];
                    self.lde_upload_rows(
                        &buffers.a.buffer,
                        shape.height,
                        tile.columns,
                        |row, dst| {
                            for (out, value) in dst
                                .iter_mut()
                                .zip(&mask.values[row * shape.width + tile.first_column..])
                            {
                                *out = value.as_canonical_u64();
                            }
                        },
                    )?;
                    let mut event = Event::empty();
                    // SAFETY: Admission covers the doubled polynomial. The mask
                    // and coefficients use the same full-height column tile.
                    unsafe {
                        self.pq
                            .kernel_builder("quotient_mask")
                            .arg(&buffers.b.buffer)
                            .arg(&buffers.a.buffer)
                            .arg(shape.height as u32)
                            .arg(tile.columns as u32)
                            .arg(Val::GENERATOR.as_canonical_u64())
                            .arg(host_shift.exp_u64(shape.height as u64).as_canonical_u64())
                            .global_work_size(shape.height * tile.columns)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    self.stats.quotient_mask_ns += self.timeline.record("quotient_mask", &event)?;
                }
                if let CommitSource::Trace(owned) = input.source {
                    owned.scale_columns(
                        self,
                        &buffers.b.buffer,
                        tile.first_column,
                        tile.columns,
                    )?;
                }
                if let CommitSource::Evaluations(owned) = input.source {
                    owned.scale_columns(self, &buffers.b.buffer, tile.columns)?;
                }
                if let CommitSource::Quotient {
                    input: owned,
                    chunk,
                } = input.source
                {
                    owned.hide_columns(
                        self,
                        &buffers.b.buffer,
                        chunk,
                        tile.first_column,
                        tile.columns,
                    )?;
                }
                #[cfg(feature = "gpu-metal")]
                let prefix = shared
                    .as_ref()
                    .filter(|_| self.pq.prefix_fusion())
                    .map(|shared| NttPrefix {
                        buffer: shared.buffer(),
                        width: shape.width,
                        first: tile.first_column,
                        height: plan.retained_height(),
                    });
                #[cfg(feature = "gpu")]
                let prefix = None;
                let in_a = self.lde_ntt(
                    &buffers.b.buffer,
                    &buffers.a.buffer,
                    &buffers.forward.buffer,
                    false,
                    height,
                    tile.columns,
                    1,
                    1,
                    true,
                    true,
                    false,
                    prefix,
                )?;
                let transformed = if in_a {
                    &buffers.a.buffer
                } else {
                    &buffers.b.buffer
                };
                self.lde_absorb(
                    transformed,
                    &buffers.sponge.buffer,
                    0,
                    height,
                    tile.columns,
                    tile.sponge_rate_offset,
                )?;
                if let Some(matrix) = device_matrices.get(matrix_index) {
                    matrix.capture_columns(self, transformed, tile.columns, tile.first_column)?;
                }
                if let Some(readback) = &mut readback {
                    self.lde_read_columns(transformed, readback, tile.first_column, tile.columns)?;
                }
                if let Some(readback) = &mut public_readback {
                    self.lde_read_columns(transformed, readback, tile.first_column, tile.columns)?;
                }
                #[cfg(feature = "gpu-metal")]
                if let Some(shared) = shared.as_ref().filter(|_| !self.pq.prefix_fusion()) {
                    let kernel = self
                        .pq
                        .kernel_builder("prefix_scatter")
                        .arg(transformed)
                        .arg(shared.buffer())
                        .arg(shape.width as u32)
                        .arg(tile.first_column as u32)
                        .arg(tile.columns as u32)
                        .global_work_size(plan.retained_height() * tile.columns)
                        .build()?;
                    unsafe {
                        kernel.cmd().enq()?;
                    }
                }
                self.stats.lde_column_tiles += 1;
            }
            if let Some(readback) = readback {
                let (matrix, reorder) = readback.finish()?;
                // Keep the existing host-materialization counters inclusive of the
                // new layout pass; the reorder counter is a nonadditive subset.
                self.stats.decode_ns += reorder.elapsed_ns;
                self.stats.download_and_decode_ns += reorder.elapsed_ns;
                self.stats.lde_host_reorder_ns += reorder.elapsed_ns;
                self.stats.lde_host_reordered_bytes += reorder.bytes as u64;
                self.stats.lde_host_workspace_peak_bytes = self
                    .stats
                    .lde_host_workspace_peak_bytes
                    .max(reorder.workspace_backing_bytes);
                if retention_bits > 0 {
                    prefixes.push(super::super::prefix_storage::host(matrix));
                } else {
                    matrices.push(matrix);
                }
            }
            if let Some(readback) = public_readback {
                prefixes.push(p3_matrix::dense::DenseMatrix::new(
                    super::super::prefix_storage::PrefixStorage::Shared(readback.finish()?),
                    shape.width,
                ));
            }
            #[cfg(feature = "gpu-metal")]
            if let Some(shared) = shared {
                prefixes.push(p3_matrix::dense::DenseMatrix::new(
                    super::super::prefix_storage::PrefixStorage::Metal(shared.freeze()?),
                    shape.width,
                ));
            }
            // Reuse a transform buffer for bounded salt bands only AFTER its
            // transformed columns have been hashed, captured and optionally read back.
            let replayed = match input.salts {
                SaltInput::Replay(recipe) => Some(recipe.materialize_in(self)?),
                _ => None,
            };
            let salts = replayed.as_ref().map_or(input.salts, SaltInput::Device);
            let salt_columns = plan.columns_per_tile().min(4);
            for first_salt in (0..4).step_by(salt_columns) {
                let columns = salt_columns.min(4 - first_salt);
                let band_rows =
                    (buffers.a.buffer.len() / columns).min(self.staging[0].map.len() / columns);
                for row0 in (0..height).step_by(band_rows) {
                    let rows = band_rows.min(height - row0);
                    match salts {
                        SaltInput::Host(salts) => {
                            self.lde_upload_rows(&buffers.a.buffer, rows, columns, |row, dst| {
                                for (dst, value) in dst
                                    .iter_mut()
                                    .zip(&salts.values[(row0 + row) * 4 + first_salt..])
                                {
                                    *dst = value.as_canonical_u64();
                                }
                            })?
                        }
                        SaltInput::Device(salts) => salts.copy_column_band(
                            self,
                            &buffers.a.buffer,
                            row0,
                            rows,
                            first_salt,
                            columns,
                        )?,
                        SaltInput::Replay(_) => unreachable!("replay materialized above"),
                    }
                    self.lde_absorb(
                        &buffers.a.buffer,
                        &buffers.sponge.buffer,
                        row0,
                        rows,
                        columns,
                        (plan.salt_rate_offset(matrix_index).unwrap() + first_salt) % 4,
                    )?;
                }
            }
        }
        let final_offset = plan.salt_rate_offset(inputs.len() - 1).unwrap();
        let mut event = Event::empty();
        // SAFETY: full-height states and leaf workspace were jointly admitted.
        unsafe {
            self.commitment_builder("lde_leaf_finalize", height)?
                .arg(&buffers.sponge.buffer)
                .arg(&self.workspace.as_ref().unwrap().a.buffer)
                .arg(height as u32)
                .arg(final_offset as u32)
                .arg(&self.constants[0].buffer)
                .arg(&self.constants[1].buffer)
                .arg(&self.constants[2].buffer)
                .arg(&self.constants[3].buffer)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = self.timeline.record("lde_leaf_finalize", &event)?;
        self.stats.lde_sponge_ns += ns;
        self.stats.leaf_kernel_ns += ns;
        let cap = self.finish_retained_layers(&storage, height, layout)?;
        fence.finish()?;
        self.stats.commits += 1;
        self.stats.lde_commits += 1;
        self.stats.lde_device_only_commits += u64::from(retention == LdeRetention::DeviceOnly);
        if masked {
            self.stats.quotient_lde_commits += 1;
        }
        self.stats.lde_wall_ns += started.elapsed().as_nanos();
        self.context_checkpoint("resident LDE complete")?;
        if crate::block_v2::worker_memory::reclaim_enabled() {
            self.workspace = None;
        }
        if buffers.bytes() <= self.lde_workspace_limit {
            // Scratch contains fresh attempt data. Scrub it before retaining
            // storage; no witness, salts, masks, or RNG state becomes a cache.
            for allocation in [&buffers.a, &buffers.b, &buffers.sponge] {
                allocation
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            fence.finish()?;
            eprintln!(
                "bounded_lde_workspace retained_bytes={} reused={reused}",
                buffers.bytes()
            );
            self.lde_workspace = Some(buffers);
        }
        Ok(LdeCommitOutput {
            matrices,
            device_matrices,
            prefixes,
            plan,
            cap_height,
            tree: RetainedTree {
                storage,
                height,
                layout,
                cap,
                _job_lease: self._job_lease.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    fn matrix(height: usize, width: usize, salt: u64) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(
            (0..height * width)
                .map(|i| {
                    Val::new(match i % 5 {
                        0 => 0,
                        1 => 1,
                        2 => 0xffff_ffff_0000_0000,
                        3 => u64::MAX,
                        _ => (i as u64)
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .wrapping_add(salt),
                    })
                })
                .collect(),
            width,
        )
    }

    #[test]
    fn input_validation_rejects_storage_domain_and_salt_mismatches() {
        let evals = matrix(8, 3, 1);
        let salts = matrix(32, 4, 2);
        let input = LdeInput {
            evaluations: &evals,
            salts: &salts,
            added_bits: 2,
            shift: Val::GENERATOR,
        };
        assert_eq!(
            validate_inputs(&[input]).unwrap(),
            vec![InputShape {
                height: 8,
                width: 3,
                added_bits: 2
            }]
        );
        assert!(validate_inputs(&[LdeInput {
            shift: Val::ZERO,
            ..input
        }])
        .is_err());
        assert!(validate_inputs(&[LdeInput {
            added_bits: usize::MAX,
            ..input
        }])
        .is_err());
        let bad_salts = matrix(32, 3, 2);
        assert!(validate_inputs(&[LdeInput {
            salts: &bad_salts,
            ..input
        }])
        .is_err());
        let short_salts = matrix(16, 4, 2);
        assert!(validate_inputs(&[LdeInput {
            salts: &short_salts,
            ..input
        }])
        .is_err());
        let mut nonrectangular = matrix(1, 7, 1);
        nonrectangular.width = 3;
        let mut zero_width = matrix(1, 1, 1);
        zero_width.width = 0;
        for malformed in [nonrectangular, zero_width, matrix(3, 3, 1), matrix(1, 3, 1)] {
            assert!(validate_inputs(&[LdeInput {
                evaluations: &malformed,
                ..input
            }])
            .is_err());
        }
    }

    #[test]
    fn ntt_schedule_covers_every_stage_with_bounded_local_storage() {
        for log_h in 1..32 {
            for width in [1usize, 2, 3, 4, 7, 16, 35, 98, 204, 1024] {
                for columns in [3, 4] {
                    for tile_log2 in 10..=12 {
                        let groups =
                            ntt_groups(1usize << log_h, width, columns, tile_log2).unwrap();
                        let mut stage = 0;
                        for (start, count, log_c) in groups {
                            assert_eq!(start, stage);
                            assert!(count > 0 && count + log_c <= tile_log2);
                            stage += count;
                        }
                        assert_eq!(stage, log_h);
                    }
                }
            }
        }
        for invalid_tile in [0, 9, 13, usize::MAX] {
            assert!(ntt_groups(1024, 4, 4, invalid_tile).is_err());
        }
        for (height, width) in [(0, 1), (1, 1), (3, 1), (8, 0), (8, usize::MAX)] {
            assert!(ntt_groups(height, width, 4, 12).is_err());
        }
    }

    #[test]
    #[cfg(feature = "gpu-metal")]
    #[ignore = "two component shapes, three samples each; Apple GPU and retained trees required"]
    fn metal_priority_components() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 512 << 20,
                tile_bytes: 64 << 20,
                staging_bytes: 8 << 20,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let snapshot = || {
            ENGINE
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .snapshot()
        };
        for (height, width) in [(8192usize, 3usize), (131072, 7)] {
            let evaluations = matrix(height, width, 17);
            let salts = matrix(height << 3, 4, 29);
            let inputs = [LdeInput {
                evaluations: &evaluations,
                salts: &salts,
                added_bits: 3,
                shift: Val::GENERATOR,
            }];
            let warmup = retained_lde_commit(&inputs, None, 2, 256 << 20, 1).unwrap();
            let expected_cap = warmup.cap().to_vec();
            drop(warmup);
            for repeat in 1..=3 {
                let before = snapshot();
                let start = std::time::Instant::now();
                let output = retained_lde_commit(&inputs, None, 2, 256 << 20, 1).unwrap();
                assert_eq!(output.cap(), expected_cap);
                drop(output);
                let wall = start.elapsed().as_secs_f64();
                let after = snapshot();
                println!(
                    "metal_priority_sample {}",
                    serde_json::json!({
                        "input_rows": height, "output_rows": height << 3, "columns": width, "repeat": repeat,
                        "wall_seconds": wall, "ntt_gpu_seconds": (after.lde_transform_ns-before.lde_transform_ns) as f64/1e9,
                        "sponge_gpu_seconds": (after.lde_sponge_ns-before.lde_sponge_ns) as f64/1e9,
                        "host_reordered_bytes": after.lde_host_reordered_bytes-before.lde_host_reordered_bytes,
                    })
                );
            }
        }
        super::super::report("priority components");
    }

    #[test]
    #[cfg(feature = "gpu-metal")]
    #[ignore = "short kernel screen; Apple GPU and retained trees required"]
    fn metal_kernel_screen() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 256 << 20,
                tile_bytes: 32 << 20,
                staging_bytes: 1 << 20,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let matrix = RowMajorMatrix::new(
            (0..8192 * 32)
                .map(|i| Val::from_u64(i as u64 * 7717 + 19))
                .collect(),
            32,
        );
        let salts = RowMajorMatrix::new(
            (0..65536 * 4)
                .map(|i| Val::from_u64(i as u64 * 1717 + 13))
                .collect(),
            4,
        );
        let inputs = [LdeInput {
            evaluations: &matrix,
            salts: &salts,
            added_bits: 3,
            shift: Val::GENERATOR,
        }];
        let warmup = coset_lde_commit(&inputs, 2, 128 << 20).unwrap();
        drop(warmup);
        let started = std::time::Instant::now();
        let mut count = 0;
        while count < 2 || (count < 10 && started.elapsed().as_secs_f64() < 2.0) {
            let output = coset_lde_commit(&inputs, 2, 128 << 20).unwrap();
            std::hint::black_box(output.cap());
            drop(output);
            count += 1;
        }
        println!(
            "metal_kernel_screen iterations={count} seconds={} seconds_per_iteration={}",
            started.elapsed().as_secs_f64(),
            started.elapsed().as_secs_f64() / count as f64
        );
        super::super::report("kernel screening");
    }

    fn check_cpu_reference(inputs: &[LdeInput<'_>], cap_height: usize) -> LdeCommitOutput {
        use crate::config::{Dft, MyCompress, MyHash};
        use p3_dft::TwoAdicSubgroupDft;
        use p3_goldilocks::default_goldilocks_poseidon2_8;
        use p3_matrix::{bitrev::BitReversibleMatrix, Matrix};
        use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
        let before = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .snapshot();
        let output = coset_lde_commit(inputs, cap_height, 32 * 1024 * 1024).unwrap();
        let after = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .snapshot();
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            (output.plan.projected_input_upload_bytes
                + output.plan.projected_salt_upload_bytes
                + output.plan.twiddle_bytes) as u64
        );
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            (output.plan.projected_host_readback_bytes + output.cap().len() * 4 * 8) as u64
        );
        let expected: Vec<_> = inputs
            .iter()
            .map(|input| {
                Dft::default()
                    .coset_lde_batch(input.evaluations.clone(), input.added_bits, input.shift)
                    .bit_reverse_rows()
                    .to_row_major_matrix()
            })
            .collect();
        for (actual, expected) in output.matrices.iter().zip(&expected) {
            assert_eq!(actual.values, expected.values);
            assert_eq!(actual.width, expected.width);
        }
        let permutation = default_goldilocks_poseidon2_8();
        let hash = MyHash::new(permutation.clone());
        let compress = MyCompress::new(permutation);
        let height = output.plan.output_height();
        let mut layers: Vec<Vec<[Val; 4]>> = vec![(0..height)
            .map(|row| {
                hash.hash_iter(expected.iter().zip(inputs).flat_map(|(matrix, input)| {
                    matrix.values[row * matrix.width..(row + 1) * matrix.width]
                        .iter()
                        .chain(&input.salts.values[row * 4..row * 4 + 4])
                        .copied()
                }))
            })
            .collect()];
        while layers.last().unwrap().len() > 1 {
            layers.push(
                layers
                    .last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| compress.compress([pair[0], pair[1]]))
                    .collect(),
            );
        }
        let path_len = height.ilog2() as usize - cap_height.min(height.ilog2() as usize);
        assert_eq!(output.cap(), layers[path_len]);
        for index in [0, height / 2, height - 1] {
            let expected_path: Vec<_> = layers[..path_len]
                .iter()
                .enumerate()
                .map(|(level, values)| values[(index >> level) ^ 1])
                .collect();
            assert_eq!(output.open(index).unwrap(), expected_path);
        }
        assert!(output.open(height).is_err());
        assert!(
            super::super::shutdown().is_err(),
            "live tree must retain context lease"
        );
        output
    }

    #[test]
    #[ignore = "requires OpenCL GPU, LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_reused_lde_workspace_matches_cpu_and_stays_charged() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 512 * 1024,
                tile_bytes: 8 * 1024,
                staging_bytes: 4 * 1024,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        let snapshots = || {
            ENGINE
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .snapshot()
        };
        ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .lde_workspace_limit = 128 * 1024;
        let evals = matrix(128, 7, 31);
        let salts = matrix(256, 4, 41);
        let inputs = [LdeInput {
            evaluations: &evals,
            salts: &salts,
            added_bits: 1,
            shift: Val::GENERATOR,
        }];
        let before = snapshots();
        let first = check_cpu_reference(&inputs, 2);
        drop(first);
        let cold = snapshots();
        {
            let mut guard = ENGINE.get().unwrap().lock().unwrap();
            let engine = guard.as_mut().unwrap();
            let cache = engine.lde_workspace.as_ref().unwrap();
            assert!(cache.bytes() <= 128 * 1024);
            assert!(cold.managed_live_bytes >= cache.bytes());
            for buffer in [&cache.a.buffer, &cache.b.buffer, &cache.sponge.buffer] {
                let mut words = vec![1u64; buffer.len()];
                buffer.read(&mut words).enq().unwrap();
                assert!(
                    words.iter().all(|word| *word == 0),
                    "attempt scratch was not cleared"
                );
            }
        }
        let second = check_cpu_reference(&inputs, 2);
        drop(second);
        let warm = snapshots();
        // The first CPU-reference audit also initializes the query buffer.
        assert!(
            (cold.allocations - before.allocations) - (warm.allocations - cold.allocations) >= 5
        );
        assert_eq!(warm.managed_live_bytes, cold.managed_live_bytes);
        // A zero limit releases the reusable payload after the next operation.
        ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .lde_workspace_limit = 0;
        drop(check_cpu_reference(&inputs, 2));
        assert!(ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .lde_workspace
            .is_none());
    }

    #[test]
    #[ignore = "requires OpenCL GPU, LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_resident_lde_columns_caps_and_paths_match_cpu() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 512 * 1024,
                tile_bytes: 8 * 1024,
                staging_bytes: 4 * 1024,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        for (height, added, widths) in [
            (2usize, 0usize, vec![1]),
            (8, 1, vec![3]),
            (8, 2, vec![4, 5]),
            (128, 3, vec![35, 7]),
            (64, 4, vec![17, 6, 1]),
        ] {
            // Different input heights are valid when their LDE heights agree.
            let evaluations: Vec<_> = widths
                .iter()
                .enumerate()
                .map(|(i, &w)| {
                    matrix(
                        if i > 0 && height >= 4 {
                            height / 2
                        } else {
                            height
                        },
                        w,
                        i as u64 + 5,
                    )
                })
                .collect();
            let salts: Vec<_> = widths
                .iter()
                .enumerate()
                .map(|(i, _)| matrix(height << added, 4, i as u64 + 11))
                .collect();
            let inputs: Vec<_> = evaluations
                .iter()
                .zip(&salts)
                .enumerate()
                .map(|(i, (evaluations, salts))| LdeInput {
                    evaluations,
                    salts,
                    added_bits: added + usize::from(i > 0 && height >= 4),
                    shift: Val::GENERATOR,
                })
                .collect();
            let output = check_cpu_reference(&inputs, 2);
            if widths[0] == 35 {
                assert!(output.plan.columns_per_tile() < 35);
            }
            drop(output);
        }
        let stats = super::super::report("resident LDE equivalence").unwrap();
        assert_eq!(stats.lde_commits, 5);
        assert!(stats.lde_transform_ns > 0 && stats.lde_sponge_ns > 0);
        assert!(stats.managed_peak_bytes <= 512 * 1024);
        assert!(stats.lde_host_reordered_bytes > 0);
        assert!(stats.lde_host_workspace_peak_bytes > 0);
        assert!(stats.lde_host_reorder_ns > 0);
        // Reordering is a subset of decode, not an extra additive stage.
        assert!(stats.decode_ns >= stats.lde_host_reorder_ns);
        assert!(stats.download_and_decode_ns >= stats.decode_ns);
    }

    #[test]
    #[ignore = "requires GPU and retained trees; run serially"]
    fn gpu_wide_lde_tiles_preserve_columns_caps_and_paths() {
        let _shutdown = super::super::TestShutdownGuard;
        // Match the 400-column preprocessing shape at a small row count. Vary
        // only the allowance so the same data exercises 64/128/256-column tiles.
        let evaluations = matrix(128, 400, 59);
        let salts = matrix(2048, 4, 61);
        let inputs = [LdeInput {
            evaluations: &evaluations,
            salts: &salts,
            added_bits: 4,
            shift: Val::GENERATOR,
        }];
        let mut reference_cap: Option<Vec<[Val; 4]>> = None;
        for (managed_mib, columns) in [(3, 64), (6, 128), (12, 256)] {
            super::super::initialize_mode(
                super::super::Limits {
                    managed_bytes: managed_mib * 1024 * 1024,
                    tile_bytes: 64 * 1024,
                    staging_bytes: 8 * 1024,
                },
                super::super::TransferMode::Serial,
            )
            .unwrap();
            let output = check_cpu_reference(&inputs, 2);
            assert_eq!(output.plan.columns_per_tile(), columns);
            if let Some(cap) = &reference_cap {
                assert_eq!(output.cap(), cap.as_slice());
            } else {
                reference_cap = Some(output.cap().to_vec());
            }
            println!("wide_lde_columns={columns} cpu_equivalence=PASS");
            drop(output);
            super::super::shutdown().unwrap();
        }
    }

    #[test]
    #[ignore = "requires OpenCL GPU, LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu() {
        let _shutdown = super::super::TestShutdownGuard;
        #[cfg(feature = "gpu")]
        let mode = super::super::TransferMode::Overlap;
        #[cfg(feature = "gpu-metal")]
        let mode = super::super::TransferMode::Serial;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 32 * 1024 * 1024,
                tile_bytes: 64 * 1024,
                staging_bytes: 32 * 1024,
            },
            mode,
        )
        .unwrap();
        let a = matrix(8192, 3, 17);
        let b = matrix(2048, 5, 19);
        let sa = matrix(32768, 4, 23);
        let sb = matrix(32768, 4, 29);
        let inputs = [
            LdeInput {
                evaluations: &a,
                salts: &sa,
                added_bits: 2,
                shift: Val::GENERATOR,
            },
            LdeInput {
                evaluations: &b,
                salts: &sb,
                added_bits: 4,
                shift: Val::GENERATOR.inverse(),
            },
        ];
        assert!(ntt_groups(8192, 3, 4, 12).unwrap().len() > 1);
        assert!(ntt_groups(32768, 3, 4, 12).unwrap().len() > 1);
        let output = check_cpu_reference(&inputs, 6);
        let before = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .snapshot();
        assert!(coset_lde_commit(&inputs, 6, 8).is_err());
        let after = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .snapshot();
        assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
        assert_eq!(after.allocations, before.allocations);
        // Admission failure must not corrupt a previously retained tree.
        assert!(output.open(32767).is_ok());
        drop(output);
    }
}

/// Hash full transforms while downloading only the admitted bit-reversed prefix.
pub(crate) fn retained_lde_commit(
    inputs: &[LdeInput<'_>],
    masks: Option<&[RowMajorMatrix<Val>]>,
    cap_height: usize,
    host_budget: usize,
    retention_bits: usize,
) -> Result<LdeCommitOutput, String> {
    retained_lde_commit_owned(inputs, masks, cap_height, host_budget, retention_bits, None)
}

pub(crate) fn retained_lde_commit_owned(
    inputs: &[LdeInput<'_>],
    masks: Option<&[RowMajorMatrix<Val>]>,
    cap_height: usize,
    host_budget: usize,
    retention_bits: usize,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    retained_lde_commit_storage(
        inputs,
        masks,
        cap_height,
        host_budget,
        LdeRetention::HostPrefix(retention_bits),
        capture,
    )
}

pub(crate) fn retained_lde_commit_storage(
    inputs: &[LdeInput<'_>],
    masks: Option<&[RowMajorMatrix<Val>]>,
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    slot.as_mut()
        .ok_or("GPU shut down")?
        .coset_lde_commit_with_capture(inputs, masks, cap_height, host_budget, retention, capture)
}

pub(crate) fn commit_owned_traces(
    inputs: &[super::device::TraceCommitInput],
    salts: &[RowMajorMatrix<Val>],
    session: &super::device::DeviceSession,
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
) -> Result<LdeCommitOutput, String> {
    let salts: Vec<_> = salts.iter().map(SaltInput::Host).collect();
    commit_traces_with_salts(inputs, &salts, session, cap_height, host_budget, retention)
}

pub(crate) fn commit_traces_with_salts(
    inputs: &[super::device::TraceCommitInput],
    salts: &[SaltInput<'_>],
    session: &super::device::DeviceSession,
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU engine is not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = slot.as_mut().ok_or("GPU engine is not initialized")?;
    if inputs.is_empty() || inputs.len() > 256 || salts.len() != inputs.len() {
        return Err("invalid device trace commitment batch".into());
    }
    let height = inputs
        .iter()
        .map(|input| input.shape.height)
        .max()
        .unwrap()
        .checked_shl(crate::block_v2::profile::LOG_BLOWUP as u32)
        .ok_or("device trace LDE height overflow")?;
    let mut prepared = Vec::with_capacity(inputs.len());
    for (input, salts) in inputs.iter().zip(salts) {
        input.check_session(session)?;
        input.check_engine(engine)?;
        salts.validate(height, Some(session), engine)?;
        prepared.push(CommitInput {
            source: CommitSource::Trace(input),
            salts: *salts,
            shape: input.shape.lde_shape(),
        });
    }
    engine.commit_inputs(
        &prepared,
        None,
        cap_height,
        host_budget,
        retention,
        Some(session),
    )
}

pub(crate) fn commit_owned_quotient(
    input: &super::device::QuotientCommitInput,
    salts: &[RowMajorMatrix<Val>],
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    let salts: Vec<_> = salts.iter().map(SaltInput::Host).collect();
    commit_quotient_with_salts(input, &salts, cap_height, host_budget, retention, capture)
}

pub(crate) fn commit_quotient_with_salts(
    input: &super::device::QuotientCommitInput,
    salts: &[SaltInput<'_>],
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    commit_quotient_batch_with_salts(&[input], salts, cap_height, host_budget, retention, capture)
}

pub(crate) fn commit_owned_quotients(
    inputs: &[&super::device::QuotientCommitInput],
    salts: &[RowMajorMatrix<Val>],
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    let salts: Vec<_> = salts.iter().map(SaltInput::Host).collect();
    commit_quotient_batch_with_salts(inputs, &salts, cap_height, host_budget, retention, capture)
}

pub(crate) fn commit_quotient_batch_with_salts(
    inputs: &[&super::device::QuotientCommitInput],
    salts: &[SaltInput<'_>],
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
    capture: Option<&super::device::DeviceSession>,
) -> Result<LdeCommitOutput, String> {
    let chunks = inputs.iter().try_fold(0usize, |total, input| {
        total
            .checked_add(input.shape.chunks)
            .ok_or("quotient batch count overflow")
    })?;
    if inputs.is_empty() || chunks > 256 || salts.len() != chunks {
        return Err("invalid owned quotient commitment batch".into());
    }
    if let Some(session) = capture {
        for input in inputs {
            input.check_session(session)?;
        }
    }
    let mut slot = ENGINE
        .get()
        .ok_or("GPU engine not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = slot.as_mut().ok_or("GPU engine shut down")?;
    for input in inputs {
        input.check_engine(engine)?;
    }
    let output_height = inputs
        .iter()
        .map(|input| input.shape.height)
        .max()
        .unwrap()
        .checked_shl((crate::block_v2::profile::LOG_BLOWUP + 1) as u32)
        .ok_or("owned quotient LDE height overflow")?;
    for salt in salts {
        salt.validate(output_height, capture, engine)?;
    }
    let mut prepared = Vec::with_capacity(chunks);
    let mut salt_iter = salts.iter();
    for input in inputs {
        let shape = InputShape {
            height: input.shape.height,
            width: input.shape.width,
            added_bits: crate::block_v2::profile::LOG_BLOWUP + 1,
        };
        for chunk in 0..input.shape.chunks {
            prepared.push(CommitInput {
                source: CommitSource::Quotient { input, chunk },
                salts: *salt_iter.next().expect("validated quotient salt count"),
                shape,
            });
        }
    }
    engine.commit_inputs(&prepared, None, cap_height, host_budget, retention, capture)
}

pub(crate) fn commit_owned_evaluations(
    inputs: &[super::device::EvaluationInput],
    added_bits: usize,
    salts: &[SaltInput<'_>],
    session: &super::device::DeviceSession,
    cap_height: usize,
    host_budget: usize,
    retention: LdeRetention,
) -> Result<LdeCommitOutput, String> {
    if inputs.is_empty() || inputs.len() > 256 || inputs.len() != salts.len() {
        return Err("invalid device evaluation commitment batch".into());
    }
    let mut slot = ENGINE
        .get()
        .ok_or("GPU engine not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = slot.as_mut().ok_or("GPU engine shut down")?;
    let mut prepared = Vec::with_capacity(inputs.len());
    for (input, salt) in inputs.iter().zip(salts) {
        input.check_session(session)?;
        input.check_engine(engine)?;
        prepared.push(CommitInput {
            source: CommitSource::Evaluations(input),
            salts: *salt,
            shape: input.shape(added_bits)?,
        });
    }
    engine.commit_inputs(
        &prepared,
        None,
        cap_height,
        host_budget,
        retention,
        Some(session),
    )
}

/// Called only from the public preprocessing PCS entry point, never for traces.
pub(crate) fn public_preprocessing_lde_commit(
    inputs: &[LdeInput<'_>],
    cap_height: usize,
    host_budget: usize,
    retention_bits: usize,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    slot.as_mut()
        .ok_or("GPU shut down")?
        .coset_lde_commit_public(inputs, None, cap_height, host_budget, retention_bits, true)
}
