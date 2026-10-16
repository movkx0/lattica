//! Owned coset transforms using the engine's existing tiled NTT. Neither
//! coefficients nor evaluations leave the device between the two transforms.
use super::*;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_transform_parameters(__global ulong *parameters,
    uint rows, ulong input_shift, ulong output_shift) {
    parameters[0] = gl_pow((ulong)rows, 0xfffffffeffffffffUL);
    parameters[1] = gl_mul(output_shift, gl_pow(input_shift, 0xfffffffeffffffffUL));
}
__kernel void device_transform_order(__global const ulong *input,
    __global ulong *output, uint width, uint rows, uint log_rows) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * width) return;
    uint row = (uint)(i / width), column = (uint)(i % width);
    output[i] = input[(size_t)brev(row, log_rows) * width + column];
}
__kernel void device_transform_scale(__global const ulong *coefficients,
    __global ulong *output, __global const ulong *parameters,
    uint width, uint input_rows, uint output_rows) {
    size_t i = get_global_id(0);
    if (i >= (size_t)output_rows * width) return;
    uint row = (uint)(i / width);
    output[i] = row < input_rows
        ? gl_canon(gl_mul(gl_mul(coefficients[i], parameters[0]),
            gl_pow(parameters[1], (ulong)row))) : 0UL;
}
"#;

fn geometry(
    input: MatrixSpec,
    log_rows: u32,
    shift: u64,
    order: RowOrder,
) -> Result<(MatrixSpec, usize, usize), String> {
    if log_rows < input.log_rows || log_rows > 31 {
        return Err("device transform requires a nonshrinking domain below 2^32 rows".into());
    }
    let output = MatrixSpec::new(log_rows, input.columns, input.extension, order, shift)?;
    let width = input
        .columns
        .checked_mul(input.extension.degree())
        .filter(|n| *n <= u32::MAX as usize)
        .ok_or("device transform width overflow")?;
    let auxiliary_words = (input.log_rows.max(1) + log_rows.max(1) + 2) as usize;
    Ok((output, width, auxiliary_words))
}

/// Only storage is planned here: output ordering and canonical coset shifts do
/// not change sizes. Runtime validates its actual domain before calling this.
pub(super) fn storage_plan(
    input: MatrixSpec, log_rows: u32, live: usize,
    limits: super::super::Limits, max_alloc: usize,
) -> Result<MemoryPlan, String> {
    let (spec, _, auxiliary_words) = geometry(input, log_rows, 1, RowOrder::BitReversed)?;
    if input.log_rows.max(log_rows).max(2) as usize * 8 > max_alloc {
        return Err("device transform constants exceed the allocation limit".into());
    }
    MemoryPlan::new(&[spec, spec],
        live.checked_add(auxiliary_words * 8).ok_or("device transform budget overflow")?,
        limits.managed_bytes, max_alloc)
}

impl DeviceSession {
    /// Interpolate this matrix on its specified coset, then evaluate it on a
    /// larger (or equal-size) coset. Extension coefficients are independent
    /// base-field columns. Input storage and its physical row order are kept.
    /// The only host transfers are immutable two-adic root constants.
    pub fn lde(
        &self,
        input: &DeviceMatrix,
        log_rows: u32,
        shift: u64,
        order: RowOrder,
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        let (spec, width, _) = geometry(input.spec, log_rows, shift, order)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (spec, width);
            Err("owned device transforms are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            self.observe_engine(engine, |engine| {
                engine.fence().finish()?;
                engine.lde_workspace = None;
                let live = engine.accounting.lock().unwrap().live;
                let _plan = storage_plan(input.spec, log_rows, live, engine.limits, engine.max_alloc)?;
                let output = self.allocate(engine, spec)?;
                let scratch = self.allocate(engine, spec)?;
                let alloc = |words| {
                    allocation(
                        &engine.pq,
                        &engine.accounting,
                        engine.limits,
                        engine.max_alloc,
                        words,
                        compute::flags::MEM_READ_WRITE,
                    )
                };
                let inverse = alloc(input.spec.log_rows.max(1) as usize)?;
                let forward = alloc(log_rows.max(1) as usize)?;
                let parameters = alloc(2)?;
                // Pinned, immutable constants, not per-proof field calculations.
                let inverse_words: Vec<_> = (1..=input.spec.log_rows.max(1))
                    .map(super::super::fri_fold::inverse_root)
                    .collect();
                let forward_words: Vec<_> = (1..=log_rows.max(1))
                    .map(super::super::fri_fold::root)
                    .collect();
                let fence = engine.fence();
                inverse
                    .buffer
                    .write(&inverse_words)
                    .enq()
                    .map_err(|e| e.to_string())?;
                forward
                    .buffer
                    .write(&forward_words)
                    .enq()
                    .map_err(|e| e.to_string())?;
                let mut event = compute::Event::empty();
                // SAFETY: two-word parameter allocation and one work item.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transform_parameters")
                        .arg(&parameters.buffer)
                        .arg(input.spec.rows() as u32)
                        .arg(input.spec.shift)
                        .arg(shift)
                        .global_work_size(1usize)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let mut device_ns = self.session.record_event(
                    engine,
                    crate::proving::Stage::Transform,
                    "device_transform_parameters",
                    &event,
                )?;
                let source = if input.spec.order == RowOrder::BitReversed && input.spec.rows() > 1 {
                    let mut event = compute::Event::empty();
                    // SAFETY: the checked matrix dimensions cover this bijective permutation.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_transform_order")
                            .arg(&input.storage.buffer)
                            .arg(&output.storage.buffer)
                            .arg(width as u32)
                            .arg(input.spec.rows() as u32)
                            .arg(input.spec.log_rows)
                            .global_work_size(input.spec.words)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(
                        engine,
                        crate::proving::Stage::Transform,
                        "device_transform_order",
                        &event,
                    )?;
                    &output.storage.buffer
                } else {
                    &input.storage.buffer
                };
                let before_ntt = engine.stats.lde_transform_ns;
                let coefficients = if input.spec.rows() > 1 {
                    // With natural output order the NTT only mutates its destination.
                    engine.lde_ntt(
                        source,
                        &scratch.storage.buffer,
                        &inverse.buffer,
                        input.spec.rows(),
                        width,
                        1,
                        1,
                        false,
                        false,
                        false,
                    )?;
                    &scratch.storage.buffer
                } else {
                    source
                };
                let mut event = compute::Event::empty();
                // SAFETY: input extent is bounded by output; each lane owns one word.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transform_scale")
                        .arg(coefficients)
                        .arg(&output.storage.buffer)
                        .arg(&parameters.buffer)
                        .arg(width as u32)
                        .arg(input.spec.rows() as u32)
                        .arg(spec.rows() as u32)
                        .global_work_size(spec.words)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(
                    engine,
                    crate::proving::Stage::Transform,
                    "device_transform_scale",
                    &event,
                )?;
                let in_scratch = if spec.rows() > 1 {
                    engine.lde_ntt(
                        &output.storage.buffer,
                        &scratch.storage.buffer,
                        &forward.buffer,
                        spec.rows(),
                        width,
                        1,
                        1,
                        true,
                        order == RowOrder::BitReversed,
                        false,
                    )?
                } else {
                    false
                };
                fence.finish()?;
                device_ns += engine.stats.lde_transform_ns - before_ntt;
                let uploaded = ((inverse_words.len() + forward_words.len()) * 8) as u64;
                engine.stats.uploaded_bytes += uploaded;
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.transforms += 1;
                stats.transform_device_ns += device_ns;
                Ok(if in_scratch { scratch } else { output })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_geometry_preserves_extension_and_rejects_shrinking_or_invalid_domains() {
        let input = MatrixSpec::new(5, 7, Extension::Cubic, RowOrder::BitReversed, 11).unwrap();
        let (out, width, _) = geometry(input, 8, 7, RowOrder::Natural).unwrap();
        assert_eq!(
            (out.columns, out.extension, out.order, out.shift),
            (7, Extension::Cubic, RowOrder::Natural, 7)
        );
        assert_eq!((out.rows(), width), (256, 21));
        assert!(geometry(input, 4, 7, RowOrder::Natural).is_err());
        assert!(geometry(input, 32, 7, RowOrder::Natural).is_err());
        assert!(geometry(input, 8, 0, RowOrder::Natural).is_err());
    }

    #[test]
    #[cfg(feature = "gpu")]
    #[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
    fn owned_transforms_match_cpu_cosets_orders_and_extension_columns() {
        use super::super::super::{
            initialize_mode, shutdown, Limits, TestShutdownGuard, TransferMode,
        };
        use crate::config::Dft;
        use p3_dft::TwoAdicSubgroupDft;
        use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
        use p3_matrix::{dense::RowMajorMatrix, Matrix};
        let _shutdown = TestShutdownGuard;
        initialize_mode(
            Limits {
                managed_bytes: 64 << 20,
                tile_bytes: 4 << 20,
                staging_bytes: 4096,
            },
            TransferMode::Serial,
        )
        .unwrap();
        for (log_input, log_output, columns, extension) in [
            (0, 0, 3, Extension::Base),
            (0, 3, 1, Extension::Cubic),
            (3, 3, 7, Extension::Base),
            (3, 8, 2, Extension::Quadratic),
            (9, 12, 5, Extension::Cubic),
        ] {
            let width = columns * extension.degree();
            let rows = 1usize << log_input;
            let values: Vec<_> = (0..rows * width)
                .map(|i| Val::from_u64(GOLDILOCKS_MODULUS - 1 - (i * 71) as u64))
                .collect();
            let expected = Dft::default()
                .coset_lde_batch(
                    RowMajorMatrix::new(values.clone(), width),
                    (log_output - log_input) as usize,
                    Val::from_u64(7) * Val::from_u64(11).inverse(),
                )
                .to_row_major_matrix();
            for input_order in [RowOrder::Natural, RowOrder::BitReversed] {
                for output_order in [RowOrder::Natural, RowOrder::BitReversed] {
                    let session = DeviceSession::new().unwrap();
                    let physical = |row: usize, log: u32, order| {
                        if order == RowOrder::BitReversed && log != 0 {
                            row.reverse_bits() >> (usize::BITS - log)
                        } else {
                            row
                        }
                    };
                    let words: Vec<_> = (0..rows)
                        .flat_map(|r| {
                            let row = physical(r, log_input, input_order);
                            values[row * width..(row + 1) * width]
                                .iter()
                                .map(|x| x.as_canonical_u64())
                        })
                        .collect();
                    let input = session
                        .upload(
                            MatrixSpec::new(log_input, columns, extension, input_order, 11)
                                .unwrap(),
                            &words,
                        )
                        .unwrap();
                    let before = session.stats();
                    let output = session.lde(&input, log_output, 7, output_order).unwrap();
                    let after = session.stats();
                    assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
                    assert_eq!(
                        after.uploaded_bytes - before.uploaded_bytes,
                        ((log_input.max(1) + log_output.max(1)) * 8) as u64
                    );
                    let actual = session.read(&output, output.spec.bytes()).unwrap();
                    for r in 0..output.spec.rows() {
                        let row = physical(r, log_output, output_order);
                        for column in 0..width {
                            assert_eq!(actual[r * width + column],
                                expected.values[row * width + column].as_canonical_u64(),
                                "logs={log_input}/{log_output} order={input_order:?}/{output_order:?} row={r} col={column}");
                        }
                    }
                    assert_eq!(session.read(&input, input.spec.bytes()).unwrap(), words);
                    let live = session.plan_outputs(&[input.spec]).unwrap().live_bytes;
                    assert!(session.lde(&input, 30, 7, output_order).is_err());
                    assert_eq!(
                        session.plan_outputs(&[input.spec]).unwrap().live_bytes,
                        live
                    );
                    assert!(DeviceSession::new()
                        .unwrap()
                        .lde(&input, log_output, 7, output_order)
                        .is_err());
                }
            }
        }
        shutdown().unwrap();
    }
}

#[test]
fn shared_transform_plan_charges_input_outputs_and_constants() {
    use crate::block_v2::gpu_hash::Limits;
    let limits = Limits { managed_bytes: 1 << 20, tile_bytes: 1 << 20, staging_bytes: 4096 };
    let input = MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap();
    let live = 71 + input.bytes();
    let expected = live + 2 * input.bytes() + (8 + 8 + 2) * 8;
    let plan = storage_plan(input, 8, live, limits, 4096).unwrap();
    assert_eq!(plan.peak_bytes, expected);
    assert!(storage_plan(input, 8, live, Limits { managed_bytes: expected - 1, ..limits }, 4096).is_err());
    assert!(storage_plan(input, 8, live, limits, input.bytes() - 1).is_err());
}
