//! Quotient evaluation with owned device matrices. Programs may be prepared
//! once and reused; witnesses and sampled parameters stay attempt-owned.
use super::super::quotient::Plan;
use super::*;
use crate::block_v2::gpu_quotient_prover::program::Program;
mod partition;
pub(crate) use partition::PartitionStorage;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_quotient_scatter_coset(__global const ulong *input,
    __global ulong *output, uint rows, uint coset, uint cosets, uint degree) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * degree) return;
    size_t row = i / degree, coefficient = i % degree;
    output[(row * cosets + coset) * degree + coefficient] = input[i];
}
__kernel void device_quotient_domain(__global ulong *status, uint log_rows, ulong shift) {
    status[0] = gl_canon(gl_pow(shift, 1UL << log_rows)) == 1UL ? 1UL : 0UL;
}
__kernel void device_quotient_gather(__global const ulong *main,
    __global const ulong *preprocessed, __global const ulong *permutation,
    __global ulong *output, uint main_width, uint pre_width, uint perm_width,
    uint main_bitreversed, uint pre_bitreversed, uint perm_bitreversed,
    uint log_rows, uint next_step, uint first_row, uint rows) {
    uint width = 2 * (main_width + pre_width + perm_width);
    size_t index = get_global_id(0);
    if (index >= (size_t)rows * width) return;
    uint row = first_row + (uint)(index / width), column = (uint)(index % width);
    __global const ulong *source = main;
    uint source_width = main_width, bitreversed = main_bitreversed;
    if (column >= 2 * main_width) {
        column -= 2 * main_width;
        source = preprocessed; source_width = pre_width; bitreversed = pre_bitreversed;
        if (column >= 2 * pre_width) {
            column -= 2 * pre_width;
            source = permutation; source_width = perm_width; bitreversed = perm_bitreversed;
        }
    }
    if (column >= source_width) {
        column -= source_width;
        row = (row + next_step) & ((1U << log_rows) - 1U);
    }
    if (bitreversed) row = brev(row, log_rows);
    output[index] = source[(size_t)row * source_width + column];
}
"#;

/// Interleave at most 256 cosets. Each input pass is sized to the largest
/// retained degree prefix, not the full quotient domain. This bounds both the
/// expansion allocation and its NTT scratch; the complete extension output is small.
fn partition_geometry(
    inputs: &[MatrixSpec],
    log_trace: u32,
    log_quotient: u32,
    shift: u64,
    extension: Extension,
) -> Result<(MatrixSpec, u32, usize), String> {
    if extension == Extension::Base
        || inputs.is_empty()
        || inputs.len() > 3
        || log_trace > log_quotient
        || log_quotient > 31
    {
        return Err("invalid partitioned quotient domain".into());
    }
    let mut part_log = log_trace;
    for spec in inputs {
        if spec.shift != shift || spec.log_rows > log_quotient {
            return Err("quotient prefixes must share the base coset and fit its domain".into());
        }
        part_log = part_log.max(spec.log_rows);
    }
    let cosets = 1usize << (log_quotient - part_log);
    if cosets > 256 {
        return Err("partitioned quotient exceeds 256 cosets".into());
    }
    Ok((
        MatrixSpec::new(log_quotient, 1, extension, RowOrder::Natural, shift)?,
        part_log,
        cosets,
    ))
}

#[cfg(test)]
mod partition_tests {
    use super::*;

    #[test]
    fn quotient_partition_bounds_large_inputs_and_preserves_next_row_cosets() {
        let input = MatrixSpec::new(19, 200, Extension::Base, RowOrder::BitReversed, 7).unwrap();
        let (output, part_log, cosets) =
            partition_geometry(&[input], 18, 22, 7, Extension::Cubic).unwrap();
        assert_eq!((part_log, cosets), (19, 8));
        assert_eq!(input.bytes(), 838_860_800);
        assert_eq!(output.bytes(), 100_663_296);
        let next_step = 1usize << (22 - 18);
        let local_step = 1usize << (part_log - 18);
        for coset in 0..cosets {
            for local in [0, 1, (1 << part_log) - 2, (1 << part_log) - 1] {
                let full = local * cosets + coset;
                let full_next = (full + next_step) % output.rows();
                assert_eq!(
                    full_next,
                    ((local + local_step) % (1 << part_log)) * cosets + coset
                );
            }
        }
        assert_eq!(
            partition_geometry(&[input], 18, 27, 7, Extension::Cubic)
                .unwrap()
                .2,
            256
        );
        assert!(partition_geometry(&[input], 18, 28, 7, Extension::Cubic).is_err());
        assert!(partition_geometry(&[input], 18, 18, 7, Extension::Cubic).is_err());
        assert!(partition_geometry(&[input], 23, 22, 7, Extension::Cubic).is_err());
        assert!(partition_geometry(&[input], 18, 22, 11, Extension::Cubic).is_err());
        assert!(partition_geometry(&[], 18, 22, 7, Extension::Cubic).is_err());
    }
}

/// Contains only public static AIR data. It is reusable by fresh attempts on
/// the same device context; no witness, salt or sampled challenge is cached.
pub(crate) struct PreparedQuotient {
    program: Arc<Program>,
    code: Allocation,
    #[cfg(feature = "gpu")]
    specialized: Option<super::super::quotient::specialized::Compiled>,
    context: Arc<JobLease>,
}

fn check_matrix(
    matrix: Option<&DeviceMatrix>,
    columns: usize,
    extension: Extension,
    domain: MatrixSpec,
) -> Result<(), String> {
    match (matrix, columns) {
        (None, 0) => Ok(()),
        (Some(matrix), columns)
            if columns > 0
                && matrix.spec.columns == columns
                && matrix.spec.extension == extension
                && matrix.spec.log_rows == domain.log_rows
                && matrix.spec.shift == domain.shift =>
        {
            Ok(())
        }
        _ => Err("device quotient matrix does not match the AIR layout/domain".into()),
    }
}

impl DeviceSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quotient_cubic_partitioned(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        main: &DeviceMatrix,
        preprocessed: Option<&DeviceMatrix>,
        permutation: Option<&DeviceMatrix>,
        alpha: [u64; 3],
        parameters: &[u64],
    ) -> Result<DeviceMatrix, String> {
        if prepared.program.extension != Extension::Cubic {
            return Err("cubic quotient adapter received another extension".into());
        }
        self.quotient_extension_partitioned(
            prepared,
            log_trace,
            log_quotient,
            shift,
            main,
            preprocessed,
            permutation,
            &alpha,
            parameters,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quotient_cubic(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        main: &DeviceMatrix,
        preprocessed: Option<&DeviceMatrix>,
        permutation: Option<&DeviceMatrix>,
        alpha: [u64; 3],
        parameters: &[u64],
    ) -> Result<DeviceMatrix, String> {
        if prepared.program.extension != Extension::Cubic {
            return Err("cubic quotient adapter received another extension".into());
        }
        self.quotient_extension(
            prepared,
            log_trace,
            main,
            preprocessed,
            permutation,
            &alpha,
            parameters,
        )
    }
    /// Evaluate and interleave a larger quotient domain without expanding all
    /// columns to that domain at once. Domain descriptors are public metadata;
    /// interpolation, constraints and output assembly execute on the GPU.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quotient_extension_partitioned(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        main: &DeviceMatrix,
        preprocessed: Option<&DeviceMatrix>,
        permutation: Option<&DeviceMatrix>,
        alpha: &[u64],
        parameters: &[u64],
    ) -> Result<DeviceMatrix, String> {
        let program = &prepared.program;
        if !Arc::ptr_eq(&self.session.context, &prepared.context)
            || program.extension == Extension::Base
            || alpha.len() != program.extension.degree()
            || parameters.len() != program.parameter_words
            || alpha
                .iter()
                .chain(parameters)
                .any(|n| *n >= GOLDILOCKS_MODULUS)
        {
            return Err("invalid partitioned quotient owner or parameters".into());
        }
        for (matrix, columns, extension) in [
            (Some(main), program.layout.main_width, Extension::Base),
            (
                preprocessed,
                program.layout.preprocessed_width,
                Extension::Base,
            ),
            (
                permutation,
                program.layout.permutation_width,
                program.extension,
            ),
        ] {
            check_matrix(matrix, columns, extension, matrix.unwrap_or(main).spec)?;
        }
        let inputs: Vec<_> = [Some(main), preprocessed, permutation]
            .into_iter()
            .flatten()
            .collect();
        for input in &inputs {
            self.check_owner(input)?;
        }
        let specs: Vec<_> = inputs.iter().map(|m| m.spec).collect();
        let storage = self.with_engine(|engine| {
            let live = engine.accounting.lock().unwrap().live;
            let cache = engine.lde_workspace.as_ref().map_or(0, |w| w.bytes());
            PartitionStorage::new(
                &specs,
                log_trace,
                log_quotient,
                shift,
                program.shape(),
                live,
                cache,
                engine.limits,
                engine.max_alloc,
            )
        })?;
        let (spec, part_log, cosets) = (storage.output, storage.part_log, storage.cosets);
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (prepared, spec, part_log, cosets, alpha, parameters);
            Err("partitioned GPU quotients are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            use p3_field::PrimeField64;
            // This is the reference domain partition, not a split of the AIR.
            // x -> x * trace_generator remains within each component coset.
            let domain = DomainSpec::new(shift, log_quotient as usize)?;
            let parts = self.split_domains(domain, cosets)?;
            let result = self.with_engine(|engine| self.allocate(engine, spec))?;
            for (coset, part) in parts.into_iter().enumerate() {
                let part_shift = part.shift().as_canonical_u64();
                let expand = |input: &DeviceMatrix| {
                    if input.spec.log_rows == part_log && input.spec.shift == part_shift {
                        self.alias_private(input)
                    } else {
                        self.lde(input, part_log, part_shift, RowOrder::BitReversed)
                    }
                };
                let part_main = expand(main)?;
                let part_pre = preprocessed.map(expand).transpose()?;
                let part_perm = permutation.map(expand).transpose()?;
                let values = self.quotient_extension(
                    prepared,
                    log_trace,
                    &part_main,
                    part_pre.as_ref(),
                    part_perm.as_ref(),
                    alpha,
                    parameters,
                )?;
                self.with_engine(|engine| {
                    let fence = engine.fence();
                    let mut event = compute::Event::empty();
                    // SAFETY: the partition is exact, each coset writes disjoint
                    // natural-order rows, and both extension allocations are owned.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_quotient_scatter_coset")
                            .arg(&values.storage.buffer)
                            .arg(&result.storage.buffer)
                            .arg(values.spec.rows() as u32)
                            .arg(coset as u32)
                            .arg(cosets as u32)
                            .arg(spec.extension.degree() as u32)
                            .global_work_size(values.spec.words())
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    let ns = self.session.record_event(
                        engine,
                        crate::proving::Stage::Quotient,
                        "device_quotient_scatter_coset",
                        &event,
                    )?;
                    fence.finish()?;
                    self.session.stats.lock().unwrap().quotient_device_ns += ns;
                    Ok(())
                })?;
            }
            eprintln!("bounded_device_quotient_partition rows={} coset_rows={} cosets={} input_matrix_upload_bytes=0", spec.rows(), 1usize << part_log, cosets);
            Ok(result)
        }
    }

    pub(crate) fn prepare_quotient(
        &self,
        program: Arc<Program>,
    ) -> Result<PreparedQuotient, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = program;
            Err("owned GPU quotient evaluation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let specialized = super::super::quotient::specialized::prepare(engine, &program)?;
            let mut code = allocation(
                &engine.pq,
                &engine.accounting,
                engine.limits,
                engine.max_alloc,
                program.instructions.len(),
                compute::flags::MEM_READ_ONLY,
            )?;
            code._lease.mark_device()?;
            let fence = engine.fence();
            code.buffer
                .write(&program.instructions)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = (program.instructions.len() * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += uploaded;
            stats.prepared_quotient_programs += 1;
            Ok(PreparedQuotient {
                program,
                code,
                specialized,
                context: self.session.context.clone(),
            })
        })
    }

    /// The trace is the subgroup of size `2^log_trace`; the supplied device
    /// matrices contain its evaluations on one larger, disjoint coset. Local
    /// and next rows are gathered on GPU, including physical bit-reversal.
    /// Returns a natural-order cubic vector without reading it back.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quotient_extension(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        main: &DeviceMatrix,
        preprocessed: Option<&DeviceMatrix>,
        permutation: Option<&DeviceMatrix>,
        alpha: &[u64],
        parameters: &[u64],
    ) -> Result<DeviceMatrix, String> {
        if !Arc::ptr_eq(&self.session.context, &prepared.context) {
            return Err("prepared quotient belongs to another device context".into());
        }
        for matrix in [Some(main), preprocessed, permutation]
            .into_iter()
            .flatten()
        {
            self.check_owner(matrix)?;
        }
        let program = &prepared.program;
        let domain = main.spec;
        if log_trace > domain.log_rows
            || domain.log_rows > 31
            || program.extension == Extension::Base
            || alpha.len() != program.extension.degree()
            || parameters.len() != program.parameter_words
            || alpha
                .iter()
                .chain(parameters)
                .any(|n| *n >= GOLDILOCKS_MODULUS)
        {
            return Err("invalid device quotient domain or parameters".into());
        }
        check_matrix(
            Some(main),
            program.layout.main_width,
            Extension::Base,
            domain,
        )?;
        check_matrix(
            preprocessed,
            program.layout.preprocessed_width,
            Extension::Base,
            domain,
        )?;
        check_matrix(
            permutation,
            program.layout.permutation_width,
            program.extension,
            domain,
        )?;
        let spec = MatrixSpec::new(
            domain.log_rows,
            1,
            program.extension,
            RowOrder::Natural,
            domain.shift,
        )?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = spec;
            Err("owned GPU quotient evaluation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            engine.fence().finish()?;
            engine.lde_workspace = None;
            let live = engine.accounting.lock().unwrap().live;
            let prospective_live = live.checked_add(spec.bytes()).ok_or("device quotient output overflow")?;
            let plan = Plan::for_device(program, spec.rows(), prospective_live, engine.limits, engine.max_alloc)?;
            let result = self.allocate(engine, spec)?;
            let alloc = |words| allocation(&engine.pq, &engine.accounting, engine.limits,
                engine.max_alloc, words, compute::flags::MEM_READ_WRITE);
            let params = alloc(plan.static_words[1])?;
            let weights = alloc(plan.static_words[2])?;
            let status = alloc(plan.static_words[3])?;
            let input = alloc(plan.tile_words[0])?;
            let scratch = alloc(plan.tile_words[1])?;
            let empty = [0u64];
            let mut validation = [0u64];
            let fence = engine.fence();
            let started = std::time::Instant::now();
            params.buffer.write(if parameters.is_empty() { &empty[..] } else { parameters })
                .enq().map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: one status word and a validated exponent/shift.
            unsafe {
                engine.pq.kernel_builder("device_quotient_domain").arg(&status.buffer)
                    .arg(domain.log_rows).arg(domain.shift).global_work_size(1usize)
                    .build().map_err(|e| e.to_string())?.cmd().enew(&mut event)
                    .enq().map_err(|e| e.to_string())?;
            }
            let mut device_ns = self.session.record_event(engine, crate::proving::Stage::Quotient, "device_quotient_domain", &event)?;
            status.buffer.read(&mut validation[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = (plan.static_words[1] * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 8;
            }
            if validation[0] != 0 {
                return Err("device quotient coset overlaps the trace subgroup".into());
            }
            let mut event = compute::Event::empty();
            // SAFETY: the compiler and plan bound every weight coefficient.
            unsafe {
                engine.pq.kernel_builder(if program.extension == Extension::Quadratic { "quadratic_quotient_alpha" } else { "cubic_quotient_alpha" }).arg(&weights.buffer)
                    .arg(program.constraints as u32).arg(alpha[0]).arg(alpha[1]).arg(alpha.get(2).copied().unwrap_or(0))
                    .global_work_size(1usize).build().map_err(|e| e.to_string())?
                    .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
            }
            device_ns += self.session.record_event(engine, crate::proving::Stage::Quotient, "quotient_alpha", &event)?;
            let pre = preprocessed.unwrap_or(main);
            let perm = permutation.unwrap_or(main);
            for first in (0..spec.rows()).step_by(plan.rows) {
                let rows = plan.rows.min(spec.rows() - first);
                let mut event = compute::Event::empty();
                // SAFETY: matrix shapes and orders were checked above; zero-width
                // optional matrices have no corresponding instructions or reads.
                unsafe {
                    engine.pq.kernel_builder("device_quotient_gather")
                        .arg(&main.storage.buffer).arg(&pre.storage.buffer).arg(&perm.storage.buffer)
                        .arg(&input.buffer).arg(program.layout.main_width as u32)
                        .arg(program.layout.preprocessed_width as u32)
                        .arg((program.layout.permutation_width * program.extension.degree()) as u32)
                        .arg(u32::from(main.spec.order == RowOrder::BitReversed))
                        .arg(u32::from(pre.spec.order == RowOrder::BitReversed))
                        .arg(u32::from(perm.spec.order == RowOrder::BitReversed))
                        .arg(domain.log_rows).arg(1u32 << (domain.log_rows - log_trace))
                        .arg(first as u32).arg(rows as u32).global_work_size(rows * program.row_words)
                        .build().map_err(|e| e.to_string())?.cmd().enew(&mut event)
                        .enq().map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(engine, crate::proving::Stage::Quotient, "device_quotient_gather", &event)?;
                let mut event = compute::Event::empty();
                // SAFETY: compiler bounds input/parameter/register indices; each
                // tile writes a disjoint slice of the full output allocation.
                let mut kernel = engine.pq.kernel_builder(if program.extension == Extension::Quadratic {
                    "quadratic_quotient"
                } else {
                    "cubic_quotient"
                });
                if let Some(compiled) = &prepared.specialized {
                    kernel.program(&compiled.program).name("specialized_quotient");
                }
                if let Some(local) = super::super::quotient::row_workgroup(engine.pq.device(), rows) {
                    kernel.local_work_size(local);
                }
                unsafe {
                    kernel
                        .arg(&prepared.code.buffer).arg(program.instruction_count() as u32)
                        .arg(&input.buffer).arg(program.row_words as u32)
                        .arg(&params.buffer).arg(&weights.buffer).arg(&scratch.buffer)
                        .arg(&result.storage.buffer).arg(rows as u32).arg(first as u32)
                        .arg(first as u32).arg(log_trace).arg(domain.shift)
                        .arg(super::super::fri_fold::root(domain.log_rows))
                        .arg(super::super::fri_fold::inverse_root(log_trace))
                        .global_work_size(rows).build().map_err(|e| e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(engine, crate::proving::Stage::Quotient, "device_extension_quotient", &event)?;
            }
            fence.finish()?;
            drop(fence);
            if let Some(compiled) = &prepared.specialized {
                compiled.check_execution(engine)?;
            }
            let mut stats = self.session.stats.lock().unwrap();
            stats.quotient_evaluations += 1;
            stats.quotient_device_ns += device_ns;
            eprintln!("bounded_device_quotient rows={} tile_rows={} managed_peak_plan_bytes={} parameter_upload_bytes={uploaded} control_download_bytes=8 device_ns={device_ns} wall_ns={}",
                spec.rows(), plan.rows, plan.peak, started.elapsed().as_nanos());
            Ok(result)
        })
    }
}
