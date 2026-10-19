//! Preflight byte budgets for reconstruction/evaluation before GPU work.
//! Degree prefixes stay immutable; at most one component coset is expanded.
use super::*;
use crate::{cuda_compute::Transforms, gpu_matrix::GOLDILOCKS_MODULUS};

const MAX_COSETS: usize = 256;

#[derive(Debug)]
struct PartitionPlan {
    output: MatrixSpec,
    part_log: u32,
    cosets: usize,
    peak_bytes: usize,
    expansion_peak_bytes: usize,
    evaluation_peak_bytes: usize,
}

impl PartitionPlan {
    fn new(
        program: &Program,
        inputs: [Option<MatrixSpec>; 3],
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        live: usize,
        limits: Limits,
    ) -> Result<Self> {
        Self::with_sources(
            program,
            inputs,
            log_trace,
            log_quotient,
            shift,
            live,
            limits,
            false,
        )
    }

    /// Extracted sources are produced one at a time from retained commitments.
    /// Only the current extraction coexists with its transform workspace; each
    /// completed expansion survives until the component quotient is evaluated.
    fn with_sources(
        program: &Program,
        inputs: [Option<MatrixSpec>; 3],
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        live: usize,
        limits: Limits,
        extracted: bool,
    ) -> Result<Self> {
        if log_trace > log_quotient || log_quotient > 31 || inputs.iter().all(Option::is_none) {
            return Err("invalid CUDA quotient partition domain".into());
        }
        let output = MatrixSpec::new(log_quotient, 1, program.extension, RowOrder::Natural, shift)?;
        if output.bytes() > limits.max_allocation_bytes {
            return Err("CUDA partition result exceeds per-allocation limit".into());
        }
        let mut part_log = log_trace;
        let mut row_words = 0usize;
        for input in inputs.into_iter().flatten() {
            if input.log_rows > log_quotient || input.shift != shift {
                return Err("CUDA quotient prefixes must fit and share the base coset".into());
            }
            if extracted && input.order != RowOrder::BitReversed {
                return Err("CUDA committed quotient requires bit-reversed prefixes".into());
            }
            part_log = part_log.max(input.log_rows);
            row_words = row_words
                .checked_add(input.words() / input.rows() * 2)
                .ok_or("CUDA partition row width overflow")?;
        }
        if row_words != program.row_words {
            return Err("CUDA partition inputs differ from AIR row width".into());
        }
        let cosets = 1usize << (log_quotient - part_log);
        if cosets > MAX_COSETS {
            return Err("CUDA quotient exceeds 256 component cosets".into());
        }
        let descriptors = if cosets == 1 { 0 } else { (cosets + 1) * 8 };
        if descriptors > limits.max_allocation_bytes {
            return Err("CUDA quotient domain descriptors exceed allocation limit".into());
        }
        // In the one-coset case evaluate() returns the final allocation directly.
        let result_bytes = if cosets == 1 { 0 } else { output.bytes() };
        let base = live
            .checked_add(result_bytes)
            .ok_or("CUDA partition result size overflow")?;
        let descriptor_peak = live
            .checked_add(descriptors)
            .ok_or("CUDA partition descriptor overflow")?;
        if base.max(descriptor_peak) > limits.managed_bytes {
            return Err("CUDA partition initial storage exceeds budget".into());
        }
        let mut retained = base;
        let mut expansion_peak_bytes = base;
        for input in inputs.into_iter().flatten() {
            let alias = cosets == 1 && input.log_rows == part_log;
            if alias && !extracted {
                continue;
            }
            let working = if extracted {
                if input.bytes() > limits.max_allocation_bytes {
                    return Err("CUDA quotient extraction exceeds allocation limit".into());
                }
                retained
                    .checked_add(input.bytes())
                    .filter(|&bytes| bytes <= limits.managed_bytes)
                    .ok_or("CUDA quotient extraction exceeds managed allowance")?
            } else {
                retained
            };
            // Later cosets transform even full-height prefixes to a new shift.
            // The shared transform planner charges both work buffers and roots.
            let peak = if alias {
                working
            } else {
                super::super::transform::storage_plan(input, part_log, working, limits)?.peak_bytes
            };
            expansion_peak_bytes = expansion_peak_bytes.max(peak);
            let expanded = MatrixSpec::new(
                part_log,
                input.columns,
                input.extension,
                RowOrder::BitReversed,
                shift,
            )?;
            retained = retained
                .checked_add(expanded.bytes())
                .ok_or("CUDA partition expansion overflow")?;
        }
        let evaluation = Plan::new(program, 1usize << part_log, retained, limits)?;
        let peak_bytes = descriptor_peak
            .max(expansion_peak_bytes)
            .max(evaluation.peak_bytes);
        Ok(Self {
            output,
            part_log,
            cosets,
            peak_bytes,
            expansion_peak_bytes,
            evaluation_peak_bytes: evaluation.peak_bytes,
        })
    }
}

impl PreparedQuotient {
    pub(in crate::cuda_compute) fn partition_storage(
        &self,
        inputs: [Option<MatrixSpec>; 3],
        log_trace: u32,
        log_quotient: u32,
        live: usize,
        limits: Limits,
    ) -> Result<(MatrixSpec, usize, usize)> {
        self.partition_storage_impl(inputs, log_trace, log_quotient, live, limits, false)
    }

    pub(in crate::cuda_compute) fn extracted_partition_storage(
        &self,
        inputs: [Option<MatrixSpec>; 3],
        log_trace: u32,
        log_quotient: u32,
        live: usize,
        limits: Limits,
    ) -> Result<(MatrixSpec, usize, usize)> {
        self.partition_storage_impl(inputs, log_trace, log_quotient, live, limits, true)
    }

    fn partition_storage_impl(
        &self,
        inputs: [Option<MatrixSpec>; 3],
        log_trace: u32,
        log_quotient: u32,
        live: usize,
        limits: Limits,
        extracted: bool,
    ) -> Result<(MatrixSpec, usize, usize)> {
        let plan = PartitionPlan::with_sources(
            &self.program,
            inputs,
            log_trace,
            log_quotient,
            7,
            live,
            limits,
            extracted,
        )?;
        let expansions = inputs
            .into_iter()
            .flatten()
            .filter(|s| extracted || plan.cosets > 1 || s.log_rows != plan.part_log)
            .count();
        // Result (unless directly returned), retained expansions, and the five
        // evaluation buffers. A transform needs five buffers before releasing
        // its scratch, so its peak count cannot exceed this bound.
        let allocations = usize::from(plan.cosets > 1) + expansions + 5 + usize::from(extracted);
        Ok((plan.output, plan.peak_bytes, allocations))
    }
}

impl Quotients {
    /// Reconstruct one component coset at a time, then interleave its quotient
    /// into the natural row order of the full domain. Prepared code, challenges,
    /// parameters and input degree prefixes stay resident and unchanged.
    pub(crate) fn evaluate_partitioned(
        &self,
        transforms: &Transforms,
        prepared: &PreparedQuotient,
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        inputs: QuotientInputs<'_>,
        alpha: &Buffer,
        parameters: Option<&Buffer>,
    ) -> Result<Matrix> {
        if !Arc::ptr_eq(&self.runtime.state, &transforms.runtime.state) {
            return Err("CUDA partition transforms belong to another runtime".into());
        }
        self.parameters(prepared, alpha, parameters)?;
        let specs = self.input_specs(&prepared.program, inputs)?;
        let plan = PartitionPlan::new(
            &prepared.program,
            specs,
            log_trace,
            log_quotient,
            shift,
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        self.evaluate_partitioned_plan(
            prepared,
            log_trace,
            alpha,
            parameters,
            &plan,
            |index, log, shift| {
                [inputs.main, inputs.preprocessed, inputs.permutation][index]
                    .map(|input| {
                        if input.spec.log_rows == log && input.spec.shift == shift {
                            Ok(input.clone())
                        } else {
                            transforms.lde(input, log, shift, RowOrder::BitReversed)
                        }
                    })
                    .transpose()
            },
        )
    }

    pub(in crate::cuda_compute) fn evaluate_partitioned_extracted(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        log_quotient: u32,
        inputs: [Option<MatrixSpec>; 3],
        alpha: &Buffer,
        parameters: Option<&Buffer>,
        mut extract: impl FnMut(usize, u32, u64) -> Result<Matrix>,
    ) -> Result<Matrix> {
        self.parameters(prepared, alpha, parameters)?;
        let plan = PartitionPlan::with_sources(
            &prepared.program,
            inputs,
            log_trace,
            log_quotient,
            7,
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
            true,
        )?;
        self.evaluate_partitioned_plan(
            prepared,
            log_trace,
            alpha,
            parameters,
            &plan,
            |index, log, shift| {
                inputs[index]
                    .map(|spec| {
                        let output = extract(index, log, shift)?;
                        let expected = MatrixSpec::new(
                            log,
                            spec.columns,
                            spec.extension,
                            RowOrder::BitReversed,
                            shift,
                        )?;
                        if output.spec != expected {
                            return Err(
                                "CUDA extracted quotient matrix differs from planned domain".into(),
                            );
                        }
                        Ok(output)
                    })
                    .transpose()
            },
        )
    }

    fn evaluate_partitioned_plan(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        alpha: &Buffer,
        parameters: Option<&Buffer>,
        plan: &PartitionPlan,
        mut expand: impl FnMut(usize, u32, u64) -> Result<Option<Matrix>>,
    ) -> Result<Matrix> {
        let shift = plan.output.shift;
        let log_quotient = plan.output.log_rows;
        let (shifts, result) = if plan.cosets == 1 {
            // Public identity mapping: avoid duplicate output or input storage.
            (vec![shift], None)
        } else {
            let buffer = self.runtime.allocate(plan.cosets + 1)?;
            // Each lane owns one shift word; only lane zero writes status.
            unsafe {
                self.partition.launch(
                    launch(plan.cosets)?,
                    &[
                        Argument::Buffer(&buffer),
                        Argument::U32(log_quotient),
                        Argument::U32(plan.cosets as u32),
                        Argument::U64(shift),
                        Argument::U64(roots::root(log_quotient)),
                    ],
                )?
            }
            .finish()?;
            let mut words = vec![0u64; plan.cosets + 1]; // <= 2,056 public host bytes
            buffer.read(0, &mut words)?;
            if words[0] != 0
                || words[1..]
                    .iter()
                    .any(|&word| word == 0 || word >= GOLDILOCKS_MODULUS)
            {
                return Err("invalid CUDA quotient component domains".into());
            }
            drop(buffer);
            words.remove(0);
            (words, Some(self.runtime.allocate(plan.output.words())?))
        };
        for (coset, part_shift) in shifts.into_iter().enumerate() {
            let main = expand(0, plan.part_log, part_shift)?;
            let preprocessed = expand(1, plan.part_log, part_shift)?;
            let permutation = expand(2, plan.part_log, part_shift)?;
            let values = self.evaluate(
                prepared,
                log_trace,
                QuotientInputs {
                    main: main.as_ref(),
                    preprocessed: preprocessed.as_ref(),
                    permutation: permutation.as_ref(),
                },
                alpha,
                parameters,
            )?;
            let Some(result) = &result else {
                return Ok(values);
            };
            // The exact power-of-two partition covers every output row once.
            // Component storage and result are distinct and all words fit their
            // admitted allocations; in-order completion precedes scratch reuse.
            unsafe {
                self.scatter.launch(
                    launch(values.spec.words())?,
                    &[
                        Argument::Buffer(&values.buffer),
                        Argument::Buffer(result),
                        Argument::U32(1u32 << plan.part_log),
                        Argument::U32(plan.output.extension.degree() as u32),
                        Argument::U32(coset as u32),
                        Argument::U32(plan.cosets as u32),
                    ],
                )?
            }
            .finish()?;
        }
        Ok(Matrix {
            spec: plan.output,
            buffer: result.ok_or("CUDA partition returned no result")?,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benchmark;
