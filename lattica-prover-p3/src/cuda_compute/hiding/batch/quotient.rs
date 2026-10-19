//! Scoped extraction of committed main/preprocessing/permutation prefixes.
//! Private aliases never escape the participating randomness-family guards.
use super::*;
use crate::cuda_compute::{PreparedQuotient, Quotients};

#[derive(Clone, Copy)]
pub(crate) struct CommittedMatrix<'a> {
    pub commitment: &'a HiddenCommitment,
    pub index: usize,
    /// Logical columns; permutation columns contain extension elements.
    pub columns: usize,
    pub extension: Extension,
}

impl CommittedMatrix<'_> {
    fn spec(self, runtime: &Runtime) -> Result<MatrixSpec> {
        self.commitment.check_runtime(runtime)?;
        let input = self
            .commitment
            .matrices
            .get(self.index)
            .ok_or("CUDA quotient matrix index exceeds commitment")?;
        let width = self
            .columns
            .checked_mul(self.extension.degree())
            .ok_or("CUDA committed quotient width overflow")?;
        if width == 0 || Some(width) != input.spec.columns.checked_sub(input.random_columns) {
            return Err("CUDA quotient width differs from committed columns".into());
        }
        MatrixSpec::new(
            input.prefix.spec.log_rows,
            self.columns,
            self.extension,
            input.prefix.spec.order,
            input.prefix.spec.shift,
        )
    }

    fn extract(self, hiding: &Hiding, spec: MatrixSpec) -> Result<Matrix> {
        let input = &self.commitment.matrices[self.index];
        let output = Matrix {
            spec,
            buffer: hiding.runtime.allocate(spec.words())?,
        };
        // Copy flattened base coefficients. Only the validated masking suffix
        // is omitted; extension columns retain their original coefficient order.
        unsafe {
            hiding
                .randomization_columns
                .launch(
                    crate::cuda_compute::transform::linear_launch(spec.words())?,
                    &[
                        Argument::Buffer(&input.prefix.buffer),
                        Argument::Buffer(&output.buffer),
                        Argument::U32(spec.rows() as u32),
                        Argument::U32(input.prefix.spec.columns as u32),
                        Argument::U32(0),
                        Argument::U32((spec.columns * spec.extension.degree()) as u32),
                    ],
                )?
                .finish()?;
        }
        Ok(output)
    }
}

impl Hiding {
    /// Ordered main, preprocessing and permutation inputs. Validate and admit
    /// the complete extraction/expansion schedule before launching; guard every
    /// family until evaluation completes, including error and unwind paths.
    pub(crate) fn evaluate_committed_quotient(
        &self,
        quotients: &Quotients,
        prepared: &PreparedQuotient,
        inputs: [Option<CommittedMatrix<'_>>; 3],
        log_trace: u32,
        log_quotient: u32,
        alpha: &Buffer,
        parameters: Option<&Buffer>,
    ) -> Result<Matrix> {
        if inputs[0].is_none()
            || inputs[..2]
                .iter()
                .flatten()
                .any(|i| i.extension != Extension::Base)
            || inputs[2].is_some_and(|i| i.extension == Extension::Base)
        {
            return Err("CUDA committed quotient input extensions differ from protocol".into());
        }
        let specs = inputs.map(|i| i.map(|i| i.spec(&self.runtime)).transpose());
        let [main, prep, perm] = specs;
        let specs = [main?, prep?, perm?];
        let state = self.runtime.snapshot();
        let limits = self.runtime.state.budget.limits;
        let (_, _, allocations) = prepared.extracted_partition_storage(
            specs,
            log_trace,
            log_quotient,
            state.live_bytes,
            limits,
        )?;
        if state
            .allocations
            .checked_add(allocations)
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA committed quotient exceeds allocation count".into());
        }
        let mut guards = Vec::with_capacity(3);
        for input in inputs.iter().flatten() {
            guards.push(input.commitment.begin_attempt(&self.runtime)?);
        }
        let result = quotients.evaluate_partitioned_extracted(
            prepared,
            log_trace,
            log_quotient,
            specs,
            alpha,
            parameters,
            |index, log, shift| {
                let input = inputs[index]
                    .unwrap()
                    .extract(self, specs[index].unwrap())?;
                if input.spec.log_rows == log && input.spec.shift == shift {
                    Ok(input)
                } else {
                    self.transforms
                        .lde(&input, log, shift, RowOrder::BitReversed)
                }
            },
        )?;
        for input in inputs.iter().flatten() {
            check_families(&input.commitment.families)?;
        }
        for guard in guards {
            guard.complete();
        }
        Ok(result)
    }
}
