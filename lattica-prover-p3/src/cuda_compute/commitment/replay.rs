//! Hiding commitment consumer for private, bounded salt replay recipes.
use super::*;
use crate::cuda_compute::ReplaySalts;

impl Commitments {
    pub(crate) fn commit_replayed(
        &self,
        input: &Matrix,
        salts: &ReplaySalts,
        cap_height: usize,
    ) -> Result<RetainedTree> {
        self.check_owner(&input.buffer)?;
        salts.check_runtime(&self.runtime)?;
        let spec = input.spec;
        if salts.spec() != MatrixSpec::new(spec.log_rows, 4, Extension::Base, spec.order, 1)?
            || spec.words() / spec.rows() > u32::MAX as usize
        {
            return Err("CUDA replayed commitment salts have an incompatible domain".into());
        }
        let layout = Layout::new(spec.log_rows, cap_height)?;
        let state_words = layout
            .height
            .checked_mul(8)
            .ok_or("CUDA sponge size overflow")?;
        // Sampling and hashing scratch do not coexist. Admit both stage peaks
        // before replay; the sampler's five allocations also cover hashing's
        // salt matrix, tree and sponge-state buffers.
        salts.preflight(&[])?;
        admit(
            &[salts.spec().words(), layout.words, state_words],
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        salts.with_materialized(|matrix| {
            // Salts are independent physical rows, not polynomial evaluations.
            // A recipe keeps canonical shift-one metadata, while absorption
            // needs a fragment on the input's public coset. This view neither
            // transforms nor copies the private values.
            let fragment = Matrix {
                spec: MatrixSpec::new(spec.log_rows, 4, Extension::Base, spec.order, spec.shift)?,
                buffer: matrix.buffer.clone(),
            };
            self.commit_salted(input, &fragment, cap_height)
        })
    }
}
