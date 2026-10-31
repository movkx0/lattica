//! Exact GBound coverage is marked only after the complete ordered-root join.
use super::*;
use lattica_prover_p3::block_v2::native_g_bound_proof::NativeGBoundProof;

impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_g_bound_batch_owned(&mut self, indices: &[usize], artifact: &NativeGBoundProof) -> Result<()> {
        let [index] = indices else { return Err(error("GBound must contain exactly one operation")); };
        let Operation::GBound { f, x, bound } = *self.pending(*index)? else {
            return Err(error("operation is not GBound"));
        };
        let key = RegisteredGBoundAir::new(bound).map_err(component_error)?;
        let f_root = self.typed_root(f, PolynomialKind::Signed { bound: key.air().f_bound() })?;
        let x_root = self.typed_root(x, PolynomialKind::Signed { bound: 1 })?;
        key.compile_root_join_owned(self.builder, self.inputs, &f_root, &x_root, artifact)
            .map_err(component_error)?;
        // GBound produces no polynomial. Do not clear either input's producer obligation.
        self.operation_bound[*index] = true;
        Ok(())
    }
}
