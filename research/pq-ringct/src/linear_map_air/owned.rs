//! Exact private metadata bridge; no graph/witness/proof/dispatch constructor.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::LinearMapDescriptor as OwnedDescriptor;
impl LinearMapDescriptor {
    pub(crate) fn owned_descriptor(&self) -> Result<OwnedDescriptor, Error> {
        let mut kinds = [[0;2];17];
        for (target,kind) in kinds.iter_mut().zip(self.inputs.iter().chain(core::iter::once(&self.output))) {
            *target = match kind { PolynomialKind::Canonical { modulus } => [*modulus,0],
                PolynomialKind::Signed { bound } => [0,u64::from(*bound)] };
        }
        let result = OwnedDescriptor::new(&kinds[..self.inputs.len()+1], &self.coefficients, &self.constant)
            .map_err(|_| Error::Descriptor)?;
        if result.bits()!=self.bits || result.quotient_bound()!=self.quotient_bound || result.bounds()!=self.bounds
            || result.coefficients()!=self.coefficients || result.constant()!=&self.constant {
            return Err(Error::Descriptor);
        }
        Ok(result)
    }
    /// Only the private-field, constructor-validated owned descriptor enters.
    /// The caller precharges all three exact-length Vec clone requests.
    pub(crate) fn from_owned(kind: &OwnedDescriptor) -> Self {
        let decode = |encoded: &[u64;2]| if encoded[0]!=0 {
            PolynomialKind::Canonical {modulus:encoded[0]}
        } else { PolynomialKind::Signed {bound:encoded[1] as u32} };
        let mut result = Self {inputs:kind.kinds()[..kind.inputs()].iter().map(decode).collect(),
            output:decode(&kind.kinds()[kind.inputs()]), coefficients:kind.coefficients().to_vec(),
            constant:*kind.constant(), quotient_bound:kind.quotient_bound(), bits:kind.bits(), bounds:kind.bounds().to_vec(), metadata_key:[0;32]};
        result.metadata_key = result.compute_metadata_key();
        result
    }
    pub(crate) const fn maximum_owned_clone_backing_bytes() -> usize {
        16 * core::mem::size_of::<PolynomialKind>() + 16 * core::mem::size_of::<[i64;D]>() + 18 * core::mem::size_of::<u32>()
    }
}
