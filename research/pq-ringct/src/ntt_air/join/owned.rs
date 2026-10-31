//! Complete unchanged NTT STARK/FRI verification over original native borrows.
use super::*;
use lattica_prover_p3::block_v2::{native_ntt_proof::NativeNttProof,
    native_gpu::ntt_preparation::NttDescriptor};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;

impl RegisteredNttAir {
    pub(crate) fn compile_root_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, requests: &[NttRootRequest], artifact: &NativeNttProof)
        -> Result<(), Error>
    {
        let descriptor = NttDescriptor::new(self.air.modulus, self.air.count)
            .map_err(|_| Error::Descriptor)?;
        if artifact.kind != descriptor
            || artifact.proof.degree_bits != self.air.height.ilog2() as usize + 1
            || requests.len() != self.air.count
            || requests.iter().any(|request| request.modulus != self.air.modulus)
            || artifact.public_values().len() != self.air.public_values()
            || artifact.public_values[8 * descriptor.count()..].iter().any(|value| *value != Val::ZERO)
        { return Err(Error::Shape("owned NTT registration/request mismatch")); }
        let public = inputs.bases(b, artifact.public_values())?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, self.air.height, &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        for (index, request) in requests.iter().enumerate() {
            for lane in 0..4 {
                b.assert_equal(public[8 * index + lane], request.input_commitment[lane]);
                b.assert_equal(public[8 * index + 4 + lane], request.output_commitment[lane]);
            }
        }
        Ok(())
    }
}
