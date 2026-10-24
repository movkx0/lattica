//! Raw graph preparation on the admitted OpenCL context. Relation acceptance
//! still requires every source, component and recursive proof.
use super::*;
use crate::{
    ntt_air::NttAir,
    permutation_air::{PermutationAir, PermutationInput, PermutationKind},
    poly_air::MulAir,
};
use lattica_prover_p3::block_v2::native_gpu::{
    operations_arithmetic::{ArithmeticOperationSpec, CanonicalOperation, SignedOperation},
    OperationContext,
};

mod raw_primitives;
#[cfg(test)]
mod tests;
type RawPoly = [u64; D];
type RawSigned = [i64; D];

fn single(words: Vec<u64>) -> Result<u64, String> {
    let [value]: [u64; 1] = words.try_into().map_err(|_| "GPU scalar output shape")?;
    Ok(value)
}
fn polynomial(words: Vec<u64>) -> Result<RawPoly, String> {
    words
        .try_into()
        .map_err(|_| "GPU polynomial output shape".into())
}

/// Object-safe boundary keeps the backend's borrow independent of the engine
/// context's internal lifetime. All methods return raw values, never traces.
pub(super) trait GraphDevice {
    fn canonical(
        &self,
        kind: CanonicalOperation,
        left: &[u64],
        right: &[u64],
        q: u64,
    ) -> Result<Vec<u64>, String>;
    fn signed(
        &self,
        kind: SignedOperation,
        input: &[u64],
        count: usize,
    ) -> Result<Vec<u64>, String>;
    fn convert(&self, input: &[i64], q: u64) -> Result<Vec<u64>, String>;
    fn ntt_poly(&self, input: &RawSigned, q: u64) -> Result<RawPoly, String>;
    fn mul_poly(&self, left: &RawPoly, right: &RawPoly, q: u64) -> Result<RawPoly, String>;
    fn aut_poly(&self, input: &RawPoly) -> Result<RawPoly, String>;
    fn commit_canonical(&self, input: &RawPoly, q: u64) -> Result<[Val; 4], String>;
    fn commit_signed(&self, input: &RawSigned) -> Result<[Val; 4], String>;
    fn commit_bytes(&self, input: &[u8; 32]) -> Result<[Val; 4], String>;
    fn parameters(
        &self,
        seed: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<primitives::Parameters, String>;
    fn sample_g(&self, seed: &[u8; 32]) -> Result<Vec<RawPoly>, String>;
    fn expand_alpha(&self, seed: &[u8; 32]) -> Result<(Vec<RawPoly>, RawSigned), String>;
    fn hash_alpha(&self, input: &[u8]) -> Result<[u8; 32], String>;
    fn hash_x(&self, input: &[u8]) -> Result<RawSigned, String>;

    fn canonical_add(&self, a: u64, b: u64, q: u64) -> Result<u64, String> {
        single(self.canonical(CanonicalOperation::Add, &[a], &[b], q)?)
    }
    fn canonical_sub(&self, a: u64, b: u64, q: u64) -> Result<u64, String> {
        single(self.canonical(CanonicalOperation::Subtract, &[a], &[b], q)?)
    }
    fn canonical_mont(&self, a: u64, b: u64, q: u64) -> Result<u64, String> {
        single(self.canonical(CanonicalOperation::Montgomery, &[a], &[b], q)?)
    }
    fn signed_to_canonical(&self, value: i64, q: u64) -> Result<u64, String> {
        single(self.convert(&[value], q)?)
    }
    fn signed_neg(&self, value: i64) -> Result<i64, String> {
        Ok(single(self.signed(SignedOperation::Negate, &[value as u64], 1)?)? as i64)
    }
    fn signed_sub(&self, a: i64, b: i64) -> Result<i64, String> {
        Ok(single(self.signed(SignedOperation::Subtract, &[a as u64, b as u64], 1)?)? as i64)
    }
    fn add_poly(&self, a: &RawPoly, b: &RawPoly, q: u64) -> Result<RawPoly, String> {
        polynomial(self.canonical(CanonicalOperation::Add, a, b, q)?)
    }
    fn sub_poly(&self, a: &RawPoly, b: &RawPoly, q: u64) -> Result<RawPoly, String> {
        polynomial(self.canonical(CanonicalOperation::Subtract, a, b, q)?)
    }
    fn signed_poly_to_canonical(&self, values: &RawSigned, q: u64) -> Result<RawPoly, String> {
        polynomial(self.convert(values, q)?)
    }
}

impl GraphDevice for OperationContext<'_> {
    fn canonical(
        &self,
        kind: CanonicalOperation,
        left: &[u64],
        right: &[u64],
        q: u64,
    ) -> Result<Vec<u64>, String> {
        if left.len() != right.len() {
            return Err("GPU canonical operand lengths differ".into());
        }
        let spec = ArithmeticOperationSpec::canonical(kind, left.len(), q)?;
        self.admit_arithmetic_operation(&spec)?;
        let mut raw = Vec::with_capacity(spec.raw_input_words());
        raw.extend_from_slice(left);
        raw.extend_from_slice(right);
        self.arithmetic_output(&spec, &raw)
    }
    fn signed(
        &self,
        kind: SignedOperation,
        input: &[u64],
        count: usize,
    ) -> Result<Vec<u64>, String> {
        let spec = ArithmeticOperationSpec::signed(kind, count)?;
        self.arithmetic_output(&spec, input)
    }
    fn convert(&self, input: &[i64], q: u64) -> Result<Vec<u64>, String> {
        let spec = ArithmeticOperationSpec::signed_to_canonical(input.len(), q)?;
        self.admit_arithmetic_operation(&spec)?;
        let raw: Vec<_> = input.iter().map(|&v| v as u64).collect();
        self.arithmetic_output(&spec, &raw)
    }
    fn ntt_poly(&self, input: &RawSigned, q: u64) -> Result<RawPoly, String> {
        let air = NttAir::new(q, 1).map_err(|e| format!("{e:?}"))?;
        let mut output = air.evaluate_gpu_operations(self, std::slice::from_ref(input))?;
        if output.len() != 1 {
            return Err("GPU NTT output count".into());
        }
        Ok(output.remove(0))
    }
    fn mul_poly(&self, left: &RawPoly, right: &RawPoly, q: u64) -> Result<RawPoly, String> {
        let air = MulAir::new(q, 1).map_err(|e| format!("{e:?}"))?;
        let mut output = air.evaluate_gpu_operations(
            self,
            std::slice::from_ref(left),
            std::slice::from_ref(right),
        )?;
        if output.len() != 1 {
            return Err("GPU product output count".into());
        }
        Ok(output.remove(0))
    }
    fn aut_poly(&self, input: &RawPoly) -> Result<RawPoly, String> {
        let air = PermutationAir::new(PermutationKind::AutomorphismQ);
        match air.evaluate_gpu_operations(self, &PermutationInput::Canonical(*input))? {
            PermutationInput::Canonical(values) => Ok(values),
            _ => Err("GPU automorphism output kind".into()),
        }
    }
    fn commit_canonical(&self, input: &RawPoly, q: u64) -> Result<[Val; 4], String> {
        Ok(self.commit_canonical_node(input, q)?.map(Val::from_u64))
    }
    fn commit_signed(&self, input: &RawSigned) -> Result<[Val; 4], String> {
        Ok(self.commit_signed_node(input)?.map(Val::from_u64))
    }
    fn commit_bytes(&self, input: &[u8; 32]) -> Result<[Val; 4], String> {
        Ok(self.commit_bytes32_node(input)?.map(Val::from_u64))
    }
    fn parameters(
        &self,
        seed: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<primitives::Parameters, String> {
        raw_primitives::parameters(self, seed, context)
    }
    fn sample_g(&self, seed: &[u8; 32]) -> Result<Vec<RawPoly>, String> {
        raw_primitives::sample_g(self, seed)
    }
    fn expand_alpha(&self, seed: &[u8; 32]) -> Result<(Vec<RawPoly>, RawSigned), String> {
        raw_primitives::expand_alpha(self, seed)
    }
    fn hash_alpha(&self, input: &[u8]) -> Result<[u8; 32], String> {
        self.shake256(input, 32)?
            .try_into()
            .map_err(|_| "GPU SHAKE digest shape".into())
    }
    fn hash_x(&self, input: &[u8]) -> Result<RawSigned, String> {
        use lattica_prover_p3::block_v2::native_gpu::SparseProfile;
        let bytes = self.shake256(input, 137)?;
        self.sparse_polynomial(&bytes, SparseProfile::ChallengeX44)
    }
}

impl<'a> CommittedBackend<'a> {
    fn with_device(setup_seed: [u8; 32], device: &'a dyn GraphDevice) -> Self {
        let mut backend = Self::new(setup_seed);
        backend.device = Some(device);
        backend
    }
    pub(super) fn on_device<T>(
        &mut self,
        operation: impl FnOnce(&dyn GraphDevice) -> Result<T, String>,
    ) -> Option<Result<T, String>> {
        let device = self.device?;
        if let Some(error) = &self.failure {
            return Some(Err(error.clone()));
        }
        let result = operation(device);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        Some(result)
    }
}

/// Byte serialization only; coefficients have already been computed on GPU.
/// The same ordered parts are authenticated by the transcript component AIR.
pub(super) fn transcript_bytes(
    graph: &UnprovedRelationGraph,
    parts: &[TranscriptPart],
) -> Result<Vec<u8>, String> {
    let bytes = parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(match part {
                TranscriptPart::Bytes(_) => 32,
                TranscriptPart::Polynomial(_) => D * 4,
            })
            .ok_or("GPU transcript size overflow")
    })?;
    if bytes > 1 << 20 {
        return Err("GPU fixed-profile transcript exceeds 1 MiB".into());
    }
    let mut output = Vec::with_capacity(bytes);
    for part in parts {
        match *part {
            TranscriptPart::Bytes(id) => output.extend_from_slice(&graph.byte_string(id).values),
            TranscriptPart::Polynomial(id) => {
                let PolynomialValues::Canonical(values) = &graph.polynomial(id).values else {
                    return Err("GPU transcript requires canonical polynomials".into());
                };
                for &value in values {
                    let value =
                        u32::try_from(value).map_err(|_| "GPU transcript coefficient width")?;
                    output.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
    }
    Ok(output)
}

pub fn lower_unproved_on_gpu(
    setup_seed: [u8; 32],
    context: &[u8; 32],
    statement: &Statement,
    proof: &Proof,
    execution: &crate::execution::ProvingContext,
    host_bytes: usize,
) -> Result<UnprovedRelationGraph, String> {
    let (graph, _) = execution.with_witness_preparation(host_bytes, |operation| {
        let mut backend = CommittedBackend::with_device(setup_seed, operation);
        let context = backend.import_bytes(*context, Source::Context);
        let statement = backend.import_statement(statement);
        let proof = backend.import_proof(proof);
        let relation = verify_relation(&mut backend, &context, &statement, &proof);
        if let Some(error) = backend.failure.take() {
            return Err(format!("GPU graph witness preparation failed: {error}"));
        }
        relation.map_err(|e| e.to_string())?;
        Ok(backend.into_unproved_graph())
    })?;
    Ok(graph)
}
