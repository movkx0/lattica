//! Constrained joins for actual SHAKE/AES component proofs.
//!
//! Descriptors and partitions are trusted registered-program inputs. Proof
//! public values are witness wires and every cryptographic verifier, endpoint,
//! commitment, and continuity equality is emitted into the machine program.
//! Returning `Ok` compiles constraints; it is not native proof acceptance.

use crate::rust_verify::constraints_crypto::{PendingAes, PendingShake};
use crate::shake_air::{self, Descriptor, ShakeAir};
use lattica_prover_p3::block_v2::{
    machine::{
        backend::RegisteredProgram,
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
        MachineAir,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Descriptor,
    Tree(String),
    Shape(&'static str),
    Compile(CompileError),
}
impl From<CompileError> for Error {
    fn from(value: CompileError) -> Self {
        Self::Compile(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// An exact contiguous partition of a fixed SHAKE request. The private fields
/// prevent arbitrary overlapping/gapped descriptors from reaching compilation.
#[derive(Clone, Debug)]
pub struct ShakePartition {
    descriptor: Descriptor,
    segments: Vec<ShakeAir>,
}
impl ShakePartition {
    pub fn new(descriptor: Descriptor, max_permutations: usize) -> Result<Self, Error> {
        if max_permutations == 0 {
            return Err(Error::Descriptor);
        }
        let total = descriptor.permutations().map_err(|_| Error::Descriptor)?;
        let mut first = 0;
        let mut segments = Vec::new();
        while first < total {
            let count = (total - first).min(max_permutations);
            segments.push(ShakeAir::new(descriptor, first, count).map_err(|_| Error::Descriptor)?);
            first += count;
        }
        Ok(Self {
            descriptor,
            segments,
        })
    }
    pub fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub fn segments(&self) -> &[ShakeAir] {
        &self.segments
    }
}

pub struct ShakeSegmentProof {
    pub public_values: [Val; shake_air::PUBLIC_VALUES],
    pub proof: Proof<Config>,
}

/// No native acceptance result is consumed here. `uni::verify` emits the full
/// pinned hiding STARK/FRI verifier, with periodic columns generated from the
/// trusted segment descriptor rather than supplied as unauthenticated masks.
pub fn verify_shake_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &PendingShake,
    partition: &ShakePartition,
    proofs: &[ShakeSegmentProof],
) -> Result<(), Error> {
    if partition.descriptor.input_len != request.input.len()
        || partition.descriptor.output_len != request.output.len()
        || partition.segments.len() != proofs.len()
    {
        return Err(Error::Shape("SHAKE request/partition/proof count"));
    }
    let mut previous: Option<[Wire; shake_air::PUBLIC_VALUES]> = None;
    for (air, proof) in partition.segments.iter().zip(proofs) {
        let public: [Wire; shake_air::PUBLIC_VALUES] = inputs
            .bases(b, &proof.public_values)?
            .try_into()
            .map_err(|_| Error::Shape("SHAKE public width"))?;
        verifier::uni::verify(b, inputs, air, air.height, &public, &proof.proof)?;
        match previous {
            None => bind_shake_initial(b, partition.descriptor, &public),
            Some(prior) => bind_shake_continuity(b, &prior, &public),
        }
        previous = Some(public);
    }
    let end = previous.ok_or(Error::Shape("empty SHAKE partition"))?;
    for i in 0..4 {
        b.assert_equal(end[shake_air::INPUT_END + i], request.input_commitment[i]);
        b.assert_equal(end[shake_air::OUTPUT_END + i], request.output_commitment[i]);
    }
    Ok(())
}

fn bind_shake_initial(
    b: &mut ScopedProgramBuilder<'_>,
    descriptor: Descriptor,
    public: &[Wire; shake_air::PUBLIC_VALUES],
) {
    let zero = b.constant(Val::ZERO);
    for i in 0..100 {
        b.assert_equal(public[shake_air::START_STATE + i], zero);
    }
    for (offset, domain, length) in [
        (
            shake_air::INPUT_START,
            shake_air::SHAKE_INPUT_DOMAIN,
            descriptor.input_len,
        ),
        (
            shake_air::OUTPUT_START,
            shake_air::SHAKE_OUTPUT_DOMAIN,
            descriptor.output_len,
        ),
    ] {
        let domain = b.constant(Val::from_u64(domain));
        let length = b.constant(Val::from_usize(length));
        for (i, value) in [domain, length, zero, zero].into_iter().enumerate() {
            b.assert_equal(public[offset + i], value);
        }
    }
}

fn bind_shake_continuity(
    b: &mut ScopedProgramBuilder<'_>,
    left: &[Wire; shake_air::PUBLIC_VALUES],
    right: &[Wire; shake_air::PUBLIC_VALUES],
) {
    for i in 0..100 {
        b.assert_equal(
            left[shake_air::END_STATE + i],
            right[shake_air::START_STATE + i],
        );
    }
    for i in 0..4 {
        b.assert_equal(
            left[shake_air::INPUT_END + i],
            right[shake_air::INPUT_START + i],
        );
        b.assert_equal(
            left[shake_air::OUTPUT_END + i],
            right[shake_air::OUTPUT_START + i],
        );
    }
}

pub struct AesRequestProof {
    pub public_values: [Val; 8],
    pub proof: Proof<Config>,
}

pub struct NttRequestProof {
    pub public_values: [Val; 8],
    pub proof: BatchProof<Config>,
}

/// A source-specific NTT registration. The constructor always compiles the
/// fixed modulus-specific NTT predicate itself; callers cannot substitute a
/// generic verifier key for an unrelated predicate.
pub struct RegisteredNtt {
    modulus: u64,
    registered: RegisteredProgram,
}

impl RegisteredNtt {
    pub fn new(modulus: u64, memory_budget: u64) -> Result<Self, Error> {
        let compiled = crate::rust_verify::constraints_ntt::compile(modulus, &[0; 256])
            .map_err(|error| Error::Compile(CompileError::Backend(error.to_string())))?;
        let registered = RegisteredProgram::new_with_memory_budget(
            MachineAir::new(compiled.program),
            memory_budget,
        )
        .map_err(|error| Error::Compile(CompileError::Backend(format!("{error:?}"))))?;
        Ok(Self {
            modulus,
            registered,
        })
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn prove(&self, input: &[u64; 256]) -> Result<NttRequestProof, Error> {
        let compiled = crate::rust_verify::constraints_ntt::compile(self.modulus, input)
            .map_err(|error| Error::Compile(CompileError::Backend(error.to_string())))?;
        if &compiled.program != self.registered.air().program() {
            return Err(Error::Shape("NTT compiler changed registered program"));
        }
        let proof = self
            .registered
            .prove(&compiled.public_values, &compiled.witness)
            .map_err(|error| Error::Compile(CompileError::Backend(format!("{error:?}"))))?;
        let artifact = NttRequestProof {
            public_values: compiled.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }

    pub fn verify(&self, artifact: &NttRequestProof) -> Result<(), Error> {
        self.registered
            .verify(&artifact.proof, &artifact.public_values)
            .map_err(|error| Error::Compile(CompileError::Backend(format!("{error:?}"))))
    }
}

pub fn verify_ntt_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &crate::rust_verify::constraints_ntt::PendingNtt,
    registered: &RegisteredNtt,
    artifact: &NttRequestProof,
) -> Result<(), Error> {
    if request.modulus != registered.modulus {
        return Err(Error::Shape("NTT request/registered modulus"));
    }
    let public = inputs.bases(b, &artifact.public_values)?;
    let cap: Vec<[Wire; 4]> = registered
        .registered
        .preprocessing_cap()
        .roots()
        .iter()
        .map(|digest| digest.map(|value| b.constant(value)))
        .collect();
    verifier::batch::verify(
        b,
        inputs,
        registered.registered.air(),
        &public,
        &cap,
        &artifact.proof,
    )?;
    for i in 0..4 {
        b.assert_equal(public[i], request.input_commitment[i]);
        b.assert_equal(public[4 + i], request.output_commitment[i]);
    }
    Ok(())
}

/// AES AIR parameters are reconstructed from the fixed pending request, never
/// taken from a purported proof. Its eight public fields bind the exact key,
/// counter/domain/length encoding and returned output bytes.
pub fn verify_aes_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &PendingAes,
    proof: &AesRequestProof,
) -> Result<(), Error> {
    let air = crate::aes_air::AesAir::new(crate::aes_air::Descriptor {
        domain: request.domain,
        start_counter: request.start_counter,
        output_len: request.output.len(),
    })
    .map_err(|_| Error::Descriptor)?;
    let public = inputs.bases(b, &proof.public_values)?;
    verifier::uni::verify(b, inputs, &air, air.height, &public, &proof.proof)?;
    for i in 0..4 {
        b.assert_equal(public[i], request.input_commitment[i]);
        b.assert_equal(public[4 + i], request.output_commitment[i]);
    }
    Ok(())
}

/// Compile every pending request, in the exact order established by the
/// arithmetic component. The caller must constrain this same arithmetic
/// component and pin the resulting whole program before proving it.
pub fn verify_all(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    obligations: &crate::rust_verify::constraints_crypto::CryptoObligations,
    shake_partitions: &[ShakePartition],
    shake_proofs: &[Vec<ShakeSegmentProof>],
    aes_proofs: &[AesRequestProof],
    ntt_registrations: &[&RegisteredNtt],
    ntt_proofs: &[NttRequestProof],
) -> Result<(), Error> {
    if obligations.shake.len() != shake_partitions.len()
        || obligations.shake.len() != shake_proofs.len()
        || obligations.aes.len() != aes_proofs.len()
        || obligations.ntt.len() != ntt_registrations.len()
        || obligations.ntt.len() != ntt_proofs.len()
        || !obligations.mul.is_empty()
    {
        return Err(Error::Shape("missing or extra cryptographic component"));
    }
    for ((request, partition), proofs) in obligations
        .shake
        .iter()
        .zip(shake_partitions)
        .zip(shake_proofs)
    {
        verify_shake_request(b, inputs, request, partition, proofs)?;
    }
    for (request, proof) in obligations.aes.iter().zip(aes_proofs) {
        verify_aes_request(b, inputs, request, proof)?;
    }
    for ((request, registered), proof) in obligations
        .ntt
        .iter()
        .zip(ntt_registrations)
        .zip(ntt_proofs)
    {
        verify_ntt_request(b, inputs, request, registered, proof)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{MachineAir, ProgramBuilder};

    #[test]
    fn all_components_rejects_an_undischarged_ntt_obligation() {
        use crate::rust_verify::{
            constraints::ConstraintContext, constraints_crypto::CryptoObligations, constraints_ntt,
            Q,
        };
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut obligations = CryptoObligations::new([0; 32]);
        let mut context = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut obligations,
        };
        let value = context.constant_signed(0, 1);
        constraints_ntt::request_ntt(&mut context, &[value; 256], Q);
        assert_eq!(obligations.ntt.len(), 1);
        assert!(verify_all(
            &mut b,
            &mut ProofInputs::default(),
            &obligations,
            &[],
            &[],
            &[],
            &[],
            &[]
        )
        .is_err());
    }

    #[test]
    fn legacy_join_rejects_an_undischarged_polynomial_product() {
        use crate::rust_verify::{
            constraints::ConstraintContext, constraints_crypto::CryptoObligations,
            constraints_poly, Q,
        };
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut obligations = CryptoObligations::new([0; 32]);
        let mut context = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut obligations,
        };
        let value = context.residue(1, Q);
        constraints_poly::request_mul(&mut context, &[value; 256], &[value; 256], Q);
        assert_eq!(obligations.mul.len(), 1);
        assert!(verify_all(
            &mut b,
            &mut ProofInputs::default(),
            &obligations,
            &[],
            &[],
            &[],
            &[],
            &[]
        )
        .is_err());
    }

    #[test]
    fn partition_is_complete_contiguous_and_descriptor_bound() {
        let descriptor = Descriptor {
            input_len: 136 * 5 + 7,
            output_len: 137,
        };
        let partition = ShakePartition::new(descriptor, 3).unwrap();
        assert_eq!(partition.segments().len(), 3);
        assert_eq!(
            partition
                .segments()
                .iter()
                .map(|a| (a.first_permutation, a.permutations))
                .collect::<Vec<_>>(),
            vec![(0, 3), (3, 3), (6, 1)]
        );
        assert!(partition
            .segments()
            .iter()
            .all(|a| a.descriptor == descriptor));
        assert!(ShakePartition::new(descriptor, 0).is_err());
    }

    #[test]
    fn joins_constrain_capacity_and_both_rolling_commitments() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut inputs = ProofInputs::default();
        let left_value: [Val; shake_air::PUBLIC_VALUES] =
            std::array::from_fn(|i| Val::from_usize(i + 1));
        let mut right_value = [Val::ZERO; shake_air::PUBLIC_VALUES];
        right_value[..100].copy_from_slice(&left_value[100..200]);
        right_value[200..204].copy_from_slice(&left_value[204..208]);
        right_value[208..212].copy_from_slice(&left_value[212..216]);
        let left = inputs
            .bases(&mut b, &left_value)
            .unwrap()
            .try_into()
            .unwrap();
        let right = inputs
            .bases(&mut b, &right_value)
            .unwrap()
            .try_into()
            .unwrap();
        bind_shake_continuity(&mut b, &left, &right);
        let air = MachineAir::new(b.finish(None).unwrap());
        air.trace(&[], &inputs.values).unwrap();
        // Includes a capacity limb, not only the Keccak rate.
        for index in [0, 99, 200, 203, 208, 211] {
            let mut changed = inputs.values.clone();
            changed[shake_air::PUBLIC_VALUES + index] += Val::ONE;
            assert!(air.trace(&[], &changed).is_err());
        }
    }
}
