use super::*;
use crate::{crypto_join::Error as JoinError, rust_verify::constraints_crypto::PendingShake};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Wire},
        verifier::{self, ProofInputs},
    },
    profile::Config,
};

pub struct LaneShakeProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}

/// Compile every full STARK verifier and every byte/state/accumulator join.
/// AIR descriptors derive only from the registered request's fixed lengths;
/// component public values and all proof openings are constrained witnesses.
pub fn verify_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &PendingShake,
    proofs: &[LaneShakeProof],
) -> Result<(), JoinError> {
    let descriptor = Descriptor {
        input_len: request.input.len(),
        output_len: request.output.len(),
    };
    if descriptor
        .permutations()
        .map_err(|_| JoinError::Descriptor)?
        != proofs.len()
    {
        return Err(JoinError::Shape("lane SHAKE permutation/proof count"));
    }
    let mut previous: Option<[Wire; PUBLIC_VALUES]> = None;
    for (permutation, proof) in proofs.iter().enumerate() {
        let air = LaneShakeAir::new(descriptor, permutation).map_err(|_| JoinError::Descriptor)?;
        let public: [Wire; PUBLIC_VALUES] = inputs
            .bases(b, &proof.public_values)?
            .try_into()
            .map_err(|_| JoinError::Shape("lane SHAKE public width"))?;
        verifier::uni::verify(b, inputs, &air, HEIGHT, &public, &proof.proof)?;
        if let Some(prior) = previous {
            for i in 0..100 {
                b.assert_equal(prior[END_STATE + i], public[START_STATE + i]);
            }
            for i in 0..4 {
                b.assert_equal(prior[INPUT_END + i], public[INPUT_START + i]);
                b.assert_equal(prior[OUTPUT_END + i], public[OUTPUT_START + i]);
            }
        } else {
            let zero = b.constant(Val::ZERO);
            for i in 0..100 {
                b.assert_equal(public[START_STATE + i], zero);
            }
            for (offset, domain, length) in [
                (INPUT_START, SHAKE_INPUT_DOMAIN, descriptor.input_len),
                (OUTPUT_START, SHAKE_OUTPUT_DOMAIN, descriptor.output_len),
            ] {
                let domain = b.constant(Val::from_u64(domain));
                let length = b.constant(Val::from_usize(length));
                for (i, value) in [domain, length, zero, zero].into_iter().enumerate() {
                    b.assert_equal(public[offset + i], value);
                }
            }
        }
        previous = Some(public);
    }
    let end = previous.ok_or(JoinError::Shape("empty lane SHAKE proof list"))?;
    for i in 0..4 {
        b.assert_equal(end[INPUT_END + i], request.input_commitment[i]);
        b.assert_equal(end[OUTPUT_END + i], request.output_commitment[i]);
    }
    Ok(())
}
