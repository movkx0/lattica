//! The fixed block-v2 binary FRI arithmetic, without host layer vectors.
//! Transcript/grinding use the selected challenger; proof assembly is on host.
//! Order follows Plonky3 0.6.1 prover.rs, MIT OR Apache-2.0; see batched_fri.rs.
use super::owned::{challenge, words};
use super::*;
use crate::block_v2::{
    gpu_hash::device::{DeviceMatrix, DeviceSession},
    profile,
};
use p3_challenger::{CanObserve, GrindingChallenger};
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};

const HOST_SALT_ALLOWANCE: usize = 1 << 30;
const HOST_QUERY_ALLOWANCE: usize = 1 << 30;

pub(super) mod general;

#[cfg(test)]
mod tests;

pub(super) fn prove(
    session: &DeviceSession,
    mmcs: &CandidateMmcs,
    params: &FriParameters<ChallengeMmcs>,
    inputs: Vec<DeviceMatrix>,
    challenger: &mut Challenger,
    max_height: usize,
    rounds: &[(&ProverData, Vec<Vec<Challenge>>)],
) -> Result<InnerProof, String> {
    if params.log_blowup != profile::LOG_BLOWUP
        || params.log_final_poly_len != 0
        || params.max_log_arity != 1
        || params.num_queries != profile::NUM_QUERIES
        || params.commit_proof_of_work_bits != 0
        || params.query_proof_of_work_bits != profile::QUERY_POW_BITS
        || inputs.is_empty()
        || inputs.len() > 26
        || max_height > 25
        || inputs[0].spec().rows().ilog2() as usize != max_height
        || inputs
            .windows(2)
            .any(|pair| pair[0].spec().rows() <= pair[1].spec().rows())
        || inputs
            .iter()
            .any(|v| v.spec().rows() < 1 << profile::LOG_BLOWUP)
    {
        return Err(
            "resident FRI requires the fixed binary cubic profile and descending inputs".into(),
        );
    }
    general::prove(
        session,
        mmcs,
        params,
        inputs,
        challenger,
        max_height,
        &rounds.iter().map(|(data, _)| *data).collect::<Vec<_>>(),
    )
}
