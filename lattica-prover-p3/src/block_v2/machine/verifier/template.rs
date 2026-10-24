//! Shape-only inputs for compiling registered programs before their keys exist.
//! These zero-filled objects are NOT proofs and must never bypass verification.
use p3_air::BaseAir;
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof, OpenedValues};
use p3_commit::BatchOpening;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_lookup::LookupTerminal;
use p3_symmetric::MerkleCap;

use super::super::{analysis, MachineAir};
use super::super::{compiler_constants::Constants, program::Val};
use super::CompileError;
use crate::block_v2::profile::{self, Challenge, Config};

pub fn batch(air: &MachineAir) -> Result<BatchProof<Config>, CompileError> {
    batch_with_constants(air, Constants::cpu())
}

pub(crate) fn batch_with_constants(
    air: &MachineAir,
    constants: Constants<'_>,
) -> Result<BatchProof<Config>, CompileError> {
    let a = {
        let prepared = super::super::symbolic::prepare_machine(air, constants)?;
        analysis::analyze_prepared(air, &prepared)
            .map_err(|_| CompileError::Shape("template AIR geometry"))?
    };
    batch_from_geometry(air, a.quotient_chunks, a.permutation_width_base)
}

/// Private shape-planning construction; enclosing storage is admitted before
/// this function. No invalid template or program escapes the bounds-only API.
pub(super) fn batch_bounded_shape(air: &MachineAir) -> Result<BatchProof<Config>, CompileError> {
    let (quotient_chunks, permutation_width_base) = {
        let prepared = super::super::symbolic::verifier::prepare_registry(
            air, super::super::symbolic::verifier::Limits::default(),
        )?;
        if prepared.log_chunks > profile::LOG_BLOWUP {
            return Err(CompileError::Shape("bounded batch template quotient degree"));
        }
        (1 << (prepared.log_chunks + 1), (prepared.lookups.len() + 1) * 3)
    };
    // Packing cannot create more lookup columns than the 4*LANES + publics
    // interactions emitted by MachineAir. This bound does not assume a sampled
    // packed count (which can vary with the number of public values).
    if air.width() > 94 || air.preprocessed_width() > 200
        || permutation_width_base > 3 * (4 * super::super::program::LANES + air.num_public_values() + 1)
        || quotient_chunks > 32 || air.num_periodic_columns() != 0
    {
        return Err(CompileError::Shape("bounded batch template dimensions"));
    }
    batch_from_geometry(air, quotient_chunks, permutation_width_base)
}

fn batch_from_geometry(
    air: &MachineAir,
    quotient_chunks: usize,
    permutation_width_base: usize,
) -> Result<BatchProof<Config>, CompileError> {
    let degree = air.program().height().ilog2() as usize + 1;
    let log_lde = degree + profile::LOG_BLOWUP;
    let cap = |log: usize| MerkleCap::new(vec![[Val::ZERO; 4]; 1 << log.min(profile::CAP_HEIGHT)]);
    let widths = [
        vec![3],
        vec![air.width()],
        vec![3; quotient_chunks],
        vec![air.preprocessed_width()],
        vec![permutation_width_base],
    ];
    let point_counts = [1, 1, 1, 1, 2];
    let random = widths
        .iter()
        .enumerate()
        .map(|(r, w)| {
            w.iter()
                .map(|_| {
                    vec![
                        vec![
                            Challenge::ZERO;
                            if r == 3 {
                                0
                            } else {
                                profile::NUM_RANDOM_CODEWORDS
                            }
                        ];
                        point_counts[r]
                    ]
                })
                .collect()
        })
        .collect();
    let queries = (0..profile::NUM_QUERIES)
        .map(|_| QueryProof {
            input_proof: widths
                .iter()
                .enumerate()
                .map(|(r, w)| {
                    BatchOpening::new(
                        w.iter()
                            .map(|&width| {
                                vec![
                                    Val::ZERO;
                                    width
                                        + if r == 3 {
                                            0
                                        } else {
                                            profile::NUM_RANDOM_CODEWORDS
                                        }
                                ]
                            })
                            .collect(),
                        (
                            vec![vec![Val::ZERO; 4]; w.len()],
                            vec![[Val::ZERO; 4]; log_lde.saturating_sub(profile::CAP_HEIGHT)],
                        ),
                    )
                })
                .collect(),
            commit_phase_openings: (0..degree)
                .map(|r| CommitPhaseProofStep {
                    log_arity: 1,
                    sibling_values: vec![Challenge::ZERO],
                    opening_proof: (
                        vec![vec![Val::ZERO; 4]],
                        vec![[Val::ZERO; 4]; (log_lde - r - 1).saturating_sub(profile::CAP_HEIGHT)],
                    ),
                })
                .collect(),
        })
        .collect();
    Ok(BatchProof {
        commitments: BatchCommitments {
            main: cap(log_lde),
            permutation: Some(cap(log_lde)),
            quotient_chunks: cap(log_lde),
            random: Some(cap(log_lde)),
        },
        opened_values: BatchOpenedValues {
            instances: vec![OpenedValuesWithLookups {
                base_opened_values: OpenedValues {
                    trace_local: vec![Challenge::ZERO; air.width()],
                    trace_next: None,
                    preprocessed_local: Some(vec![Challenge::ZERO; air.preprocessed_width()]),
                    preprocessed_next: None,
                    quotient_chunks: vec![vec![Challenge::ZERO; 3]; quotient_chunks],
                    random: Some(vec![Challenge::ZERO; 3]),
                },
                permutation_local: vec![Challenge::ZERO; permutation_width_base],
                permutation_next: vec![Challenge::ZERO; permutation_width_base],
            }],
        },
        opening_proof: (
            random,
            FriProof {
                commit_phase_commits: (0..degree).map(|r| cap(log_lde - r - 1)).collect(),
                commit_pow_witnesses: vec![Val::ZERO; degree],
                query_proofs: queries,
                final_poly: vec![Challenge::ZERO],
                query_pow_witness: Val::ZERO,
            },
        ),
        lookup_terminals: vec![Some(LookupTerminal(Challenge::ZERO))],
        degree_bits: vec![degree],
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::ProgramBuilder;
    use super::super::{batch, ProofInputs};
    use super::*;

    #[test]
    fn fixed_height_shapes_compile_but_zero_filled_proofs_do_not_verify() {
        for height in [8, 256] {
            let air = MachineAir::new(
                ProgramBuilder::new(1)
                    .unwrap()
                    .finish(Some(height))
                    .unwrap(),
            );
            let proof = super::batch(&air).unwrap();
            let mut b = ProgramBuilder::new(1).unwrap();
            let public = b.public(0).unwrap();
            let zero = b.constant(Val::ZERO);
            let cap = vec![
                [zero; 4];
                1 << ((height.ilog2() as usize + 1 + profile::LOG_BLOWUP)
                    .min(profile::CAP_HEIGHT))
            ];
            let mut inputs = ProofInputs::default();
            batch::verify(&mut b, &mut inputs, &air, &[public], &cap, &proof).unwrap();
            assert!(b
                .finish(None)
                .unwrap()
                .evaluate(&[Val::ZERO], &inputs.values)
                .is_err());
        }
    }
}
