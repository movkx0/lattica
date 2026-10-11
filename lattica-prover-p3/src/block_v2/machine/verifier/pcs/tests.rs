use super::*;
use crate::block_v2::machine::Program;
use crate::block_v2::profile::Challenge;
use p3_commit::BatchOpening;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::MerkleCap;

mod reference;

// Shape-only inputs exercise compilation, never proof acceptance. The native
// uni/batch verifier tests separately check real and tampered proofs.
fn fixture(logs: &[usize], counts: &[usize], points: usize) -> p3_batch_stark::PcsProof<Config> {
    let log_global = logs.iter().max().unwrap() + profile::LOG_BLOWUP;
    let folds = log_global - profile::LOG_BLOWUP;
    let cap = |log: usize| MerkleCap::new(vec![[Val::ZERO; 4]; 1 << log.min(profile::CAP_HEIGHT)]);
    let random = logs
        .iter()
        .enumerate()
        .map(|(r, _)| {
            vec![
                vec![
                    vec![
                        Challenge::ZERO;
                        if r == 3 {
                            0
                        } else {
                            profile::NUM_RANDOM_CODEWORDS
                        }
                    ];
                    points
                ];
                counts[r]
            ]
        })
        .collect();
    let queries = (0..profile::NUM_QUERIES)
        .map(|_| QueryProof {
            input_proof: logs
                .iter()
                .enumerate()
                .map(|(r, log)| {
                    BatchOpening::new(
                        vec![
                            vec![
                                Val::ZERO;
                                2 + if r == 3 {
                                    0
                                } else {
                                    profile::NUM_RANDOM_CODEWORDS
                                }
                            ];
                            counts[r]
                        ],
                        (
                            vec![vec![Val::ZERO; 4]; counts[r]],
                            vec![
                                [Val::ZERO; 4];
                                (log + profile::LOG_BLOWUP).saturating_sub(profile::CAP_HEIGHT)
                            ],
                        ),
                    )
                })
                .collect(),
            commit_phase_openings: (0..folds)
                .map(|i| CommitPhaseProofStep {
                    log_arity: 1,
                    sibling_values: vec![Challenge::ZERO],
                    opening_proof: (
                        vec![vec![Val::ZERO; 4]],
                        vec![
                            [Val::ZERO; 4];
                            (log_global - i - 1).saturating_sub(profile::CAP_HEIGHT)
                        ],
                    ),
                })
                .collect(),
        })
        .collect();
    (
        random,
        FriProof {
            commit_phase_commits: (0..folds).map(|i| cap(log_global - i - 1)).collect(),
            commit_pow_witnesses: vec![Val::ZERO; folds],
            query_proofs: queries,
            final_poly: vec![Challenge::ZERO],
            query_pow_witness: Val::ZERO,
        },
    )
}

fn compile(logs: &[usize], counts: &[usize], points: usize, legacy: bool) -> (Program, Vec<Val>) {
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    let mut transcript = Transcript::new(&mut b);
    let rounds: Vec<reference::Round> = logs
        .iter()
        .enumerate()
        .map(|(r, &log)| {
            let commitment = vec![
                [b.constant(Val::ZERO); 4];
                1 << (log + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT)
            ];
            let matrices = (0..counts[r])
                .map(|_| {
                    (0..points)
                        .map(|p| reference::Point {
                            point: b.ext_constant([Val::from_usize(7 + p); 3]),
                            values: inputs.extensions(&mut b, &[Challenge::ZERO; 2]).unwrap(),
                        })
                        .collect()
                })
                .collect();
            reference::Round {
                commitment,
                log_domain: log,
                matrices,
                preprocessing: r == 3,
            }
        })
        .collect();
    let proof = fixture(logs, counts, points);
    if legacy {
        reference::verify(&mut b, &mut inputs, &mut transcript, rounds, &proof).unwrap();
    } else {
        let matrices: Vec<Vec<Vec<Point<'_>>>> = rounds
            .iter()
            .map(|r| {
                r.matrices
                    .iter()
                    .map(|m| {
                        m.iter()
                            .map(|p| Point {
                                point: p.point,
                                values: &p.values,
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let slices: Vec<Vec<&[Point<'_>]>> = matrices
            .iter()
            .map(|m| m.iter().map(Vec::as_slice).collect())
            .collect();
        let borrowed: Vec<_> = rounds
            .iter()
            .zip(&slices)
            .map(|(r, m)| Round {
                commitment: &r.commitment,
                log_domain: r.log_domain,
                matrices: m,
                preprocessing: r.preprocessing,
            })
            .collect();
        verify(&mut b, &mut inputs, &mut transcript, &borrowed, &proof).unwrap();
    }
    (b.finish(None).unwrap(), inputs.values)
}

#[test]
fn borrowed_openings_preserve_legacy_program_and_input_order() {
    for (logs, counts, points) in [
        (vec![1], vec![1], 1),
        (vec![3, 2, 3, 1, 2], vec![1, 2, 1, 2, 1], 2),
        (vec![1], vec![MAX_MATRICES], 1),
    ] {
        let (old, old_inputs) = compile(&logs, &counts, points, true);
        let old_manifest = old.manifest_fields();
        // Keep only the manifest while compiling the second program under the
        // same native host cap; its equality includes all wire IDs and rows.
        drop(old);
        let (new, new_inputs) = compile(&logs, &counts, points, false);
        assert_eq!(old_inputs, new_inputs);
        assert_eq!(old_manifest, new.manifest_fields());
    }
}

#[test]
fn oversized_descriptors_and_domain_overflow_fail_before_inputs() {
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    let mut transcript = Transcript::new(&mut b);
    let cap = [[Wire(0); 4]; 1 << profile::CAP_HEIGHT];
    let values = [[Wire(0); 3]; 2];
    let points = [Point {
        point: [Wire(0); 3],
        values: &values,
    }; MAX_POINTS + 1];
    let matrices = [&points[..1]; MAX_MATRICES + 1];
    let ordinary = Round {
        commitment: &cap,
        log_domain: 2,
        matrices: &matrices[..1],
        preprocessing: false,
    };
    let too_many_points = [&points[..]];
    let proof = fixture(&[2], &[1], 1);
    for rounds in [
        vec![],
        vec![ordinary; MAX_ROUNDS + 1],
        vec![Round {
            matrices: &matrices,
            ..ordinary
        }],
        vec![Round {
            matrices: &too_many_points,
            ..ordinary
        }],
        vec![Round {
            log_domain: usize::MAX,
            ..ordinary
        }],
        vec![Round {
            log_domain: MAX_LOG - profile::LOG_BLOWUP + 1,
            ..ordinary
        }],
        vec![Round {
            log_domain: 0,
            ..ordinary
        }],
    ] {
        assert!(verify(&mut b, &mut inputs, &mut transcript, &rounds, &proof).is_err());
        assert!(inputs.values.is_empty());
        assert!(b.resource_failure().is_none());
    }
}

#[test]
fn authentication_rejects_oversized_scratch_before_inputs() {
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    let cap = [[Wire(0); 4]];
    let row = [Wire(0); 6];
    let rows = [&row[..]; MAX_MATRICES + 1];
    let salts = vec![vec![Val::ZERO; 4]; MAX_MATRICES + 1];
    assert!(salted_authentication(&mut b, &mut inputs, &cap, &[], &rows, &salts, &[]).is_err());
    assert!(salted_authentication(
        &mut b,
        &mut inputs,
        &cap,
        &[Wire(0); MAX_LOG + 1],
        &rows[..1],
        &salts[..1],
        &[[Val::ZERO; 4]; MAX_LOG + 1 - profile::CAP_HEIGHT]
    )
    .is_err());
    assert!(inputs.values.is_empty());
    assert!(b.resource_failure().is_none());
}
