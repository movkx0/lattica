//! Structural scheduler tests; private fake tickets are not proof qualification.
use super::*;
use crate::block_v2::{
    commitment::{self, Context, Entry as CommitmentEntry, Kind},
    execution::{
        dag::{Dag, JobStatus, Limits},
        job::{
            test_support::{typed_pin, typed_wallet, wallet},
            Operation,
        },
        resources::Resources,
    },
    machine::typed_pairs,
};
use std::collections::BTreeSet;

fn inputs(count: usize) -> Vec<PublicInput> {
    (0..count)
        .map(|i| {
            let mode = [1, 4, 4, 5][i % 4];
            let bytes = vec![i as u8 + 1, mode];
            PublicInput::new(typed_wallet(i as u64 + 1, mode, &bytes), bytes).unwrap()
        })
        .collect()
}

fn limits() -> Limits {
    Limits {
        jobs: 512,
        candidates: 16,
        attempts: 256,
        artifact_bytes: 32 << 20,
        recovery_window_ms: 10,
        workers: Resources {
            ram_bytes: 400,
            vram_bytes: 40,
            scratch_bytes: 400,
            threads: 4,
        },
    }
}

#[test]
fn every_typed_count_matches_native_commitment_and_minimal_plan() {
    for count in 1..=64 {
        let public = inputs(count);
        let selection = Selection::new(typed_pin(), [9; 32], &public).unwrap();
        let entries: Vec<_> = (0..count)
            .map(|i| CommitmentEntry {
                kind: match i % 4 {
                    0 => Kind::JoinSplit,
                    1 | 2 => Kind::Htlc,
                    _ => Kind::Coinbase,
                },
                statement_digest: [i as u64 + 1, 0, 0, 0],
            })
            .collect();
        let expected = commitment::root(
            Context {
                profile_id: [8; 32],
                chain_id: [9; 32],
            },
            &entries,
        )
        .unwrap();
        assert_eq!(selection.root().expected().root, expected, "count {count}");
        assert_eq!(selection.root().expected().count as usize, count);
        assert_eq!(selection.root().expected().level, 6);
        assert_eq!(
            selection.jobs().len(),
            typed_pairs::proof_plan(count as u8)
                .unwrap()
                .proposed_proofs as usize
        );
        assert_eq!(
            selection.root().operation() == Operation::Finalize,
            count <= 32
        );
        let mut finished = BTreeSet::new();
        let mut covered = BTreeSet::new();
        let mut padding = 0;
        for job in selection.jobs() {
            assert!(job.dependencies().iter().all(|id| finished.contains(id)));
            assert!(finished.insert(job.id()));
            if let Operation::TypedPair { mode, padded } = job.operation() {
                assert_eq!(job.expected().level, 1);
                assert!(typed_pairs::leaf_modes(u64::from(mode)).is_ok());
                for index in job.start()..job.start() + job.expected().count {
                    assert!(covered.insert(index));
                }
                if padded {
                    padding += 1;
                    assert_eq!(job.expected().count, 1);
                    assert_eq!(job.wallet_inputs()[0], job.wallet_inputs()[1]);
                } else {
                    assert_eq!(job.expected().count, 2);
                }
            }
        }
        assert_eq!(covered, (0..count as u8).collect());
        assert_eq!(padding, count % 2);
    }
}

#[test]
fn later_arrival_reuses_complete_pairs_and_replaces_partial_pair() {
    let public = inputs(4);
    let selections: Vec<_> = (1..=4)
        .map(|count| Selection::new(typed_pin(), [9; 32], &public[..count]).unwrap())
        .collect();
    let pair = |s: &Selection, start| {
        s.jobs()
            .find(|j| j.start() == start && j.expected().level == 1)
            .unwrap()
            .clone()
    };
    assert_ne!(pair(&selections[0], 0).id(), pair(&selections[1], 0).id());
    assert_eq!(pair(&selections[1], 0), pair(&selections[2], 0));
    assert_eq!(pair(&selections[1], 0), pair(&selections[3], 0));
    assert_ne!(pair(&selections[2], 2).id(), pair(&selections[3], 2).id());
    assert!(Job::finalize(selections[3].root()).is_err());
    let legacy = PublicInput::new(wallet(1, &[1]), vec![1]).unwrap();
    assert!(Selection::new(typed_pin(), [9; 32], &[legacy]).is_err());
    assert!(Job::wrap_pair(0, public[0].wallet, public[1].wallet).is_err());
}

#[test]
fn operation_codes_reject_holes_and_bind_padding() {
    for code in 0..=255 {
        let decoded = Operation::from_code(code);
        let valid = (1..=4).contains(&code)
            || code == 64
            || typed_pairs::PAIRS
                .iter()
                .any(|(m, _)| code as u64 == m + 16 || code as u64 == m + 32);
        assert_eq!(decoded.is_ok(), valid, "operation {code}");
        if let Ok(op) = decoded {
            assert_eq!(op.code(), code as u64);
        }
    }
}

#[test]
fn all_ordered_type_pairs_and_single_type_padding_select_the_right_program() {
    for (mode, leaves) in typed_pairs::PAIRS {
        let left = typed_wallet(1, leaves[0] as u8, &[1]);
        let right = typed_wallet(2, leaves[1] as u8, &[2]);
        let job = Job::typed_pair(0, left, Some(right)).unwrap();
        assert_eq!(
            job.operation(),
            Operation::TypedPair {
                mode: mode as u8,
                padded: false
            }
        );
        assert_eq!(job.expected().count, 2);
    }
    for mode in [1, 4, 5] {
        let wallet = typed_wallet(1, mode, &[1]);
        let job = Job::typed_pair(0, wallet, None).unwrap();
        assert_eq!(
            job.operation(),
            Operation::TypedPair {
                mode: typed_pairs::mode_for([mode as u64; 2]).unwrap() as u8,
                padded: true,
            }
        );
        assert_eq!(job.expected().count, 1);
        assert_eq!(job.wallet_inputs()[0], job.wallet_inputs()[1]);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn typed_checkpoint_reconstructs_jobs_and_rejects_registry_or_mode_changes() {
    use crate::block_v2::execution::dag::snapshot::restore_with;
    let public = inputs(3);
    let selection = Selection::new(typed_pin(), [9; 32], &public).unwrap();
    let mut dag = Dag::new(typed_pin(), [9; 32], 1, limits()).unwrap();
    for entry in &selection.entries {
        dag.admit(
            entry.job.clone(),
            entry.inputs.iter().map(|p| p.bytes.to_vec()).collect(),
            0,
        )
        .unwrap();
    }
    let bytes = dag.snapshot().unwrap();
    let restore = |bytes: &[u8]| {
        restore_with(
            bytes,
            typed_pin(),
            [9; 32],
            2,
            limits(),
            |identity| {
                let p = public
                    .iter()
                    .find(|p| p.wallet.artifact() == identity)
                    .ok_or("unknown test wallet")?;
                Ok((p.wallet, p.bytes.to_vec()))
            },
            |_, _| Err("no completed test nodes".into()),
        )
    };
    let recovered = restore(&bytes).unwrap();
    for job in selection.jobs() {
        assert_eq!(recovered.dag.status(job.id()).unwrap(), JobStatus::Dormant);
    }
    let mut wrong = bytes.clone();
    wrong[8 + 32] = 2; // Pin-family discriminator is after magic and profile.
    assert!(restore(&wrong).is_err());
    let first = selection.jobs().next().unwrap();
    let offset = bytes
        .windows(32)
        .position(|w| w == first.id().to_bytes())
        .unwrap()
        + 32;
    assert_eq!(bytes[offset], first.operation().code() as u8);
    for code in [2, 23, 36, 64] {
        let mut wrong = bytes.clone();
        wrong[offset] = code;
        assert!(restore(&wrong).is_err(), "mutated first operation {code}");
    }
}
