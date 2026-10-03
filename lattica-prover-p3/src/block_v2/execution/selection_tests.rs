//! Structural selection/scheduling checks. Synthetic tickets below grant no
//! cryptographic validity or OS-stop authority. Real public fixtures are opt-in.

#[cfg(target_os = "linux")]
#[test]
fn durable_selection_attachment_is_idempotent_and_partial_admission_grants_no_work() {
    use crate::block_v2::execution::{
        artifact_store::{hex, ArtifactStore, StoreLimits},
        journal::{DurableDag, JournalLimits},
    };
    use rand::TryRng;
    use std::{
        fs::{self, DirBuilder},
        os::unix::fs::DirBuilderExt,
    };
    let mut name = [0; 16];
    rand::rngs::SysRng.try_fill_bytes(&mut name).unwrap();
    let path = std::env::temp_dir().join(format!("lattica-selection-{}", hex(&name)));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    let selection = plan(WrapperConstruction::SingleWallet, 3);
    for (label, jobs) in [("complete", 128), ("partial", 1)] {
        let root = path.join(label);
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let store = ArtifactStore::create(
            &root.join("artifacts"),
            StoreLimits {
                bytes: 32 << 20,
                entries: 256,
            },
        )
        .unwrap();
        let mut owner = DurableDag::create(
            &root.join("journal"),
            JournalLimits {
                snapshot_bytes: 256 << 10,
            },
            store,
            pin_for(WrapperConstruction::SingleWallet),
            [9; 32],
            1,
            Limits {
                jobs,
                candidates: 8,
                attempts: 128,
                artifact_bytes: 32 << 20,
                recovery_window_ms: 10,
                workers: resources(),
            },
        )
        .unwrap();
        if jobs == 1 {
            assert!(selection.attach(&mut owner, [1; 32], 10_000, 0).is_err());
            assert!(owner.ready().unwrap().is_empty());
            assert_eq!(
                owner.status(selection.jobs().next().unwrap().id()).unwrap(),
                JobStatus::Dormant
            );
        } else {
            let first = selection.attach(&mut owner, [1; 32], 10_000, 0).unwrap();
            let before = owner.store_usage().unwrap();
            let second = selection.attach(&mut owner, [2; 32], 10_000, 0).unwrap();
            assert_ne!(first, second);
            assert_eq!(owner.store_usage().unwrap(), before);
            owner.cancel(first, 0).unwrap();
            assert!(!owner.ready().unwrap().is_empty());
            owner.seal(second, [2; 32], 0).unwrap();
            assert_eq!(owner.candidate_result(second, [2; 32], 0).unwrap(), None);
        }
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
    }
}
use super::*;
use crate::block_v2::{
    commitment::{self, Context, Entry as CommitmentEntry, Kind},
    execution::{
        dag::{Completion, Dag, JobStatus, Limits, WorkerId},
        job::{
            test_support::{node, pin_for, wallet_for},
            Operation,
        },
        resources::Resources,
    },
};
use std::collections::BTreeSet;

fn inputs(construction: WrapperConstruction, count: usize) -> Vec<PublicInput> {
    (0..count)
        .map(|i| {
            let bytes = vec![i as u8 + 1];
            PublicInput::new(wallet_for(construction, i as u64 + 1, &bytes), bytes).unwrap()
        })
        .collect()
}

fn plan(construction: WrapperConstruction, count: usize) -> Selection {
    Selection::new(pin_for(construction), [9; 32], &inputs(construction, count)).unwrap()
}

fn expected(count: usize) -> commitment::Digest {
    commitment::root(
        Context {
            profile_id: [7; 32],
            chain_id: [9; 32],
        },
        &(0..count)
            .map(|i| CommitmentEntry {
                kind: Kind::JoinSplit,
                statement_digest: [i as u64 + 1, 0, 0, 0],
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn resources() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 0,
        scratch_bytes: 100,
        threads: 1,
    }
}

fn dag() -> Dag {
    Dag::new(
        pin_for(WrapperConstruction::SingleWallet),
        [9; 32],
        1,
        Limits {
            jobs: 512,
            candidates: 16,
            attempts: 256,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 10,
            workers: resources(),
        },
    )
    .unwrap()
}

fn admit(dag: &mut Dag, selection: &Selection, now: u64) {
    for entry in &selection.entries {
        dag.admit(
            entry.job.clone(),
            entry.inputs.iter().map(|i| i.bytes.to_vec()).collect(),
            now,
        )
        .unwrap();
    }
}

// Structural scheduler simulation only, never a live-worker reconciliation.
fn complete(dag: &mut Dag, job: JobId, now: &mut u64) {
    let lease = dag
        .lease(job, WorkerId(1), resources(), 1, 100, *now)
        .unwrap();
    let expected = dag.leased_job(lease).unwrap().clone();
    *now += 1;
    dag.worker_stopped(lease, *now).unwrap();
    dag.begin_verification(lease, *now).unwrap();
    *now += 1;
    assert_eq!(
        dag.finish_verification(lease, Some((node(&expected, &[42]), vec![42])), *now)
            .unwrap(),
        Completion::Accepted
    );
}

#[test]
fn every_single_count_has_exact_ordered_root_and_dependency_first_graph() {
    for count in 1..=CAPACITY {
        let selection = plan(WrapperConstruction::SingleWallet, count);
        assert_eq!(selection.root().expected().root, expected(count));
        assert_eq!(selection.root().expected().count as usize, count);
        assert_eq!(selection.root().expected().level, DEPTH);
        assert!(selection.jobs().len() <= 127);
        assert_eq!(
            selection
                .jobs()
                .filter(|j| j.operation() == Operation::Wrap)
                .count(),
            count
        );
        let mut seen = BTreeSet::new();
        for entry in &selection.entries {
            assert!(entry.job.dependencies().iter().all(|id| seen.contains(id)));
            assert!(seen.insert(entry.job.id()));
            assert_eq!(entry.job.wallet_inputs().len(), entry.inputs.len());
        }
    }
}

#[test]
fn grouped_selection_is_exactly_even_and_never_substitutes_a_single_wrapper() {
    let construction = WrapperConstruction::GroupedPair;
    for count in 0..=65 {
        let result = Selection::new(pin_for(construction), [9; 32], &inputs(construction, count));
        if count == 0 || count > CAPACITY || count % 2 != 0 {
            assert!(result.is_err());
        } else {
            let selection = result.unwrap();
            assert_eq!(selection.root().expected().root, expected(count));
            assert_eq!(
                selection
                    .jobs()
                    .filter(|j| j.operation() == Operation::WrapPair)
                    .count(),
                count / 2
            );
            assert!(!selection.jobs().any(|j| j.operation() == Operation::Wrap));
            assert!(selection.jobs().len() <= 63);
        }
    }
}

#[test]
fn selection_rejects_wrong_artifacts_context_construction_and_capacity() {
    let single = WrapperConstruction::SingleWallet;
    assert!(PublicInput::new(wallet_for(single, 1, &[1]), vec![2]).is_err());
    assert!(Selection::new(pin_for(single), [8; 32], &inputs(single, 1)).is_err());
    assert!(Selection::new(pin_for(single), [9; 32], &[]).is_err());
    assert!(Selection::new(pin_for(single), [9; 32], &inputs(single, 65)).is_err());
    assert!(Selection::new(
        pin_for(WrapperConstruction::GroupedPair),
        [9; 32],
        &inputs(single, 2)
    )
    .is_err());
    assert!(Selection::new(
        pin_for(single),
        [9; 32],
        &inputs(WrapperConstruction::GroupedPair, 2)
    )
    .is_err());
}

#[test]
fn selection_order_is_host_supplied_not_sorted_by_arrival_or_artifact_digest() {
    let single = WrapperConstruction::SingleWallet;
    let mut ordered = inputs(single, 3);
    let a = Selection::new(pin_for(single), [9; 32], &ordered).unwrap();
    ordered.swap(0, 1);
    let b = Selection::new(pin_for(single), [9; 32], &ordered).unwrap();
    assert_ne!(a.root().id(), b.root().id());
    assert_ne!(a.root().expected().root, b.root().expected().root);
}

#[test]
fn later_arrivals_reuse_completed_subtree_and_do_not_mutate_sealed_selection() {
    let single = WrapperConstruction::SingleWallet;
    let mut dag = dag();
    let first = plan(single, 2);
    admit(&mut dag, &first, 0);
    let old = dag.attach(first.root().id(), [1; 32], 10_000, 0).unwrap();
    let subtree = first
        .jobs()
        .find(|j| j.start() == 0 && j.expected().level == 1)
        .unwrap()
        .clone();
    let mut now = 0;
    for id in subtree.dependencies() {
        complete(&mut dag, *id, &mut now);
    }
    complete(&mut dag, subtree.id(), &mut now);

    let next = plan(single, 3);
    admit(&mut dag, &next, now);
    let current = dag.attach(next.root().id(), [2; 32], 10_000, now).unwrap();
    dag.cancel(old, now).unwrap();
    assert_eq!(dag.status(subtree.id()).unwrap(), JobStatus::Completed);
    assert!(!dag.ready().contains(&subtree.id()));
    assert!(next.jobs().any(|j| j.id() == subtree.id()));
    assert!(dag.candidate_result(current, [2; 32], now).is_err());
    assert!(dag.seal(current, [1; 32], now).is_err());
    dag.seal(current, [2; 32], now).unwrap();
    let sealed_root = next.root().id();

    let later = plan(single, 4);
    admit(&mut dag, &later, now);
    let future = dag.attach(later.root().id(), [3; 32], 10_000, now).unwrap();
    assert_ne!(sealed_root, later.root().id());
    assert_eq!(next.root().id(), sealed_root);
    assert_eq!(dag.status(subtree.id()).unwrap(), JobStatus::Completed);
    while let Some(id) = dag.ready().first().copied() {
        complete(&mut dag, id, &mut now);
    }
    assert_eq!(
        dag.candidate_result(current, [2; 32], now).unwrap(),
        Some(&[42][..])
    );
    assert!(dag.candidate_result(current, [3; 32], now).is_err());
    assert!(dag.candidate_result(old, [1; 32], now).is_err());
    assert!(dag.candidate_result(future, [3; 32], now).is_err()); // not sealed
    assert_eq!(dag.resource_use(), Resources::default());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit pinned public wallet/root fixtures; bounded CPU verification, no proving"]
fn cpu_selection_matches_pinned_subtree_and_rejects_reordered_statement() -> Result<(), Error> {
    use crate::block_v2::execution::{job::VerifiedNode, test_fixture};
    let fixture = test_fixture::load()?;
    let public = fixture
        .wallets
        .iter()
        .zip(&fixture.bytes)
        .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = Selection::new(fixture.pin, [0x5a; 32], &public)?;
    let subtree = selected
        .jobs()
        .find(|j| j.start() == 0 && j.expected().level == 3)
        .ok_or("missing subtree")?;
    assert_eq!(subtree, &fixture.root);
    VerifiedNode::verify(subtree, &fixture.registry, &fixture.root_bytes)?;
    let mut reordered = public.clone();
    reordered.swap(0, 1);
    let other = Selection::new(fixture.pin, [0x5a; 32], &reordered)?;
    let wrong = other
        .jobs()
        .find(|j| j.start() == 0 && j.expected().level == 3)
        .ok_or("missing reordered subtree")?;
    assert!(VerifiedNode::verify(wrong, &fixture.registry, &fixture.root_bytes).is_err());
    assert_eq!(selected.root().expected().count, 8);
    assert_eq!(selected.root().expected().level, 6);
    println!("cpu_selection=PASS count=8 level=6 subtree_cpu_verified=true reordered_root_rejected=true full_root_proved=false");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "pinned current-layout SingleWallet research registration; CPU verification only"]
fn cpu_selection_accepts_current_single_registry_and_odd_count() -> Result<(), Error> {
    use crate::block_v2::execution::test_fixture;
    let f = test_fixture::load_single_public()?;
    assert_eq!(f.registry.id()?, f.pin.profile());
    let public = f
        .wallets
        .iter()
        .zip(&f.bytes)
        .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let before = Selection::new(f.pin, [0x5a; 32], &public[..2])?;
    let after = Selection::new(f.pin, [0x5a; 32], &public[..3])?;
    assert_eq!(after.root().expected().count, 3);
    assert_eq!(after.root().expected().level, 6);
    let pair = before
        .jobs()
        .find(|j| j.start() == 0 && j.expected().level == 1)
        .ok_or("missing pair")?;
    assert!(after.jobs().any(|j| j == pair));
    assert_eq!(
        after
            .jobs()
            .filter(|j| j.operation() == Operation::Wrap)
            .count(),
        3
    );
    assert_eq!(
        after
            .jobs()
            .filter(|j| j.operation() == Operation::Empty)
            .count(),
        5
    );
    assert_eq!(
        after
            .jobs()
            .filter(|j| j.operation() == Operation::Merge)
            .count(),
        7
    );
    println!("single_selection=PASS profile={} count=3 level=6 jobs=15 reused_subtree=true proof_generated=false",
        test_fixture::SINGLE_PROFILE_HEX);
    Ok(())
}
