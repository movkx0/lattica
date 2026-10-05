//! Structural scheduler tests, not cryptographic proof acceptance tests.
//! The private cfg(test) fixtures deliberately use tiny synthetic artifacts and
//! byte-sized admission budgets. Real CPU acceptance is replayed separately.

use super::{
    dag::{AttemptStatus, CandidateId, Completion, Dag, JobStatus, Lease, Limits, WorkerId},
    job::{
        test_support::{node, pin, wallet},
        ArtifactKind, ArtifactRef, Job, JobId,
    },
    resources::Resources,
};
use crate::block_v2::{commitment::DEPTH, profile::MAX_PROOF_BYTES};

fn request() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 10,
        scratch_bytes: 100,
        threads: 1,
    }
}

fn limits() -> Limits {
    Limits {
        jobs: 512,
        candidates: 16,
        attempts: 256,
        artifact_bytes: 32 * (1 << 20),
        recovery_window_ms: 10,
        workers: Resources {
            ram_bytes: 400,
            vram_bytes: 40,
            scratch_bytes: 400,
            threads: 4,
        },
    }
}

fn dag() -> Dag {
    Dag::new(pin(), [9; 32], 1, limits()).unwrap()
}

fn leaf(start: u8) -> Job {
    Job::wrap(start, wallet(u64::from(start) + 1, &[start + 1])).unwrap()
}

fn tree(dag: &mut Dag, count: u8, start: u8, level: u8, now: u64) -> Job {
    let (job, artifacts) = if start >= count {
        (Job::empty(pin(), [9; 32], start, level).unwrap(), vec![])
    } else if level == 0 {
        (leaf(start), vec![vec![start + 1]])
    } else {
        let left = tree(dag, count, start, level - 1, now);
        let right = tree(dag, count, start + (1 << (level - 1)), level - 1, now);
        (Job::merge(&left, &right).unwrap(), vec![])
    };
    dag.admit(job.clone(), artifacts, now).unwrap();
    job
}

fn candidate(dag: &mut Dag, count: u8) -> (Job, CandidateId) {
    let root = tree(dag, count, 0, DEPTH, 0);
    let id = dag.attach(root.id(), [1; 32], 1000, 0).unwrap();
    (root, id)
}

fn complete(dag: &mut Dag, id: JobId, bytes: &[u8], now: &mut u64) -> Lease {
    let lease = dag.lease(id, WorkerId(1), request(), 1, 100, *now).unwrap();
    let job = dag.leased_job(lease).unwrap().clone();
    *now += 1;
    dag.worker_stopped(lease, *now).unwrap();
    assert_eq!(dag.begin_verification(lease, *now).unwrap().id(), id);
    *now += 1;
    assert_eq!(
        dag.finish_verification(lease, Some((node(&job, bytes), bytes.to_vec())), *now)
            .unwrap(),
        Completion::Accepted,
    );
    lease
}

fn finish_all(dag: &mut Dag, now: &mut u64) {
    while let Some(id) = dag.ready().first().copied() {
        complete(dag, id, &[42], now);
    }
}

#[test]
fn graph_admission_requires_inputs_dependencies_and_full_nonempty_candidates() {
    let mut d = dag();
    let left = leaf(0);
    let right = leaf(1);
    let parent = Job::merge(&left, &right).unwrap();
    assert!(d.admit(parent.clone(), vec![], 0).is_err());
    assert!(d.admit(left.clone(), vec![vec![99]], 0).is_err());
    assert_eq!(d.job_count(), 0);
    assert_eq!(d.stored_bytes(), 0);
    d.admit(left.clone(), vec![vec![1]], 0).unwrap();
    assert!(d.admit(parent, vec![], 0).is_err());
    assert!(d.attach(left.id(), [1; 32], 1000, 0).is_err());
    let empty = Job::empty(pin(), [9; 32], 0, DEPTH).unwrap();
    d.admit(empty.clone(), vec![], 0).unwrap();
    assert!(d.attach(empty.id(), [1; 32], 1000, 0).is_err());
}

#[test]
fn verified_siblings_release_parent_without_unrelated_level_barrier() {
    let mut d = dag();
    let (root, _) = candidate(&mut d, 4);
    let parent = Job::merge(&leaf(0), &leaf(1)).unwrap();
    let mut now = 0;
    complete(&mut d, leaf(0).id(), &[11], &mut now);
    assert_eq!(d.status(parent.id()).unwrap(), JobStatus::Waiting);
    complete(&mut d, leaf(1).id(), &[22], &mut now);
    assert_eq!(d.status(parent.id()).unwrap(), JobStatus::Ready);
    let ready = d.ready();
    assert!(ready.contains(&parent.id()));
    // Higher-level padding is also ready; readiness does not promise this
    // parent outranks it. The parent does outrank the remaining leaf work.
    assert_eq!(
        ready[0],
        Job::empty(pin(), [9; 32], 32, DEPTH - 1).unwrap().id()
    );
    assert!(
        ready.iter().position(|id| *id == parent.id()).unwrap()
            < ready.iter().position(|id| *id == leaf(2).id()).unwrap()
    );
    assert_eq!(d.status(leaf(2).id()).unwrap(), JobStatus::Ready);
    assert_eq!(d.status(root.id()).unwrap(), JobStatus::Waiting);
}

#[test]
fn randomized_duplicate_wallet_cannot_replace_leased_input() {
    let mut d = dag();
    candidate(&mut d, 1);
    let original = leaf(0);
    let lease = d
        .lease(original.id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let bytes_before = d.stored_bytes();
    let alternate = Job::wrap(0, wallet(1, &[9, 9])).unwrap();
    assert_eq!(alternate.id(), original.id());
    d.admit(alternate, vec![vec![9, 9]], 0).unwrap();
    assert_eq!(d.stored_bytes(), bytes_before);
    assert_eq!(d.input_bytes(lease, 0).unwrap(), &[1]);
    assert_eq!(d.input_manifest(lease).unwrap(), original.wallet_inputs());
    assert_eq!(
        d.leased_job(lease).unwrap().wallet_inputs(),
        original.wallet_inputs()
    );
}

#[test]
fn completion_is_idempotent_and_merge_inputs_preserve_left_right_order() {
    let mut d = dag();
    candidate(&mut d, 2);
    let left = leaf(0);
    let right = leaf(1);
    let mut now = 0;
    let lease = complete(&mut d, left.id(), &[11], &mut now);
    let stored = d.stored_bytes();
    assert_eq!(d.resource_use(), Resources::default());
    assert_eq!(d.reserved_output_bytes(), 0);
    assert_eq!(
        d.finish_verification(lease, Some((node(&left, &[11]), vec![11])), now)
            .unwrap(),
        Completion::Duplicate
    );
    assert_eq!(d.stored_bytes(), stored);
    assert_eq!(d.resource_use(), Resources::default());
    assert!(d
        .finish_verification(lease, Some((node(&left, &[12]), vec![12])), now)
        .is_err());
    assert!(d
        .finish_verification(lease, Some((node(&left, &[11]), vec![12])), now)
        .is_err());
    assert!(d.leased_job(lease).is_err());
    complete(&mut d, right.id(), &[22], &mut now);
    let parent = Job::merge(&left, &right).unwrap();
    let merge = d
        .lease(parent.id(), WorkerId(1), request(), 1, 100, now)
        .unwrap();
    assert_eq!(
        d.input_manifest(merge).unwrap(),
        &[
            ArtifactRef::from_bytes(ArtifactKind::Node, &[11]).unwrap(),
            ArtifactRef::from_bytes(ArtifactKind::Node, &[22]).unwrap(),
        ]
    );
    assert_eq!(d.input_bytes(merge, 0).unwrap(), &[11]);
    assert_eq!(d.input_bytes(merge, 1).unwrap(), &[22]);
}

#[test]
fn cancellation_keeps_reservations_until_authoritative_worker_stop() {
    let mut d = dag();
    let (root, c) = candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.cancel(c, 1).unwrap();
    assert_eq!(d.attempt_status(lease).unwrap(), AttemptStatus::Cancelled);
    assert_eq!(d.resource_use(), request());
    assert_eq!(d.reserved_output_bytes(), MAX_PROOF_BYTES);
    assert_eq!(d.pending_stops(), vec![lease]);
    assert_eq!(d.prune(11).unwrap(), 0);
    d.attach(root.id(), [2; 32], 1000, 11).unwrap();
    assert!(d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 11)
        .is_err());
    d.worker_stopped(lease, 12).unwrap();
    assert_eq!(d.resource_use(), Resources::default());
    assert_eq!(d.reserved_output_bytes(), 0);
    assert!(d.pending_stops().is_empty());
    // Recovery retention starts at actual release, not the earlier cancellation.
    d.prune(12).unwrap();
    assert_eq!(d.attempt_status(lease).unwrap(), AttemptStatus::Cancelled);
    assert!(d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 12)
        .is_ok());
}

#[test]
fn cancellation_during_verification_fences_valid_late_result_and_holds_budget() {
    let mut d = dag();
    let (_, c) = candidate(&mut d, 1);
    let job = leaf(0);
    let lease = d
        .lease(job.id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert!(d.begin_verification(lease, 0).is_err());
    d.worker_stopped(lease, 1).unwrap();
    d.begin_verification(lease, 1).unwrap();
    d.cancel(c, 2).unwrap();
    assert_eq!(d.resource_use(), request());
    assert_eq!(d.reserved_output_bytes(), MAX_PROOF_BYTES);
    assert_eq!(d.prune(2).unwrap(), 0);
    assert!(d.reject_worker(lease, 2).is_err());
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &[3]), vec![3])), 3)
            .unwrap(),
        Completion::Fenced
    );
    assert_eq!(d.resource_use(), Resources::default());
    assert_eq!(d.reserved_output_bytes(), 0);
    assert_eq!(d.status(job.id()).unwrap(), JobStatus::Dormant);
    assert!(d.candidate_result(c, [1; 32], 3).is_err());
}

#[test]
fn shared_candidate_work_survives_cancellation_and_sealing_checks_eligibility() {
    let mut d = dag();
    let (root, a) = candidate(&mut d, 1);
    let b = d.attach(root.id(), [2; 32], 1000, 0).unwrap();
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.seal(a, [1; 32], 0).unwrap();
    assert!(d.seal(b, [1; 32], 0).is_err());
    assert!(d.candidate_result(b, [2; 32], 0).is_err());
    d.cancel(a, 0).unwrap();
    assert_eq!(d.attempt_status(lease).unwrap(), AttemptStatus::Leased);
    assert!(d.pending_stops().is_empty());
    d.seal(b, [2; 32], 0).unwrap();
    assert!(d.candidate_result(b, [2; 32], 0).unwrap().is_none());
    d.worker_stopped(lease, 1).unwrap();
    let job = d.begin_verification(lease, 1).unwrap();
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &[42]), vec![42])), 2)
            .unwrap(),
        Completion::Accepted
    );
    let mut now = 2;
    finish_all(&mut d, &mut now);
    assert_eq!(
        d.candidate_result(b, [2; 32], now).unwrap(),
        Some(&[42][..])
    );
    assert!(d.candidate_result(b, [1; 32], now).is_err());
    assert!(d.candidate_result(a, [1; 32], now).is_err());
    // Result lookup itself must advance time and reject the expired selection.
    assert!(d.candidate_result(b, [2; 32], 1000).is_err());
}

#[test]
fn incremental_append_reuses_completed_prefix_and_rebuilds_only_changed_ancestors() {
    let mut d = dag();
    let (_, old) = candidate(&mut d, 1);
    d.seal(old, [1; 32], 0).unwrap();
    let mut now = 0;
    finish_all(&mut d, &mut now);
    assert!(d.candidate_result(old, [1; 32], now).unwrap().is_some());
    let count = d.job_count();
    let next_root = tree(&mut d, 2, 0, DEPTH, now);
    assert_eq!(d.job_count(), count + 1 + usize::from(DEPTH));
    let next = d.attach(next_root.id(), [2; 32], 1000, now).unwrap();
    d.cancel(old, now).unwrap();
    assert_eq!(d.status(leaf(0).id()).unwrap(), JobStatus::Completed);
    assert_eq!(d.ready(), vec![leaf(1).id()]);
    assert!(d.seal(old, [1; 32], now).is_err());
    d.seal(next, [2; 32], now).unwrap();
    finish_all(&mut d, &mut now);
    assert!(d.candidate_result(next, [2; 32], now).unwrap().is_some());
    assert!(d.candidate_result(old, [1; 32], now).is_err());
}

#[test]
fn expiry_during_verification_fences_result_and_allows_explicit_retry() {
    let mut d = dag();
    candidate(&mut d, 1);
    let job = leaf(0);
    let lease = d.lease(job.id(), WorkerId(1), request(), 1, 2, 0).unwrap();
    d.worker_stopped(lease, 1).unwrap();
    d.begin_verification(lease, 1).unwrap();
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &[3]), vec![3])), 2)
            .unwrap(),
        Completion::Fenced
    );
    assert_eq!(d.attempt_status(lease).unwrap(), AttemptStatus::Expired);
    assert_eq!(d.status(job.id()).unwrap(), JobStatus::Ready);
    assert_eq!(d.resource_use(), Resources::default());
    let retry = d
        .lease(job.id(), WorkerId(1), request(), 1, 100, 2)
        .unwrap();
    assert_ne!(retry.id(), lease.id());
    assert!(d.advance(1).is_err());
}

#[test]
fn wrong_ticket_changed_bytes_verification_failure_and_worker_failure_do_not_publish() {
    let mut d = dag();
    candidate(&mut d, 2);
    let job = leaf(0);
    let parent = Job::merge(&job, &leaf(1)).unwrap();
    for case in 0..3u64 {
        let now = case * 3;
        let lease = d
            .lease(job.id(), WorkerId(1), request(), 1, 100, now)
            .unwrap();
        d.worker_stopped(lease, now + 1).unwrap();
        d.begin_verification(lease, now + 1).unwrap();
        let result = match case {
            0 => Some((node(&leaf(1), &[1]), vec![1])),
            1 => Some((node(&job, &[1]), vec![2])),
            _ => None,
        };
        let outcome = d.finish_verification(lease, result, now + 2);
        if case < 2 {
            assert!(outcome.is_err());
        } else {
            assert_eq!(outcome.unwrap(), Completion::Rejected);
        }
        assert_eq!(d.status(job.id()).unwrap(), JobStatus::Ready);
        assert_eq!(d.status(parent.id()).unwrap(), JobStatus::Waiting);
        assert_eq!(d.resource_use(), Resources::default());
        assert_eq!(d.reserved_output_bytes(), 0);
    }
    let lease = d
        .lease(job.id(), WorkerId(1), request(), 1, 100, 9)
        .unwrap();
    d.reject_worker(lease, 10).unwrap();
    assert_eq!(d.resource_use(), request());
    assert_eq!(d.status(parent.id()).unwrap(), JobStatus::Waiting);
    d.worker_stopped(lease, 11).unwrap();
    assert_eq!(d.resource_use(), Resources::default());
}

#[test]
fn aggregate_resources_output_space_and_deadlines_are_admitted_before_dispatch() {
    let mut d = dag();
    candidate(&mut d, 4);
    for (remaining, duration) in [(0, 10), (1, 0), (1000, 10), (u64::MAX, 10), (1, u64::MAX)] {
        assert!(d
            .lease(leaf(0).id(), WorkerId(1), request(), remaining, duration, 1)
            .is_err());
        assert_eq!(d.resource_use(), Resources::default());
        assert_eq!(d.reserved_output_bytes(), 0);
    }
    d.lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 1)
        .unwrap();
    for oversized in [
        Resources {
            ram_bytes: 301,
            ..request()
        },
        Resources {
            vram_bytes: 31,
            ..request()
        },
        Resources {
            scratch_bytes: 301,
            ..request()
        },
        Resources {
            threads: 4,
            ..request()
        },
    ] {
        assert!(d
            .lease(leaf(1).id(), WorkerId(2), oversized, 1, 100, 1)
            .is_err());
        assert_eq!(d.resource_use(), request());
        assert_eq!(d.reserved_output_bytes(), MAX_PROOF_BYTES);
    }
    let mut small = Dag::new(
        pin(),
        [9; 32],
        1,
        Limits {
            artifact_bytes: MAX_PROOF_BYTES + 8,
            ..limits()
        },
    )
    .unwrap();
    candidate(&mut small, 4);
    small
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert!(small
        .lease(leaf(1).id(), WorkerId(2), request(), 1, 100, 0)
        .is_err());
    assert_eq!(small.resource_use(), request());
}

#[test]
fn old_session_handles_cannot_acknowledge_current_workers_or_candidates() {
    let mut first = dag();
    let (_, a) = candidate(&mut first, 1);
    let old = first
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let mut second = dag();
    let (_, b) = candidate(&mut second, 1);
    let current = second
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert_ne!(a, b);
    assert_ne!(old.id(), current.id());
    assert!(second.cancel(a, 0).is_err());
    assert!(second.worker_stopped(old, 1).is_err());
    assert!(second.input_manifest(old).is_err());
    assert_eq!(
        second.attempt_status(current).unwrap(),
        AttemptStatus::Leased
    );
    assert_eq!(second.resource_use(), request());
    assert!(second.begin_verification(current, 1).is_err());
}

#[test]
fn pruning_retains_transitive_dependencies_of_newer_unattached_parent() {
    let mut d = dag();
    for start in 0..4 {
        d.admit(leaf(start), vec![vec![start + 1]], 0).unwrap();
    }
    let left = Job::merge(&leaf(0), &leaf(1)).unwrap();
    let right = Job::merge(&leaf(2), &leaf(3)).unwrap();
    d.admit(left.clone(), vec![], 0).unwrap();
    d.admit(right.clone(), vec![], 0).unwrap();
    let parent = Job::merge(&left, &right).unwrap();
    d.admit(parent, vec![], 9).unwrap();
    assert_eq!(d.prune(11).unwrap(), 0);
    assert_eq!(d.job_count(), 7);
    assert_eq!(d.stored_bytes(), 4);
    assert_eq!(d.prune(20).unwrap(), 7);
    assert_eq!(d.stored_bytes(), 0);
    assert_eq!(d.job_count(), 0);
}

#[test]
fn maximum_graph_completes_with_shuffled_workers_within_aggregate_admission() {
    let mut d = dag();
    let (root, c) = candidate(&mut d, 64);
    d.seal(c, [1; 32], 0).unwrap();
    let mut now = 0;
    let mut completed = 0;
    while d.status(root.id()).unwrap() != JobStatus::Completed {
        let ready: Vec<_> = d.ready().into_iter().take(4).collect();
        assert!(!ready.is_empty());
        let mut leases: Vec<_> = ready
            .into_iter()
            .enumerate()
            .map(|(index, id)| {
                d.lease(id, WorkerId(index as u64 + 1), request(), 1, 100, now)
                    .unwrap()
            })
            .collect();
        assert!(d.resource_use().fits(limits().workers));
        assert_eq!(d.reserved_output_bytes(), leases.len() * MAX_PROOF_BYTES);
        leases.reverse();
        if leases.len() > 1 {
            leases.rotate_left(1);
        }
        for lease in leases {
            now += 1;
            d.worker_stopped(lease, now).unwrap();
            let job = d.begin_verification(lease, now).unwrap();
            now += 1;
            assert_eq!(
                d.finish_verification(lease, Some((node(&job, &[42]), vec![42])), now)
                    .unwrap(),
                Completion::Accepted
            );
            completed += 1;
        }
        assert_eq!(d.resource_use(), Resources::default());
        assert_eq!(d.reserved_output_bytes(), 0);
    }
    assert_eq!(completed, 127);
    assert_eq!(d.job_count(), 127);
    assert_eq!(d.stored_bytes(), 64 + 127);
    assert_eq!(
        d.candidate_result(c, [1; 32], now).unwrap(),
        Some(&[42][..])
    );
}

#[test]
fn metadata_limits_bound_graph_candidates_and_attempt_history() {
    let mut one_job = Dag::new(
        pin(),
        [9; 32],
        1,
        Limits {
            jobs: 1,
            ..limits()
        },
    )
    .unwrap();
    one_job.admit(leaf(0), vec![vec![1]], 0).unwrap();
    assert!(one_job.admit(leaf(1), vec![vec![2]], 0).is_err());
    assert_eq!(one_job.job_count(), 1);
    let mut d = Dag::new(
        pin(),
        [9; 32],
        1,
        Limits {
            candidates: 1,
            attempts: 1,
            ..limits()
        },
    )
    .unwrap();
    let (root, _) = candidate(&mut d, 1);
    assert!(d.attach(root.id(), [2; 32], 1000, 0).is_err());
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.reject_worker(lease, 1).unwrap();
    d.worker_stopped(lease, 2).unwrap();
    assert!(d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 2)
        .is_err());
    assert_eq!(d.prune(12).unwrap(), 0);
    assert!(d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 12)
        .is_ok());
}
