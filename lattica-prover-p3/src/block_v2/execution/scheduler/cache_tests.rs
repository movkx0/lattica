//! Synthetic mixed-mode regressions; these observations do not qualify a GPU.
use super::*;
use crate::block_v2::execution::{
    job::test_support::{typed_pin, typed_wallet},
    selection::{PublicInput, Selection},
};

fn mixed(count: u8) -> (BTreeMap<JobId, Job>, WorkerCapabilities, CostModel) {
    let inputs: Vec<_> = (1..=count)
        .map(|i| {
            let bytes = vec![i];
            let mode = if i <= count / 2 { 1 } else { 5 };
            PublicInput::new(typed_wallet(u64::from(i), mode, &bytes), bytes).unwrap()
        })
        .collect();
    let selection = Selection::new(typed_pin(), [9; 32], &inputs).unwrap();
    let jobs: BTreeMap<_, _> = selection.jobs().map(|j| (j.id(), j.clone())).collect();
    let mut worker = super::tests::worker(1);
    worker.profile = typed_pin().profile();
    worker.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    worker.forecast_retained_mode = true;
    let mut costs = CostModel::new(180_000).unwrap();
    for job in jobs.values() {
        for warm in [false, true] {
            let elapsed = match (job.expected().level, warm) {
                (1, false) => 45_000,
                (1, true) => 11_000,
                (crate::block_v2::commitment::DEPTH, _) => 37_000,
                (_, false) => 65_000,
                (_, true) => 13_000,
            };
            costs.observe(&worker, job, warm, elapsed).unwrap();
        }
    }
    (jobs, worker, costs)
}

#[test]
fn mixed_dag_reuses_each_mode_and_completes_with_unchanged_deadline() {
    let (jobs, mut worker, costs) = mixed(32);
    let mut done = std::collections::BTreeSet::new();
    let mut modes = Vec::new();
    let mut cold_jobs = 0;
    let mut now = 0;
    while done.len() < jobs.len() {
        let ready: Vec<_> = jobs
            .values()
            .filter(|job| {
                !done.contains(&job.id()) && job.dependencies().iter().all(|id| done.contains(id))
            })
            .map(Job::id)
            .collect();
        let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
        let choice = costs
            .select(&jobs, &ready, &[worker.clone()], &deadlines, now)
            .unwrap()
            .unwrap();
        assert_eq!(choice.worker, worker.worker);
        assert!(now + choice.remaining_path_ms <= 600_000);
        assert!(done.insert(choice.job));
        now += choice.service_ms;
        cold_jobs += usize::from(!choice.warm);
        let mode = jobs[&choice.job].operation().proof_mode();
        modes.push(mode);
        worker.resident_mode = Some(mode);
    }
    assert_eq!(done.len(), 32);
    assert_eq!(cold_jobs, 4); // Two pair modes, merges, and finalizer.
    assert_eq!(modes.windows(2).filter(|w| w[0] != w[1]).count(), 3);
    assert!(now <= 600_000);
}

fn pair_case() -> (
    BTreeMap<JobId, Job>,
    Vec<JobId>,
    WorkerCapabilities,
    CostModel,
) {
    let (jobs, mut worker, costs) = mixed(8);
    let warm = jobs
        .values()
        .find(|j| j.expected().level == 1 && j.start() == 0)
        .unwrap();
    let cold = jobs
        .values()
        .find(|j| j.expected().level == 1 && j.start() == 4)
        .unwrap();
    worker.resident_mode = Some(warm.operation().proof_mode());
    let ready = vec![warm.id(), cold.id()];
    (jobs, ready, worker, costs)
}

#[test]
fn warm_delay_preserves_the_most_urgent_deadline_at_the_exact_boundary() {
    let (jobs, ready, worker, costs) = pair_case();
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    let cold = costs
        .select(&jobs, &ready[1..], &[worker.clone()], &deadlines, 0)
        .unwrap()
        .unwrap();
    let warm = costs.estimate(&worker, &jobs[&ready[0]], true).unwrap().0;
    let boundary = cold.remaining_path_ms + warm;
    for (deadline, expected) in [(boundary - 1, ready[1]), (boundary, ready[0])] {
        let deadlines = ready.iter().map(|id| (*id, deadline)).collect();
        let choice = costs
            .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
            .unwrap()
            .unwrap();
        assert_eq!(choice.job, expected);
        if choice.warm {
            assert!(choice.service_ms + cold.remaining_path_ms <= deadline);
        }
    }
    // Giving the warm job a later deadline must not override earlier urgency.
    let deadlines = BTreeMap::from([(ready[0], 600_001), (ready[1], 600_000)]);
    assert_eq!(
        costs
            .select(&jobs, &ready, &[worker], &deadlines, 0)
            .unwrap()
            .unwrap()
            .job,
        ready[1]
    );
}

#[test]
fn cache_preference_requires_qualified_retention_and_exact_savings() {
    for missing in ["permission", "identity", "warm", "cold", "saving"] {
        let (jobs, ready, mut worker, mut costs) = pair_case();
        let job = &jobs[&ready[0]];
        match missing {
            "permission" => worker.forecast_retained_mode = false,
            "identity" => {
                // Keep observations exact for the unqualified session.
                let mut unqualified = CostModel::new(180_000).unwrap();
                worker.timing_identity = None;
                for job in jobs.values() {
                    unqualified.observe(&worker, job, false, 45_000).unwrap();
                    unqualified.observe(&worker, job, true, 11_000).unwrap();
                }
                costs = unqualified;
            }
            "warm" | "cold" => {
                let key = CostModel::key(&worker, job, missing == "warm").unwrap();
                costs.samples.remove(&key);
                costs.insertion_order.retain(|stored| *stored != key);
            }
            "saving" => {
                let key = CostModel::key(&worker, job, false).unwrap();
                costs.samples.remove(&key);
                costs.insertion_order.retain(|stored| *stored != key);
                costs.observe(&worker, job, false, 1_000).unwrap();
            }
            _ => unreachable!(),
        }
        let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
        let choice = costs
            .select(&jobs, &ready, &[worker], &deadlines, 0)
            .unwrap()
            .unwrap();
        // With a missing warm class, the provisional cost ties the cold job;
        // compare against the unchanged urgency ranking explicitly.
        if missing == "warm" {
            let expected = ready.iter().copied().min().unwrap();
            assert_eq!(choice.job, expected);
        } else {
            assert_eq!(choice.job, ready[1], "missing {missing}");
        }
    }
}

#[test]
fn cache_preference_keeps_the_fastest_physical_placement() {
    let (jobs, ready, first, mut costs) = pair_case();
    let mut second = first.clone();
    second.worker = WorkerId(2);
    second.resident_mode = None;
    for job in jobs.values() {
        // This worker is faster for the warm candidate even without its cache,
        // but much slower for the urgent cold job and their descendants.
        let elapsed = if job.operation().proof_mode() == jobs[&ready[0]].operation().proof_mode() {
            1_000
        } else {
            100_000
        };
        costs.observe(&second, job, false, elapsed).unwrap();
    }
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    assert_eq!(
        costs
            .select(
                &jobs,
                &ready[..1],
                &[first.clone(), second.clone()],
                &deadlines,
                0
            )
            .unwrap()
            .unwrap()
            .worker,
        second.worker
    );
    let choice = costs
        .select(&jobs, &ready, &[first.clone(), second], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.job, ready[1]);
    assert_eq!(choice.worker, first.worker);
}

#[test]
fn remaining_service_time_does_not_force_an_avoidable_cold_mode_switch() {
    let (jobs, ready, mut worker, costs) = pair_case();
    let warm = costs.estimate(&worker, &jobs[&ready[0]], true).unwrap().0;
    let cold = costs.estimate(&worker, &jobs[&ready[1]], false).unwrap().0;
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    // A deferred cold job owns no reservation in this process. It can use a
    // replacement; preserving that hypothetical placement must not force a
    // cold setup while ready cached work fits both its service and job limits.
    for limit in [warm, warm + cold - 1, warm + cold] {
        worker.dispatch_deadline_ms = Some(limit);
        assert_eq!(
            costs
                .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
                .unwrap()
                .unwrap()
                .job,
            ready[0]
        );
    }
}
