use super::*;
use crate::block_v2::execution::job::test_support::pin;

fn worker(id: u64) -> WorkerCapabilities {
    WorkerCapabilities {
        worker: WorkerId(id),
        profile: pin().profile(),
        resources: Resources {
            ram_bytes: 1024,
            vram_bytes: 0,
            scratch_bytes: 0,
            threads: 2,
        },
        resident_mode: None,
    }
}

fn tree() -> (Job, Job, Job, BTreeMap<JobId, Job>) {
    let left = Job::empty(pin(), [9; 32], 0, 0).unwrap();
    let right = Job::empty(pin(), [9; 32], 1, 0).unwrap();
    let root = Job::merge(&left, &right).unwrap();
    let jobs = [left.clone(), right.clone(), root.clone()]
        .into_iter()
        .map(|j| (j.id(), j))
        .collect();
    (left, right, root, jobs)
}

#[test]
fn includes_downstream_work_and_defers_impossible_deadlines() {
    let (left, _, _, jobs) = tree();
    let model = CostModel::new(100).unwrap();
    let mut deadlines = BTreeMap::from([(left.id(), 300)]);
    let choice = model
        .select(&jobs, &[left.id()], &[worker(1)], &deadlines, 50)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 200);
    assert!(!choice.measured);
    deadlines.insert(left.id(), 249);
    assert!(model
        .select(&jobs, &[left.id()], &[worker(1)], &deadlines, 50)
        .unwrap()
        .is_none());
}

#[test]
fn deadline_slack_wins_over_input_order() {
    let (left, right, _, jobs) = tree();
    let deadlines = BTreeMap::from([(left.id(), 1000), (right.id(), 300)]);
    let choice = CostModel::new(100)
        .unwrap()
        .select(&jobs, &[left.id(), right.id()], &[worker(1)], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.job, right.id());
}

#[test]
fn estimates_are_separated_by_worker_threads_and_cache_state() {
    let (left, _, _, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    let mut first = worker(1);
    model.observe(&first, &left, false, 100).unwrap();
    assert_eq!(model.estimate(&first, &left, false).unwrap(), (110, true));
    assert_eq!(model.estimate(&first, &left, true).unwrap(), (1000, false));
    assert_eq!(
        model.estimate(&worker(2), &left, false).unwrap(),
        (1000, false)
    );
    first.resources.threads = 1;
    assert_eq!(model.estimate(&first, &left, false).unwrap(), (1000, false));
    first.profile[0] ^= 1;
    assert!(model.observe(&first, &left, false, 100).is_err());
}

#[test]
fn p95_is_bounded_and_zero_duration_is_rejected() {
    let (left, _, _, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    assert!(model.observe(&worker(1), &left, false, 0).is_err());
    for ms in 1..=100 {
        model.observe(&worker(1), &left, false, ms).unwrap();
    }
    assert_eq!(model.samples.values().next().unwrap().len(), MAX_SAMPLES);
    assert_eq!(
        model.estimate(&worker(1), &left, false).unwrap(),
        (107, true)
    );
}

#[test]
fn unqualified_profiles_and_missing_deadlines_cannot_dispatch() {
    let (left, _, _, jobs) = tree();
    let model = CostModel::new(100).unwrap();
    assert!(model
        .select(&jobs, &[left.id()], &[worker(1)], &BTreeMap::new(), 0)
        .is_err());
    let mut other = worker(1);
    other.profile = [0; 32];
    let deadlines = BTreeMap::from([(left.id(), 1000)]);
    assert!(model
        .select(&jobs, &[left.id()], &[other], &deadlines, 0)
        .unwrap()
        .is_none());
}

#[test]
fn placement_prefers_the_faster_worker_not_artificially_smaller_slack() {
    let (left, _, _, jobs) = tree();
    let mut model = CostModel::new(100).unwrap();
    model.observe(&worker(1), &left, false, 10).unwrap();
    model.observe(&worker(2), &left, false, 90).unwrap();
    let deadlines = BTreeMap::from([(left.id(), 1000)]);
    let choice = model
        .select(&jobs, &[left.id()], &[worker(2), worker(1)], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.worker, WorkerId(1));
}
