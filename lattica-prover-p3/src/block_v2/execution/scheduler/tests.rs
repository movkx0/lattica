use super::*;
use crate::block_v2::execution::job::test_support::pin;

pub(super) fn worker(id: u64) -> WorkerCapabilities {
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
        timing_identity: None,
        forecast_retained_mode: false,
        dispatch_deadline_ms: None,
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
fn provisional_warm_estimates_stay_within_the_cold_cost_class() {
    let (left, _, root, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    let mut first = worker(1);
    model.observe(&first, &left, false, 100).unwrap();
    assert_eq!(model.estimate(&first, &left, false).unwrap(), (110, true));
    assert_eq!(model.estimate(&first, &left, true).unwrap(), (110, false));
    let higher = Job::empty(pin(), [9; 32], 0, 1).unwrap();
    let other_profile = Job::empty(
        crate::block_v2::execution::job::test_support::typed_pin(),
        [9; 32],
        0,
        0,
    )
    .unwrap();
    let mut other_worker_profile = first.clone();
    other_worker_profile.profile = other_profile.pin().profile();
    for warm in [false, true] {
        assert_eq!(
            model.estimate(&worker(2), &left, warm).unwrap(),
            (1000, false)
        );
        assert_eq!(
            model.estimate(&first, &higher, warm).unwrap(),
            (1000, false)
        );
        assert_eq!(
            model
                .estimate(&other_worker_profile, &other_profile, warm)
                .unwrap(),
            (1000, false)
        );
    }
    model.observe(&first, &higher, false, 200).unwrap();
    // Same level and worker, different operation mode.
    assert_eq!(model.estimate(&first, &root, true).unwrap(), (1000, false));
    first.resources.threads = 1;
    assert_eq!(model.estimate(&first, &left, false).unwrap(), (1000, false));
    assert_eq!(model.estimate(&first, &left, true).unwrap(), (1000, false));
    first.profile[0] ^= 1;
    assert!(model.observe(&first, &left, false, 100).is_err());
}

#[test]
fn warm_fallback_uses_cold_p95_until_a_warm_observation_exists() {
    let (left, _, _, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    for ms in 1..=100 {
        model.observe(&worker(1), &left, false, ms).unwrap();
    }
    assert_eq!(
        model.estimate(&worker(1), &left, true).unwrap(),
        (107, false)
    );
    model.observe(&worker(1), &left, true, 10).unwrap();
    assert_eq!(model.estimate(&worker(1), &left, true).unwrap(), (11, true));
    assert_eq!(
        model.estimate(&worker(1), &left, false).unwrap(),
        (107, true)
    );
    model.observe(&worker(2), &left, true, 20).unwrap();
    // A warm observation never estimates an unknown cold start.
    assert_eq!(
        model.estimate(&worker(2), &left, false).unwrap(),
        (1000, false)
    );
}

#[test]
fn forgetting_a_worker_removes_exact_and_provisional_estimates() {
    let (left, _, root, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    model.observe(&worker(1), &left, false, 100).unwrap();
    model.observe(&worker(1), &root, false, 200).unwrap();
    model.observe(&worker(1), &root, true, 20).unwrap();
    model.observe(&worker(2), &left, false, 50).unwrap();
    assert_eq!(
        model.estimate(&worker(1), &left, true).unwrap(),
        (110, false)
    );
    assert_eq!(model.estimate(&worker(1), &root, true).unwrap(), (22, true));
    model.forget_worker(WorkerId(1));
    for job in [&left, &root] {
        for warm in [false, true] {
            assert_eq!(
                model.estimate(&worker(1), job, warm).unwrap(),
                (1000, false)
            );
        }
    }
    assert!(model.insertion_order.iter().all(|key| key.worker != 1));
    assert_eq!(
        model.estimate(&worker(2), &left, true).unwrap(),
        (55, false)
    );
}

#[test]
fn resident_job_uses_provisional_cost_without_relaxing_its_deadline() {
    let (left, right, _, jobs) = tree();
    let mut model = CostModel::new(100).unwrap();
    let mut resident = worker(1);
    model.observe(&resident, &left, false, 10).unwrap();
    resident.resident_mode = Some(left.operation().proof_mode());
    let mut deadlines = BTreeMap::from([(right.id(), 300)]);
    let choice = model
        .select(&jobs, &[right.id()], &[resident.clone()], &deadlines, 150)
        .unwrap()
        .unwrap();
    assert!(choice.warm && !choice.measured);
    assert_eq!(choice.service_ms, 11);
    assert_eq!(choice.remaining_path_ms, 111);
    deadlines.insert(right.id(), 260);
    assert!(model
        .select(&jobs, &[right.id()], &[resident], &deadlines, 150)
        .unwrap()
        .is_none());
}

#[test]
fn p95_is_bounded_and_zero_duration_is_rejected() {
    let (left, _, _, _) = tree();
    let mut model = CostModel::new(1000).unwrap();
    assert!(model.observe(&worker(1), &left, false, 0).is_err());
    for ms in 1..=100 {
        model.observe(&worker(1), &left, false, ms).unwrap();
    }
    assert_eq!(
        model.samples.values().next().unwrap().samples.len(),
        MAX_SAMPLES
    );
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

#[test]
fn service_window_filters_placement_at_the_exact_finish_boundary() {
    let (left, _, _, jobs) = tree();
    let model = CostModel::new(100).unwrap();
    let deadlines = BTreeMap::from([(left.id(), 1_000)]);
    let mut first = worker(1);
    first.dispatch_deadline_ms = Some(107);
    assert_eq!(
        model
            .select(&jobs, &[left.id()], &[first.clone()], &deadlines, 7)
            .unwrap()
            .unwrap()
            .worker,
        first.worker
    );
    assert!(model
        .select(&jobs, &[left.id()], &[first.clone()], &deadlines, 8)
        .unwrap()
        .is_none());
    let second = worker(2);
    assert_eq!(
        model
            .select(&jobs, &[left.id()], &[first, second.clone()], &deadlines, 8)
            .unwrap()
            .unwrap()
            .worker,
        second.worker
    );
}

#[test]
fn a_changed_service_window_preserves_exact_calibration_but_not_admission() {
    let (left, _, _, jobs) = tree();
    let mut worker = worker(1);
    worker.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    let mut observed = CostModel::new(100).unwrap();
    observed.observe(&worker, &left, false, 10).unwrap();
    let record = observed.export_calibration(&worker, &left, false).unwrap();
    worker.dispatch_deadline_ms = Some(10);
    let mut imported = CostModel::new(100).unwrap();
    imported
        .import_calibration(&worker, &record, [7; 32])
        .unwrap();
    assert_eq!(
        imported
            .estimate_with_source(&worker, &left, false)
            .unwrap(),
        (11, EstimateSource::Calibration([7; 32]))
    );
    let deadlines = BTreeMap::from([(left.id(), 1_000)]);
    assert!(imported
        .select(&jobs, &[left.id()], &[worker.clone()], &deadlines, 0)
        .unwrap()
        .is_none());
    worker.dispatch_deadline_ms = Some(11);
    assert!(imported
        .select(&jobs, &[left.id()], &[worker], &deadlines, 0)
        .unwrap()
        .is_some());
}
