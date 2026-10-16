//! Placement regressions use structural tickets and synthetic observations.
use super::depth_tests::wallet_dag;
use super::*;

fn qualification() -> TimingIdentity {
    TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap()
}

fn seed_sixteen(
    model: &mut CostModel,
    worker: &WorkerCapabilities,
    jobs: &BTreeMap<JobId, Job>,
    level_four: bool,
) {
    for (mode, level, count, warm, elapsed) in [
        (1, 1, 2, false, 78_573),
        (1, 1, 2, true, 11_981),
        (3, 2, 4, false, 114_978),
        (3, 2, 4, true, 13_768),
        (3, 3, 8, true, 13_814),
        (3, 4, 16, true, 13_106),
        (12, crate::block_v2::commitment::DEPTH, 16, false, 61_868),
    ] {
        if level == 4 && !level_four {
            continue;
        }
        let job = jobs
            .values()
            .find(|j| {
                (
                    j.operation().proof_mode(),
                    j.expected().level,
                    j.expected().count,
                ) == (mode, level, count)
            })
            .unwrap();
        model.observe(worker, job, warm, elapsed).unwrap();
    }
}

#[test]
fn qualified_continuation_admits_exact_sixteen_wallet_boundary() {
    let (jobs, ready, mut worker) = wallet_dag(16);
    worker.timing_identity = Some(qualification());
    worker.forecast_retained_mode = true;
    let mut source = CostModel::new(180_000).unwrap();
    seed_sixteen(&mut source, &worker, &jobs, true);
    let mut model = CostModel::new(180_000).unwrap();
    for job in jobs.values() {
        for warm in [false, true] {
            if let Ok(record) = source.export_calibration(&worker, job, warm) {
                // Different jobs can share one exact timing class.
                if model.estimate_with_source(&worker, job, warm).unwrap().1
                    != EstimateSource::Calibration([7; 32])
                {
                    model.import_calibration(&worker, &record, [7; 32]).unwrap();
                }
            }
        }
    }
    let deadlines = ready.iter().map(|id| (*id, 310_592)).collect();
    let choice = model
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 17)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 310_575);
    assert_eq!(choice.service_ms, 86_431);
    assert_eq!(choice.source, EstimateSource::Calibration([7; 32]));
    assert!(!choice.warm && !choice.measured);
    assert!(model
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 18)
        .unwrap()
        .is_none());
    worker.forecast_retained_mode = false;
    assert!(model
        .select(&jobs, &ready, &[worker], &deadlines, 17)
        .unwrap()
        .is_none());
}

#[test]
fn unknown_classes_replacement_and_configuration_changes_keep_bootstrap() {
    let (jobs, ready, mut worker) = wallet_dag(16);
    worker.timing_identity = Some(qualification());
    worker.forecast_retained_mode = true;
    let mut model = CostModel::new(180_000).unwrap();
    seed_sixteen(&mut model, &worker, &jobs, false);
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    let choice = model
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 476_158);
    let level_four = jobs.values().find(|j| j.expected().level == 4).unwrap();
    assert_eq!(
        model
            .estimate_with_source(&worker, level_four, true)
            .unwrap(),
        (180_000, EstimateSource::Bootstrap)
    );
    let mut changed = worker.clone();
    changed.resources.ram_bytes += 1;
    assert!(model
        .select(&jobs, &ready, &[changed], &deadlines, 0)
        .unwrap()
        .is_none());
    let mut changed = worker.clone();
    changed.timing_identity =
        Some(TimingIdentity::new([9; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    assert!(model
        .select(&jobs, &ready, &[changed], &deadlines, 0)
        .unwrap()
        .is_none());
    model.forget_worker(worker.worker);
    assert!(model
        .select(&jobs, &ready, &[worker], &deadlines, 0)
        .unwrap()
        .is_none());
}

#[test]
fn retention_permission_without_qualification_keeps_cold_path() {
    let (jobs, ready, mut worker) = wallet_dag(16);
    worker.forecast_retained_mode = true;
    assert!(worker.timing_identity.is_none());
    let mut model = CostModel::new(180_000).unwrap();
    seed_sixteen(&mut model, &worker, &jobs, true);
    let deadlines = ready.iter().map(|id| (*id, 640_962)).collect();
    let choice = model
        .select(&jobs, &ready, &[worker], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 640_962);
}

fn placement_case(
    migration: bool,
) -> (
    BTreeMap<JobId, Job>,
    JobId,
    Vec<WorkerCapabilities>,
    CostModel,
) {
    let (jobs, _, mut first) = wallet_dag(16);
    first.timing_identity = Some(qualification());
    first.forecast_retained_mode = true;
    let mut second = first.clone();
    second.worker = WorkerId(2);
    // Resident mode on a destination does not authorize a warm migration.
    second.resident_mode = Some(3);
    let mut model = CostModel::new(180_000).unwrap();
    for worker in [&first, &second] {
        for job in jobs.values() {
            for warm in [false, true] {
                let elapsed = match (worker.worker.0, job.expected().level, warm, migration) {
                    (1, 2, _, _) => 1,
                    (2, 2, _, _) => 10_000,
                    (_, crate::block_v2::commitment::DEPTH, _, _) => 1,
                    (2, 3, true, _) => 1,
                    (2, 3, false, true) => 10,
                    (2, 4, true, true) => 20,
                    (1, 4, true, false) => 1,
                    _ => 1000,
                };
                model.observe(worker, job, warm, elapsed).unwrap();
            }
        }
    }
    let ready = jobs
        .values()
        .find(|j| j.expected().level == 2 && j.start() == 0)
        .unwrap()
        .id();
    (jobs, ready, vec![first, second], model)
}

#[test]
fn descendants_cannot_stitch_warm_costs_from_different_workers() {
    let (jobs, ready, workers, model) = placement_case(false);
    let deadlines = BTreeMap::from([(ready, 1106)]);
    let choice = model
        .select(&jobs, &[ready], &workers, &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.worker, WorkerId(1));
    assert_eq!(choice.remaining_path_ms, 1106);
    assert!(model
        .select(&jobs, &[ready], &workers, &deadlines, 1)
        .unwrap()
        .is_none());
}

#[test]
fn migration_pays_destination_cold_cost_before_qualified_continuation() {
    let (jobs, ready, workers, model) = placement_case(true);
    let deadlines = BTreeMap::from([(ready, 37)]);
    let choice = model
        .select(&jobs, &[ready], &workers, &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.worker, WorkerId(1));
    assert_eq!(choice.remaining_path_ms, 37); // 2 + 11 cold + 22 warm + 2 finalizer.
    assert!(model
        .select(&jobs, &[ready], &workers, &deadlines, 1)
        .unwrap()
        .is_none());
}

#[test]
fn retained_worker_cannot_replace_a_slow_warm_class_with_its_own_cold_class() {
    let (jobs, _, mut worker) = wallet_dag(8);
    worker.timing_identity = Some(qualification());
    worker.forecast_retained_mode = true;
    let mut model = CostModel::new(180_000).unwrap();
    for job in jobs.values() {
        model.observe(&worker, job, false, 1).unwrap();
        model
            .observe(
                &worker,
                job,
                true,
                if job.expected().level == 3 { 1000 } else { 1 },
            )
            .unwrap();
    }
    let ready = jobs
        .values()
        .find(|j| j.expected().level == 2 && j.start() == 0)
        .unwrap()
        .id();
    let deadlines = BTreeMap::from([(ready, 1104)]);
    assert_eq!(
        model
            .select(&jobs, &[ready], &[worker], &deadlines, 0)
            .unwrap()
            .unwrap()
            .remaining_path_ms,
        1104
    );
}

#[test]
fn maximum_job_worker_table_is_bounded_and_duplicate_placements_reject() {
    let mut jobs = BTreeMap::new();
    for i in 0..MAX_JOBS {
        let mut chain = [0; 32];
        chain[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let job = Job::empty(super::super::job::test_support::pin(), chain, 0, 0).unwrap();
        jobs.insert(job.id(), job);
    }
    let workers: Vec<_> = (1..=MAX_WORKERS)
        .map(|i| super::tests::worker(i as u64))
        .collect();
    let ready = *jobs.keys().next().unwrap();
    let deadlines = BTreeMap::from([(ready, 1)]);
    let model = CostModel::new(1).unwrap();
    assert_eq!(
        model
            .select(&jobs, &[ready], &workers, &deadlines, 0)
            .unwrap()
            .unwrap()
            .remaining_path_ms,
        1
    );
    let mut duplicate = workers.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(model
        .select(&jobs, &[ready], &duplicate, &deadlines, 0)
        .unwrap_err()
        .to_string()
        .contains("duplicate worker"));
    let mut excess = workers;
    excess.push(super::tests::worker(MAX_WORKERS as u64 + 1));
    assert!(model
        .select(&jobs, &[ready], &excess, &deadlines, 0)
        .is_err());
}
