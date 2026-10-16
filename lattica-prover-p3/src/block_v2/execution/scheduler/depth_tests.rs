//! Structural DAG admission; synthetic tickets do not qualify GPU performance.
use super::*;
use crate::block_v2::execution::{
    job::test_support::{typed_pin, typed_wallet},
    selection::{PublicInput, Selection},
};

pub(super) fn wallet_dag(count: u8) -> (BTreeMap<JobId, Job>, Vec<JobId>, WorkerCapabilities) {
    let inputs: Vec<_> = (1..=count)
        .map(|i| {
            let bytes = vec![i];
            PublicInput::new(typed_wallet(u64::from(i), 1, &bytes), bytes).unwrap()
        })
        .collect();
    let selection = Selection::new(typed_pin(), [9; 32], &inputs).unwrap();
    assert_eq!(selection.jobs().len(), usize::from(count));
    let ready = selection
        .jobs()
        .filter(|job| job.dependencies().is_empty())
        .map(Job::id)
        .collect::<Vec<_>>();
    assert_eq!(ready.len(), usize::from(count) / 2);
    let jobs = selection
        .jobs()
        .map(|job| (job.id(), job.clone()))
        .collect();
    let mut worker = super::tests::worker(1);
    worker.profile = typed_pin().profile();
    (jobs, ready, worker)
}

#[test]
fn eight_wallet_bootstrap_path_exceeds_unchanged_six_hundred_second_deadline() {
    let (jobs, ready, worker) = wallet_dag(8);
    let model = CostModel::new(180_000).unwrap();
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    assert!(model
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
        .unwrap()
        .is_none());
    // Diagnose the actual four-stage path; the production deadline stays 600 s.
    let diagnostic = ready.iter().map(|id| (*id, 720_000)).collect();
    let choice = model
        .select(&jobs, &ready, &[worker], &diagnostic, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 720_000);
    assert!(!choice.measured);
}

#[test]
fn calibrated_deep_path_preserves_deadline_margin_and_unknown_class_bootstrap() {
    let (jobs, ready, mut worker) = wallet_dag(8);
    worker.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    let mut source = CostModel::new(180_000).unwrap();
    let mut target = CostModel::new(180_000).unwrap();
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    let pair = &jobs[&ready[0]];
    source.observe(&worker, pair, false, 100_000).unwrap();
    target
        .import_calibration(
            &worker,
            &source.export_calibration(&worker, pair, false).unwrap(),
            [7; 32],
        )
        .unwrap();
    // One calibrated stage leaves three unknown stages: 110 + 3*180 = 650 s.
    assert!(target
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
        .unwrap()
        .is_none());
    let mut classes = std::collections::BTreeSet::from([(
        pair.operation().proof_mode(),
        pair.expected().level,
        pair.expected().count,
    )]);
    for job in jobs.values() {
        if classes.insert((
            job.operation().proof_mode(),
            job.expected().level,
            job.expected().count,
        )) {
            source.observe(&worker, job, false, 100_000).unwrap();
            let record = source.export_calibration(&worker, job, false).unwrap();
            target
                .import_calibration(&worker, &record, [7; 32])
                .unwrap();
        }
    }
    assert_eq!(classes.len(), 4);
    let choice = target
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 440_000); // Existing 10% margin on all four stages.
    assert_eq!(choice.source, EstimateSource::Calibration([7; 32]));
    assert!(!choice.measured);
    let exact = ready.iter().map(|id| (*id, 440_017)).collect();
    assert!(target
        .select(&jobs, &ready, &[worker.clone()], &exact, 17)
        .unwrap()
        .is_some());
    assert!(target
        .select(&jobs, &ready, &[worker.clone()], &exact, 18)
        .unwrap()
        .is_none());
    // Both finalizers are mode 12/level 6, but their subtree sizes differ.
    let (smaller, _, _) = wallet_dag(4);
    let finalizer = smaller
        .values()
        .find(|job| job.expected().level == crate::block_v2::commitment::DEPTH)
        .unwrap();
    assert_eq!(
        target
            .estimate_with_source(&worker, finalizer, false)
            .unwrap(),
        (180_000, EstimateSource::Bootstrap)
    );
}

#[test]
fn sixteen_wallet_warm_calibration_does_not_enable_unqualified_forecasts() {
    let (jobs, ready, mut worker) = wallet_dag(16);
    worker.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    let mut observed = CostModel::new(180_000).unwrap();
    let mut model = CostModel::new(180_000).unwrap();
    // Structural replay of §9.167's class maxima, not another GPU measurement.
    for (mode, level, count, warm, elapsed) in [
        (1, 1, 2, false, 78_573),
        (1, 1, 2, true, 11_981),
        (3, 2, 4, false, 114_978),
        (3, 2, 4, true, 13_768),
        (3, 3, 8, true, 13_814),
        (3, 4, 16, true, 13_106),
        (12, crate::block_v2::commitment::DEPTH, 16, false, 61_868),
    ] {
        let job = jobs
            .values()
            .find(|job| {
                (
                    job.operation().proof_mode(),
                    job.expected().level,
                    job.expected().count,
                ) == (mode, level, count)
            })
            .unwrap();
        observed.observe(&worker, job, warm, elapsed).unwrap();
        model
            .import_calibration(
                &worker,
                &observed.export_calibration(&worker, job, warm).unwrap(),
                [7; 32],
            )
            .unwrap();
    }
    let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
    assert!(model
        .select(&jobs, &ready, &[worker.clone()], &deadlines, 0)
        .unwrap()
        .is_none());
    let diagnostic = ready.iter().map(|id| (*id, 640_962)).collect();
    let choice = model
        .select(&jobs, &ready, &[worker], &diagnostic, 0)
        .unwrap()
        .unwrap();
    assert_eq!(choice.remaining_path_ms, 640_962);
    assert_eq!(choice.source, EstimateSource::Calibration([7; 32]));
    assert!(!choice.measured);
}
