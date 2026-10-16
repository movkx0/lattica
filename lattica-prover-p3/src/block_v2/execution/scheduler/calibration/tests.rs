use super::*;
use crate::block_v2::execution::{job::test_support::pin, scheduler::tests::worker};

fn fixture() -> (WorkerCapabilities, Job, CostModel) {
    let mut worker = worker(1);
    worker.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    let job = Job::empty(pin(), [9; 32], 0, 0).unwrap();
    let mut model = CostModel::new(1000).unwrap();
    for ms in 1..=100 {
        model.observe(&worker, &job, false, ms).unwrap();
    }
    (worker, job, model)
}

#[test]
fn imported_history_stays_distinct_until_replaced_by_live_observations() {
    let (mut worker, job, source) = fixture();
    let record = source.export_calibration(&worker, &job, false).unwrap();
    assert_eq!(usize::from(record.count), MAX_SAMPLES);
    let encoded = record.encode();
    let record = TimingCalibration::decode_host(&encoded).unwrap();
    assert_eq!(record.encode(), encoded);
    worker.worker = WorkerId(2); // New physical session, same host-approved class.
    let mut model = CostModel::new(1000).unwrap();
    model.import_calibration(&worker, &record, [7; 32]).unwrap();
    assert_eq!(
        model.estimate_with_source(&worker, &job, false).unwrap(),
        (107, EstimateSource::Calibration([7; 32]))
    );
    assert_eq!(
        model.estimate_with_source(&worker, &job, true).unwrap(),
        (107, EstimateSource::ColdCalibration([7; 32]))
    );
    assert_eq!(model.estimate(&worker, &job, false).unwrap(), (107, false));
    assert!(model.export_calibration(&worker, &job, false).is_err());
    assert!(model.import_calibration(&worker, &record, [8; 32]).is_err());
    model.observe(&worker, &job, false, 10).unwrap();
    assert_eq!(
        model.estimate_with_source(&worker, &job, false).unwrap(),
        (11, EstimateSource::Live)
    );
    assert_eq!(
        model
            .export_calibration(&worker, &job, false)
            .unwrap()
            .count,
        1
    );
    assert!(model.import_calibration(&worker, &record, [7; 32]).is_err());
    assert_eq!(record.encode(), encoded);
}

#[test]
fn every_identity_and_resource_dimension_invalidates_reuse() {
    let (worker, job, source) = fixture();
    let record = source.export_calibration(&worker, &job, false).unwrap();
    let mut changed = Vec::new();
    for index in 0..6 {
        let mut cap = worker.clone();
        cap.timing_identity.as_mut().unwrap().fingerprints[index][0] ^= 128;
        changed.push(cap);
    }
    for index in 0..4 {
        let mut cap = worker.clone();
        match index {
            0 => cap.resources.ram_bytes += 1,
            1 => cap.resources.vram_bytes += 1,
            2 => cap.resources.scratch_bytes += 1,
            _ => cap.resources.threads += 1,
        }
        changed.push(cap);
    }
    let mut unqualified = worker.clone();
    unqualified.timing_identity = None;
    changed.push(unqualified);
    for cap in changed {
        let mut target = CostModel::new(1000).unwrap();
        assert!(target.import_calibration(&cap, &record, [7; 32]).is_err());
        assert!(target.samples.is_empty());
        for warm in [false, true] {
            assert_eq!(source.estimate(&cap, &job, warm).unwrap(), (1000, false));
        }
    }
    let mut other_profile = worker.clone();
    other_profile.profile[0] ^= 1;
    let mut target = CostModel::new(1000).unwrap();
    assert!(target
        .import_calibration(&other_profile, &record, [7; 32])
        .is_err());
    assert!(target
        .import_calibration(&worker, &record, [0; 32])
        .is_err());
    assert!(target.samples.is_empty());
    for index in 0..6 {
        let mut f = worker.timing_identity.unwrap().fingerprints;
        f[index] = [0; 32];
        assert!(TimingIdentity::new(f[0], f[1], f[2], f[3], f[4], f[5]).is_err());
    }
}

#[test]
fn bounded_codec_rejects_malformed_classes_samples_and_noncanonical_padding() {
    let (worker, job, mut source) = fixture();
    source.observe(&worker, &job, true, 50).unwrap();
    let valid = source
        .export_calibration(&worker, &job, true)
        .unwrap()
        .encode();
    for len in [0, 7, 8, valid.len() - 1] {
        assert!(TimingCalibration::decode_host(&valid[..len]).is_err());
    }
    let mut extended = valid.to_vec();
    extended.push(0);
    assert!(TimingCalibration::decode_host(&extended).is_err());
    let replacements: &[(usize, &[u8])] = &[
        (0, b"INVALID!"),
        (8, &[0; 32]),
        (200, &[0; 32]),
        (232, &[0; 8]),
        (256, &[0; 4]),
        (260, &[0; 8]),
        (268, &[crate::block_v2::commitment::DEPTH + 1]),
        (269, &[(crate::block_v2::commitment::CAPACITY + 1) as u8]),
        (270, &[2]),
        (271, &[0]),
        (271, &[65]),
        (272, &[0; 8]),
        (272, &7_200_001u64.to_le_bytes()),
        (280, &1u64.to_le_bytes()),
    ];
    for (offset, replacement) in replacements {
        let mut invalid = valid;
        invalid[*offset..*offset + replacement.len()].copy_from_slice(replacement);
        assert!(
            TimingCalibration::decode_host(&invalid).is_err(),
            "offset {offset}"
        );
    }
    let mut invalid = source.export_calibration(&worker, &job, false).unwrap();
    invalid.samples[0] = 0;
    let mut target = CostModel::new(1000).unwrap();
    assert!(target
        .import_calibration(&worker, &invalid, [7; 32])
        .is_err());
    assert!(target.samples.is_empty() && target.insertion_order.is_empty());
}

#[test]
fn exact_warm_measurements_win_and_forgetting_removes_imported_and_live_classes() {
    let (worker, job, source) = fixture();
    let record = source.export_calibration(&worker, &job, false).unwrap();
    let mut target = CostModel::new(1000).unwrap();
    target.observe(&worker, &job, true, 10).unwrap();
    target
        .import_calibration(&worker, &record, [7; 32])
        .unwrap();
    assert_eq!(
        target.estimate_with_source(&worker, &job, true).unwrap(),
        (11, EstimateSource::Live)
    );
    target.forget_worker(worker.worker);
    for warm in [false, true] {
        assert_eq!(
            target.estimate_with_source(&worker, &job, warm).unwrap(),
            (1000, EstimateSource::Bootstrap)
        );
        assert!(target.export_calibration(&worker, &job, warm).is_err());
    }
    assert!(target.samples.is_empty() && target.insertion_order.is_empty());
    // Reuse after replacement is a new explicit host decision, never automatic.
    target
        .import_calibration(&worker, &record, [7; 32])
        .unwrap();
}

#[test]
fn imported_rings_and_eviction_fit_the_source_derived_storage_bound() {
    let (mut worker, job, source) = fixture();
    let record = source.export_calibration(&worker, &job, false).unwrap();
    let mut target = CostModel::new(1000).unwrap();
    for id in 1..=MAX_CLASSES as u64 + 1 {
        worker.worker = WorkerId(id);
        target
            .import_calibration(&worker, &record, [7; 32])
            .unwrap();
    }
    assert_eq!(target.samples.len(), MAX_CLASSES);
    assert_eq!(target.insertion_order.len(), MAX_CLASSES);
    worker.worker = WorkerId(1);
    assert_eq!(
        target.estimate(&worker, &job, false).unwrap(),
        (1000, false)
    );
    worker.worker = WorkerId(2);
    assert_eq!(target.estimate(&worker, &job, false).unwrap(), (107, false));
    let plan = CostModel::storage_plan().unwrap();
    assert!(target.retained_storage_bytes().unwrap() <= plan.retained_bytes);
    assert!(plan.calibration_bytes >= 2 * TimingCalibration::ENCODED_BYTES);
    eprintln!("bounded_scheduler_calibration retained_bytes={} selection_bytes={} calibration_bytes={} total_bytes={}",
        plan.retained_bytes, plan.selection_bytes, plan.calibration_bytes, plan.total_bytes().unwrap());
}
