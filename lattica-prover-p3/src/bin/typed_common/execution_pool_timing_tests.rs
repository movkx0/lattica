use super::*;
use lattica_prover_p3::block_v2::execution::job::{Job, RegistryPin};
use p3_field::PrimeCharacteristicRing;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    approval: serde_json::Value,
    capabilities: WorkerCapabilities,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "lattica-pool-timing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let registry = lattica_prover_p3::block_v2::recursive::Registry {
            height: 8,
            caps: std::array::from_fn(|_| vec![[Val::ONE; 4]; 1 << profile::CAP_HEIGHT]),
        };
        let pin = RegistryPin::new(
            &registry,
            registry.id().unwrap(),
            lattica_prover_p3::block_v2::recursive::WrapperConstruction::SingleWallet,
        )
        .unwrap();
        let job = Job::empty(pin, [9; 32], 0, 0).unwrap();
        let capabilities = WorkerCapabilities {
            worker: WorkerId(2),
            profile: pin.profile(),
            resources: Resources {
                ram_bytes: 1024,
                vram_bytes: 0,
                scratch_bytes: 0,
                threads: 1,
            },
            resident_mode: None,
            timing_identity: Some(
                TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap(),
            ),
            forecast_retained_mode: false,
            dispatch_deadline_ms: None,
        };
        let mut model = CostModel::new(SERVICE_MS).unwrap();
        for ms in [10, 12, 11] {
            model.observe(&capabilities, &job, false, ms).unwrap();
        }
        let bytes = model
            .export_calibration(&capabilities, &job, false)
            .unwrap()
            .encode();
        let record = directory.join("record.bin");
        std::fs::write(&record, bytes).unwrap();
        let approval = json!({"schema_version":1,"gpu_uuid":"GPU-test","executable":vec![3;32],
            "identity":vec![vec![1;32],vec![2;32],vec![4;32],vec![5;32],vec![6;32]],
            "records":[{"path":record,"content_identity":configuration_digest(&bytes).unwrap(),"evidence":vec![7;32]}]});
        Self {
            directory,
            approval,
            capabilities,
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.join("approval.json")
    }
    fn write(&self) {
        std::fs::write(self.path(), serde_json::to_vec(&self.approval).unwrap()).unwrap();
    }
    fn load(&self) -> Result<Loaded, Error> {
        self.write();
        Loaded::load(&self.path(), [3; 32], "GPU-test")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn bounded_host_records_load_and_match_only_the_approved_capabilities() {
    let f = Fixture::new();
    let loaded = f.load().unwrap();
    assert_eq!(loaded.records.len(), 1);
    loaded.check_capabilities(&f.capabilities).unwrap();
    for field in 0..3 {
        let mut changed = f.capabilities.clone();
        match field {
            0 => changed.profile[0] ^= 1,
            1 => changed.resources.ram_bytes += 1,
            _ => changed.timing_identity = None,
        }
        assert!(loaded.check_capabilities(&changed).is_err());
    }
}

#[test]
fn worker_image_device_and_empty_fingerprints_fail_before_record_access() {
    let mut f = Fixture::new();
    f.write();
    assert!(Loaded::load(&f.path(), [8; 32], "GPU-test").is_err());
    assert!(Loaded::load(&f.path(), [3; 32], "GPU-other").is_err());
    f.approval["identity"][0] = json!(vec![0; 32]);
    assert!(f.load().is_err());
}

#[test]
fn record_bytes_and_host_evidence_are_required() {
    let mut f = Fixture::new();
    let path = f.directory.join("record.bin");
    let original = std::fs::read(&path).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    std::fs::write(&path, changed).unwrap();
    assert!(f.load().is_err());
    std::fs::write(&path, original).unwrap();
    f.approval["records"][0]["evidence"] = json!(vec![0; 32]);
    assert!(f.load().is_err());
}

#[test]
fn duplicate_histories_cannot_replace_an_approved_class() {
    let mut f = Fixture::new();
    let record = f.approval["records"][0].clone();
    f.approval["records"].as_array_mut().unwrap().push(record);
    assert!(f
        .load()
        .unwrap()
        .check_capabilities(&f.capabilities)
        .is_err());
}

#[test]
fn record_count_is_bounded_before_an_extra_payload_is_decoded() {
    let mut f = Fixture::new();
    let record = f.approval["records"][0].clone();
    let mut records = vec![record; MAX_RECORDS];
    records.push(json!({"unexpected_nested_payload":[[[],[]]]}));
    f.approval["records"] = json!(records);
    assert!(f
        .load()
        .err()
        .unwrap()
        .to_string()
        .contains("preparation collection limit"));
    f.approval["records"] = json!([]);
    assert!(f.load().is_err());
}

#[test]
fn approval_and_record_symlinks_and_relative_paths_are_rejected() {
    let mut f = Fixture::new();
    f.write();
    let link = f.directory.join("linked.json");
    std::os::unix::fs::symlink(f.path(), &link).unwrap();
    assert!(Loaded::load(&link, [3; 32], "GPU-test").is_err());
    let record_link = f.directory.join("linked.bin");
    std::os::unix::fs::symlink(f.directory.join("record.bin"), &record_link).unwrap();
    f.approval["records"][0]["path"] = json!(record_link);
    assert!(f.load().is_err());
    f.approval["records"][0]["path"] = json!("record.bin");
    assert!(f.load().is_err());
}

fn window() -> Window {
    Window {
        schema_version: 1,
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        issued_monotonic_ms: 10,
        dispatch_deadline_monotonic_ms: 10 + DISPATCH_MS,
    }
}

#[test]
fn original_boot_and_dispatch_deadline_cannot_be_extended_or_rebased() {
    let w = window();
    w.validate_at(&w.boot_id, 10).unwrap();
    w.validate_at(&w.boot_id, 10 + DISPATCH_MS - 1).unwrap();
    assert!(w.validate_at(&w.boot_id, 9).is_err());
    assert!(w.validate_at(&w.boot_id, 10 + DISPATCH_MS).is_err());
    assert!(w
        .validate_at("11234567-89ab-cdef-0123-456789abcdef", 10)
        .is_err());
    let mut extended = w.clone();
    extended.dispatch_deadline_monotonic_ms += 1;
    assert!(extended.validate_at(&w.boot_id, 10).is_err());
    let mut overflow = w.clone();
    overflow.issued_monotonic_ms = u64::MAX;
    assert!(overflow.validate_at(&w.boot_id, u64::MAX).is_err());
}

#[test]
fn known_timing_payloads_fit_the_existing_shared_floor() {
    for workers in 1..=16 {
        assert!(storage_bytes(workers).unwrap() < 2 << 20);
    }
    assert!(storage_bytes(0).is_err());
    assert!(storage_bytes(17).is_err());
}

#[test]
fn scheduling_approval_cannot_be_attached_to_a_non_pool_or_partial_fleet() {
    let mut plan = super::super::tests::plan();
    plan.workers[0].pool_timing = Some("/tmp/timing.json".into());
    assert!(validate_plan(&plan).is_err());
    plan.pool_scheduling = Some(window());
    assert!(validate_plan(&plan).is_err());
    plan.workers[1].pool_timing = Some("/tmp/timing2.json".into());
    assert!(validate_plan(&plan).is_err());
}

#[test]
fn workflow_keeps_one_clock_origin_across_expired_and_live_service_windows() {
    let original = Workflow {
        schema_version: 1,
        boot_id: window().boot_id,
        started_monotonic_ms: 10,
        deadline_monotonic_ms: 10 + CANDIDATE_MS,
    };
    let old = window();
    let mut next = old.clone();
    next.issued_monotonic_ms += SERVICE_MS;
    next.dispatch_deadline_monotonic_ms += SERVICE_MS;
    assert!(old
        .validate_at(&old.boot_id, next.issued_monotonic_ms)
        .is_err());
    original.check_window(&old).unwrap();
    original.check_window(&next).unwrap();
    next.validate_at(&next.boot_id, next.issued_monotonic_ms)
        .unwrap();
    original
        .validate_at(&original.boot_id, next.issued_monotonic_ms)
        .unwrap();
    assert!(original.validate_at(&original.boot_id, 9).is_err());
    assert!(original
        .validate_at(&original.boot_id, original.deadline_monotonic_ms)
        .is_err());
    assert!(original
        .validate_at("11234567-89ab-cdef-0123-456789abcdef", 20)
        .is_err());
    let mut changed = original.clone();
    changed.deadline_monotonic_ms += 1;
    assert!(changed.check_window(&old).is_err());
    changed.started_monotonic_ms = u64::MAX;
    assert!(changed.check_window(&old).is_err());
    next.issued_monotonic_ms = original.deadline_monotonic_ms;
    next.dispatch_deadline_monotonic_ms = next.issued_monotonic_ms + DISPATCH_MS;
    assert!(original.check_window(&next).is_err());
}

#[test]
fn recovered_clock_counts_time_before_the_new_process() {
    let now = monotonic_ms().unwrap();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let original = Workflow {
        schema_version: 1,
        boot_id: boot.trim().into(),
        started_monotonic_ms: now.saturating_sub(1000),
        deadline_monotonic_ms: now.saturating_sub(1000) + CANDIDATE_MS,
    };
    let first = Clock::new(Some(&original), Instant::now()).unwrap();
    assert!(first.now() >= now - original.started_monotonic_ms);
    let second = Clock::new(Some(&original), Instant::now()).unwrap();
    assert!(second.now() >= now - original.started_monotonic_ms);
    let mut wrong_boot = original.clone();
    wrong_boot.boot_id = "00000000-0000-0000-0000-000000000000".into();
    assert!(Clock::new(Some(&wrong_boot), Instant::now()).is_err());
}
