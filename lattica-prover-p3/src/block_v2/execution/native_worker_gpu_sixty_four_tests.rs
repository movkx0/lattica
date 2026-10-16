//! Full-count fixture, admission and exact-image timing census.
use super::*;
#[path = "native_worker_gpu_sixty_four_calibration_tests.rs"]
mod calibration;
#[path = "native_worker_gpu_sixty_four_fixture.rs"]
mod fixture64;
use crate::block_v2::execution::scheduler::EstimateSource;
use fixture64::{full_fixture, JOBS};

fn pool_workload() -> super::fresh_pool::PoolWorkload {
    super::fresh_pool::PoolWorkload {
        name: "sixty_four",
        wallets: &fixture64::WALLETS,
        jobs: JOBS,
        eligibility: [41; 32],
        timing_classes: 14,
        fixture: full_fixture,
        store_limits: fixture64::store_limits,
        limits: fixture64::limits,
    }
}

#[test]
#[ignore = "fresh natural-order 64-wallet DAG through the real GPU pool; fixed 600-second candidate and 180-second workers"]
fn native_sixty_four_fresh_pool_phase() {
    super::fresh_pool::run_phase(pool_workload());
}

#[test]
#[ignore = "independent CPU recovery of the complete 64-wallet candidate or its retained prefix after worker exit"]
fn native_sixty_four_fresh_saved_dag_verifies_without_worker() {
    super::fresh_pool::audit_saved(pool_workload());
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRecord {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

fn imported_costs(cap: &WorkerCapabilities) -> (CostModel, usize) {
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_RECORDS").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 16 << 10);
    let records: Vec<ApprovedRecord> = serde_json::from_slice(&read(&path)).unwrap();
    assert!(!records.is_empty() && records.len() <= 32);
    let count = records.len();
    let mut costs = CostModel::new(180_000).unwrap();
    for record in records {
        let bytes = read(&record.path);
        assert_eq!(bytes.len(), TimingCalibration::ENCODED_BYTES);
        assert_eq!(
            process::configuration_digest(&bytes).unwrap(),
            record.content_identity
        );
        costs
            .import_calibration(
                cap,
                &TimingCalibration::decode_host(&bytes).unwrap(),
                record.evidence,
            )
            .unwrap();
    }
    (costs, count)
}

#[test]
#[ignore = "CPU-only full-64 fixture and scheduling census; no native worker or proofs"]
fn native_sixty_four_fixture_and_timing_inventory() {
    assert!(!gpu_hash::is_enabled());
    let (registry, selection, context) = full_fixture();
    let f = Fixture::with_registry(
        "inventory",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    let (peak, resources) = worker_budget::resources(&f.assignment).unwrap();
    let store =
        ArtifactStore::create(&f.directory.join("artifacts"), fixture64::store_limits()).unwrap();
    let mut owner = DurableDag::create(
        &f.directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        typed_fixture::CHAIN,
        1,
        fixture64::limits(peak, resources),
    )
    .unwrap();
    // This is a simulated admission clock, not a native candidate measurement.
    let candidate = selection.attach(&mut owner, [41; 32], 600_000, 0).unwrap();
    owner.seal(candidate, [41; 32], 0).unwrap();
    assert!(selection
        .jobs()
        .all(|job| owner.verified_node_bytes(job.id()).unwrap().is_none()));
    let worker = ProcessWorker::prepare(
        &mut owner,
        f.bootstrap.config(&f.assignment).unwrap(),
        WorkerId(1),
        WorkerId(2),
        0,
    )
    .unwrap();
    let cap = worker
        .scheduling_capabilities_with_timing(host_identity(&f))
        .unwrap();
    let (costs, imported) = imported_costs(&cap);
    let mut groups = BTreeMap::new();
    for job in selection.jobs() {
        let key = (
            job.operation().proof_mode(),
            job.expected().level,
            job.expected().count,
        );
        let count = groups.entry(key).or_insert((0usize, job));
        count.0 += 1;
    }
    let mut classes = Vec::new();
    for ((mode, level, count), (jobs, job)) in groups {
        for warm in [false, true] {
            let (ms, source) = costs.estimate_with_source(&cap, job, warm).unwrap();
            classes.push(serde_json::json!({"mode":mode,"level":level,"input_count":count,
                "jobs":jobs,"warm":warm,"estimated_ms":ms,"source":format!("{source:?}"),
                "missing_exact_class":matches!(source,EstimateSource::Bootstrap|EstimateSource::ColdCalibration(_)|EstimateSource::ColdLive),
                "bootstrap":matches!(source,EstimateSource::Bootstrap)}));
        }
    }
    assert!(worker.pid().is_none() && worker.service_identity().is_none() && !worker.has_pending());
    let workspace = worker.workspace().unwrap();
    drop(worker);
    drop(owner);
    let store =
        ArtifactStore::open(&f.directory.join("artifacts"), fixture64::store_limits()).unwrap();
    let recovery = DurableDag::recover_typed(
        &f.directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        2,
        fixture64::limits(peak, resources),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert!(recovery.unresolved_attempts().is_empty());
    assert_eq!(recovery.unresolved_workspaces(), &[workspace]);
    let owner = recovery
        .resume_with_workspaces(
            |_| Err("inventory has no attempts".into()),
            |previous| {
                assert_eq!(*previous, workspace);
                Ok(())
            },
            || 0,
        )
        .unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(!gpu_hash::is_enabled());
    let report = serde_json::json!({"wallets":64,"wallet_types":{"joinsplit":16,"htlc_redeem":16,"htlc_refund":16,"issuance":16},
        "jobs":JOBS,"pair_modes":{"4":16,"8":16},"merges":31,"finalizers":0,"root_level":6,"root_count":64,
        "root_mode":selection.root().operation().proof_mode(),"wallet_order":fixture64::WALLETS.as_slice(),
        "all_wallets_cpu_verified":true,"wrong_policies_rejected":64,"complete_workflow_qualified":false,
        "gpu_initialized":false,"native_worker_started":false,"prepared_workspace_reconciled":true,"fresh_proofs":0,
        "clock_simulated":true,"imported_classes":imported,"classes":classes,
        "artifact_bytes":fixture64::artifact_bytes(),"store_bytes":fixture64::store_limits().bytes,
        "store_entries":fixture64::store_limits().entries,"dag_jobs":JOBS,"attempts":JOBS,
        "coordinator_cap_increased":false,"worker_cap_increased":false});
    fs::write(
        f.directory.join("full64-inventory.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("native_sixty_four_inventory_verified wallets=64 jobs=63 root_level=6 root_count=64 all_wallets_cpu_verified=true gpu_initialized=false fresh_proofs=0");
}

#[test]
#[ignore = "CPU geometry admission for full-size mixed pair modes under <=3 GiB"]
fn native_sixty_four_pair_geometry_fits_existing_assignment() {
    use crate::block_v2::machine::gpu_backend::resources::{validate_assignment, Bounds};
    assert!(!gpu_hash::is_enabled());
    let mode = setting("LATTICA_FULL_SIZE_MODE");
    let indices = match mode {
        4 => [0, 1],
        8 => [2, 3],
        _ => panic!("full-64 pair mode"),
    };
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let wallets = indices.map(|index| {
        let bytes = read(&directory.join(format!("wallet.{index}")));
        assert!(bytes.starts_with(b"LBV2TW01"));
        codec::decode::<crate::block_v2::recursive::WalletProof>(&bytes[8..]).unwrap()
    });
    let height = serde_json::from_slice(&read(&directory.join("height.json"))).unwrap();
    let compiled =
        typed_pairs::compile_registration(height, mode, Some([&wallets[0], &wallets[1]])).unwrap();
    let program = compiled.program.pad_to(height).unwrap();
    let bounds = Bounds::for_program_with_device_salts(&program, true).unwrap();
    let assignment: serde_json::Value = serde_json::from_slice(&read(&PathBuf::from(
        std::env::var_os("LATTICA_V2_WORKER_BUDGET").unwrap(),
    )))
    .unwrap();
    validate_assignment(&assignment, true, Some(&bounds)).unwrap();
    let partition = bounds
        .partition_host(assignment["host"]["worker_bytes"].as_u64().unwrap())
        .unwrap();
    assert!(partition.pcs_bytes >= crate::block_v2::machine::symbolic::HOST_BYTES);
    let output = PathBuf::from(std::env::var_os("LATTICA_GEOMETRY_OUTPUT").unwrap());
    let report = serde_json::json!({"mode":mode,"height":height,"active_rows":program.active_rows(),
        "bounds":bounds,"existing_assignment_covers":true,"budget_increased":false,"gpu_initialized":false,
        "proof_produced":false,"host_reserved_bytes":partition.reserved_bytes,"pcs_host_bytes":partition.pcs_bytes});
    fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("native_sixty_four_pair_geometry_verified mode={mode} rows={height} existing_assignment_covers=true gpu_initialized=false proof_produced=false");
}
