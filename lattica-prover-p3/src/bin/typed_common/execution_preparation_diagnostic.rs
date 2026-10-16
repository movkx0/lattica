//! Preparation and dormant admission diagnostics without a candidate or worker.
use super::*;
use std::path::PathBuf;

#[test]
#[ignore = "requires explicit archived public fixture and isolated diagnostic output; never attaches a candidate"]
fn wallet_preparation_and_dormant_admission_without_candidate() -> Result<(), Error> {
    let config_path = std::env::var_os("LATTICA_WALLET_OWNERSHIP_DIAGNOSTIC")
        .ok_or("explicit wallet ownership diagnostic is required")?;
    let config: serde_json::Value = read_json(Path::new(&config_path))?;
    let path = |key: &str| -> Result<PathBuf, Error> {
        let value = PathBuf::from(config[key].as_str().ok_or("diagnostic path missing")?);
        if !value.is_absolute() {
            return Err("diagnostic path must be absolute".into());
        }
        Ok(value)
    };
    let fixture = path("fixture")?;
    let out = path("output")?;
    let request: serde_json::Value = read_json(&path("request")?)?;
    let assignment: serde_json::Value = read_json(&path("assignment")?)?;
    let (peak, jobs) = budget::resources(&assignment)?;
    let limits = budget::limits(peak, jobs)?;
    let before = Instant::now();
    let prepared = prepare(&fixture, &fixture.join("expected.json"))?;
    let preparation_seconds = before.elapsed().as_secs_f64();
    assert_eq!(request["native_host"]["expected"], serde_json::to_value(&prepared.expected)?);
    assert_eq!(prepared.expected.count, 64);
    std::fs::DirBuilder::new().mode(0o700).create(&out)?;
    let store = ArtifactStore::create(&out.join("artifacts"), StoreLimits {
        bytes: budget::ARTIFACT_BYTES, entries: budget::ARTIFACT_ENTRIES,
    })?;
    let mut owner = DurableDag::create(&out.join("journal"), JournalLimits {
        snapshot_bytes: budget::SNAPSHOT_BYTES,
    }, store, prepared.pin, prepared.expected.chain, 1, limits)?;
    let first = Instant::now();
    prepared.selection.admit(&mut owner, 0)?;
    let first_admission_seconds = first.elapsed().as_secs_f64();
    assert!(owner.ready()?.is_empty());
    assert_eq!(owner.resource_use()?, Resources::default());
    let usage = owner.store_usage()?;
    let repeated = Instant::now();
    prepared.selection.admit(&mut owner, 0)?;
    let repeated_admission_seconds = repeated.elapsed().as_secs_f64();
    assert_eq!(owner.store_usage()?, usage);
    assert!(owner.ready()?.is_empty());
    assert_eq!(owner.resource_use()?, Resources::default());
    let jobs = prepared.selection.jobs().map(|job| hex(&job.id().to_bytes())).collect::<Vec<_>>();
    assert_eq!(jobs.len(), 63);
    let retained = prepared.selection.retained_storage_bytes()?;
    assert!(retained <= Selection::storage_plan()?.retained_bytes()?);
    let root = hex(&prepared.selection.root().id().to_bytes());
    let expected = serde_json::to_value(&prepared.expected)?;
    drop(owner);
    drop(prepared);
    write_json(&out.join("summary.json"), &json!({
        "status":"passed", "cpu_verified_wallets":64, "dormant_jobs":63, "jobs":jobs,
        "expected":expected, "root_job":root, "preparation_seconds":preparation_seconds,
        "first_admission_seconds":first_admission_seconds,
        "repeated_admission_seconds":repeated_admission_seconds,
        "elapsed_seconds":before.elapsed().as_secs_f64(), "selection_retained_bytes":retained,
        "candidate_count":0, "prover_jobs_started":0, "native_blocks_applied":0,
        "original_journal_opened":false, "workflow_issued":false, "candidate_renewed":false,
        "throughput_qualified":false
    }))?;
    Ok(())
}

#[test]
#[ignore = "requires explicit archived native fixture/binding and new diagnostic output"]
fn retained_preparation_handoff_without_candidate() -> Result<(), Error> {
    let config_path = std::env::var_os("LATTICA_PREPARATION_DIAGNOSTIC")
        .ok_or("explicit preparation diagnostic configuration is required")?;
    let config: serde_json::Value = read_json(Path::new(&config_path))?;
    let path = |key: &str| -> Result<PathBuf, Error> {
        let value = PathBuf::from(config[key].as_str().ok_or("diagnostic path missing")?);
        if !value.is_absolute() {
            return Err("diagnostic path must be absolute".into());
        }
        Ok(value)
    };
    let mode = config["mode"].as_str().ok_or("diagnostic mode missing")?;
    if !matches!(mode, "reference" | "retained") {
        return Err("diagnostic mode invalid".into());
    }
    let fixture = path("fixture")?;
    let out = path("output")?;
    let binding: serde_json::Value = read_json(&path("binding")?)?;
    assert!(binding.get("scope").is_none() || binding["scope"] == "candidate");
    let started = Instant::now();
    let initial = prepare(&fixture, &fixture.join("expected.json"))?;
    assert_eq!(binding["expected"], serde_json::to_value(&initial.expected)?);
    let root = initial.selection.root().id();
    let first_job = initial.selection.jobs().next().unwrap() as *const _;
    let policies = initial.policies.as_ptr();
    let cap = initial.registry.caps[0].as_ptr();
    let initial_seconds = started.elapsed().as_secs_f64();
    let handoff = Instant::now();
    let (registry, initial) = initial.into_pool_parts();
    assert_eq!(registry.caps[0].as_ptr(), cap);
    assert_eq!(initial.selection.jobs().next().unwrap() as *const _, first_job);
    assert_eq!(initial.policies.as_ptr(), policies);
    let prepared = if mode == "reference" {
        // Reproduce the old service boundary: discard the initial preparation
        // and independently prepare the exact same request again.
        drop(initial);
        prepare(&fixture, &fixture.join("expected.json"))?.into_pool_parts().1
    } else {
        initial
    };
    assert_eq!(binding["expected"], serde_json::to_value(&prepared.expected)?);
    assert_eq!(prepared.selection.root().id(), root);
    let handoff_seconds = handoff.elapsed().as_secs_f64();
    let selection_bytes = prepared.selection.retained_storage_bytes()?;
    assert!(selection_bytes <= Selection::storage_plan()?.retained_bytes()?);
    PreparationStorage::policy_list_storage_bytes(&prepared.policies)?;
    registry.storage_bytes()?;
    let jobs = prepared.selection.jobs().map(|job| hex(&job.id().to_bytes())).collect::<Vec<_>>();
    let expected = serde_json::to_value(&prepared.expected)?;
    let wallet_count = prepared.expected.count;
    drop(prepared);
    drop(registry);
    std::fs::DirBuilder::new().mode(0o700).create(&out)?;
    write_json(&out.join("summary.json"), &json!({
        "status":"passed","mode":mode,"cpu_verified_wallets":wallet_count,
        "wallet_verification_passes":if mode == "reference" {2} else {1},
        "initial_seconds":initial_seconds,"handoff_seconds":handoff_seconds,
        "elapsed_seconds":started.elapsed().as_secs_f64(),"jobs":jobs,"expected":expected,
        "selection_retained_bytes":selection_bytes,"moved_allocations_preserved":true,
        "candidate_count":0,"prover_jobs_started":0,"native_blocks_applied":0,
        "original_journal_opened":false,"workflow_issued":false,"candidate_renewed":false,
        "throughput_qualified":false
    }))?;
    Ok(())
}
