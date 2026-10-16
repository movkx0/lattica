//! Explicit retained-proof CPU diagnostic. No candidate is attached or resumed,
//! no prover is launched, and the original failed journal is never opened here.
use super::*;

// Reference is the pre-ownership import loop from the preserved implementation.
// It is compiled only into this opt-in CPU test, never a production entry point.
fn reference_import(
    directory: &Path,
    binding: &native::Binding,
    prepared: &Prepared,
    owner: &mut DurableDag,
    out: &Path,
    now: impl Fn() -> u64,
) -> Result<Vec<serde_json::Value>, Error> {
    let cache: Cache = read_json(&directory.join("result.json"))?;
    if cache.schema_version != 1
        || cache.status != "preseal_verified"
        || !cache.preseal_only
        || cache.stable_nodes.len() > 62
    {
        return Err("invalid bounded pre-seal cache manifest".into());
    }
    cache.native_host.check_cache_session(binding)?;
    let jobs: BTreeMap<_, _> = prepared.selection.jobs().map(|job| (job.id().to_bytes(), job)).collect();
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for node in cache.stable_nodes {
        let Some(job) = jobs.get(&node.job) else { continue };
        if !stable(job)
            || node.level != job.expected().level
            || node.index as usize != job.start() as usize >> job.expected().level
            || node.bytes == 0
            || node.bytes > profile::MAX_PROOF_BYTES
        {
            return Err("pre-seal cache geometry differs from the current semantic job".into());
        }
        if seen.contains(&node.job) { continue }
        let path = directory.join(name(job));
        let proof = bytes(&path)?;
        let artifact = ArtifactRef::from_bytes(ArtifactKind::Node, &proof)?;
        if proof.len() != node.bytes || artifact.digest_bytes() != node.artifact_digest {
            return Err("pre-seal cache artifact bytes changed".into());
        }
        let ticket = VerifiedNode::verify_typed(job, &prepared.registry, &proof)?;
        owner.cache_node(ticket, proof.clone(), now())?;
        write_bytes(&out.join(name(job)), &proof, profile::MAX_PROOF_BYTES)?;
        seen.insert(node.job);
        records.push(json!({"job":hex(&node.job),"source":path,"level":node.level,
            "index":node.index,"bytes":node.bytes,"cpu_reverified":true}));
    }
    Ok(records)
}

#[test]
#[ignore = "requires explicit archived native fixture, prefix cache, binding, budget and new output"]
fn retained_native_prefix_import_without_candidate() -> Result<(), Error> {
    let config_path = std::env::var_os("LATTICA_PREFIX_IMPORT_DIAGNOSTIC")
        .ok_or("explicit retained prefix diagnostic configuration is required")?;
    let config: serde_json::Value = read_json(Path::new(&config_path))?;
    let path = |key: &str| -> Result<PathBuf, Error> {
        let value = PathBuf::from(config[key].as_str().ok_or("diagnostic path missing")?);
        if !value.is_absolute() { return Err("diagnostic path must be absolute".into()); }
        Ok(value)
    };
    let mode = config["mode"].as_str().ok_or("diagnostic mode missing")?;
    if !matches!(mode, "reference" | "owned") { return Err("diagnostic mode invalid".into()); }
    let fixture = path("fixture")?;
    let cache = path("cache")?;
    let out = path("output")?;
    let started = Instant::now();
    let prepared = prepare(&fixture, &fixture.join("expected.json"))?;
    let binding: native::Binding = read_json(&path("binding")?)?;
    binding.check_scope(false)?;
    binding.head_for(&prepared.expected)?;
    let assignment: serde_json::Value = read_json(&path("assignment")?)?;
    let (peak, jobs) = budget::resources(&assignment)?;
    TypedRegistryContext::admit_recovery_storage(jobs.ram_bytes)?;
    let mut limits = budget::limits(peak, jobs)?;
    limits.recovery_window_ms = 0;
    std::fs::DirBuilder::new().mode(0o700).create(&out)?;
    let store = ArtifactStore::create(&out.join("artifacts"), StoreLimits {
        bytes: budget::ARTIFACT_BYTES, entries: budget::ARTIFACT_ENTRIES,
    })?;
    let mut owner = DurableDag::create(&out.join("journal"), JournalLimits {
        snapshot_bytes: budget::SNAPSHOT_BYTES,
    }, store, prepared.pin, prepared.expected.chain, 1, limits)?;
    // Dormant jobs are not a candidate: no deadline, native eligibility,
    // selection claim or launch authority is created by this diagnostic.
    let now = || started.elapsed().as_millis() as u64;
    prepared.selection.admit(&mut owner, now())?;
    assert!(prepared.selection.jobs().all(|job| owner.job_deadline(job.id()).unwrap() == 0));
    assert!(owner.ready()?.is_empty());
    let imported_at = Instant::now();
    let records = if mode == "reference" {
        reference_import(&cache, &binding, &prepared, &mut owner, &out, now)?
    } else {
        // No workflow is issued or renewed. Expired historical bytes can be
        // diagnosed only in this graph without a candidate or proving endpoint.
        import(&[cache.clone()], Some(&binding), &prepared, &mut owner, &out, now, None)?
    };
    let import_seconds = imported_at.elapsed().as_secs_f64();
    let descriptor: Cache = read_json(&cache.join("result.json"))?;
    assert_eq!(records.len(), descriptor.stable_nodes.len());
    assert!(!records.is_empty() && records.len() <= 62);
    for node in &descriptor.stable_nodes {
        let job = prepared.selection.jobs().find(|job| job.id().to_bytes() == node.job)
            .ok_or("retained prefix diagnostic job missing")?;
        let retained = owner.verified_node_bytes(job.id())?.ok_or("verified imported node missing")?;
        assert_eq!(retained, bytes(&cache.join(name(job)))?);
        assert_eq!(retained, bytes(&out.join(name(job)))?);
        assert_eq!(owner.job_deadline(job.id())?, 0);
    }
    assert!(owner.verified_node_bytes(prepared.selection.root().id())?.is_none());
    assert!(!out.join("node.6.0").exists());
    drop(owner);
    // Independently reload every imported proof and inspect, without resume.
    let store = ArtifactStore::open(&out.join("artifacts"), StoreLimits {
        bytes: budget::ARTIFACT_BYTES, entries: budget::ARTIFACT_ENTRIES,
    })?;
    let recovery = DurableDag::recover_typed(&out.join("journal"), JournalLimits {
        snapshot_bytes: budget::SNAPSHOT_BYTES,
    }, store, prepared.pin, &prepared.registry, prepared.expected.chain, 2, limits,
        |artifact| prepared.policies.iter().find(|(id, _)| *id == artifact)
            .map(|(_, policy)| *policy).ok_or_else(|| "diagnostic wallet policy missing".into()))?;
    assert!(recovery.previous_candidates().is_empty());
    assert!(recovery.unresolved_attempts().is_empty());
    assert!(recovery.unresolved_workspaces().is_empty());
    for node in &descriptor.stable_nodes {
        let job = prepared.selection.jobs().find(|job| job.id().to_bytes() == node.job).unwrap();
        assert!(recovery.verified_node_bytes(job.id())?.is_some());
    }
    // Real retained bytes exercise both borrowed and consuming numerical paths.
    let context = TypedRegistryContext::new(&prepared.registry, prepared.pin.profile())?;
    let first = &descriptor.stable_nodes[0];
    let job = prepared.selection.jobs().find(|job| job.id().to_bytes() == first.job).unwrap();
    let original = bytes(&cache.join(name(job)))?;
    let pointer = original.as_ptr();
    let payload = context.verify_node_owned(job, original)?;
    assert_eq!(payload.bytes().as_ptr(), pointer);
    assert_eq!(payload.ticket().artifact().digest_bytes(), first.artifact_digest);
    let mut corrupted = payload.bytes().to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(context.verify_node_owned(job, corrupted).is_err());
    let another = prepared.selection.jobs().find(|other| other.id() != job.id()
        && other.expected().level == job.expected().level).unwrap();
    assert!(context.verify_node_owned(another, payload.bytes().to_vec()).is_err());
    write_json(&out.join("summary.json"), &json!({
        "status":"passed","mode":mode,"cpu_verified_wallets":prepared.expected.count,
        "imported_nodes":records.len(),"independently_replayed_nodes":records.len(),
        "candidate_count":0,"prover_jobs_started":0,"native_blocks_applied":0,
        "original_journal_opened":false,"workflow_issued":false,"candidate_renewed":false,
        "workflow_gate_qualified":false,"import_seconds":import_seconds,
        "elapsed_seconds":started.elapsed().as_secs_f64(),"records":records,
        "owned_buffer_preserved":true,"corrupted_proof_rejected":true,"wrong_job_rejected":true
    }))?;
    Ok(())
}
