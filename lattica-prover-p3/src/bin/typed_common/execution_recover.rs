//! Fresh-process, CPU-only recovery of an actual typed GPU journal.
//! Recovery advances the supplied journal's epoch. The separate pool audit only
//! inspects retained proofs. Both require cleanly drained workers/workspaces.
use super::*;

fn head_token(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("independently supplied host head must be 32 hex bytes".into());
    }
    let mut head = [0u8; 32];
    for (index, byte) in head.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)?;
    }
    Ok(head)
}

/// Audit a bounded pool's complete retained graph without resuming its journal.
/// This can inspect historical evidence but never renews a workflow deadline.
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn audit_pool_journal(
    fixture: &Path,
    expected: &Path,
    runtime: &Path,
    assignment: &Path,
    root_file: &Path,
    head: &str,
    epoch: u64,
    out: &Path,
) -> Result<(), Error> {
    let started = Instant::now();
    let eligibility = head_token(head)?;
    let prepared = prepare(fixture, expected)?;
    let assignment: serde_json::Value = read_json(assignment)?;
    let (peak, jobs) = budget::resources(&assignment)?;
    TypedRegistryContext::admit_recovery_storage(jobs.ram_bytes)?;
    let mut limits = budget::limits(peak, jobs)?;
    // Bounded native pool journals use the ordinary quotas and zero retention;
    // never import these trusted limits from the journal being audited.
    limits.recovery_window_ms = 0;
    let root = bytes(root_file)?;
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    let store = ArtifactStore::open(
        &runtime.join("artifacts"),
        StoreLimits { bytes: budget::ARTIFACT_BYTES, entries: budget::ARTIFACT_ENTRIES },
    )?;
    let recovery = DurableDag::recover_typed(
        &runtime.join("journal"),
        JournalLimits { snapshot_bytes: budget::SNAPSHOT_BYTES },
        store,
        prepared.pin,
        &prepared.registry,
        prepared.expected.chain,
        epoch,
        limits,
        |identity| {
            prepared.policies.iter()
                .find(|(artifact, _)| *artifact == identity)
                .map(|(_, policy)| *policy)
                .ok_or_else(|| "audit wallet absent from independent host policy".into())
        },
    )?;
    if !recovery.unresolved_attempts().is_empty() || !recovery.unresolved_workspaces().is_empty() {
        return Err("pool audit refuses unresolved worker attempts or workspaces".into());
    }
    if recovery.previous_epoch().checked_add(1) != Some(epoch) {
        return Err("pool audit requires the immediate next in-memory epoch".into());
    }
    let candidates = recovery.previous_candidates();
    if candidates.len() != 1 {
        return Err("bounded pool audit requires one retained candidate".into());
    }
    let candidate = &candidates[0];
    if candidate.root != prepared.selection.root().id()
        || candidate.eligibility != eligibility
        || !candidate.sealed
        || candidate.cancelled
        || candidate.deadline_ms != 600_000
    {
        return Err("pool audit candidate differs from independent selection, head or deadline".into());
    }
    // Recovery has freshly verified each complete artifact against reconstructed
    // jobs and independent policy. Matching every independently prepared job ID
    // binds that verification to this selection without verifying each twice.
    let mut verified = 0;
    for job in prepared.selection.jobs() {
        if recovery.verified_node_bytes(job.id())?.is_none() {
            return Err("pool audit lacks a verified node from the independent selection".into());
        }
        verified += 1;
    }
    if recovery.verified_node_bytes(prepared.selection.root().id())? != Some(root.as_slice()) {
        return Err("pool audit root differs from independently verified retained bytes".into());
    }
    write_json(&out.join("summary.json"), &json!({
        "schema_version":1,"record_type":"typed_pool_journal_audit","status":"succeeded",
        "count":prepared.expected.count,"height":prepared.expected.block_height,
        "cpu_verified_wallets":prepared.expected.count,"cpu_audited_nodes":verified,
        "cpu_audited_root":true,"root_identical":true,"root_bytes":root.len(),
        "root_job":hex(&candidate.root.to_bytes()),"previous_epoch":recovery.previous_epoch(),
        "original_candidate_deadline_ms":candidate.deadline_ms,
        "journal_resumed":false,"journal_epoch_advanced":false,"candidate_renewed":false,
        "unresolved_attempts":0,"unresolved_workspaces":0,
        "prover_jobs_started":0,"fresh_recursive_proofs":0,"native_blocks_applied":0,
        "workflow_gate_qualified":false,"production_ready":false,
        "elapsed_seconds":started.elapsed().as_secs_f64()
    }))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn recover(
    fixture: &Path,
    expected: &Path,
    runtime: &Path,
    assignment: &Path,
    root_file: &Path,
    head: &str,
    epoch: u64,
    out: &Path,
) -> Result<(), Error> {
    let started = Instant::now();
    let eligibility = head_token(head)?;
    let prepared = prepare(fixture, expected)?;
    let assignment: serde_json::Value = read_json(assignment)?;
    let (peak, jobs) = budget::resources(&assignment)?;
    TypedRegistryContext::admit_recovery_storage(jobs.ram_bytes)?;
    let limits = budget::limits(peak, jobs)?;
    let registry = TypedRegistryContext::new(&prepared.registry, prepared.pin.profile())?;
    let root = bytes(root_file)?;
    registry.verify_node(prepared.selection.root(), &root)?;
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    let store = ArtifactStore::open(
        &runtime.join("artifacts"),
        StoreLimits {
            bytes: budget::ARTIFACT_BYTES,
            entries: budget::ARTIFACT_ENTRIES,
        },
    )?;
    let recovery = DurableDag::recover_typed(
        &runtime.join("journal"),
        JournalLimits {
            snapshot_bytes: budget::SNAPSHOT_BYTES,
        },
        store,
        prepared.pin,
        &prepared.registry,
        prepared.expected.chain,
        epoch,
        limits,
        |identity| {
            prepared
                .policies
                .iter()
                .find(|(a, _)| *a == identity)
                .map(|(_, policy)| *policy)
                .ok_or_else(|| "wallet absent from independent host policy".into())
        },
    )?;
    if !recovery.unresolved_attempts().is_empty() || !recovery.unresolved_workspaces().is_empty() {
        return Err("clean recovery refuses unresolved worker attempts or workspaces".into());
    }
    if !recovery.previous_candidates().iter().any(|candidate| {
        candidate.root == prepared.selection.root().id()
            && candidate.eligibility == eligibility
            && candidate.sealed
            && !candidate.cancelled
    }) {
        return Err(
            "no retained sealed candidate matches the independent selection and head".into(),
        );
    }
    let now = || started.elapsed().as_millis() as u64;
    let mut owner = recovery.resume(
        |_| Err("clean recovery cannot issue a worker stop receipt".into()),
        now,
    )?;
    let candidate = prepared.selection.attach(
        &mut owner,
        eligibility,
        now() + budget::RECOVERY_WINDOW_MS,
        now(),
    )?;
    if !owner.ready()?.is_empty() || owner.resource_use()? != Resources::default() {
        return Err(
            "recovered graph lacks a verified cached node or retains worker resources".into(),
        );
    }
    owner.seal(candidate, eligibility, now())?;
    if owner.candidate_result(candidate, eligibility, now())? != Some(root.as_slice()) {
        return Err("recovered cached root differs from the independent audited root".into());
    }
    let mut wrong_head = eligibility;
    wrong_head[0] ^= 1;
    if owner.candidate_result(candidate, wrong_head, now()).is_ok() {
        return Err("recovered candidate accepted a different host head".into());
    }
    write_bytes(&out.join("recovered-root"), &root, profile::MAX_PROOF_BYTES)?;
    write_json(
        &out.join("summary.json"),
        &json!({
            "schema_version":1,"record_type":"typed_gpu_journal_recovery",
            "status":"succeeded","recovery_epoch":epoch,"count":prepared.expected.count,
            "height":prepared.expected.block_height,"cpu_audited_root":true,
            "verified_cached_nodes":prepared.selection.jobs().len(),"root_bytes":root.len(),
            "original_gpu_journal":true,"fresh_process_required":true,
            "unresolved_attempts":0,"unresolved_workspaces":0,"resources_released":true,
            "root_identical":true,"wrong_head_rejected":true,
            "prover_jobs_started":0,"fresh_recursive_proofs":0,"native_blocks_applied":0,
            "arrival_backend_integrated":false,"active_worker_recovery_qualified":false,
            "production_ready":false,"elapsed_seconds":started.elapsed().as_secs_f64()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_head_requires_exact_independent_hex_identity() {
        assert_eq!(head_token(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        for invalid in [
            "aa".repeat(31),
            "aa".repeat(33),
            "gg".repeat(32),
            "é".repeat(32),
        ] {
            assert!(head_token(&invalid).is_err());
        }
    }
}
