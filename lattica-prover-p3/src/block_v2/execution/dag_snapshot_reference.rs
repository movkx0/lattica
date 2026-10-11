//! Frozen pre-9.105 encoder, used only as an independent wire-format oracle.
use super::*;

fn byte(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}
fn u32le(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    out.extend(u32::try_from(value)?.to_le_bytes());
    Ok(())
}
fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_le_bytes());
}
fn resources(out: &mut Vec<u8>, value: Resources) {
    u64le(out, value.ram_bytes);
    u64le(out, value.vram_bytes);
    u64le(out, value.scratch_bytes);
    out.extend(value.threads.to_le_bytes());
}
fn artifact(out: &mut Vec<u8>, value: ArtifactRef) {
    byte(
        out,
        match value.kind() {
            ArtifactKind::Wallet => 1,
            ArtifactKind::Node => 2,
        },
    );
    out.extend(value.byte_len().to_le_bytes());
    out.extend(value.digest_bytes());
}
fn construction(value: RegistryPin) -> u8 {
    value.code() as u8
}
fn operation(value: Operation) -> u8 {
    value.code() as u8
}
fn attempt_status(value: AttemptStatus) -> Result<u8, Error> {
    Ok(match value {
        AttemptStatus::Leased => 1,
        AttemptStatus::Verifying => 2,
        AttemptStatus::Rejected => 3,
        AttemptStatus::Cancelled => 4,
        AttemptStatus::Expired => 5,
        AttemptStatus::Completed => {
            return Err("checkpoint completed reservation is not released".into())
        }
    })
}

pub(super) fn encode(dag: &Dag) -> Result<Vec<u8>, Error> {
    let base = encode_base(dag)?;
    if dag.workspaces.is_empty() {
        return Ok(base);
    }
    if dag.workspaces.len() > dag.limits.attempts {
        return Err("checkpoint workspace count bound".into());
    }
    let mut out = WORKSPACE_MAGIC.to_vec();
    u32le(&mut out, base.len())?;
    out.extend(base);
    u64le(&mut out, dag.workspace_sequence);
    u32le(&mut out, dag.workspaces.len())?;
    let mut workers: BTreeSet<_> = dag
        .attempts
        .values()
        .filter(|a| !a.released)
        .map(|a| a.lease.worker)
        .collect();
    for (id, lease) in &dag.workspaces {
        lease.resources.validate_workspace()?;
        if *id != lease.id
            || id.session != dag.session
            || id.epoch != dag.epoch
            || id.sequence == 0
            || id.sequence > dag.workspace_sequence
            || lease.worker.0 == 0
            || !workers.insert(lease.worker)
        {
            return Err("checkpoint workspace identity".into());
        }
        u64le(&mut out, id.sequence);
        u64le(&mut out, lease.worker.0);
        resources(&mut out, lease.resources);
    }
    if out.len() > MAX_SNAPSHOT_BYTES {
        return Err("checkpoint workspace byte bound".into());
    }
    Ok(out)
}

fn encode_base(dag: &Dag) -> Result<Vec<u8>, Error> {
    dag.limits.validate()?;
    let unassigned_store = dag.launch_root.is_some_and(|root| root.store == [0; 2]);
    let staged = unassigned_store
        || dag
            .attempts
            .values()
            .any(|a| !a.released && a.launch_binding.is_some_and(LaunchBinding::is_staged));
    if staged && dag.launch_root.is_none() {
        return Err("staged checkpoint requires pinned journal".into());
    }
    let mut out = if staged {
        STAGED_MAGIC
    } else if dag.launch_root.is_some() {
        BOUND_MAGIC
    } else {
        MAGIC
    }
    .to_vec();
    out.extend(dag.pin.profile());
    byte(&mut out, construction(dag.pin));
    out.extend(dag.chain);
    out.extend(dag.session);
    u64le(&mut out, dag.epoch);
    u64le(&mut out, dag.now_ms);
    u64le(&mut out, dag.candidate_sequence);
    u64le(&mut out, dag.attempt_sequence);
    u32le(&mut out, dag.limits.jobs)?;
    u32le(&mut out, dag.limits.candidates)?;
    u32le(&mut out, dag.limits.attempts)?;
    u64le(&mut out, dag.limits.artifact_bytes as u64);
    u64le(&mut out, dag.limits.recovery_window_ms);
    resources(&mut out, dag.limits.workers);
    let mut jobs: Vec<_> = dag.jobs.values().collect();
    jobs.sort_by_key(|r| (r.job.expected().level, r.job.start(), r.job.id()));
    u32le(&mut out, jobs.len())?;
    let mut logical = 0usize;
    for record in jobs {
        let job = &record.job;
        out.extend(job.id().to_bytes());
        byte(&mut out, operation(job.operation()));
        byte(&mut out, job.start());
        byte(&mut out, job.expected().level);
        byte(&mut out, job.wallet_inputs().len() as u8);
        for identity in job.wallet_inputs() {
            artifact(&mut out, *identity);
            logical = logical
                .checked_add(identity.byte_len() as usize)
                .ok_or("checkpoint artifact overflow")?;
        }
        byte(&mut out, job.dependencies().len() as u8);
        for id in job.dependencies() {
            out.extend(id.to_bytes());
        }
        byte(&mut out, u8::from(record.output.is_some()));
        if let Some((identity, bytes)) = &record.output {
            if bytes.len() != identity.byte_len() as usize {
                return Err("checkpoint output length invariant".into());
            }
            artifact(&mut out, *identity);
            logical = logical
                .checked_add(bytes.len())
                .ok_or("checkpoint artifact overflow")?;
        }
    }
    if logical != dag.stored_bytes {
        return Err("checkpoint stored-byte invariant".into());
    }
    u32le(&mut out, dag.candidates.len())?;
    for (id, c) in &dag.candidates {
        if id.session != dag.session {
            return Err("checkpoint candidate session".into());
        }
        u64le(&mut out, id.sequence);
        out.extend(c.root.to_bytes());
        out.extend(c.eligibility);
        u64le(&mut out, c.deadline_ms);
        byte(&mut out, u8::from(c.sealed));
        byte(&mut out, u8::from(c.cancelled));
    }
    let attempts: Vec<_> = dag.attempts.values().filter(|a| !a.released).collect();
    u32le(&mut out, attempts.len())?;
    let mut used = Resources::default();
    let mut reserved = 0usize;
    for a in attempts {
        if a.lease.id.session != dag.session
            || a.lease.id.epoch != dag.epoch
            || !a.output_reserved
            || a.accepted.is_some()
        {
            return Err("checkpoint attempt invariant".into());
        }
        u64le(&mut out, a.lease.id.sequence);
        out.extend(a.lease.job.to_bytes());
        u64le(&mut out, a.lease.worker.0);
        u64le(&mut out, a.lease.deadline_ms);
        resources(&mut out, a.resources);
        byte(&mut out, attempt_status(a.status)?);
        byte(&mut out, u8::from(a.worker_stopped));
        byte(&mut out, u8::from(a.verification_active));
        byte(&mut out, a.manifest.len() as u8);
        for identity in &a.manifest {
            artifact(&mut out, *identity);
        }
        used = used
            .add(a.resources)
            .ok_or("checkpoint reservation overflow")?;
        reserved = reserved
            .checked_add(MAX_PROOF_BYTES)
            .ok_or("checkpoint output reservation overflow")?;
    }
    if staged {
        byte(&mut out, 1);
    }
    if let Some(root) = dag.launch_root {
        root.validate()?;
        for value in root.journal.into_iter().chain(root.store) {
            u64le(&mut out, value);
        }
    }
    if staged || dag.launch_root.is_some() {
        let bindings: Vec<_> = dag
            .attempts
            .values()
            .filter(|a| !a.released && a.launch_binding.is_some())
            .collect();
        u32le(&mut out, bindings.len())?;
        for a in bindings {
            u64le(&mut out, a.lease.id.sequence);
            let binding = a.launch_binding.unwrap();
            binding.validate()?;
            if unassigned_store && binding != LaunchBinding::Unissued {
                return Err("attempt launch binding without assigned store".into());
            }
            match binding {
                LaunchBinding::Direct => byte(&mut out, 1),
                LaunchBinding::Supervised(path) => {
                    byte(&mut out, 2);
                    out.extend(path);
                }
                LaunchBinding::Unissued => byte(&mut out, 3),
                LaunchBinding::Preparing(path) => {
                    byte(&mut out, 4);
                    out.extend(path);
                }
                LaunchBinding::Authorized { path, directory } => {
                    byte(&mut out, 5);
                    out.extend(path);
                    for value in directory {
                        u64le(&mut out, value);
                    }
                }
            }
        }
    }
    let total = used
        .add(dag.workspace_resources()?)
        .ok_or("checkpoint resource overflow")?;
    if total != dag.used
        || !total.fits(dag.limits.workers)
        || reserved != dag.reserved_output_bytes
        || out.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("checkpoint aggregate invariant or size".into());
    }
    Ok(out)
}
