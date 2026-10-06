//! Pin recovery generations before mutation and trace interrupted admissions.
use super::*;
use lattica_prover_p3::block_v2::execution::journal::Recovery;
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

const NAME: &str = "recovery-admission.json";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema_version: u32,
    source: PathBuf,
    state: State,
}

pub(super) struct Origin {
    pub state: State,
    pub previous_coordinator_pid: u32,
    pub worker_source: PathBuf,
    pub plan: Plan,
    pub coordinator: Coordinator,
    pub interrupted_epochs: Vec<u64>,
    worker_epoch: u64,
}

impl Origin {
    pub fn check_checkpoint(&self, recovery: &Recovery) -> Result<(), Error> {
        check_epoch(
            recovery.previous_epoch(),
            self.worker_epoch,
            &self.interrupted_epochs,
            !recovery.unresolved_attempts().is_empty()
                || !recovery.unresolved_workspaces().is_empty(),
        )
    }
}

fn check_epoch(
    actual: u64,
    worker_epoch: u64,
    interrupted: &[u64],
    has_work: bool,
) -> Result<(), Error> {
    if actual == worker_epoch {
        return Ok(());
    }
    if !interrupted.contains(&actual) || has_work {
        return Err("checkpoint generation or reservations differ from recovery admission".into());
    }
    Ok(())
}

fn validate_state(source: &Path, plan: &Plan, state: &State) -> Result<(), Error> {
    if state.schema_version != 1 || state.epoch == 0 || !state.durable_runtime.is_absolute() {
        return Err("invalid retained recovery state".into());
    }
    let expected = if let Some(prior) = &plan.recover_from {
        let prior: State = read_json(&prior.join("recovery-state.json"))?;
        (
            prior
                .epoch
                .checked_add(1)
                .ok_or("recovery epoch exhausted")?,
            prior.durable_runtime,
        )
    } else {
        (1, source.join("execution"))
    };
    if (state.epoch, &state.durable_runtime) != (expected.0, &expected.1) {
        return Err("recovery journal origin differs from its prior owner".into());
    }
    Ok(())
}

fn interrupted(source: &Path, plan: &Plan, state: &State) -> Result<bool, Error> {
    let Some(gate) = &plan.coordinator_bootstrap_guard else {
        return Ok(false);
    };
    if gate.join("initialized.json").exists() {
        return Ok(false);
    }
    if !plan.startup_fenced
        || *gate
            != source
                .parent()
                .ok_or("missing owner directory")?
                .join("coordinator-startup")
        || std::fs::symlink_metadata(gate)?.file_type().is_symlink()
    {
        return Err("interrupted recovery lacks its coordinator admission fence".into());
    }
    let intent: serde_json::Value = read_json(&gate.join("intent.json"))?;
    let revoked: serde_json::Value = read_json(&gate.join("revoked.json"))?;
    let bound_plan: Plan = serde_json::from_str(
        intent["plan_text"]
            .as_str()
            .ok_or("missing admitted plan")?,
    )?;
    if intent["schema_version"] != 1
        || revoked["schema_version"] != 1
        || intent["unit"].as_str() != Some(plan.coordinator_unit.as_str())
        || intent["proofs"].as_str() != source.to_str()
        || serde_json::to_value(bound_plan)? != serde_json::to_value(plan)?
    {
        return Err("interrupted recovery admission differs from its retained plan".into());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(gate.join("lock"))?;
    // SAFETY: the descriptor is live. Revocation prevents future owner entry.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("interrupted recovery owner lifetime has not ended".into());
    }
    let admission: Admission = read_json(&source.join(NAME))?;
    if admission.schema_version != 1
        || admission.state != *state
        || plan.recover_from.as_ref() != Some(&admission.source)
    {
        return Err("interrupted recovery metadata differs from durable admission".into());
    }
    for index in 0..plan.workers.len() {
        for name in [
            format!("worker-{index}.session"),
            format!("worker-{index}-start.json"),
            format!("worker-{index}-startup/authorization.json"),
            format!("worker-{index}-startup/started.json"),
        ] {
            if source.join("execution").join(name).exists() {
                return Err("interrupted recovery initialized a worker before its marker".into());
            }
        }
    }
    Ok(true)
}

pub(super) fn trace(source: &Path, current: &Plan, expected: &Expected) -> Result<Origin, Error> {
    let mut cursor = source.to_owned();
    let mut seen = BTreeSet::new();
    let mut interrupted_epochs = Vec::new();
    let mut newest = None;
    let executable = image_fingerprint(&std::env::current_exe()?)?;
    loop {
        if !cursor.is_absolute()
            || cursor.canonicalize()? != cursor
            || !seen.insert(cursor.clone())
            || seen.len() > 64
        {
            return Err("recovery lineage must be bounded, distinct canonical directories".into());
        }
        let previous: Plan = read_json(&cursor.join("fleet-plan.json"))?;
        compatible(&previous, current)?;
        let state: State = read_json(&cursor.join("recovery-state.json"))?;
        validate_state(&cursor, &previous, &state)?;
        let old: Coordinator = read_json(&cursor.join("coordinator.json"))?;
        if old.schema_version != 1
            || old.unit != previous.coordinator_unit
            || old.executable != executable
            || !os_worker::exited(&old.identity, &old.unit)?
        {
            return Err("old coordinator is not quiescent or its binary identity differs".into());
        }
        if read_json::<serde_json::Value>(&cursor.join("expected.json"))?
            != serde_json::to_value(expected)?
        {
            return Err("recovery expected statement differs".into());
        }
        newest.get_or_insert((state.clone(), old.identity.pid()));
        if interrupted(&cursor, &previous, &state)? {
            interrupted_epochs.push(state.epoch);
            cursor = previous
                .recover_from
                .ok_or("interrupted admission lacks recovery source")?;
        } else {
            let (latest, previous_coordinator_pid) = newest.unwrap();
            return Ok(Origin {
                state: latest,
                previous_coordinator_pid,
                worker_source: cursor,
                plan: previous,
                coordinator: old,
                interrupted_epochs,
                worker_epoch: state.epoch,
            });
        }
    }
}

pub(super) fn publish(source: &Path, state: &State, out: &Path) -> Result<(), Error> {
    let temporary = out.join(format!(
        ".recovery-admission-{}.partial",
        std::process::id()
    ));
    write_json(
        &temporary,
        &Admission {
            schema_version: 1,
            source: source.to_owned(),
            state: state.clone(),
        },
    )?;
    std::fs::hard_link(&temporary, out.join(NAME))?;
    File::open(out)?.sync_all()?;
    std::fs::remove_file(temporary)?;
    File::open(out)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admitted_epochs_can_be_resumed_and_only_original_epoch_can_have_workers() {
        for epoch in [1, 2, 4] {
            assert!(check_epoch(epoch, 1, &[4, 2], false).is_ok());
        }
        assert!(check_epoch(1, 1, &[4, 2], true).is_ok());
        for epoch in [0, 3, 5] {
            assert!(check_epoch(epoch, 1, &[4, 2], false).is_err());
        }
        for epoch in [2, 4] {
            assert!(check_epoch(epoch, 1, &[4, 2], true).is_err());
        }
    }
}
