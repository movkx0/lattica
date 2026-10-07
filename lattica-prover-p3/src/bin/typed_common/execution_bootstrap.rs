//! Publish initialization before any GPU workspace can be reserved.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

pub(super) struct Entry {
    gate: PathBuf,
    intent: serde_json::Value,
    started: serde_json::Value,
}

fn require_held_lock(gate: &Path) -> Result<(), Error> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(gate.join("lock"))?;
    if !lock.metadata()?.is_file() || lock.metadata()?.len() != 0 {
        return Err("invalid coordinator bootstrap lock".into());
    }
    // SAFETY: a live descriptor and constant flock flags are passed to libc.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Err("coordinator bootstrap lifetime lock is not held".into());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() != std::io::ErrorKind::WouldBlock {
        return Err(error.into());
    }
    Ok(())
}

pub(super) fn enter(plan: &Plan, plan_path: &Path, out: &Path) -> Result<Option<Entry>, Error> {
    let Some(gate) = &plan.coordinator_bootstrap_guard else {
        return Ok(None);
    };
    if !plan.startup_fenced
        || !gate.is_absolute()
        || *gate
            != out
                .parent()
                .ok_or("missing owner directory")?
                .join("coordinator-startup")
        || std::fs::symlink_metadata(gate)?.file_type().is_symlink()
    {
        return Err("coordinator bootstrap guard differs from owner admission".into());
    }
    require_held_lock(gate)?;
    if gate.join("revoked.json").exists() || gate.join("initialized.json").exists() {
        return Err("coordinator bootstrap was revoked or already initialized".into());
    }
    let intent: serde_json::Value = read_json(&gate.join("intent.json"))?;
    let started: serde_json::Value = read_json(&gate.join("started.json"))?;
    if intent["schema_version"].as_u64() != Some(1)
        || intent["unit"].as_str() != Some(plan.coordinator_unit.as_str())
        || intent["proofs"].as_str() != out.to_str()
        || intent["plan_path"].as_str() != plan_path.to_str()
        || intent["plan_text"].as_str() != Some(std::fs::read_to_string(plan_path)?.as_str())
    {
        return Err("coordinator bootstrap intent differs from actual plan".into());
    }
    // SAFETY: getppid has no arguments and only reads the current parent PID.
    let parent = unsafe { libc::getppid() };
    let invocation = std::env::var("INVOCATION_ID")?;
    let stat = std::fs::read_to_string(format!("/proc/{parent}/stat"))?;
    let start_ticks = stat
        .rsplit_once(')')
        .ok_or("invalid coordinator parent stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("missing coordinator parent birth")?
        .parse::<u64>()?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let group = std::fs::read_to_string("/proc/self/cgroup")?;
    if parent <= 0
        || started["pid"].as_u64() != Some(parent as u64)
        || started["start_ticks"].as_u64() != Some(start_ticks)
        || started["boot"].as_str() != Some(boot.trim())
        || started["unit"].as_str() != Some(plan.coordinator_unit.as_str())
        || started["invocation"].as_str() != Some(invocation.as_str())
        || started["group"].as_str() != group.trim().strip_prefix("0::")
        || std::fs::read_to_string(format!("/proc/{parent}/cgroup"))? != group
    {
        return Err("coordinator bootstrap parent or service identity differs".into());
    }
    Ok(Some(Entry {
        gate: gate.clone(),
        intent,
        started,
    }))
}

impl Entry {
    pub(super) fn complete(&self, out: &Path) -> Result<(), Error> {
        require_held_lock(&self.gate)?;
        if self.gate.join("revoked.json").exists()
            || read_json::<serde_json::Value>(&self.gate.join("intent.json"))? != self.intent
            || read_json::<serde_json::Value>(&self.gate.join("started.json"))? != self.started
            || self.intent["proofs"].as_str() != out.to_str()
        {
            return Err("coordinator bootstrap admission changed before initialization".into());
        }
        let value = json!({"schema_version":1,"proofs":out,
            "plan_sha256":self.intent["plan_sha256"],"owner_pid":self.started["pid"],
            "coordinator_pid":std::process::id()});
        File::open(out)?.sync_all()?;
        File::open(out.join("execution"))?.sync_all()?;
        let temporary = self
            .gate
            .join(format!(".initialized-{}.partial", std::process::id()));
        write_json(&temporary, &value)?;
        // The canonical marker is either absent or complete, including after SIGKILL.
        std::fs::hard_link(&temporary, self.gate.join("initialized.json"))?;
        File::open(&self.gate)?.sync_all()?;
        std::fs::remove_file(temporary)?;
        File::open(&self.gate)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        directory: PathBuf,
        entry: Entry,
        lock: File,
        out: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "lattica-coordinator-bootstrap-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            let gate = directory.join("coordinator-startup");
            std::fs::create_dir(&gate).unwrap();
            let out = directory.join("proofs");
            std::fs::create_dir_all(out.join("execution")).unwrap();
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(gate.join("lock"))
                .unwrap();
            // SAFETY: the test owns the live descriptor.
            assert_eq!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            let intent = json!({"proofs":out,"plan_sha256":"frozen-plan"});
            let started = json!({"pid":123});
            write_json(&gate.join("intent.json"), &intent).unwrap();
            write_json(&gate.join("started.json"), &started).unwrap();
            Self {
                directory,
                entry: Entry {
                    gate,
                    intent,
                    started,
                },
                lock,
                out,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn initialization_marker_is_bound_and_published_once() {
        let fixture = Fixture::new();
        fixture.entry.complete(&fixture.out).unwrap();
        let marker: serde_json::Value =
            read_json(&fixture.entry.gate.join("initialized.json")).unwrap();
        assert_eq!(marker["plan_sha256"], "frozen-plan");
        assert_eq!(marker["owner_pid"], 123);
        assert!(fixture.entry.complete(&fixture.out).is_err());
    }

    #[test]
    fn revoked_or_changed_admission_cannot_publish_initialization() {
        for changed in [false, true] {
            let fixture = Fixture::new();
            if changed {
                std::fs::remove_file(fixture.entry.gate.join("intent.json")).unwrap();
                write_json(&fixture.entry.gate.join("intent.json"), &json!({})).unwrap();
            } else {
                write_json(&fixture.entry.gate.join("revoked.json"), &true).unwrap();
            }
            assert!(fixture.entry.complete(&fixture.out).is_err());
            assert!(!fixture.entry.gate.join("initialized.json").exists());
        }
    }

    #[test]
    fn owner_lifetime_lock_must_still_be_held_at_initialization() {
        let fixture = Fixture::new();
        // SAFETY: the test owns the live descriptor.
        assert_eq!(
            unsafe { libc::flock(fixture.lock.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        assert!(fixture.entry.complete(&fixture.out).is_err());
        assert!(!fixture.entry.gate.join("initialized.json").exists());
    }
}
