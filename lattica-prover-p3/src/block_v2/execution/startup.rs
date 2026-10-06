//! Durable admission fence for a single-use persistent worker service.
//!
//! The GPU worker must enter before initializing any device state and retain
//! its lock until process exit. Recovery fences future entry before releasing
//! an interrupted startup's workspace. This grants no proof-validity authority.

use super::{os_worker, transport};
use crate::block_v2::recursive::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const MAX_RECORD: u64 = 65536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub schema_version: u32,
    pub unit: String,
    pub executable: [u8; 32],
    pub arguments: Vec<String>,
    pub assignment: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub identity: os_worker::Identity,
    pub execution_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciled {
    pub intent: Intent,
    pub started: Option<Started>,
    pub observed_before_entry: Option<os_worker::Identity>,
    pub future_start_fenced: bool,
    pub process_and_service_quiescent: bool,
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_RECORD {
        return Err("invalid startup record size or file type".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err("startup record grew beyond its bound".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write(path: &Path, name: &str, value: &impl Serialize) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err("startup record exceeds bound".into());
    }
    let temporary = path.join(format!(".{name}.{}.partial", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path.join(name))?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn lock(path: &Path) -> Result<Option<File>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join("lock"))?;
    if !file.metadata()?.is_file() {
        return Err("startup lock is not a regular file".into());
    }
    // SAFETY: flock only inspects the live file descriptor and constant flags.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error.into())
}

fn check(path: &Path, expected: &Intent) -> Result<(), Error> {
    if !path.is_absolute() || expected.schema_version != 1 || expected.arguments.is_empty() {
        return Err("invalid persistent worker startup intent".into());
    }
    os_worker::persistent_unit_name(&expected.unit)?;
    let actual: Intent = read(&path.join("intent.json"))?;
    if actual != *expected {
        return Err("persistent worker startup intent changed".into());
    }
    Ok(())
}

pub fn create(path: &Path, intent: &Intent) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.is_absolute() || intent.schema_version != 1 || intent.arguments.is_empty() {
        return Err("invalid persistent worker startup intent".into());
    }
    os_worker::persistent_unit_name(&intent.unit)?;
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("lock"))?
        .sync_all()?;
    write(path, "intent.json", intent)?;
    File::open(path.parent().ok_or("startup directory has no parent")?)?.sync_all()?;
    Ok(())
}

pub fn authorize(path: &Path, intent: &Intent, execution_digest: [u8; 32]) -> Result<(), Error> {
    check(path, intent)?;
    let _lock = lock(path)?.ok_or("startup authorization is locked")?;
    if path.join("revoked.json").exists() || path.join("authorization.json").exists() {
        return Err("startup was already authorized or fenced".into());
    }
    write(path, "authorization.json", &execution_digest)
}

/// Must be called before device discovery, backend initialization or GPU work.
/// The descriptor intentionally remains open until OS process teardown.
pub fn enter_until_process_exit(
    path: &Path,
    arguments: &[String],
    assignment: &serde_json::Value,
) -> Result<(), Error> {
    let intent: Intent = read(&path.join("intent.json"))?;
    check(path, &intent)?;
    let guard = lock(path)?.ok_or("persistent startup gate is locked")?;
    if path.join("revoked.json").exists() || path.join("started.json").exists() {
        return Err("persistent startup was revoked or already consumed".into());
    }
    let execution_digest = read(&path.join("authorization.json"))?;
    if arguments != intent.arguments.as_slice()
        || *assignment != intent.assignment
        || transport::image_fingerprint(&std::env::current_exe()?)? != intent.executable
    {
        return Err("persistent startup executable or arguments differ".into());
    }
    let args: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    let live = os_worker::observe_persistent(&intent.unit, intent.executable, &args)?
        .ok_or("persistent startup cannot observe its service")?;
    if live.identity().pid() != std::process::id() {
        return Err("persistent startup identity is not the current process".into());
    }
    write(
        path,
        "started.json",
        &Started {
            identity: live.identity().clone(),
            execution_digest,
        },
    )?;
    // Global GPU state can outlive a function's local destructors. Keeping this
    // descriptor open prevents recovery from interpreting that gap as teardown.
    std::mem::forget(guard);
    Ok(())
}

pub fn inspect_started(path: &Path, intent: &Intent) -> Result<Option<Started>, Error> {
    check(path, intent)?;
    if !path.join("started.json").exists() {
        return Ok(None);
    }
    let started: Started = read(&path.join("started.json"))?;
    if started.execution_digest != read::<[u8; 32]>(&path.join("authorization.json"))? {
        return Err("persistent startup authorization changed".into());
    }
    Ok(Some(started))
}

/// The original coordinator must already be quiescent and job launches revoked.
pub fn reconcile(path: &Path, intent: &Intent) -> Result<Reconciled, Error> {
    check(path, intent)?;
    // Fence first, including while an admitted worker owns the lifetime lock.
    // Existing holders stay charged until exact OS exit and lock acquisition.
    if !path.join("revoked.json").exists() {
        write(path, "revoked.json", &true)?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let arguments: Vec<OsString> = intent.arguments.iter().map(OsString::from).collect();
    let mut observed_before_entry: Option<os_worker::Identity> = None;
    loop {
        let started = inspect_started(path, intent)?;
        if let Some(started) = &started {
            if !os_worker::exited(&started.identity, &intent.unit)? {
                os_worker::request_stop(&started.identity, &intent.unit)?;
            }
        }
        if let Some(live) =
            os_worker::observe_persistent(&intent.unit, intent.executable, &arguments)?
        {
            if started
                .as_ref()
                .is_some_and(|old| old.identity != *live.identity())
            {
                return Err("persistent startup service invocation was substituted".into());
            }
            if observed_before_entry
                .as_ref()
                .is_some_and(|old| old != live.identity())
            {
                return Err("persistent service invocation changed before startup entry".into());
            }
            observed_before_entry = Some(live.identity().clone());
            os_worker::request_stop(live.identity(), &intent.unit)?;
        }
        if let Some(_guard) = lock(path)? {
            // A worker may publish its identity and exit between inspection and
            // lock acquisition. Preserve that identity in the final receipt.
            let started = inspect_started(path, intent)?;
            if let (Some(started), Some(observed)) = (&started, &observed_before_entry) {
                if started.identity != *observed {
                    return Err(
                        "startup identity differs from the observed service invocation".into(),
                    );
                }
            }
            let exited = match &started {
                Some(old) => os_worker::exited(&old.identity, &intent.unit)?,
                None => true,
            };
            let observed_exited = match &observed_before_entry {
                Some(identity) => os_worker::exited(identity, &intent.unit)?,
                None => true,
            };
            if exited && observed_exited && os_worker::persistent_service_quiescent(&intent.unit)? {
                return Ok(Reconciled {
                    intent: intent.clone(),
                    started,
                    observed_before_entry,
                    future_start_fenced: true,
                    process_and_service_quiescent: true,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err("persistent startup remains active after its durable fence".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            use std::{
                os::unix::fs::DirBuilderExt,
                sync::atomic::{AtomicU64, Ordering},
            };
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "lattica-startup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn intent() -> Intent {
        Intent {
            schema_version: 1,
            unit: format!("lattica-v2-multi-persistent-{}.service", "a".repeat(64)),
            executable: [1; 32],
            arguments: vec!["serve-shared-process-gpu".into()],
            assignment: serde_json::json!({}),
        }
    }

    #[test]
    fn startup_is_once_authorized_and_cannot_enter_without_authorization() {
        let temporary = Temp::new();
        let path = temporary.path().join("startup");
        let intent = intent();
        create(&path, &intent).unwrap();
        assert!(enter_until_process_exit(&path, &intent.arguments, &intent.assignment).is_err());
        authorize(&path, &intent, [2; 32]).unwrap();
        assert!(authorize(&path, &intent, [2; 32]).is_err());
        assert!(enter_until_process_exit(&path, &intent.arguments, &intent.assignment).is_err());
        assert!(!path.join("started.json").exists());
    }

    #[test]
    fn held_startup_lock_excludes_quiescence_and_delayed_entry_is_denied() {
        let temporary = Temp::new();
        let path = temporary.path().join("startup");
        let intent = intent();
        create(&path, &intent).unwrap();
        authorize(&path, &intent, [2; 32]).unwrap();
        let guard = lock(&path).unwrap().unwrap();
        assert!(lock(&path).unwrap().is_none());
        assert!(
            enter_until_process_exit(&path, &intent.arguments, &intent.assignment)
                .unwrap_err()
                .to_string()
                .contains("gate is locked")
        );
        write(&path, "revoked.json", &true).unwrap();
        drop(guard);
        assert!(lock(&path).unwrap().is_some());
        assert!(
            enter_until_process_exit(&path, &intent.arguments, &intent.assignment)
                .unwrap_err()
                .to_string()
                .contains("revoked or already consumed")
        );
    }

    #[test]
    fn changed_intent_and_symlinked_lock_are_rejected() {
        let temporary = Temp::new();
        let path = temporary.path().join("startup");
        let original = intent();
        create(&path, &original).unwrap();
        let mut changed = original.clone();
        changed.executable = [3; 32];
        assert!(authorize(&path, &changed, [2; 32]).is_err());
        std::fs::remove_file(path.join("lock")).unwrap();
        std::os::unix::fs::symlink(path.join("intent.json"), path.join("lock")).unwrap();
        assert!(lock(&path).is_err());
    }
}
