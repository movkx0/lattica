//! Opt-in coordination for Apple workers sharing one physical memory pool.
//! File locks are released by the OS on worker exit, including SIGKILL. Permits
//! cover allocations, not paused processes which already hold large scratch.
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.to_string()),
    }
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err(
            "Apple worker coordination directory must be private and owned by this user".into(),
        );
    }
    Ok(())
}

pub(crate) fn lock_file(path: &Path) -> Result<File, String> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err("invalid Apple worker lock file".into());
    }
    Ok(f)
}

pub(crate) fn lock(f: &File, nonblocking: bool) -> Result<bool, String> {
    loop {
        if unsafe {
            libc::flock(
                f.as_raw_fd(),
                libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 },
            )
        } == 0
        {
            return Ok(true);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if nonblocking && e.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(e.to_string());
    }
}

pub(crate) fn reclaim_enabled() -> bool {
    std::env::var("LATTICA_APPLE_MEMORY_RECLAIM").as_deref() == Ok("1")
}

pub(crate) fn checkpoint(label: &str) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    if unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            usage.as_mut_ptr().cast(),
        )
    } == 0
    {
        let u = unsafe { usage.assume_init() };
        eprintln!(
            "apple_memory_phase pid={} label={label:?} clock_ns={} rss_bytes={} footprint_bytes={}",
            std::process::id(),
            crate::metal_compute::diagnostics::clock_ns(),
            u.ri_resident_size,
            u.ri_phys_footprint
        );
    }
}

pub(crate) struct PhaseGuard {
    _permit: File,
    label: &'static str,
    pool: &'static str,
    slot: usize,
    started: Instant,
}
impl PhaseGuard {
    pub(crate) fn acquire(label: &'static str) -> Result<Option<Self>, String> {
        let Some(dir) = std::env::var_os("LATTICA_APPLE_PHASE_DIR") else {
            return Ok(None);
        };
        let slots: usize = std::env::var("LATTICA_APPLE_PHASE_SLOTS")
            .unwrap_or_else(|_| "2".into())
            .parse()
            .map_err(|_| "invalid Apple memory phase slot count")?;
        Self::acquire_in(&PathBuf::from(dir), slots, label).map(Some)
    }

    pub(crate) fn acquire_late() -> Result<Option<Self>, String> {
        let slots = match std::env::var("LATTICA_APPLE_LATE_PHASE_SLOTS") {
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Ok(value) => value.parse::<usize>().map_err(|_| "invalid Apple late phase slot count")?,
            Err(_) => return Err("invalid Apple late phase environment".into()),
        };
        let dir = std::env::var_os("LATTICA_APPLE_PHASE_DIR")
            .ok_or("Apple late phase coordination requires a phase directory")?;
        let dir = PathBuf::from(dir);
        private_directory(&dir)?;
        Self::acquire_pool(&dir.join("late"), slots, "quotient commitment through queries", "late").map(Some)
    }

    pub(crate) fn acquire_query() -> Result<Option<Self>, String> {
        let slots = match std::env::var("LATTICA_APPLE_QUERY_PHASE_SLOTS") {
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Ok(value) => value.parse::<usize>().map_err(|_| "invalid Apple query phase slot count")?,
            Err(_) => return Err("invalid Apple query phase environment".into()),
        };
        let dir = std::env::var_os("LATTICA_APPLE_PHASE_DIR")
            .ok_or("Apple query phase coordination requires phase directory")?;
        let dir = PathBuf::from(dir);
        private_directory(&dir)?;
        Self::acquire_pool(&dir.join("query"), slots, "query reconstruction", "query").map(Some)
    }

    fn acquire_in(dir: &Path, slots: usize, label: &'static str) -> Result<Self, String> {
        Self::acquire_pool(dir, slots, label, "heavy")
    }

    fn acquire_pool(dir: &Path, slots: usize, label: &'static str, pool: &'static str) -> Result<Self, String> {
        if !(1..=3).contains(&slots) {
            return Err("Apple memory phase slots must be 1..3".into());
        }
        private_directory(dir)?;
        let start = Instant::now();
        // Serialize admission attempts so a hot worker cannot continually take
        // released slots ahead of workers already waiting at this boundary.
        let admission = lock_file(&dir.join("admission.lock"))?;
        lock(&admission, false)?;
        let permits: Vec<_> = (0..slots)
            .map(|i| lock_file(&dir.join(format!("phase-{i}.lock"))))
            .collect::<Result<_, _>>()?;
        loop {
            for (slot, f) in permits.iter().enumerate() {
                if lock(f, true)? {
                    eprintln!("apple_memory_admit pid={} phase={label:?} pool={pool} slot={slot} waited_ms={} clock_ns={}",
                        std::process::id(), start.elapsed().as_millis(), crate::metal_compute::diagnostics::clock_ns());
                    checkpoint(label);
                    let permit = permits.into_iter().nth(slot).unwrap();
                    return Ok(Self {
                        _permit: permit,
                        label,
                        pool,
                        slot,
                        started: Instant::now(),
                    });
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        checkpoint("before phase release");
        eprintln!(
            "apple_memory_release pid={} phase={:?} pool={} slot={} elapsed_ms={} clock_ns={}",
            std::process::id(),
            self.label,
            self.pool,
            self.slot,
            self.started.elapsed().as_millis(),
            crate::metal_compute::diagnostics::clock_ns()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apple_phase_permits_block_until_release_and_recover_after_unwind() {
        let dir = std::env::temp_dir().join(format!("lattica-phase-test-{}", std::process::id()));
        private_directory(&dir).unwrap();
        let first = PhaseGuard::acquire_in(&dir, 1, "test first").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let other = dir.clone();
        let thread = std::thread::spawn(move || {
            let _guard = PhaseGuard::acquire_in(&other, 1, "test second").unwrap();
            tx.send(()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(first);
        rx.recv_timeout(Duration::from_secs(3)).unwrap();
        thread.join().unwrap();
        let _ = std::panic::catch_unwind(|| {
            let _g = PhaseGuard::acquire_in(&dir, 1, "test unwind").unwrap();
            panic!("test unwind");
        });
        drop(PhaseGuard::acquire_in(&dir, 1, "after unwind").unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn apple_phase_permits_handoff_keeps_early_slot_until_late_admission() {
        let dir = std::env::temp_dir().join(format!("lattica-handoff-test-{}", std::process::id()));
        private_directory(&dir).unwrap();
        let late = dir.join("late");
        let first = PhaseGuard::acquire_pool(&late, 1, "existing tail", "late").unwrap();
        let heavy = PhaseGuard::acquire_in(&dir, 1, "waiting early",).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let tail_dir = late.clone();
        let thread = std::thread::spawn(move || {
            let tail = PhaseGuard::acquire_pool(&tail_dir, 1, "handoff tail", "late").unwrap();
            drop(heavy);
            tx.send(()).unwrap();
            drop(tail);
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        let probe = lock_file(&dir.join("phase-0.lock")).unwrap();
        assert!(!lock(&probe, true).unwrap(), "early permit escaped while tail was blocked");
        drop(first);
        rx.recv_timeout(Duration::from_secs(3)).unwrap();
        thread.join().unwrap();
        assert!(lock(&probe, true).unwrap());
        drop(probe);
        let _ = std::panic::catch_unwind(|| {
            let _late = PhaseGuard::acquire_pool(&late, 1, "unwind tail", "late").unwrap();
            panic!("test late unwind");
        });
        drop(PhaseGuard::acquire_pool(&late, 1, "after unwind", "late").unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn apple_phase_permits_subprocess_holder() {
        let Some(dir) = std::env::var_os("LATTICA_TEST_PHASE_DIR") else { return; };
        let dir = PathBuf::from(dir);
        let _early = PhaseGuard::acquire_in(&dir, 1, "subprocess early").unwrap();
        let _late = PhaseGuard::acquire_pool(&dir.join("late"), 1, "subprocess late", "late").unwrap();
        let _query = PhaseGuard::acquire_pool(&dir.join("query"), 1, "subprocess query", "query").unwrap();
        std::fs::write(dir.join("ready"), b"locked").unwrap();
        loop { std::thread::sleep(Duration::from_secs(1)); }
    }

    #[test]
    fn apple_phase_permits_process_death_releases_all_pools() {
        use std::process::{Command, Stdio};
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let dir = std::env::temp_dir().join(format!("lattica-phase-death-{}", std::process::id()));
        private_directory(&dir).unwrap();
        let mut child = Child(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "block_v2::apple_memory::tests::apple_phase_permits_subprocess_holder", "--test-threads=1"])
            .env("LATTICA_TEST_PHASE_DIR", &dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap());
        let start = Instant::now();
        while !dir.join("ready").exists() {
            assert!(child.0.try_wait().unwrap().is_none(), "permit child exited before ready");
            assert!(start.elapsed() < Duration::from_secs(5), "permit child startup timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
        let early = lock_file(&dir.join("phase-0.lock")).unwrap();
        let late = lock_file(&dir.join("late/phase-0.lock")).unwrap();
        let query = lock_file(&dir.join("query/phase-0.lock")).unwrap();
        assert!(!lock(&early, true).unwrap());
        assert!(!lock(&late, true).unwrap());
        assert!(!lock(&query, true).unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(lock(&early, true).unwrap());
        assert!(lock(&late, true).unwrap());
        assert!(lock(&query, true).unwrap());
        drop((early, late, query));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn apple_phase_permits_four_process_pipeline_progress_and_query_unwind() {
        use std::process::{Command, Stdio};
        struct Children(Vec<std::process::Child>);
        impl Drop for Children {
            fn drop(&mut self) { for c in &mut self.0 { let _ = c.kill(); let _ = c.wait(); } }
        }
        let dir = std::env::temp_dir().join(format!("lattica-four-phase-test-{}", std::process::id()));
        private_directory(&dir).unwrap();
        let mut children = Children(Vec::new());
        for i in 0..4 {
            children.0.push(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "block_v2::apple_memory::tests::apple_phase_permits_pipeline_subprocess", "--test-threads=1"])
                .env("LATTICA_TEST_PIPELINE_DIR", &dir).env("LATTICA_TEST_PIPELINE_WORKER", i.to_string())
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        }
        let start = Instant::now();
        loop {
            let mut done = 0;
            for child in &mut children.0 {
                if let Some(status) = child.try_wait().unwrap() { assert!(status.success()); done += 1; }
            }
            if done == 4 { break; }
            assert!(start.elapsed() < Duration::from_secs(10), "phase pipeline deadlocked");
            std::thread::sleep(Duration::from_millis(10));
        }
        for i in 0..4 { assert_eq!(std::fs::read_to_string(dir.join(format!("done-{i}"))).unwrap(), "3"); }
        // Holding a late permit while blocked on query cannot release query early.
        let held = PhaseGuard::acquire_pool(&dir.join("query"), 1, "held", "query").unwrap();
        let (tx, rx) = std::sync::mpsc::channel(); let next = dir.clone();
        let waiter = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| {
                let _late = PhaseGuard::acquire_pool(&next.join("late"), 2, "waiting", "late").unwrap();
                tx.send("waiting").unwrap();
                let _query = PhaseGuard::acquire_pool(&next.join("query"), 1, "waiting", "query").unwrap();
                tx.send("admitted").unwrap(); panic!("query unwind");
            });
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "waiting");
        assert!(rx.recv_timeout(Duration::from_millis(75)).is_err());
        drop(held);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "admitted");
        waiter.join().unwrap();
        drop(PhaseGuard::acquire_pool(&dir.join("query"), 1, "after unwind", "query").unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn apple_phase_permits_pipeline_subprocess() {
        let Some(dir) = std::env::var_os("LATTICA_TEST_PIPELINE_DIR") else { return; };
        let dir = PathBuf::from(dir);
        for _ in 0..3 {
            let early = PhaseGuard::acquire_in(&dir, 2, "pipeline early").unwrap();
            std::thread::sleep(Duration::from_millis(5));
            let late = PhaseGuard::acquire_pool(&dir.join("late"), 2, "pipeline late", "late").unwrap();
            drop(early);
            let query = PhaseGuard::acquire_pool(&dir.join("query"), 1, "pipeline query", "query").unwrap();
            // Independent lock detects overlapping holders, even across processes.
            let sentinel = lock_file(&dir.join("query-exclusive.lock")).unwrap();
            assert!(lock(&sentinel, true).unwrap());
            std::thread::sleep(Duration::from_millis(10));
            drop(sentinel); drop(query); drop(late);
        }
        std::fs::write(dir.join(format!("done-{}", std::env::var("LATTICA_TEST_PIPELINE_WORKER").unwrap())), "3").unwrap();
    }

}
