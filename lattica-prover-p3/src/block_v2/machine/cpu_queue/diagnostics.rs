//! Optional CPU-only measurement. The guard enables this only for exact tests.
//! Fixed thread/helper reservations cover the bounded /proc reads and reports.
#[cfg(target_os = "linux")]
mod platform {
    use std::io::Read;

    #[derive(Clone, Copy)]
    struct Usage {
        user_ns: u64,
        system_ns: u64,
        voluntary: u64,
        involuntary: u64,
    }
    fn usage() -> Option<Usage> {
        let mut value = std::mem::MaybeUninit::<libc::rusage>::uninit();
        if unsafe { libc::getrusage(libc::RUSAGE_THREAD, value.as_mut_ptr()) } != 0 {
            return None;
        }
        let r = unsafe { value.assume_init() };
        let ns = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1_000;
        Some(Usage {
            user_ns: ns(r.ru_utime),
            system_ns: ns(r.ru_stime),
            voluntary: r.ru_nvcsw as u64,
            involuntary: r.ru_nivcsw as u64,
        })
    }
    fn migrations() -> Option<u64> {
        let mut text = String::new();
        std::fs::File::open("/proc/thread-self/sched")
            .ok()?
            .take(16 << 10)
            .read_to_string(&mut text)
            .ok()?;
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "se.nr_migrations")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
    }
    pub struct Thread {
        before: Usage,
        migrations: Option<u64>,
        tid: i64,
        cpu: i32,
    }
    impl Thread {
        pub fn begin() -> Option<Self> {
            if std::env::var("LATTICA_CPU_SCALING_PROFILE").as_deref() != Ok("1") {
                return None;
            }
            Some(Self {
                before: usage()?,
                migrations: migrations(),
                tid: unsafe { libc::syscall(libc::SYS_gettid) } as i64,
                cpu: unsafe { libc::sched_getcpu() },
            })
        }
        pub fn job(&self) -> Option<Job> {
            Some(Job {
                before: usage()?,
                tid: self.tid,
            })
        }
    }
    impl Drop for Thread {
        fn drop(&mut self) {
            if let Some(after) = usage() {
                eprintln!(
                    "CPU_SCALING_THREAD {}",
                    serde_json::json!({
                        "tid":self.tid, "start_cpu":self.cpu, "end_cpu":unsafe { libc::sched_getcpu() },
                        "user_ns":after.user_ns-self.before.user_ns,
                        "system_ns":after.system_ns-self.before.system_ns,
                        "voluntary_switches":after.voluntary-self.before.voluntary,
                        "involuntary_switches":after.involuntary-self.before.involuntary,
                        "migrations":self.migrations.zip(migrations()).and_then(|(a,b)| b.checked_sub(a)),
                    })
                );
            }
        }
    }
    pub struct Job {
        before: Usage,
        tid: i64,
    }
    impl Job {
        pub fn finish(self, slot: usize, elapsed_ns: u128) {
            if let Some(after) = usage() {
                eprintln!(
                    "CPU_SCALING_JOB {}",
                    serde_json::json!({
                        "tid":self.tid, "slot":slot, "elapsed_ns":elapsed_ns,
                        "user_ns":after.user_ns-self.before.user_ns,
                        "system_ns":after.system_ns-self.before.system_ns,
                    })
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    pub struct Thread;
    pub struct Job;
    impl Thread {
        pub fn begin() -> Option<Self> {
            None
        }
        pub fn job(&self) -> Option<Job> {
            None
        }
    }
    impl Job {
        pub fn finish(self, _: usize, _: u128) {}
    }
}
pub(super) use platform::Thread;
