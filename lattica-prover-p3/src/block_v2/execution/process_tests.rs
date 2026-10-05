//! Explicit experiment-controller integration, not a durable service supervisor.
//! Runs the preserved CPU executable in the exact token-named systemd unit.
use super::*;
use crate::block_v2::execution::{dag::Completion, job::VerifiedNode};
use std::{
    collections::BTreeMap,
    os::fd::{AsRawFd, FromRawFd},
    process::Child,
    time::{Duration, Instant},
};

fn status_fields(status: &str) -> BTreeMap<&str, &str> {
    status
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}
fn service_status(name: &str) -> Result<String, Error> {
    let output = Command::new("/usr/bin/systemctl").args(["--user", "show",
        "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ControlGroup,InvocationID"])
        .arg(name).output()?;
    if output.stdout.len() > 16384 {
        return Err("worker status byte bound".into());
    }
    let text = String::from_utf8(output.stdout)?;
    if !output.status.success()
        && status_fields(&text).get("LoadState").copied() != Some("not-found")
    {
        return Err("worker status observation failed".into());
    }
    Ok(text)
}
fn observe_running(child: &mut Child, name: &str) -> Result<(File, File, String), Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = service_status(name)?;
        let values = status_fields(&status);
        if values.get("LoadState").copied() == Some("loaded")
            && values.get("ActiveState").copied() == Some("active")
            && values.get("SubState").copied() == Some("running")
        {
            let id = values
                .get("InvocationID")
                .ok_or("worker invocation missing")?;
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("worker invocation identity malformed".into());
            }
            let pid: libc::pid_t = values.get("MainPID").ok_or("worker PID missing")?.parse()?;
            if pid <= 1 {
                return Err("worker PID invalid".into());
            }
            let group = values.get("ControlGroup").ok_or("worker cgroup missing")?;
            absolute_path(Path::new(group))?;
            if Path::new(group).file_name().and_then(|s| s.to_str()) != Some(name) {
                return Err("worker cgroup identity mismatch".into());
            }
            let cgroup =
                open_directory(&Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))?;
            // SAFETY: pidfd_open takes a positive PID and flags=0, no memory arguments.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: successful pidfd_open returns a new descriptor owned here.
            let pidfd = unsafe { File::from_raw_fd(fd as i32) };
            let check = service_status(name)?;
            let again = status_fields(&check);
            if again.get("InvocationID") != values.get("InvocationID")
                || again.get("MainPID") != values.get("MainPID")
                || again.get("ControlGroup") != values.get("ControlGroup")
            {
                return Err("worker changed during OS identity capture".into());
            }
            let processes = fs::read_to_string(fd_path(&cgroup).join("cgroup.procs"))?;
            if !processes.lines().any(|line| line == pid.to_string()) {
                return Err("captured worker PID is not in captured cgroup".into());
            }
            return Ok((pidfd, cgroup, status));
        }
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("worker terminated or was not observed before identity deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_real_process(mode: Mode) -> Result<(), Error> {
    if std::env::var("LATTICA_V2_RUN_CPU_PROCESS_TEST").as_deref() != Ok("1") {
        return Err("explicit bounded process-test opt-in required".into());
    }
    let controller = std::env::var("LATTICA_V2_ACCOUNTING_UNIT")?;
    if !controller.starts_with("lattica-v2-")
        || !controller.ends_with(".service")
        || !controller
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err("bounded controller identity".into());
    }
    let image = PathBuf::from(std::env::var("LATTICA_V2_CPU_WORKER_IMAGE")?);
    let root = PathBuf::from(std::env::var("LATTICA_V2_PROCESS_TEST_DIR")?);
    absolute_path(&root)?;
    DirBuilder::new().mode(0o700).create(&root)?;
    // Preserve task, journal, launch and result evidence even after a failed run.
    let temp = std::mem::ManuallyDrop::new(Temp(root));
    let f = test_fixture::load()?;
    let r = Resources {
        ram_bytes: if mode == Mode::Prove {
            44 << 30
        } else {
            3 << 30
        },
        vram_bytes: 0,
        scratch_bytes: if mode == Mode::Prove {
            120 << 30
        } else {
            32 << 20
        },
        threads: 8,
    };
    let (mut owner, assignment) = real_pair(&temp, &f, r)?;
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 16 })?;
    let mut task = TaskOwner::create(&temp.path())?;
    let config = WorkerConfig {
        registry: f.registry.clone(),
        pin: f.pin,
        chain: [0x5a; 32],
        executable: image_fingerprint(&image)?,
        timeout_seconds: 1800,
        mode,
    };
    let token = task.issue(
        &mut owner,
        &mut launches,
        &launch_path,
        assignment.lease(),
        config,
    )?;
    let name = token.service_name();
    println!(
        "cpu_process_unit={name} task={} mode={mode:?}",
        temp.path().display()
    );
    let started = Instant::now();
    let mut child = Command::new("/usr/bin/systemd-run")
        .args(["--user", "--wait", "--pipe", "--expand-environment=no"])
        .arg(format!("--unit={name}"))
        .args([
            "--slice=lattica-v2-grouped.slice",
            "--property=MemoryAccounting=yes",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=800%",
            "--property=CPUQuotaPeriodSec=100ms",
            "--property=TasksMax=16",
            "--property=RuntimeMaxSec=1830",
            "--property=TimeoutStopSec=15",
            "--property=KillMode=control-group",
            "--property=Restart=no",
            "--property=LimitCORE=0",
            "--property=UMask=0077",
        ])
        .arg(format!("--property=MemoryMax={}", r.ram_bytes))
        .arg(format!("--property=BindsTo={controller}"))
        .arg(format!("--property=After={controller}"))
        .arg("--property=ExecStopPost=/usr/bin/python3 -B /home/access/code/lattica/lattica-prover-p3/scripts/block-v2-accounting.py")
        .arg(format!("--setenv=LATTICA_V2_ACCOUNTING_UNIT={name}"))
        .args([
            "--setenv=LATTICA_V2_GPU_HASH=0",
            "--setenv=LATTICA_V2_GPU_PIPELINE=0",
            "--setenv=LATTICA_V2_GPU_RETAIN_TREES=0",
            "--setenv=LATTICA_V2_GPU_RESIDENT_LDE=0",
            "--setenv=LATTICA_V2_GPU_OPENINGS=0",
            "--setenv=LATTICA_V2_QUOTIENT_FUSION=0",
        ])
        .arg("--")
        .arg(&image)
        .arg("--task")
        .arg(temp.path())
        .stdin(Stdio::null())
        .spawn()?;
    let (pidfd, cgroup, identity) = observe_running(&mut child, &name)?;
    private_file(
        &temp.0.join("worker-started.txt"),
        identity.as_bytes(),
        0o600,
    );
    let status = child.wait()?;
    // systemd-run's handle is terminal before the OS-state query. On any error
    // the preserved journal still owns the resource reservation; no retry here.
    if !status.success() {
        return Err(format!("worker unit failed: {status}").into());
    }
    let revoked = launches.revoke(assignment.lease())?;
    let _idle = launches
        .try_idle(&revoked)?
        .ok_or("worker still holds its guard")?;
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd and zero timeout; pidfd identifies the exact process.
    if unsafe { libc::poll(&mut poll, 1, 0) } != 1 || poll.revents & libc::POLLIN == 0 {
        return Err("exact worker process has not exited".into());
    }
    if cgroup.metadata()?.nlink() != 0 {
        let events = fs::read_to_string(fd_path(&cgroup).join("cgroup.events"))?;
        if !events.lines().any(|line| line == "populated 0") {
            return Err("exact worker cgroup is still populated".into());
        }
    }
    let status = service_status(&name)?;
    let values = status_fields(&status);
    match values.get("LoadState").copied() {
        Some("not-found") => (), // GC is allowed only after the pinned kernel checks above.
        Some("loaded") => {
            for (key, expected) in [
                ("ActiveState", "inactive"),
                ("MainPID", "0"),
                ("ControlPID", "0"),
                ("Result", "success"),
            ] {
                if values.get(key).copied() != Some(expected) {
                    return Err(format!("worker service is not stopped: {key}").into());
                }
            }
        }
        _ => return Err("worker service state is uncertain".into()),
    }
    let receipt = format!("PIDFDExited=true\nCgroupQuiescent=true\n{status}");
    private_file(&temp.0.join("worker-status.txt"), receipt.as_bytes(), 0o600);
    let now = u64::try_from(started.elapsed().as_millis())?;
    owner.worker_stopped(assignment.lease(), now)?;
    match mode {
        Mode::Check => {
            assert!(!temp.path().join("result").exists());
            owner.begin_verification(assignment.lease(), now)?;
            assert_eq!(
                owner.finish_verification(assignment.lease(), None, now)?,
                Completion::Rejected
            );
            println!("cpu_process_check=PASS no_proof=true elapsed_ms={now}");
        }
        Mode::Prove => {
            drop(task);
            let task = TaskOwner::open(&temp.path())?;
            let result = task.result(&assignment)?;
            let expected = owner.begin_verification(assignment.lease(), now)?;
            let ticket = VerifiedNode::verify(&expected, &f.registry, result.bytes())?;
            assert_eq!(
                owner.finish_verification(
                    assignment.lease(),
                    Some((ticket, result.bytes().to_vec())),
                    u64::try_from(started.elapsed().as_millis())?
                )?,
                Completion::Accepted
            );
            private_file(&temp.0.join("pair.1.0"), result.bytes(), 0o600);
            println!("cpu_process_proof=PASS transactions=2 proof_bytes={} elapsed_ms={} input_verification_ms={} proving_ms={}",
                result.bytes().len(), started.elapsed().as_millis(), result.timings().input_verification_ms, result.timings().proving_ms);
        }
    }
    assert_eq!(owner.resource_use()?, Resources::default());
    Ok(())
}

#[test]
#[ignore = "actual CPU worker service, explicit bounded controller and pinned image required"]
fn cpu_process_checks_real_task_under_exact_cgroup() -> Result<(), Error> {
    run_real_process(Mode::Check)
}

#[test]
#[ignore = "actual 44 GiB worker process and new paired-wrapper proof, explicit bounded controller required"]
fn cpu_process_proves_real_task_and_owner_reopens_result() -> Result<(), Error> {
    run_real_process(Mode::Prove)
}
