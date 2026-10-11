//! Real child/socket lifecycle checks with synthetic registry data; no proofs.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::Limits,
    journal::JournalLimits,
};
use p3_field::PrimeCharacteristicRing;
use std::{
    fs,
    os::{fd::AsFd, unix::fs::DirBuilderExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lattica-typed-process-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config() -> Config {
    let registry = TypedRegistry {
        height: 8,
        caps: std::array::from_fn(|_| {
            vec![[crate::config::Val::ZERO; 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    Config::new(
        registry,
        pin,
        [9; 32],
        Resources {
            ram_bytes: storage::STARTUP_HOST_BYTES + 1000,
            vram_bytes: 0,
            scratch_bytes: 500,
            threads: 2,
        },
        Resources {
            ram_bytes: coordinator::HOST_BYTES + 100,
            vram_bytes: 0,
            scratch_bytes: 0,
            threads: 2,
        },
        image_fingerprint(&std::env::current_exe().unwrap()).unwrap(),
        configuration_digest(b"independent synthetic public policy").unwrap(),
    )
    .unwrap()
}

fn fixture(temp: &Temp) -> (DurableDag, ProcessWorker) {
    fixture_capacity(temp, 1)
}

#[test]
fn process_configuration_rejects_coordinator_shortfall_before_launch() {
    let cfg = config();
    for bytes in [
        0,
        coordinator::PACKET_HOST_BYTES,
        coordinator::HOST_BYTES - 1,
    ] {
        let jobs = Resources {
            ram_bytes: bytes,
            ..cfg.jobs
        };
        assert!(Config::new(
            cfg.registry.as_registry().clone(),
            cfg.pin,
            cfg.chain,
            cfg.peak,
            jobs,
            cfg.executable,
            cfg.policy_assignment,
        )
        .is_err());
    }
    Config::new(
        cfg.registry.as_registry().clone(),
        cfg.pin,
        cfg.chain,
        cfg.peak,
        Resources {
            ram_bytes: coordinator::HOST_BYTES,
            ..cfg.jobs
        },
        cfg.executable,
        cfg.policy_assignment,
    )
    .unwrap();
}

#[test]
fn process_configuration_reserves_session_storage_before_launch() {
    use crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES;
    let cfg = config();
    for bytes in [
        0,
        storage::HOST_BYTES - 1,
        storage::HOST_BYTES,
        storage::HOST_BYTES + SESSION_HOST_BYTES - 1,
        storage::HOST_BYTES + SESSION_HOST_BYTES,
        storage::STARTUP_HOST_BYTES - 1,
    ] {
        let peak = Resources {
            ram_bytes: bytes,
            ..cfg.peak
        };
        assert!(Config::new(
            cfg.registry.as_registry().clone(),
            cfg.pin,
            cfg.chain,
            peak,
            cfg.jobs,
            cfg.executable,
            cfg.policy_assignment,
        )
        .is_err());
    }
    let active =
        cfg.peak.ram_bytes - storage::HOST_BYTES - storage::INPUT_HOST_BYTES - SESSION_HOST_BYTES;
    assert!(cfg.clone().with_preprocessing_cache(2, active).is_err());
    assert!(cfg.clone().with_preprocessing_cache(2, u64::MAX).is_err());
    let admitted = cfg.with_preprocessing_cache(2, active - 1).unwrap();
    assert_eq!(admitted.cache_reserve_bytes, active - 1);
    assert!(admitted.with_preprocessing_cache(1, 0).is_ok());
}

#[test]
fn process_descriptor_reuses_immutable_approval_without_allocating() {
    let cfg = config();
    let expected = cfg.bytes().unwrap();
    let (_, requested) = crate::spill_alloc::allocation_requests::measure(|| {
        for _ in 0..128 {
            assert_eq!(cfg.bytes().unwrap(), expected);
        }
    });
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    eprintln!("typed_descriptor_approval records=128 allocations=0 config_bytes={CONFIG_BYTES} session_bytes={SESSION_BYTES}");
}

fn fixture_capacity(temp: &Temp, workers: u32) -> (DurableDag, ProcessWorker) {
    let config = config();
    let store = ArtifactStore::create(
        &temp.0.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 64,
        },
    )
    .unwrap();
    let mut owner = DurableDag::create(
        &temp.0.join("journal"),
        JournalLimits {
            snapshot_bytes: 1 << 20,
        },
        store,
        config.pin,
        config.chain,
        1,
        Limits {
            jobs: 32,
            candidates: 4,
            attempts: 16,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 1000,
            workers: Resources {
                ram_bytes: (storage::STARTUP_HOST_BYTES + coordinator::HOST_BYTES + 1100)
                    * u64::from(workers),
                vram_bytes: 0,
                scratch_bytes: 500 * u64::from(workers),
                threads: 2 * workers,
            },
        },
    )
    .unwrap();
    let worker = ProcessWorker::prepare(&mut owner, config, WorkerId(1), WorkerId(2), 0).unwrap();
    (owner, worker)
}

fn command(case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "block_v2::execution::worker::typed::process::tests::child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LATTICA_TYPED_PROCESS_TEST_CASE", case);
    command
}

#[test]
#[ignore = "subprocess entry point; called by lifecycle tests"]
fn child() {
    let Ok(case) = std::env::var("LATTICA_TYPED_PROCESS_TEST_CASE") else {
        return;
    };
    let mut socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
    if case == "idle" {
        serve(
            socket,
            config(),
            Path::new("/unused-no-jobs"),
            |_| panic!("no jobs"),
            || Ok(()),
        )
        .unwrap();
        return;
    }
    let spec = receive(&mut socket, HELLO, 1024).unwrap();
    if case == "exit-before-ready" {
        return;
    }
    let mut ready = std::process::id().to_le_bytes().to_vec();
    ready.extend(launch::digest(DOMAIN, &spec).unwrap());
    if case == "wrong-session" {
        ready[4] ^= 1;
    }
    send(&mut socket, READY, &ready).unwrap();
    if case == "wrong-session" {
        return;
    }
    if case == "dies-idle" {
        std::process::exit(7);
    }
    if case == "held-result" {
        let root = PathBuf::from(std::env::var_os("LATTICA_TYPED_PROCESS_TEST_DIR").unwrap());
        let bytes = receive(&mut socket, JOB, MAX_FRAME).unwrap();
        let token_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        let token = Token::decode(&bytes[8..8 + token_len]).unwrap();
        let request_bytes = &bytes[8 + token_len..];
        let request = packet::Request::decode(request_bytes, config().pin, config().chain).unwrap();
        let gate = WorkerGate::enter(&root.join("launches"), &token, request_bytes).unwrap();
        fs::write(root.join("received"), []).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.join("release").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let result = packet::encode_result_for(
            true,
            request.key,
            request.job,
            launch::request_digest(request_bytes).unwrap(),
            &[9],
            Timings {
                input_verification_ms: 0,
                proving_ms: 0,
                serialization_ms: 0,
            },
            CacheStats { setups: 1, hits: 0 },
        )
        .unwrap();
        drop(gate);
        send(&mut socket, RESULT, &result).unwrap();
        receive(&mut socket, STOP, 0).unwrap();
        let counters: Vec<_> = [1u64, 0, 1]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        send(&mut socket, STOPPED, &counters).unwrap();
        return;
    }
    assert_eq!(case, "bad-exit");
    receive(&mut socket, STOP, 0).unwrap();
    send(&mut socket, STOPPED, &[0; 24]).unwrap();
    std::process::exit(7);
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn idle_context_switch_preserves_process_and_reservation_but_fences_old_identity() {
    let temp = Temp::new();
    let (mut owner, mut worker) = fixture(&temp);
    worker.start(command("idle")).unwrap();
    let storage = ProcessWorker::storage_plan().unwrap();
    let idle_bytes = worker.persistent_storage_bytes().unwrap();
    assert!(idle_bytes <= storage.retained_bytes);
    let pid = worker.pid();
    let initial = worker.execution_digest().unwrap();
    let initial_frame = worker.session_bytes().to_vec();
    let reserved = owner.resource_use().unwrap();
    let context = PolicyContext::new([42; 32], vec![]).unwrap();
    worker.replace_context(&context).unwrap();
    worker.heartbeat().unwrap();
    assert_ne!(worker.execution_digest().unwrap(), initial);
    // The v1 policy digest alone changes; the registry, assignment and
    // reservation suffix retain their established byte positions.
    assert_eq!(&worker.session_bytes()[..136], &initial_frame[..136]);
    assert_ne!(&worker.session_bytes()[136..168], &initial_frame[136..168]);
    assert_eq!(&worker.session_bytes()[168..], &initial_frame[168..]);
    assert_eq!(worker.pid(), pid);
    assert_eq!(owner.resource_use().unwrap(), reserved);
    let next = worker.execution_digest().unwrap();
    worker.replace_context(&context).unwrap();
    assert_eq!(worker.execution_digest().unwrap(), next);
    worker
        .replace_context(&PolicyContext::new([43; 32], vec![]).unwrap())
        .unwrap();
    assert_ne!(worker.execution_digest().unwrap(), next);
    assert_eq!(worker.stats().unwrap(), CacheStats { setups: 0, hits: 0 });
    worker.close(&mut owner, 1).unwrap();
    let closed_bytes = worker.persistent_storage_bytes().unwrap();
    assert!(closed_bytes <= storage.retained_bytes);
    eprintln!("bounded_persistent_process retained_bytes={} control_bytes={} idle_bytes={idle_bytes} closed_bytes={closed_bytes}",
        storage.retained_bytes, storage.control_bytes);
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn pending_dispatch_keeps_reservations_while_another_worker_shuts_down() {
    use crate::block_v2::execution::{
        dag::Completion,
        job::{test_support::typed_wallet_for, VerifiedNode},
        launch::{LaunchLimits, LaunchStore},
        selection::{PublicInput, Selection},
    };
    let temp = Temp::new();
    let (mut owner, mut first) = fixture_capacity(&temp, 2);
    let cfg = config();
    let wallet = typed_wallet_for(cfg.pin, 1, 1, &[1]);
    let selection = Selection::new(
        cfg.pin,
        cfg.chain,
        &[PublicInput::new(wallet, vec![1]).unwrap()],
    )
    .unwrap();
    selection.attach(&mut owner, [8; 32], 1000, 0).unwrap();
    let mut second =
        ProcessWorker::prepare(&mut owner, cfg.clone(), WorkerId(3), WorkerId(4), 0).unwrap();
    second.start(command("idle")).unwrap();
    let mut child = command("held-result");
    child.env("LATTICA_TYPED_PROCESS_TEST_DIR", &temp.0);
    first.start(child).unwrap();
    let job = selection.jobs().next().unwrap();
    let lease = owner
        .lease(job.id(), WorkerId(2), cfg.jobs, 1, 1000, 0)
        .unwrap();
    let task = first.task(&mut owner, lease, 0).unwrap();
    let request = task.request().unwrap();
    let mut launches =
        LaunchStore::create(&temp.0.join("launches"), LaunchLimits { records: 4 }).unwrap();
    let token = launches
        .issue_bound(
            &mut owner,
            lease,
            &request,
            first.execution_digest().unwrap(),
        )
        .unwrap();
    first.dispatch(&token, task).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !temp.0.join("received").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(first.has_pending());
    assert!(first.try_collect().unwrap().is_none());
    let charged = owner.resource_use().unwrap();
    assert!(first
        .stop_failed_supervised(&mut owner, &mut launches, lease, || 0)
        .is_err());
    assert!(first.has_pending());
    assert_eq!(owner.resource_use().unwrap(), charged);
    assert!(first.close(&mut owner, 1).is_err());
    assert!(first.stats().is_err());
    second.close(&mut owner, 1).unwrap();
    assert_eq!(
        owner.resource_use().unwrap(),
        Resources {
            threads: 0,
            ..cfg.peak
        }
        .add(cfg.jobs)
        .unwrap()
    );
    fs::write(temp.0.join("release"), []).unwrap();
    let completed = loop {
        if let Some(completed) = first.try_collect().unwrap() {
            break completed;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(!first.has_pending());
    let revoked = launches.revoke(lease).unwrap();
    assert!(launches.try_idle(&revoked).unwrap().is_some());
    let output = completed.reconcile(&mut owner, 2).unwrap();
    assert_eq!(
        owner.resource_use().unwrap().ram_bytes,
        cfg.peak.ram_bytes + cfg.jobs.ram_bytes
    );
    let expected = owner.begin_verification(lease, 2).unwrap();
    assert_eq!(
        owner.resource_use().unwrap().ram_bytes,
        cfg.peak.ram_bytes + cfg.jobs.ram_bytes
    );
    // A correctly bound IPC result still cannot qualify this synthetic proof.
    assert!(
        VerifiedNode::verify_typed(&expected, cfg.registry.as_registry(), output.bytes()).is_err()
    );
    assert_eq!(
        owner.finish_verification(lease, None, 2).unwrap(),
        Completion::Rejected
    );
    first.close(&mut owner, 3).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
}

#[test]
#[ignore = "native user-systemd IPC/identity check; no GPU proving"]
fn supervised_proxy_exit_requires_exact_worker_and_cgroup_quiescence() {
    assert_eq!(
        std::env::var("LATTICA_TYPED_PROCESS_SYSTEMD_TEST").as_deref(),
        Ok("1")
    );
    let temp = Temp::new();
    let (mut owner, mut worker) = fixture(&temp);
    let digest = configuration_digest(temp.0.as_os_str().as_encoded_bytes()).unwrap();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let unit = format!("lattica-v2-multi-persistent-{hex}.service");
    let child = command("idle");
    let arguments: Vec<_> = child.get_args().map(|value| value.to_owned()).collect();
    let log = fs::File::create(temp.0.join("service.log")).unwrap();
    let mut launcher = Command::new("/usr/bin/systemd-run");
    launcher
        .args([
            "--user",
            "--pipe",
            "--wait",
            "--quiet",
            "--service-type=exec",
            "--property=MemoryMax=134217728",
            "--property=MemorySwapMax=0",
            "--property=LimitCORE=0",
            "--property=CPUQuota=100%",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=60",
            "--setenv=LATTICA_TYPED_PROCESS_TEST_CASE=idle",
        ])
        .arg(format!("--unit={unit}"))
        .arg("--slice=lattica-v2-multi.slice")
        .arg(child.get_program())
        .args(&arguments)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    worker
        .start_supervised(launcher, &unit, &arguments)
        .unwrap();
    assert_ne!(worker.pid().unwrap(), worker.child.as_ref().unwrap().id());
    let owned = worker.persistent_storage_bytes().unwrap();
    assert!(owned <= ProcessWorker::storage_plan().unwrap().retained_bytes);
    eprintln!(
        "bounded_supervised_storage persistent_bytes={owned} identity_heap_bytes={}",
        worker
            .service_identity()
            .unwrap()
            .storage_heap_bytes()
            .unwrap()
    );
    assert_eq!(
        worker.service_identity().unwrap().pid(),
        worker.pid().unwrap()
    );
    assert!(worker.service_identity().unwrap().cgroup().ends_with(&unit));
    assert!(worker.service_identity().unwrap().start_ticks() > 0);
    assert!(worker.service_identity().unwrap().cgroup_inode() > 0);
    assert_eq!(
        owner.resource_use().unwrap().ram_bytes,
        config().peak.ram_bytes
    );
    worker.close(&mut owner, 1).unwrap();
    assert!(worker.exited_cleanly);
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
}

#[test]
fn bounded_protocol_rejects_oversized_truncated_and_unexpected_frames() {
    for (kind, size, expected) in [(RESULT, u64::MAX, RESULT), (STOPPED, 0, RESULT)] {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[kind]).unwrap();
        a.write_all(&size.to_le_bytes()).unwrap();
        assert!(receive(&mut b, expected, 24).is_err());
    }
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&[JOB]).unwrap();
    a.write_all(&4u64.to_le_bytes()).unwrap();
    a.write_all(&[1]).unwrap();
    drop(a);
    assert!(receive_command(&mut b).is_err());
    let (mut a, mut b) = UnixStream::pair().unwrap();
    send(&mut a, STOP, &[1]).unwrap();
    assert!(receive_command(&mut b).is_err());
}

#[test]
fn frame_storage_is_exact_and_each_command_bound_precedes_body_read() {
    for (kind, bound) in [
        (STOP, 0),
        (PING, 0),
        (CONTEXT, MAX_CONTEXT_BYTES),
        (JOB, MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 8),
    ] {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        // Only a header is available: an over-bound frame must return without
        // trying to read its body while the peer is still connected.
        b.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        a.write_all(&[kind]).unwrap();
        a.write_all(&(bound as u64 + 1).to_le_bytes()).unwrap();
        assert_eq!(
            receive_command(&mut b).unwrap_err().to_string(),
            "typed process command size"
        );
        drop(a);
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || send(&mut a, kind, &vec![0x5a; bound]).unwrap());
        let (received_kind, bytes) = receive_command(&mut b).unwrap();
        writer.join().unwrap();
        assert_eq!(received_kind, kind);
        assert_eq!(bytes.len(), bound);
        assert_eq!(bytes.capacity(), bound);
        assert!(bytes.iter().all(|value| *value == 0x5a));
    }
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || send(&mut a, RESULT, &vec![7; MAX_FRAME]).unwrap());
    let bytes = receive(&mut b, RESULT, usize::MAX).unwrap();
    writer.join().unwrap();
    assert_eq!(bytes.len(), MAX_FRAME);
    assert_eq!(bytes.capacity(), MAX_FRAME);
    assert!(bytes.iter().all(|value| *value == 7));
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&[RESULT]).unwrap();
    a.write_all(&(MAX_FRAME as u64 + 1).to_le_bytes()).unwrap();
    b.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(
        receive(&mut b, RESULT, usize::MAX).unwrap_err().to_string(),
        "typed process frame kind or size"
    );
}

#[test]
fn multipart_send_preserves_frame_bytes_and_admits_before_any_write() {
    for size in [0, 1, 4096, MAX_FRAME] {
        let expected = vec![0x6a; size];
        let sent = expected.clone();
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let split = sent.len() / 2;
            send_parts(&mut a, JOB, &[&[], &sent[..split], &[], &sent[split..]]).unwrap();
        });
        let mut header = [0; 9];
        b.read_exact(&mut header).unwrap();
        assert_eq!(header[0], JOB);
        assert_eq!(
            u64::from_le_bytes(header[1..].try_into().unwrap()),
            size as u64
        );
        let mut payload = vec![0; size];
        b.read_exact(&mut payload).unwrap();
        writer.join().unwrap();
        assert_eq!(payload, expected);
    }
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let full = vec![0; MAX_FRAME];
    assert!(send_parts(&mut a, JOB, &[&full, &[1]]).is_err());
    b.set_nonblocking(true).unwrap();
    assert_eq!(
        b.read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
#[ignore = "native user-systemd forced-stop check; no GPU proving"]
fn supervised_active_stop_revokes_launch_and_releases_only_after_exit() {
    use crate::block_v2::execution::{
        job::test_support::typed_wallet_for,
        launch::{LaunchLimits, LaunchStore},
        selection::{PublicInput, Selection},
    };
    assert_eq!(
        std::env::var("LATTICA_TYPED_PROCESS_SYSTEMD_TEST").as_deref(),
        Ok("1")
    );
    let temp = Temp::new();
    let (mut owner, mut worker) = fixture(&temp);
    let cfg = config();
    let wallet = typed_wallet_for(cfg.pin, 1, 1, &[1]);
    let selection = Selection::new(
        cfg.pin,
        cfg.chain,
        &[PublicInput::new(wallet, vec![1]).unwrap()],
    )
    .unwrap();
    selection.attach(&mut owner, [8; 32], 1000, 0).unwrap();
    let job = selection.jobs().next().unwrap();
    let lease = owner
        .lease(job.id(), WorkerId(2), cfg.jobs, 1, 1000, 0)
        .unwrap();
    let digest = configuration_digest(temp.0.as_os_str().as_encoded_bytes()).unwrap();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let unit = format!("lattica-v2-multi-persistent-{hex}.service");
    let child = command("held-result");
    let arguments: Vec<_> = child.get_args().map(|value| value.to_owned()).collect();
    let log = fs::File::create(temp.0.join("service.log")).unwrap();
    let mut launcher = Command::new("/usr/bin/systemd-run");
    launcher
        .args([
            "--user",
            "--pipe",
            "--wait",
            "--quiet",
            "--service-type=exec",
            "--property=MemoryMax=134217728",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=60",
            "--property=LimitCORE=0",
            "--setenv=LATTICA_TYPED_PROCESS_TEST_CASE=held-result",
        ])
        .arg(format!(
            "--setenv=LATTICA_TYPED_PROCESS_TEST_DIR={}",
            temp.0.display()
        ))
        .arg(format!("--unit={unit}"))
        .arg("--slice=lattica-v2-multi.slice")
        .arg(child.get_program())
        .args(&arguments)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    worker
        .start_supervised(launcher, &unit, &arguments)
        .unwrap();
    let task = worker.task(&mut owner, lease, 0).unwrap();
    let request = task.request().unwrap();
    let mut launches =
        LaunchStore::create(&temp.0.join("launches"), LaunchLimits { records: 4 }).unwrap();
    let token = launches
        .issue_bound(
            &mut owner,
            lease,
            &request,
            worker.execution_digest().unwrap(),
        )
        .unwrap();
    worker.dispatch(&token, task).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !temp.0.join("received").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(worker.has_pending());
    assert_ne!(owner.resource_use().unwrap(), Resources::default());
    worker
        .stop_failed_supervised(&mut owner, &mut launches, lease, || 1)
        .unwrap();
    assert!(crate::block_v2::execution::os_worker::exited(
        worker.service_identity().unwrap(),
        &unit
    )
    .unwrap());
    assert!(worker.child.is_none() && !worker.has_pending());
    assert!(!worker.exited_cleanly);
    assert!(launch::WorkerGate::enter(&temp.0.join("launches"), &token, &request).is_err());
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(owner.ready().unwrap().contains(&job.id()));
}

#[test]
fn per_job_cache_deltas_accumulate_across_hits_and_mode_changes() {
    let mut total = CacheStats::default();
    for (index, setup) in [true, false, true, false, true, false, false, true]
        .into_iter()
        .enumerate()
    {
        let job = CacheStats {
            setups: u64::from(setup),
            hits: u64::from(!setup),
        };
        total = accumulate_stats(total, job, index as u64 + 1).unwrap();
    }
    assert_eq!(total, CacheStats { setups: 4, hits: 4 });
    for job in [
        CacheStats::default(),
        total,
        CacheStats {
            setups: u64::MAX,
            hits: 1,
        },
    ] {
        assert!(accumulate_stats(total, job, 9).is_err());
    }
    assert!(accumulate_stats(
        CacheStats {
            setups: 0,
            hits: u64::MAX
        },
        CacheStats { setups: 0, hits: 1 },
        0
    )
    .is_err());
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn idle_child_retains_memory_until_clean_shutdown_and_observed_exit() {
    let temp = Temp::new();
    let (mut owner, mut worker) = fixture(&temp);
    let reserved = owner.resource_use().unwrap();
    assert_eq!(reserved.threads, 0);
    assert_eq!(reserved.ram_bytes, config().peak.ram_bytes);
    worker.start(command("idle")).unwrap();
    assert_ne!(worker.pid().unwrap(), std::process::id());
    assert_eq!(owner.resource_use().unwrap(), reserved);
    worker.close(&mut owner, 1).unwrap();
    assert!(worker.exited_cleanly && worker.child.is_none());
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(worker.start(command("idle")).is_err());
}

#[test]
fn wrong_session_identity_and_unsuccessful_exit_never_release_workspace() {
    for case in ["wrong-session", "dies-idle", "bad-exit"] {
        let temp = Temp::new();
        let (mut owner, mut worker) = fixture(&temp);
        let reserved = owner.resource_use().unwrap();
        let start = worker.start(command(case));
        if case == "wrong-session" {
            assert!(start.is_err());
        } else {
            start.unwrap();
        }
        assert!(worker.close(&mut owner, 1).is_err());
        assert_eq!(owner.resource_use().unwrap(), reserved);
        drop(worker);
        assert_eq!(owner.resource_use().unwrap(), reserved);
    }
}

#[test]
fn child_exit_before_ready_is_prompt_and_preserves_workspace() {
    for supervised in [false, true] {
        let temp = Temp::new();
        let (owner, mut worker) = fixture(&temp);
        let reserved = owner.resource_use().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let error = if supervised {
                worker.start_supervised(
                    command("exit-before-ready"),
                    &format!("lattica-v2-multi-persistent-{}.service", "a".repeat(64)),
                    &["test-worker".into()],
                )
            } else {
                worker.start(command("exit-before-ready"))
            }
            .expect_err("an exited worker must not complete the handshake")
            .to_string();
            assert!(worker.child.as_mut().unwrap().wait().unwrap().success());
            sender.send((worker, error)).unwrap();
        });
        let (worker, error) = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("worker exit was hidden by a retained socket endpoint");
        task.join().unwrap();
        assert!(worker.poisoned && worker.socket.is_none(), "{error}");
        assert_eq!(owner.resource_use().unwrap(), reserved);
    }
}

#[test]
fn independent_assignment_changes_session_identity_and_rejects_other_image() {
    let original = config();
    let mut changed = original.clone();
    changed.jobs.ram_bytes += 1;
    assert_ne!(original.bytes().unwrap(), changed.bytes().unwrap());
    changed = original.clone();
    changed.peak.scratch_bytes += 1;
    assert_ne!(original.bytes().unwrap(), changed.bytes().unwrap());
    let temp = Temp::new();
    let (owner, mut worker) = fixture(&temp);
    let reserved = owner.resource_use().unwrap();
    assert!(worker.start(Command::new("/bin/true")).is_err());
    assert!(worker.pid().is_none());
    assert_eq!(owner.resource_use().unwrap(), reserved);
}

#[test]
fn configuration_moves_registry_and_preserves_v1_wire_layout() {
    let mut cfg = config();
    cfg.chain = [0x22; 32];
    cfg.executable = [0x33; 32];
    cfg.policy_assignment = [0x44; 32];
    let registry_id = cfg.registry.as_registry().id().unwrap();
    let backing: [usize; 12] =
        std::array::from_fn(|i| cfg.registry.as_registry().caps[i].as_ptr() as usize);
    let ((registry, descriptor), requested) =
        crate::spill_alloc::allocation_requests::measure(|| cfg.into_parts().unwrap());
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    let moved_backing: [usize; 12] =
        std::array::from_fn(|i| registry.as_registry().caps[i].as_ptr() as usize);
    assert_eq!(backing, moved_backing);
    assert!(!std::mem::needs_drop::<Descriptor>());
    assert_eq!(CONFIG_BYTES, 248);
    assert_eq!(SESSION_BYTES, 312);
    let wire = descriptor.bytes();
    assert_eq!(&wire[..8], b"LTTYIPC1");
    assert_eq!(&wire[8..40], &registry_id);
    assert_eq!(&wire[40..72], &registry_id);
    assert_eq!(&wire[72..104], &[0x22; 32]);
    assert_eq!(&wire[104..136], &[0x33; 32]);
    assert_eq!(&wire[136..168], &[0x44; 32]);
    // v1 fixture: peak RAM/VRAM/scratch/threads, job resources, then cache.
    let expected_tail: Vec<u8> = [
        storage::STARTUP_HOST_BYTES + 1000,
        0,
        500,
        2,
        coordinator::HOST_BYTES + 100,
        0,
        0,
        2,
        1,
        0,
    ]
    .into_iter()
    .flat_map(u64::to_le_bytes)
    .collect();
    assert_eq!(&wire[168..], expected_tail);
    eprintln!(
        "typed_process_descriptor_storage bytes={} config_bytes={CONFIG_BYTES} session_bytes={SESSION_BYTES} registry_moved=true heap_owners=0",
        std::mem::size_of::<Descriptor>()
    );
}
