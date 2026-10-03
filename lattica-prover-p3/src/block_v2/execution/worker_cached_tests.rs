use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::{Completion, JobStatus, Limits},
    journal::JournalLimits,
    launch::{LaunchLimits, LaunchStore},
    selection::{PublicInput, Selection},
    test_fixture::{self, Fixture},
};
use rand::TryRng;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lattica-cached-test-{}",
            super::super::super::artifact_store::hex(&nonce)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> Limits {
    Limits {
        jobs: 512,
        candidates: 16,
        attempts: 256,
        artifact_bytes: 32 << 20,
        recovery_window_ms: 10,
        workers: WORKSPACE_RESOURCES.add(JOB_RESOURCES).unwrap(),
    }
}

fn owner(path: &Path, f: &Fixture) -> Result<DurableDag, Error> {
    owner_for_pin(path, f.pin)
}

fn owner_for_pin(path: &Path, pin: super::super::RegistryPin) -> Result<DurableDag, Error> {
    let store = ArtifactStore::create(
        &path.join("store"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 512,
        },
    )?;
    DurableDag::create(
        &path.join("journal"),
        JournalLimits {
            snapshot_bytes: 256 << 10,
        },
        store,
        pin,
        [0x5a; 32],
        1,
        limits(),
    )
}

fn admit(owner: &mut DurableDag, f: &Fixture) -> Result<Vec<Job>, Error> {
    let inputs = f.wallets[..4]
        .iter()
        .zip(&f.bytes[..4])
        .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let selection = Selection::new(f.pin, [0x5a; 32], &inputs)?;
    selection.attach(owner, [1; 32], 7_200_000, 0)?;
    let mut jobs: Vec<_> = selection
        .jobs()
        .filter(|job| job.operation() == Operation::WrapPair)
        .cloned()
        .collect();
    jobs.sort_by_key(|job| job.start());
    Ok(jobs)
}

#[test]
fn cached_policy_keeps_one_session_and_one_job_within_aggregate_budgets() {
    let combined = WORKSPACE_RESOURCES.add(JOB_RESOURCES).unwrap();
    assert_eq!(combined.ram_bytes + (3 << 30), 48 << 30);
    assert_eq!(combined.vram_bytes, 0);
    assert_eq!(combined.scratch_bytes, 128 << 30);
    assert_eq!(combined.threads, 9);
    limits().workers.validate_capacity().unwrap();
    assert!(!combined.add(JOB_RESOURCES).unwrap().fits(limits().workers));
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn cached_cpu_owner_tasks_and_completions_can_move_to_threads() {
    fn is_send<T: Send>() {}
    is_send::<Task>();
    is_send::<CompletedJob>();
    is_send::<CachedCpuWorker>();
}

#[test]
#[ignore = "requires pinned public CPU fixtures; no proving or actual preprocessing"]
fn cpu_cached_adapter_binds_owner_budget_and_close_lifetime() -> Result<(), Error> {
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let mut d = owner(&temp.0, &f)?;
    let jobs = admit(&mut d, &f)?;
    let mut cached = CachedCpuWorker::new(&mut d, f.registry.clone(), f.pin, WorkerId(100), 0)?;
    assert_eq!(d.resource_use()?, WORKSPACE_RESOURCES);
    assert_eq!(cached.stats()?, CacheStats::default());
    let lease = d.lease(jobs[0].id(), WorkerId(1), JOB_RESOURCES, 1, 1000, 0)?;
    let task = cached.task(&mut d, lease, 0)?;
    assert!(cached.close(&mut d, 1).is_err());
    assert_eq!(cached.stats()?, CacheStats::default());
    assert_eq!(d.resource_use()?, limits().workers);
    let other = Temp::new();
    let mut wrong = owner(&other.0, &f)?;
    assert!(cached.close(&mut wrong, 1).is_err());
    assert!(cached.task(&mut wrong, lease, 1).is_err());
    drop(task);
    d.reject_worker(lease, 1)?;
    d.worker_stopped(lease, 1)?; // No token was issued and no local call began.
    let small = Resources {
        ram_bytes: 1,
        vram_bytes: 0,
        scratch_bytes: 0,
        threads: 1,
    };
    let lease = d.lease(jobs[0].id(), WorkerId(2), small, 1, 1000, 2)?;
    assert!(cached.task(&mut d, lease, 2).is_err());
    d.reject_worker(lease, 3)?;
    d.worker_stopped(lease, 3)?;
    cached.close(&mut d, 4)?;
    assert_eq!(d.resource_use()?, Resources::default());
    assert!(cached.stats().is_err());
    assert!(cached.workspace().is_err());
    Ok(())
}

#[test]
#[ignore = "requires pinned public CPU fixtures; checks bound-token rejection without proving"]
fn cpu_cached_adapter_rejects_process_bound_token_before_setup() -> Result<(), Error> {
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let mut d = owner(&temp.0, &f)?;
    let jobs = admit(&mut d, &f)?;
    let mut cached = CachedCpuWorker::new(&mut d, f.registry.clone(), f.pin, WorkerId(100), 0)?;
    let lease = d.lease(jobs[0].id(), WorkerId(1), JOB_RESOURCES, 1, 1000, 0)?;
    let task = cached.task(&mut d, lease, 0)?;
    let request = task.request()?;
    let path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&path, LaunchLimits { records: 2 })?;
    let token = launches.issue_bound(&mut d, lease, &request, [1; 32])?;
    let gate = WorkerGate::enter(&path, &token, &request)?;
    assert!(cached.execute(gate, task).is_err());
    assert_eq!(cached.stats()?, CacheStats::default());
    d.reject_worker(lease, 1)?;
    let revoked = launches.revoke(lease)?;
    assert!(launches.try_idle(&revoked)?.is_some());
    d.worker_stopped(lease, 1)?; // Entered call returned before CPU preparation.
    cached.close(&mut d, 2)?;
    assert_eq!(d.resource_use()?, Resources::default());
    Ok(())
}

fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("proof parent missing")?)?.sync_all()?;
    Ok(())
}

#[test]
#[ignore = "requires explicit full-strength two-pair cached proving under44GiB worker/48GiB aggregate caps"]
fn cpu_cached_adapter_proves_two_pairs_retains_one_setup_and_closes() -> Result<(), Error> {
    if std::env::var("LATTICA_V2_RUN_CACHED_PROOFS").as_deref() != Ok("1") {
        return Err("cached real-proof opt-in required".into());
    }
    let output = PathBuf::from(std::env::var("LATTICA_V2_CACHED_OUTPUT")?);
    let f = test_fixture::load()?;
    let mut d = owner(&output, &f)?;
    let jobs = admit(&mut d, &f)?;
    assert_eq!(jobs.len(), 2);
    let path = output.join("launches");
    let mut launches = LaunchStore::create(&path, LaunchLimits { records: 4 })?;
    let mut cached = CachedCpuWorker::new(&mut d, f.registry.clone(), f.pin, WorkerId(100), 0)?;
    let start = Instant::now();
    let mut now = 0;
    for (i, job) in jobs.iter().enumerate() {
        let lease = d.lease(
            job.id(),
            WorkerId(i as u64 + 1),
            JOB_RESOURCES,
            1,
            7_200_000,
            now,
        )?;
        let task = cached.task(&mut d, lease, now)?;
        let packet = task.request()?;
        let token = launches.issue(&mut d, lease, &packet)?;
        let gate = WorkerGate::enter(&path, &token, &packet)?;
        let complete = cached.execute(gate, task)?;
        now = u64::try_from(start.elapsed().as_millis())?;
        assert!(cached.close(&mut d, now).is_err());
        assert_eq!(d.resource_use()?, limits().workers);
        let result = complete.acknowledge(&mut d, now)?;
        assert_eq!(result.lease(), lease);
        assert_eq!(result.job(), job.id());
        assert_eq!(
            result.stats(),
            CacheStats {
                setups: u64::from(i == 0),
                hits: u64::from(i == 1)
            }
        );
        let timings = result.timings();
        let bytes = result.into_bytes();
        let checked = d
            .begin_guarded_verification(lease, now)?
            .verify(&f.registry, bytes.clone());
        assert!(checked.error().is_none());
        now = u64::try_from(start.elapsed().as_millis())?;
        assert_eq!(
            d.finish_guarded_verification(checked, now)?,
            Completion::Accepted
        );
        assert_eq!(d.status(job.id())?, JobStatus::Completed);
        assert_eq!(d.resource_use()?, WORKSPACE_RESOURCES);
        assert!(!crate::spill_alloc::is_armed());
        let (mappings, live) = crate::spill_alloc::spill_stats();
        assert!(mappings > 0 && live > 0);
        assert!(crate::spill_alloc::spill_peak_bytes() <= WORKSPACE_RESOURCES.scratch_bytes);
        publish(&output.join(format!("pair.1.{i}")), &bytes)?;
        let revoked = launches.revoke(lease)?;
        assert!(launches.try_idle(&revoked)?.is_some());
        println!("cached_pair=PASS index={i} proof_bytes={} input_verification_ms={} proving_ms={} serialization_ms={} retained_spill_bytes={live} cache_setups={} cache_hits={} elapsed_ms={now}", bytes.len(), timings.input_verification_ms, timings.proving_ms, timings.serialization_ms, cached.stats()?.setups, cached.stats()?.hits);
    }
    assert_eq!(cached.stats()?, CacheStats { setups: 1, hits: 1 });
    cached.close(&mut d, now)?;
    assert_eq!(d.resource_use()?, Resources::default());
    assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
    assert!(!crate::spill_alloc::is_armed());
    println!("cached_cpu_session=PASS proofs=2 setups=1 hits=1 cache_closed=true spill_live_bytes=0 full_block=false matched_speedup=false production_ready=false");
    Ok(())
}

#[test]
#[ignore = "requires the two saved cached pair outputs and pinned public CPU fixtures"]
fn cpu_cached_outputs_replay_in_fresh_process() -> Result<(), Error> {
    let output = PathBuf::from(std::env::var("LATTICA_V2_CACHED_OUTPUT")?);
    let f = test_fixture::load()?;
    for i in 0..2 {
        let job = Job::wrap_pair((2 * i) as u8, f.wallets[2 * i], f.wallets[2 * i + 1])?;
        let bytes = test_fixture::read(
            &output.join(format!("pair.1.{i}")),
            crate::block_v2::profile::MAX_PROOF_BYTES,
        )?;
        VerifiedNode::verify(&job, &f.registry, &bytes)?;
        let wrong = Job::wrap_pair((2 * i) as u8, f.wallets[2 * i + 1], f.wallets[2 * i])?;
        assert!(VerifiedNode::verify(&wrong, &f.registry, &bytes).is_err());
        let mut mutation = bytes;
        *mutation.last_mut().ok_or("empty proof")? ^= 1;
        assert!(VerifiedNode::verify(&job, &f.registry, &mutation).is_err());
    }
    println!("cached_fresh_replay=PASS proofs=2 wrong_order_rejected=true mutation_rejected=true root_only_block_replay=false");
    Ok(())
}

#[path = "worker_cached_bench_tests.rs"]
mod bench;
