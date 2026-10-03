use super::*;
use crate::block_v2::{
    commitment::DEPTH,
    execution::{
        dag::{Dag, JobStatus, Limits, WorkerId},
        job::test_support::{node, pin, wallet},
        resources::Resources,
    },
};

fn request() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 0,
        scratch_bytes: 100,
        threads: 1,
    }
}
fn limits() -> Limits {
    Limits {
        jobs: 512,
        candidates: 16,
        attempts: 256,
        artifact_bytes: 32 * (1 << 20),
        recovery_window_ms: 10,
        workers: request(),
    }
}
fn leaf(start: u8) -> Job {
    Job::wrap(start, wallet(u64::from(start) + 1, &[start + 1])).unwrap()
}
fn tree(d: &mut Dag, count: u8, start: u8, level: u8) -> Job {
    let (job, bytes) = if start >= count {
        (Job::empty(pin(), [9; 32], start, level).unwrap(), vec![])
    } else if level == 0 {
        (leaf(start), vec![vec![start + 1]])
    } else {
        let left = tree(d, count, start, level - 1);
        let right = tree(d, count, start + (1 << (level - 1)), level - 1);
        (Job::merge(&left, &right).unwrap(), vec![])
    };
    d.admit(job.clone(), bytes, 0).unwrap();
    job
}
fn dag(count: u8) -> (Dag, super::super::dag::CandidateId) {
    let mut d = Dag::new(pin(), [9; 32], 1, limits()).unwrap();
    let root = tree(&mut d, count, 0, DEPTH);
    let id = d.attach(root.id(), [1; 32], 1000, 0).unwrap();
    (d, id)
}

#[test]
fn assignment_preserves_exact_inputs_and_rejects_stale_export() {
    let (mut d, candidate) = dag(1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let a = d.assignment(lease).unwrap();
    assert_eq!(a.lease(), lease);
    assert_eq!(a.resources(), request());
    assert_eq!(a.job(), &leaf(0));
    assert_eq!(a.manifest(), leaf(0).wallet_inputs());
    let alternate = Job::wrap(0, wallet(1, &[9, 9])).unwrap();
    d.admit(alternate, vec![vec![9, 9]], 0).unwrap();
    assert_eq!(a.inputs[0].as_ref(), [1]);
    d.cancel(candidate, 1).unwrap();
    assert!(d.assignment(lease).is_err());
    // A captured task stays immutable, but cannot override coordinator fencing.
    a.validate().unwrap();
    d.worker_stopped(lease, 2).unwrap();
    assert_eq!(d.status(a.job().id()).unwrap(), JobStatus::Dormant);
}

#[test]
fn assignment_rejects_wrong_job_bytes_manifests_and_arity() {
    let (mut d, _) = dag(2);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let mut a = d.assignment(lease).unwrap();
    a.job = leaf(1);
    assert!(a.validate().is_err());
    let mut a = d.assignment(lease).unwrap();
    a.inputs[0] = Arc::from([2]);
    assert!(a.validate().is_err());
    let mut a = d.assignment(lease).unwrap();
    a.manifest[0] = wallet(1, &[9]).artifact();
    assert!(a.validate().is_err());
    let mut a = d.assignment(lease).unwrap();
    a.inputs.clear();
    assert!(a.validate().is_err());
    let mut a = d.assignment(lease).unwrap();
    a.dependencies.push(leaf(1));
    assert!(a.validate().is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn merge_assignment_binds_both_ordered_children_and_node_bytes() {
    let (mut d, _) = dag(2);
    for i in 0..2 {
        let job = leaf(i);
        d.cache_node(node(&job, &[i + 40]), vec![i + 40], 0)
            .unwrap();
    }
    let job = Job::merge(&leaf(0), &leaf(1)).unwrap();
    let lease = d
        .lease(job.id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let a = d.assignment(lease).unwrap();
    a.validate().unwrap();
    assert_eq!(a.inputs[0].as_ref(), [40]);
    assert_eq!(a.inputs[1].as_ref(), [41]);
    let mut a = d.assignment(lease).unwrap();
    a.dependencies.swap(0, 1);
    assert!(a.validate().is_err());
    let mut a = d.assignment(lease).unwrap();
    a.inputs.swap(0, 1);
    a.manifest.swap(0, 1);
    // Manifest digests are self-consistent here but proof/job checking is still
    // mandatory. Tiny synthetic artifacts never become valid CPU inputs.
    let invalid_registry = Registry {
        height: 8,
        caps: core::array::from_fn(|_| Vec::new()),
    };
    assert!(CpuWorker::new(invalid_registry, pin()).is_err());
    a.dependencies[1] = a.dependencies[0].clone();
    assert!(a.validate().is_err());
}

#[test]
fn cpu_reference_switches_are_explicit_and_fail_closed() {
    use std::ffi::OsStr;
    assert!(cpu_switch(None).is_ok());
    assert!(cpu_switch(Some(OsStr::new("0"))).is_ok());
    for value in ["", "1", "false", " 0", "00"] {
        assert!(cpu_switch(Some(OsStr::new(value))).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert!(cpu_switch(Some(OsStr::from_bytes(&[255]))).is_err());
    }
}

#[cfg(target_os = "linux")]
mod real {
    use super::*;
    use crate::block_v2::execution::{
        artifact_store::{ArtifactStore, StoreLimits},
        dag::Completion,
        journal::{DurableDag, JournalLimits},
        test_fixture,
    };
    use rand::TryRng;
    use std::{
        fs::{self, DirBuilder, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::PathBuf,
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut bytes = [0; 16];
            rand::rngs::SysRng.try_fill_bytes(&mut bytes).unwrap();
            let path = std::env::temp_dir().join(format!(
                "lattica-worker-test-{}",
                crate::block_v2::execution::artifact_store::hex(&bytes)
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
    fn store_limits() -> StoreLimits {
        StoreLimits {
            bytes: 32 * (1 << 20),
            entries: 512,
        }
    }
    fn journal_limits() -> JournalLimits {
        JournalLimits {
            snapshot_bytes: 256 * 1024,
        }
    }
    fn admit(d: &mut DurableDag, f: &test_fixture::Fixture) -> Job {
        let mut nodes = Vec::new();
        for i in 0..4 {
            let job =
                Job::wrap_pair((2 * i) as u8, f.wallets[2 * i], f.wallets[2 * i + 1]).unwrap();
            d.admit(
                job.clone(),
                vec![f.bytes[2 * i].clone(), f.bytes[2 * i + 1].clone()],
                0,
            )
            .unwrap();
            nodes.push(job);
        }
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    let job = Job::merge(&pair[0], &pair[1]).unwrap();
                    d.admit(job.clone(), vec![], 0).unwrap();
                    job
                })
                .collect();
        }
        assert_eq!(nodes[0], f.root);
        let mut root = nodes.pop().unwrap();
        for level in 3..DEPTH {
            let empty = Job::empty(f.pin, [0x5a; 32], 1 << level, level).unwrap();
            d.admit(empty.clone(), vec![], 0).unwrap();
            root = Job::merge(&root, &empty).unwrap();
            d.admit(root.clone(), vec![], 0).unwrap();
        }
        d.attach(root.id(), [1; 32], 7_200_000, 0).unwrap();
        root
    }
    fn owner(temp: &Temp, f: &test_fixture::Fixture, limits: Limits) -> DurableDag {
        let store = ArtifactStore::create(&temp.0.join("store"), store_limits()).unwrap();
        DurableDag::create(
            &temp.0.join("journal"),
            journal_limits(),
            store,
            f.pin,
            [0x5a; 32],
            1,
            limits,
        )
        .unwrap()
    }

    #[test]
    #[ignore = "requires independently pinned public eight-wallet fixture; CPU input verification only"]
    fn cpu_worker_prepares_pinned_inputs_and_rejects_substitution() -> Result<(), Error> {
        let f = test_fixture::load()?;
        let temp = Temp::new();
        let mut d = owner(&temp, &f, limits());
        admit(&mut d, &f);
        let job = Job::wrap_pair(0, f.wallets[0], f.wallets[1])?;
        let lease = d.lease(job.id(), WorkerId(1), request(), 1, 1000, 0)?;
        let worker = CpuWorker::new(f.registry.clone(), f.pin)?;
        assert!(matches!(
            worker.prepare(&d.assignment(lease)?),
            Ok(Inputs::Pair(_))
        ));
        let mut a = d.assignment(lease)?;
        a.inputs.swap(0, 1);
        a.manifest.swap(0, 1);
        assert!(worker.prepare(&a).is_err());
        let mut a = d.assignment(lease)?;
        a.inputs[0] = Arc::from(f.root_bytes.clone());
        a.manifest[0] = node(&job, &f.root_bytes).artifact();
        assert!(worker.prepare(&a).is_err());
        d.worker_stopped(lease, 1)?;
        d.reject_worker(lease, 1)?;
        let empty = Job::empty(f.pin, [0x5a; 32], 32, 5)?;
        let lease = d.lease(empty.id(), WorkerId(1), request(), 1, 1000, 1)?;
        assert!(matches!(
            worker.prepare(&d.assignment(lease)?),
            Ok(Inputs::Empty)
        ));
        Ok(())
    }

    #[test]
    #[cfg(feature = "stream")]
    #[ignore = "full-strength paired-wrapper proving; requires explicitly bounded 44 GiB service and spill workspace"]
    fn cpu_worker_proves_leased_pair_and_owner_reverifies() -> Result<(), Error> {
        if std::env::var("LATTICA_V2_RUN_CPU_WORKER_PROOF").as_deref() != Ok("1") {
            return Err("explicit bounded proving opt-in required".into());
        }
        let output = PathBuf::from(std::env::var("LATTICA_V2_WORKER_TEST_OUTPUT")?);
        let f = test_fixture::load()?;
        let temp = Temp::new();
        let resources = Resources {
            ram_bytes: 44 * (1 << 30),
            vram_bytes: 0,
            scratch_bytes: 120 * (1 << 30),
            threads: 8,
        };
        let config = Limits {
            workers: resources,
            ..limits()
        };
        let mut d = owner(&temp, &f, config);
        admit(&mut d, &f);
        let job = Job::wrap_pair(0, f.wallets[0], f.wallets[1])?;
        let lease = d.lease(job.id(), WorkerId(1), resources, 1, 7_000_000, 0)?;
        let mut worker = CpuWorker::new(f.registry.clone(), f.pin)?;
        let assignment = d.assignment(lease)?;
        let packet = packet::encode_request(&assignment)?;
        let launch_path = temp.0.join("launches");
        let mut launches = crate::block_v2::execution::launch::LaunchStore::create(
            &launch_path,
            crate::block_v2::execution::launch::LaunchLimits { records: 1 },
        )?;
        let token = launches.issue(&mut d, lease, &packet)?;
        let gate =
            crate::block_v2::execution::launch::WorkerGate::enter(&launch_path, &token, &packet)?;
        let started = Instant::now();
        let result = {
            let _spill = crate::spill_alloc::SpillScope::arm();
            worker.execute(&gate, assignment)?
        };
        drop(gate);
        let now = u64::try_from(started.elapsed().as_millis())?;
        assert_eq!(result.lease(), lease);
        assert_eq!(result.job(), job.id());
        assert_eq!(result.stats(), CacheStats { setups: 1, hits: 0 });
        assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
        assert!(crate::spill_alloc::spill_peak_bytes() <= resources.scratch_bytes);
        let timings = result.timings();
        let bytes = result.into_bytes();
        d.worker_stopped(lease, now)?;
        let expected = d.begin_verification(lease, now)?;
        let ticket = VerifiedNode::verify(&expected, &f.registry, &bytes)?;
        assert_eq!(
            d.finish_verification(lease, Some((ticket, bytes.clone())), now)?,
            Completion::Accepted
        );
        assert_eq!(d.status(job.id())?, JobStatus::Completed);
        assert_eq!(d.resource_use()?, Resources::default());
        // Preserve the newly generated public proof for independent replay.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::File::open(output.parent().ok_or("output parent")?)?.sync_all()?;
        drop(d);
        let store = ArtifactStore::open(&temp.0.join("store"), store_limits())?;
        let recovery = DurableDag::recover(
            &temp.0.join("journal"),
            journal_limits(),
            store,
            f.pin,
            &f.registry,
            [0x5a; 32],
            2,
            config,
        )?;
        assert!(recovery.unresolved_attempts().is_empty());
        let d = recovery.resume(|_| panic!("completed local work revived"), || now)?;
        assert_eq!(d.status(job.id())?, JobStatus::Completed);
        println!("cpu_worker_pair_verified bytes={} input_verification_ms={} proving_ms={} serialization_ms={} wall_ms={} spill_peak_bytes={} full_block=false production_ready=false",
            bytes.len(), timings.input_verification_ms, timings.proving_ms, timings.serialization_ms, started.elapsed().as_millis(), crate::spill_alloc::spill_peak_bytes());
        Ok(())
    }

    #[test]
    #[ignore = "requires a separately generated worker pair output and pinned public input fixture"]
    fn cpu_worker_output_replays_in_fresh_process() -> Result<(), Error> {
        let f = test_fixture::load()?;
        let output = PathBuf::from(std::env::var("LATTICA_V2_WORKER_TEST_OUTPUT")?);
        let bytes = test_fixture::read(&output, crate::block_v2::profile::MAX_PROOF_BYTES)?;
        let job = Job::wrap_pair(0, f.wallets[0], f.wallets[1])?;
        VerifiedNode::verify(&job, &f.registry, &bytes)?;
        let swapped = Job::wrap_pair(0, f.wallets[1], f.wallets[0])?;
        assert!(VerifiedNode::verify(&swapped, &f.registry, &bytes).is_err());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(VerifiedNode::verify(&job, &f.registry, &changed).is_err());
        println!("cpu_worker_pair_replayed bytes={} wrong_order_rejected=true mutation_rejected=true production_ready=false", bytes.len());
        Ok(())
    }
}
