//! Opt-in matched-workload instrumentation, not a scheduler or block benchmark.
//! Cold means cleared preprocessing in the same reserved process, not cold OS caches.
use super::*;
use crate::block_v2::{commitment, recursive::WrapperConstruction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    ColdPreprocessing,
    Retained,
}

impl Policy {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "cold-preprocessing" => Ok(Self::ColdPreprocessing),
            "retained" => Ok(Self::Retained),
            _ => Err("explicit cache benchmark policy required".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::ColdPreprocessing => "cold-preprocessing",
            Self::Retained => "retained",
        }
    }
    fn expected(self, modes: &[u64]) -> CacheStats {
        let mut stats = CacheStats::default();
        let mut prior = None;
        for &mode in modes {
            if self == Self::Retained && prior == Some(mode) {
                stats.hits += 1;
            } else {
                stats.setups += 1;
            }
            prior = Some(mode);
        }
        stats
    }
    fn prepare(self, worker: &mut CachedCpuWorker) -> Result<(), Error> {
        worker.reservation.require_idle()?;
        if self == Self::ColdPreprocessing {
            worker
                .session
                .as_mut()
                .ok_or("closed benchmark cache")?
                .clear();
            if crate::spill_alloc::spill_stats() != (0, 0) {
                return Err("cold preprocessing control retained mapped storage".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Workload {
    PairedFour,
    PairedEightGrouped,
    PairedEightInterleaved,
    PaddedFour,
    SingleThree,
}

impl Workload {
    const ALL: [Self; 5] = [
        Self::PairedFour,
        Self::PairedEightGrouped,
        Self::PairedEightInterleaved,
        Self::PaddedFour,
        Self::SingleThree,
    ];
    fn parse(value: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|workload| workload.name() == value)
            .ok_or_else(|| "unknown cache benchmark workload".into())
    }
    fn name(self) -> &'static str {
        match self {
            Self::PairedFour => "paired-four",
            Self::PairedEightGrouped => "paired-eight-grouped",
            Self::PairedEightInterleaved => "paired-eight-interleaved",
            Self::PaddedFour => "padded-four",
            Self::SingleThree => "single-three",
        }
    }
    fn count(self) -> usize {
        match self {
            Self::PairedFour | Self::PaddedFour => 4,
            Self::PairedEightGrouped | Self::PairedEightInterleaved => 8,
            Self::SingleThree => 3,
        }
    }
    /// (level, start). Every job is an ancestor of the final measured subtree.
    /// The attached selection remains depth six, but is deliberately not completed.
    fn positions(self) -> &'static [(u8, u8)] {
        match self {
            Self::PairedFour => &[(1, 0), (1, 2), (2, 0)],
            Self::PairedEightGrouped => &[(1, 0), (1, 2), (1, 4), (1, 6), (2, 0), (2, 4), (3, 0)],
            Self::PairedEightInterleaved => {
                &[(1, 0), (1, 2), (2, 0), (1, 4), (1, 6), (2, 4), (3, 0)]
            }
            Self::PaddedFour => &[(1, 0), (1, 2), (2, 0), (2, 4), (3, 0)],
            Self::SingleThree => &[(0, 0), (0, 1), (1, 0), (0, 2), (0, 3), (1, 2), (2, 0)],
        }
    }
    fn modes(self) -> &'static [u64] {
        match self {
            Self::PairedFour => &[1, 1, 3],
            Self::PairedEightGrouped => &[1, 1, 1, 1, 3, 3, 3],
            Self::PairedEightInterleaved => &[1, 1, 3, 1, 1, 3, 3],
            Self::PaddedFour => &[1, 1, 3, 2, 3],
            Self::SingleThree => &[1, 1, 3, 1, 2, 3, 3],
        }
    }
    fn load(self) -> Result<test_fixture::PublicFixture, Error> {
        if self == Self::SingleThree {
            test_fixture::load_single_public()
        } else {
            let f = test_fixture::load()?;
            Ok(test_fixture::PublicFixture {
                registry: f.registry,
                pin: f.pin,
                wallets: f.wallets,
                bytes: f.bytes,
            })
        }
    }
    fn selection(self, f: &test_fixture::PublicFixture) -> Result<(Selection, Vec<Job>), Error> {
        if (self == Self::SingleThree)
            != (f.pin.construction() == WrapperConstruction::SingleWallet)
            || f.wallets.len() < self.count()
            || f.bytes.len() < self.count()
        {
            return Err("benchmark fixture/construction mismatch".into());
        }
        let inputs = f.wallets[..self.count()]
            .iter()
            .zip(&f.bytes[..self.count()])
            .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let selection = Selection::new(f.pin, [0x5a; 32], &inputs)?;
        let mut jobs = Vec::new();
        for (&(level, start), &mode) in self.positions().iter().zip(self.modes()) {
            let job = selection
                .jobs()
                .find(|job| job.start() == start && job.expected().level == level)
                .ok_or("benchmark job missing")?;
            if job.operation().proof_mode() != mode
                || jobs.iter().any(|prior: &Job| prior.id() == job.id())
                || job
                    .dependencies()
                    .iter()
                    .any(|id| !jobs.iter().any(|prior| prior.id() == *id))
            {
                return Err("benchmark order/mode/dependency mismatch".into());
            }
            jobs.push(job.clone());
        }
        if jobs.len() != self.positions().len()
            || jobs.len() != self.modes().len()
            || jobs.last().ok_or("empty benchmark")?.expected().count as usize != self.count()
        {
            return Err("benchmark coverage mismatch".into());
        }
        Ok((selection, jobs))
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    crate::block_v2::execution::artifact_store::hex(bytes)
}

#[test]
fn cache_bench_policy_and_workload_options_fail_closed() {
    assert!(Policy::parse("").is_err());
    assert!(Policy::parse("cold").is_err());
    assert!(Workload::parse("full64").is_err());
    for policy in [Policy::ColdPreprocessing, Policy::Retained] {
        assert_eq!(Policy::parse(policy.name()).unwrap(), policy);
    }
    for workload in Workload::ALL {
        assert_eq!(Workload::parse(workload.name()).unwrap(), workload);
        assert_eq!(workload.positions().len(), workload.modes().len());
        assert!(workload.positions().iter().all(|&(level, _)| level < 6));
    }
}

#[test]
fn cache_bench_models_repeated_programs_and_mode_evictions() {
    for (workload, setups, hits) in [
        (Workload::PairedFour, 2, 1),
        (Workload::PairedEightGrouped, 2, 5),
        (Workload::PairedEightInterleaved, 4, 3),
        (Workload::PaddedFour, 4, 1),
        (Workload::SingleThree, 5, 2),
    ] {
        assert_eq!(
            Policy::Retained.expected(workload.modes()),
            CacheStats { setups, hits }
        );
        assert_eq!(
            Policy::ColdPreprocessing.expected(workload.modes()),
            CacheStats {
                setups: workload.modes().len() as u64,
                hits: 0,
            }
        );
    }
}

#[test]
#[ignore = "requires pinned grouped/single public fixtures; no preprocessing or proving"]
fn cpu_cache_bench_preflight_validates_all_workloads_and_idle_reset() -> Result<(), Error> {
    for workload in Workload::ALL {
        let f = workload.load()?;
        let (selection, jobs) = workload.selection(&f)?;
        let temp = Temp::new();
        let mut d = owner_for_pin(&temp.0, f.pin)?;
        let candidate = selection.attach(&mut d, [1; 32], 7_200_000, 0)?;
        let mut worker = CachedCpuWorker::new(&mut d, f.registry, f.pin, WorkerId(100), 0)?;
        Policy::ColdPreprocessing.prepare(&mut worker)?;
        let lease = d.lease(jobs[0].id(), WorkerId(1), JOB_RESOURCES, 1, 1000, 0)?;
        let task = worker.task(&mut d, lease, 0)?;
        assert!(Policy::ColdPreprocessing.prepare(&mut worker).is_err());
        assert!(Policy::Retained.prepare(&mut worker).is_err());
        drop(task);
        d.reject_worker(lease, 1)?;
        d.worker_stopped(lease, 1)?; // No token issued or computation launched.
        Policy::ColdPreprocessing.prepare(&mut worker)?;
        Policy::Retained.prepare(&mut worker)?;
        assert_eq!(worker.stats()?, CacheStats::default());
        worker.close(&mut d, 2)?;
        assert!(Policy::ColdPreprocessing.prepare(&mut worker).is_err());
        assert!(Policy::Retained.prepare(&mut worker).is_err());
        d.cancel(candidate, 3)?;
        assert_eq!(d.resource_use()?, Resources::default());
        println!(
            "cache_bench_preflight=PASS workload={} jobs={} actual_preprocessing=false",
            workload.name(),
            jobs.len()
        );
    }
    Ok(())
}

#[test]
#[ignore = "explicit bounded full-strength cache comparison arm; not full-block qualification"]
fn cpu_cache_bench_runs_one_public_workload_arm() -> Result<(), Error> {
    if std::env::var("LATTICA_V2_CACHE_BENCH_RUN").as_deref() != Ok("1") {
        return Err("explicit cache benchmark proving opt-in required".into());
    }
    let policy = Policy::parse(&std::env::var("LATTICA_V2_CACHE_BENCH_POLICY")?)?;
    let workload = Workload::parse(&std::env::var("LATTICA_V2_CACHE_BENCH_WORKLOAD")?)?;
    let output = PathBuf::from(std::env::var("LATTICA_V2_CACHED_OUTPUT")?);
    let whole = Instant::now();
    let f = workload.load()?;
    let (selection, jobs) = workload.selection(&f)?;
    let mut d = owner_for_pin(&output, f.pin)?;
    let candidate = selection.attach(&mut d, [1; 32], 7_200_000, 0)?;
    let path = output.join("launches");
    let mut launches = LaunchStore::create(
        &path,
        LaunchLimits {
            records: jobs.len(),
        },
    )?;
    let mut worker = CachedCpuWorker::new(&mut d, f.registry.clone(), f.pin, WorkerId(100), 0)?;
    assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
    crate::spill_alloc::reset_spill_peak();
    let prepared_ms = whole.elapsed().as_millis();
    let mut now = u64::try_from(prepared_ms)?;
    println!("cache_bench_start=PASS workload={} policy={} jobs={} profile={} prepared_ms={prepared_ms} full_block=false process_cold=false", workload.name(), policy.name(), jobs.len(), hex(&f.pin.profile()));
    for (i, job) in jobs.iter().enumerate() {
        let started = Instant::now();
        policy.prepare(&mut worker)?;
        let lease = d.lease(
            job.id(),
            WorkerId(i as u64 + 1),
            JOB_RESOURCES,
            1,
            7_200_000,
            now,
        )?;
        let task = worker.task(&mut d, lease, now)?;
        let packet = task.request()?;
        let token = launches.issue(&mut d, lease, &packet)?;
        let gate = WorkerGate::enter(&path, &token, &packet)?;
        let completed = worker.execute(gate, task)?;
        now = u64::try_from(whole.elapsed().as_millis())?;
        let report = completed.acknowledge(&mut d, now)?;
        assert_eq!(report.lease(), lease);
        assert_eq!(report.job(), job.id());
        let expected = policy.expected(&workload.modes()[..=i]);
        assert_eq!(worker.stats()?, expected);
        let previous = policy.expected(&workload.modes()[..i]);
        assert_eq!(
            report.stats(),
            CacheStats {
                setups: expected.setups - previous.setups,
                hits: expected.hits - previous.hits
            }
        );
        let timings = report.timings();
        let bytes = report.into_bytes();
        let verification = Instant::now();
        let checked = d
            .begin_guarded_verification(lease, now)?
            .verify(&f.registry, bytes.clone());
        assert!(checked.error().is_none());
        now = u64::try_from(whole.elapsed().as_millis())?;
        assert_eq!(
            d.finish_guarded_verification(checked, now)?,
            Completion::Accepted
        );
        let acceptance_ms = verification.elapsed().as_millis();
        assert_eq!(d.status(job.id())?, JobStatus::Completed);
        assert_eq!(d.resource_use()?, WORKSPACE_RESOURCES);
        let publication = Instant::now();
        publish(&output.join(format!("job-{i:02}.proof")), &bytes)?;
        let revoked = launches.revoke(lease)?;
        assert!(launches.try_idle(&revoked)?.is_some());
        let publication_ms = publication.elapsed().as_millis();
        assert!(!crate::spill_alloc::is_armed());
        let (mappings, live) = crate::spill_alloc::spill_stats();
        assert!(mappings > 0 && live > 0);
        assert!(crate::spill_alloc::spill_peak_bytes() <= WORKSPACE_RESOURCES.scratch_bytes);
        now = u64::try_from(whole.elapsed().as_millis())?;
        println!("cache_bench_job=PASS index={i} job={} mode={} level={} start={} count={} bytes={} input_verification_ms={} proving_ms={} serialization_ms={} owner_acceptance_ms={acceptance_ms} publication_revoke_ms={publication_ms} job_elapsed_ms={} elapsed_ms={now} cache_setups={} cache_hits={} retained_mapped_bytes={live} spill_peak_bytes={}", hex(&job.id().to_bytes()), job.operation().proof_mode(), job.expected().level, job.start(), job.expected().count, bytes.len(), timings.input_verification_ms, timings.proving_ms, timings.serialization_ms, started.elapsed().as_millis(), expected.setups, expected.hits, crate::spill_alloc::spill_peak_bytes());
    }
    let stats = worker.stats()?;
    worker.close(&mut d, now)?;
    d.cancel(candidate, u64::try_from(whole.elapsed().as_millis())?)?;
    assert_eq!(d.resource_use()?, Resources::default());
    assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
    assert!(!crate::spill_alloc::is_armed());
    let last = jobs.last().ok_or("empty benchmark")?;
    println!("cache_bench_complete=PASS workload={} policy={} proofs={} cache_setups={} cache_hits={} prepared_ms={prepared_ms} complete_elapsed_ms={} subtree_level={} subtree_count={} subtree_root={} cache_closed=true spill_live_bytes=0 full_block=false matched_speedup=false production_ready=false", workload.name(), policy.name(), jobs.len(), stats.setups, stats.hits, whole.elapsed().as_millis(), last.expected().level, last.expected().count, hex(&commitment::digest_bytes(last.expected().root)?));
    Ok(())
}

#[test]
#[ignore = "requires a completed cache benchmark arm and pinned public fixtures"]
fn cpu_cache_bench_replays_every_output_in_fresh_process() -> Result<(), Error> {
    let workload = Workload::parse(&std::env::var("LATTICA_V2_CACHE_BENCH_WORKLOAD")?)?;
    let output = PathBuf::from(std::env::var("LATTICA_V2_CACHED_OUTPUT")?);
    let f = workload.load()?;
    let (_, jobs) = workload.selection(&f)?;
    for (i, job) in jobs.iter().enumerate() {
        let bytes = test_fixture::read(
            &output.join(format!("job-{i:02}.proof")),
            crate::block_v2::profile::MAX_PROOF_BYTES,
        )?;
        VerifiedNode::verify(job, &f.registry, &bytes)?;
        assert!(VerifiedNode::verify(&jobs[(i + 1) % jobs.len()], &f.registry, &bytes).is_err());
        let mut mutated = bytes;
        *mutated.last_mut().ok_or("empty benchmark proof")? ^= 1;
        assert!(VerifiedNode::verify(job, &f.registry, &mutated).is_err());
    }
    println!("cache_bench_replay=PASS workload={} proofs={} wrong_job_rejected=true mutation_rejected=true root_only_block_replay=false", workload.name(), jobs.len());
    Ok(())
}
