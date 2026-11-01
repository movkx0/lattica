use super::*;
use crate::block_v2::machine::{compiler_constants, symbolic};
use p3_uni_stark::StarkGenericConfig;
use std::{marker::PhantomData, time::Instant};

pub struct BorrowedIdentityBatchPlan<'a> {
    authority: Arc<()>,
    batch: u64,
    options: IdentityCpuOptions,
    programs: Vec<(u64, Arc<Program>)>,
    footprint: IdentityBatchFootprint,
    owners: PhantomData<&'a Arc<Program>>,
}
impl IdentityCpuContext {
    pub fn plan_borrowed<'a>(
        &self,
        options: IdentityCpuOptions,
        programs: Vec<(u64, &'a Arc<Program>)>,
        host_allowance: u64,
        managed_allowance: u64,
    ) -> Result<BorrowedIdentityBatchPlan<'a>, String> {
        if programs.is_empty()
            || programs.len() > options.max_streams()
            || programs.capacity() > MAX_IDENTITY_STREAMS
            || host_allowance > 40 << 30
            || managed_allowance > 8 << 30
        {
            return Err("CPU identity admission geometry".into());
        }
        let mut source = 0u64;
        for (i, (job, program)) in programs.iter().enumerate() {
            if programs[..i].iter().any(|(id, _)| job == id) || !program.height().is_power_of_two()
            {
                return Err("CPU identity duplicate job or invalid height".into());
            }
            source = source
                .checked_add(program.source_host_bytes()? as u64)
                .ok_or("CPU identity source overflow")?;
        }
        let footprint =
            IdentityBatchFootprint::for_borrowed_program_bounds(programs.len(), source)?;
        if footprint.host_bytes > host_allowance {
            return Err("CPU identity exceeds admitted memory".into());
        }
        let mut shared = Vec::new();
        shared
            .try_reserve_exact(programs.len())
            .map_err(|_| "CPU identity handles allocation")?;
        if shared.capacity() > MAX_IDENTITY_STREAMS {
            return Err("CPU identity handles capacity".into());
        }
        for (job, program) in programs {
            shared.push((job, Arc::clone(program)));
        }
        let batch = self
            .next_batch
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "CPU identity ordinal overflow")?;
        Ok(BorrowedIdentityBatchPlan {
            authority: Arc::clone(&self.authority),
            batch,
            options,
            programs: shared,
            footprint,
            owners: PhantomData,
        })
    }
}
struct Prepared {
    job: u64,
    program: Arc<Program>,
    air: MachineAir,
    analysis: analysis::MachineAnalysis,
    fingerprint: Vec<u64>,
    fields: usize,
    cap_fields: usize,
}
pub struct PendingBorrowedIdentityBatch<'a> {
    authority: Arc<()>,
    batch: u64,
    options: IdentityCpuOptions,
    prepared: Vec<Prepared>,
    footprint: IdentityBatchFootprint,
    analysis_ns: u128,
    analysis_report: Report,
    fence: crate::block_v2::gpu_hash::device::RetirementFence,
    owners: PhantomData<&'a Arc<Program>>,
}
impl<'a> BorrowedIdentityBatchPlan<'a> {
    pub fn footprint(&self) -> IdentityBatchFootprint {
        self.footprint
    }
    /// Coordinator-only symbolic analysis; this performs no identity hashing.
    pub fn execute(self, request: Request) -> Result<PendingBorrowedIdentityBatch<'a>, String> {
        if request.policy != Policy::GpuRequired {
            return Err("identity source analysis requires GPU policy".into());
        }
        crate::block_v2::machine::gpu_backend::check_selected()?;
        let _phase = crate::block_v2::worker_memory::PhaseGuard::acquire("preprocessing")?;
        let mut caps = Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, false)
            .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
        caps.set(Stage::Preprocessing, Backend::OpenCl);
        let run = Run::new("block_v2_identity_source_analysis", request, caps)
            .map_err(|e| e.to_string())?;
        let started = Instant::now();
        let config =
            profile::preprocessing_config_with_host_budget(self.footprint.host_bytes as usize)
                .map_err(|e| e.to_string())?;
        let session = config.pcs().quotient_session()?;
        let fence = session.retirement_fence();
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(self.programs.len())
            .map_err(|_| "CPU identity descriptors allocation")?;
        for (job, program) in self.programs {
            let air = MachineAir::from_shared_program(Arc::clone(&program));
            let symbolic = symbolic::prepare_machine(
                &air,
                compiler_constants::Constants::device(&session, &run),
            )
            .map_err(|e| format!("CPU prefix analysis: {e:?}"))?;
            let analysis = analysis::analyze_prepared(&air, &symbolic)
                .map_err(|e| format!("CPU prefix analysis: {e:?}"))?;
            let (_, constraints) = symbolic.into_parts();
            let fingerprint = fingerprint::bounded::encode(
                &constraints.base,
                &constraints.extension,
                &constraints.order,
                fingerprint::bounded::HOST_BYTES,
            )?;
            let fields = prefix_len(&air, &analysis, &fingerprint)?;
            let cap_fields = 4usize
                << ((air.program().height().ilog2() as usize + 1 + profile::LOG_BLOWUP)
                    .min(profile::CAP_HEIGHT));
            fields
                .checked_add(cap_fields)
                .ok_or("CPU prefix length overflow")?;
            prepared.push(Prepared {
                job,
                program,
                air,
                analysis,
                fingerprint,
                fields,
                cap_fields,
            });
        }
        let analysis_ns = started.elapsed().as_nanos();
        let analysis_report = run.finish(true).map_err(|e| e.to_string())?;
        Ok(PendingBorrowedIdentityBatch {
            authority: self.authority,
            batch: self.batch,
            options: self.options,
            prepared,
            footprint: self.footprint,
            analysis_ns,
            analysis_report,
            fence,
            owners: PhantomData,
        })
    }
}
#[derive(serde::Serialize)]
pub struct CpuWorkerReport {
    pub job: u64,
    pub fields: u64,
    pub elapsed_ns: u128,
}
#[derive(serde::Serialize)]
pub struct IdentityBatchReport {
    pub schema: &'static str,
    pub batch: u64,
    pub streams: usize,
    pub requested_workers: Option<usize>,
    pub effective_workers: usize,
    pub peak_active_workers: usize,
    pub analysis_ns: u128,
    pub hash_wall_ns: u128,
    pub worker_elapsed_ns: u128,
    pub fields: u64,
    pub footprint: IdentityBatchFootprint,
    pub analysis: Report,
    pub cpu: Report,
    pub workers: Vec<CpuWorkerReport>,
}
impl PendingBorrowedIdentityBatch<'_> {
    pub fn complete_after_retirement(
        self,
    ) -> Result<(Vec<CompletedIdentityPrefix>, IdentityBatchReport), String> {
        self.complete_with_cancellation(&AtomicBool::new(false))
    }
    /// Cancellation is cooperative and always joins workers before releasing
    /// descriptors, fingerprints, stacks or the caller's original owners.
    pub fn complete_with_cancellation(
        self,
        cancel: &AtomicBool,
    ) -> Result<(Vec<CompletedIdentityPrefix>, IdentityBatchReport), String> {
        if !self.fence.retired() {
            return Err("CPU workers require retired GPU analysis epoch".into());
        }
        let count = self.prepared.len();
        if count > physical_core_count().unwrap_or(1) {
            return Err("CPU affinity changed after admission".into());
        }
        let run = cpu_run("block_v2_cpu_identity_prefixes")?;
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let started = Instant::now();
        let outputs = run
            .measure(Stage::Preprocessing, Backend::Cpu, || {
                execute_workers(self.prepared, cancel, &active, &peak, |p, cancel| {
                    let started = Instant::now();
                    let mut state = State::new(DOMAIN, p.fields + p.cap_fields)
                        .map_err(|e| format!("{e:?}"))?;
                    for (i, field) in
                        identity_stream::Cursor::new(&p.air, &p.analysis, &p.fingerprint)
                            .enumerate()
                    {
                        if i % 1024 == 0 && cancel.load(Ordering::Acquire) {
                            return Err("CPU identity cancelled".into());
                        }
                        state.push(field?).map_err(|e| format!("{e:?}"))?;
                    }
                    let report = CpuWorkerReport {
                        job: p.job,
                        fields: p.fields as u64,
                        elapsed_ns: started.elapsed().as_nanos(),
                    };
                    let token = CompletedIdentityPrefix {
                        authority: Arc::clone(&self.authority),
                        batch: self.batch,
                        job: p.job,
                        header: identity_stream::header(&p.air),
                        trailer: identity_stream::trailer(&p.analysis),
                        program: p.program,
                        fingerprint: p.fingerprint,
                        cap_fields: p.cap_fields,
                        state,
                    };
                    Ok((token, report))
                })
            })
            .map_err(|e| e.to_string())??;
        let hash_wall_ns = started.elapsed().as_nanos();
        let mut tokens = Vec::new();
        let mut workers = Vec::new();
        tokens
            .try_reserve_exact(count)
            .map_err(|_| "CPU token result allocation")?;
        workers
            .try_reserve_exact(count)
            .map_err(|_| "CPU worker report allocation")?;
        let mut fields = 0u64;
        let mut worker_elapsed_ns = 0u128;
        for (token, report) in outputs {
            fields = fields
                .checked_add(report.fields)
                .ok_or("CPU field total overflow")?;
            worker_elapsed_ns = worker_elapsed_ns
                .checked_add(report.elapsed_ns)
                .ok_or("CPU timing total overflow")?;
            tokens.push(token);
            workers.push(report);
        }
        let report = IdentityBatchReport {
            schema: "identity-cpu-prefix-v1",
            batch: self.batch,
            streams: count,
            requested_workers: self.options.requested_workers,
            effective_workers: count,
            peak_active_workers: peak.load(Ordering::Acquire),
            analysis_ns: self.analysis_ns,
            hash_wall_ns,
            worker_elapsed_ns,
            fields,
            footprint: self.footprint,
            analysis: self.analysis_report,
            cpu: run.finish(true).map_err(|e| e.to_string())?,
            workers,
        };
        Ok((tokens, report))
    }
}

// Exactly one job per scoped worker, bounded by admission. Results retain input
// order regardless of completion order. No Rayon/global pool or shared Run.
fn execute_workers<T: Send, R: Send, F: Fn(T, &AtomicBool) -> Result<R, String> + Sync>(
    jobs: Vec<T>,
    cancel: &AtomicBool,
    active: &AtomicUsize,
    peak: &AtomicUsize,
    work: F,
) -> Result<Vec<R>, String> {
    execute_workers_with_spawn_limit(jobs, cancel, active, peak, work, None)
}

fn execute_workers_with_spawn_limit<
    T: Send,
    R: Send,
    F: Fn(T, &AtomicBool) -> Result<R, String> + Sync,
>(
    jobs: Vec<T>,
    cancel: &AtomicBool,
    active: &AtomicUsize,
    peak: &AtomicUsize,
    work: F,
    spawn_limit: Option<usize>,
) -> Result<Vec<R>, String> {
    if jobs.is_empty() || jobs.len() > MAX_IDENTITY_STREAMS || cancel.load(Ordering::Acquire) {
        return Err("CPU identity empty cohort or cancellation".into());
    }
    let count = jobs.len();
    let mut results = Vec::new();
    results
        .try_reserve_exact(count)
        .map_err(|_| "CPU results allocation")?;
    if count == 1 {
        peak.store(1, Ordering::Release);
        results.push(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                work(jobs.into_iter().next().unwrap(), cancel)
            }))
            .map_err(|_| "CPU identity inline panic")??,
        );
        return Ok(results);
    }
    let start = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(count)
            .map_err(|_| "CPU thread handles allocation")?;
        let mut error = None;
        for (index, job) in jobs.into_iter().enumerate() {
            if spawn_limit == Some(index) {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                error = Some("CPU identity injected spawn failure".into());
                break;
            }
            if cancel.load(Ordering::Acquire) || failed.load(Ordering::Acquire) {
                error = Some("CPU identity cancelled".to_string());
                break;
            }
            let (work, start, failed) = (&work, &start, &failed);
            match std::thread::Builder::new()
                .stack_size(WORKER_STACK_BYTES as usize)
                .spawn_scoped(scope, move || {
                    while !start.load(Ordering::Acquire)
                        && !failed.load(Ordering::Acquire)
                        && !cancel.load(Ordering::Acquire)
                    {
                        std::thread::yield_now();
                    }
                    if failed.load(Ordering::Acquire) || cancel.load(Ordering::Acquire) {
                        return Err("CPU identity cancelled".into());
                    }
                    let n = active.fetch_add(1, Ordering::AcqRel) + 1;
                    peak.fetch_max(n, Ordering::AcqRel);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        work(job, cancel)
                    }))
                    .unwrap_or_else(|_| Err("CPU identity worker panic".into()));
                    active.fetch_sub(1, Ordering::AcqRel);
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                        cancel.store(true, Ordering::Release);
                    }
                    result
                }) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    failed.store(true, Ordering::Release);
                    cancel.store(true, Ordering::Release);
                    error = Some("CPU identity worker spawn failed".into());
                    break;
                }
            }
        }
        start.store(true, Ordering::Release);
        for handle in handles {
            match handle
                .join()
                .unwrap_or_else(|_| Err("CPU identity worker panic".into()))
            {
                Ok(result) => results.push(result),
                Err(e) => {
                    if error.is_none() {
                        error = Some(e);
                    }
                }
            }
        }
        if let Some(error) = error {
            Err(error)
        } else if cancel.load(Ordering::Acquire) {
            Err("CPU identity cancelled".into())
        } else {
            Ok(results)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_worker_widths_execute_concurrently_and_preserve_order() {
        for width in [1usize, 2, 4, 8, 16] {
            for count in [width, width.saturating_sub(1).max(1), 1] {
                let barrier = std::sync::Barrier::new(count);
                let active = AtomicUsize::new(0);
                let peak = AtomicUsize::new(0);
                let result = execute_workers(
                    (0..count).collect(),
                    &AtomicBool::new(false),
                    &active,
                    &peak,
                    |n, _| {
                        barrier.wait();
                        Ok(n)
                    },
                )
                .unwrap();
                assert_eq!(result, (0..count).collect::<Vec<_>>());
                assert_eq!(peak.load(Ordering::Acquire), count);
                assert_eq!(active.load(Ordering::Acquire), 0);
            }
        }
    }
    #[test]
    fn failure_cancellation_and_panics_join_before_releasing_owners() {
        struct Owner(Arc<AtomicUsize>, usize);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        for mode in 0..5 {
            let dropped = Arc::new(AtomicUsize::new(0));
            let active = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let cancel = AtomicBool::new(mode == 0);
            let owners = (0..8).map(|n| Owner(Arc::clone(&dropped), n)).collect();
            let result = execute_workers_with_spawn_limit(
                owners,
                &cancel,
                &active,
                &peak,
                |owner, cancel| {
                    if owner.1 == 0 {
                        match mode {
                            1 => return Err("invalid input".into()),
                            2 => panic!("injected worker panic"),
                            3 => cancel.store(true, Ordering::Release),
                            _ => {}
                        }
                    }
                    Ok(())
                },
                if mode == 4 { Some(3) } else { None },
            );
            assert!(result.is_err());
            assert_eq!(active.load(Ordering::Acquire), 0);
            assert_eq!(dropped.load(Ordering::Acquire), 8);
        }
    }
}
