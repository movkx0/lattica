//! Compiler growth is reserved for active jobs. Idle slots retain only their
//! measured map backing; the owning worker must drop it before credit returns.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Maintenance jobs are queue work, but do not count as active compilers.
struct CompilerActivity {
    active: AtomicUsize,
    peak: AtomicUsize,
}
impl CompilerActivity {
    fn enter(&self) -> CompilerLease<'_> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        CompilerLease(self)
    }
}
struct CompilerLease<'a>(&'a CompilerActivity);
impl Drop for CompilerLease<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) enum Job {
    Compile {
        index: usize,
        cap: usize,
        compatible: bool,
    },
    Trim,
}
pub(super) struct Output {
    result: Option<(usize, Result<NativeCoreBound, CompileError>)>,
    retained: usize,
    reuses: u64,
    trimmed: usize,
    preparation_ns: u128,
    prepared_bytes: usize,
}
#[derive(Clone, Copy)]
enum Task {
    Idle,
    Compile(usize),
    Trim,
}
pub(super) struct State {
    tasks: [Task; cpu_queue::MAX_WORKERS],
    graphs: [usize; cpu_queue::MAX_WORKERS],
    compiler: [usize; cpu_queue::MAX_WORKERS],
    grants: [usize; cpu_queue::MAX_WORKERS],
    used: [bool; cpu_queue::MAX_WORKERS],
    preparing: [bool; cpu_queue::MAX_WORKERS],
    layout: [Option<super::super::NativeGeometry>; cpu_queue::MAX_WORKERS],
    dispatched: [bool; MAX],
    active: usize,
    failure: Option<CompileError>,
}
fn workspace_error(
    _: lattica_prover_p3::block_v2::machine::program::ExecutionError,
) -> CompileError {
    CompileError::Shape("native compiler workspace state")
}
impl State {
    fn new() -> Self {
        Self {
            tasks: [Task::Idle; cpu_queue::MAX_WORKERS],
            graphs: [0; cpu_queue::MAX_WORKERS],
            compiler: [0; cpu_queue::MAX_WORKERS],
            grants: [0; cpu_queue::MAX_WORKERS],
            used: [false; cpu_queue::MAX_WORKERS],
            preparing: [false; cpu_queue::MAX_WORKERS],
            layout: [None; cpu_queue::MAX_WORKERS],
            dispatched: [false; MAX],
            active: 0,
            failure: None,
        }
    }
    fn live(&self, base: usize) -> Result<usize, CompileError> {
        self.graphs
            .iter()
            .chain(&self.compiler)
            .try_fold(base, |sum, &n| add(sum, n))
    }
    fn retire(
        &mut self,
        event: cpu_queue::Event<Result<Output, CompileError>>,
        results: &mut [Option<NativeCoreBound>; MAX],
        desired: &mut [usize; MAX],
        limits: ConstructionLimits,
        storage: &[Option<NativePlanningStorage>; MAX],
        prepared: &[AtomicUsize; cpu_queue::MAX_WORKERS],
        stats: &mut Statistics,
    ) -> Result<(), CompileError> {
        let done = match event {
            cpu_queue::Event::Completed(done) => done,
            cpu_queue::Event::Progress(slot) => {
                let bytes = prepared[slot].load(Ordering::Acquire);
                if !matches!(self.tasks[slot], Task::Compile(_))
                    || bytes == 0
                    || bytes > self.graphs[slot]
                {
                    return Err(CompileError::Shape("native preparation phase receipt"));
                }
                // Scratch and excess old backing were dropped before publication.
                self.graphs[slot] = bytes;
                self.compiler[slot] = self.grants[slot];
                self.preparing[slot] = false;
                return Ok(());
            }
        };
        let slot = done.slot;
        let task = self.tasks[slot];
        if matches!(task, Task::Idle) {
            return Err(CompileError::Shape("native duplicate completion"));
        }
        self.tasks[slot] = Task::Idle;
        self.preparing[slot] = false;
        self.active -= 1;
        self.graphs[slot] = 0; // worker has dropped the prepared owner
        let output = match done.result {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                self.failure.get_or_insert(error);
                return Ok(());
            }
            Err(_) => {
                self.failure
                    .get_or_insert(CompileError::Shape("native metadata worker panic"));
                return Ok(());
            }
        };
        if output.retained > self.compiler[slot] {
            return Err(CompileError::ResourceAdmission(
                "native retained compiler census",
            ));
        }
        self.compiler[slot] = output.retained;
        stats.idle_compiler_bytes_peak = stats.idle_compiler_bytes_peak.max(
            self.compiler
                .iter()
                .zip(&self.tasks)
                .filter(|(_, t)| matches!(t, Task::Idle))
                .map(|(&b, _)| b)
                .sum(),
        );
        stats.workspace_reuses += output.reuses;
        stats.trimmed_compiler_bytes += output.trimmed as u64;
        stats.preparation_ns += output.preparation_ns;
        stats.retained_worker_bytes_peak =
            stats.retained_worker_bytes_peak.max(output.prepared_bytes);
        match (task, output.result) {
            (Task::Trim, None) => {}
            (Task::Compile(expected), Some((i, result))) if expected == i => {
                stats.job_ns[i] += done.elapsed_ns;
                match result {
                    Ok(value) => results[i] = Some(value),
                    Err(CompileError::ResourceAdmission(uni::shape::NATIVE_PROGRAM_BYTE_LIMIT))
                        if self.grants[slot] < limits.max_requested_program_bytes =>
                    {
                        desired[i] = self.grants[slot]
                            .saturating_mul(2)
                            .min(limits.max_requested_program_bytes);
                        self.dispatched[i] = false;
                        stats.budget_reductions += 1;
                        // Learn only within this exact public geometry. A hint is
                        // never allocation authority: every retry is readmitted.
                        for j in 0..MAX {
                            if !self.dispatched[j]
                                && storage[j].map(|s| s.geometry) == storage[i].map(|s| s.geometry)
                            {
                                desired[j] = desired[j].max(desired[i]);
                            }
                        }
                    }
                    Err(error) => {
                        self.failure.get_or_insert(error);
                    }
                }
            }
            _ => return Err(CompileError::Shape("native completion binding")),
        }
        Ok(())
    }
}

pub(super) fn run_accounted<P: Send>(
    storage: &[Option<NativePlanningStorage>; MAX],
    duplicates: &[Option<usize>; MAX],
    count: usize,
    limits: ConstructionLimits,
    budget: usize,
    shared: usize,
    ceiling: usize,
    results: &mut [Option<NativeCoreBound>; MAX],
    stats: &mut Statistics,
    prepare: impl Fn(usize) -> Result<P, CompileError> + Sync,
    retained: impl Fn(usize, &P) -> Result<usize, CompileError> + Sync,
    compile: impl Fn(usize, &P, usize) -> Result<NativeCoreBound, CompileError> + Sync,
) -> Result<(), CompileError> {
    let mut desired = [0; MAX];
    for i in 0..count {
        desired[i] = initial_cap(storage[i].unwrap(), limits);
    }
    let prep_bound = |i: usize| {
        add(
            worker_bytes(storage[i].unwrap())?,
            storage[i].unwrap().symbolic_workspace_bytes,
        )
    };
    loop {
        let mut indices = [0; MAX];
        let mut ready = 0;
        for i in 0..count {
            if results[i].is_none() && duplicates[i].is_none() {
                indices[ready] = i;
                ready += 1;
            }
        }
        if ready == 0 {
            return Ok(());
        }
        indices[..ready]
            .sort_unstable_by_key(|&i| (core::cmp::Reverse(work(storage[i].unwrap())), i));
        let base = add(COORDINATOR, shared)?;
        // Preparation finishes before this job starts compiling. Charge the
        // maximum of those two phases, while other jobs retain their full cost.
        let largest_job = indices[..ready].iter().try_fold(0usize, |largest, &i| {
            Ok::<_, CompileError>(
                largest
                    .max(prep_bound(i)?.max(add(worker_bytes(storage[i].unwrap())?, desired[i])?)),
            )
        })?;
        let width = (2..=ceiling.min(ready).min(cpu_queue::MAX_WORKERS))
            .rev()
            .find(|&n| {
                base.checked_add(n * THREAD)
                    .and_then(|b| b.checked_add(largest_job))
                    .is_some_and(|b| b <= budget)
            })
            .unwrap_or(1);
        stats.cohorts += 1;
        if width == 1 {
            let i = indices[0];
            let peak = add(
                base,
                prep_bound(i)?.max(add(
                    worker_bytes(storage[i].unwrap())?,
                    limits.max_requested_program_bytes,
                )?),
            )?;
            if peak > budget {
                return Err(CompileError::ResourceAdmission("native inline allowance"));
            }
            stats.admitted_host_bytes_peak = stats.admitted_host_bytes_peak.max(peak);
            let start = std::time::Instant::now();
            let prepared =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(i)))
                    .map_err(|_| CompileError::Shape("native metadata preparation panic"))??;
            let elapsed = start.elapsed().as_nanos();
            stats.preparation_ns += elapsed;
            stats.job_ns[i] += elapsed;
            let start = std::time::Instant::now();
            stats.jobs_started += 1;
            stats.peak_workers = stats.peak_workers.max(1);
            results[i] = Some(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    compile(i, &prepared, limits.max_requested_program_bytes)
                }))
                .map_err(|_| CompileError::Shape("native metadata worker panic"))??,
            );
            stats.job_ns[i] += start.elapsed().as_nanos();
            continue;
        }
        let base = add(base, width * THREAD)?;
        let mut maintenance = 0u64;
        let activity = CompilerActivity {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        };
        let prepared: [AtomicUsize; cpu_queue::MAX_WORKERS] =
            core::array::from_fn(|_| AtomicUsize::new(0));
        let (outcome, pool) = cpu_queue::scoped_with_progress(
            width,
            |_| CountingWorkspace::begin_dynamic().map(Some),
            |scratch, job: Job, progress| -> Result<Output, CompileError> {
                let scratch = scratch
                    .as_mut()
                    .map_err(|_| CompileError::Shape("native workspace unavailable"))?;
                match job {
                    Job::Trim => {
                        let workspace = scratch
                            .as_ref()
                            .ok_or(CompileError::Shape("native workspace missing"))?;
                        let before = workspace.retained_bytes().map_err(workspace_error)?;
                        let retained = workspace.trim_idle(0).map_err(workspace_error)?;
                        Ok(Output {
                            result: None,
                            retained,
                            reuses: 0,
                            trimmed: before - retained,
                            preparation_ns: 0,
                            prepared_bytes: 0,
                        })
                    }
                    Job::Compile {
                        index,
                        cap,
                        compatible,
                    } => {
                        // The coordinator reserved both phases, including the
                        // old compiler backing, before submitting this job.
                        let started = std::time::Instant::now();
                        let graph = prepare(index)?;
                        let preparation_ns = started.elapsed().as_nanos();
                        let prepared_bytes = retained(index, &graph)?;
                        if prepared_bytes == 0
                            || prepared_bytes > worker_bytes(storage[index].unwrap())?
                        {
                            return Err(CompileError::ResourceAdmission(
                                "native retained storage census",
                            ));
                        }
                        // Full-cap retries preserve the original fresh-builder
                        // behavior and cannot inherit a poisoned or large cache.
                        let full = cap == limits.max_requested_program_bytes;
                        let before = scratch.as_ref().map_or(0, CountingWorkspace::reuses);
                        let trimmed = if full {
                            let bytes = scratch
                                .as_ref()
                                .unwrap()
                                .retained_bytes()
                                .map_err(workspace_error)?;
                            scratch.take();
                            bytes
                        } else {
                            let workspace = scratch.as_ref().unwrap();
                            let held = workspace.retained_bytes().map_err(workspace_error)?;
                            // Reserve growth room for a different public layout.
                            let trimmed = if !compatible && held > cap / 4 * 3 {
                                held - workspace.trim_idle(cap / 2).map_err(workspace_error)?
                            } else {
                                0
                            };
                            trimmed + workspace.activate(cap).map_err(workspace_error)?
                        };
                        prepared[progress.slot()].store(prepared_bytes, Ordering::Release);
                        progress.notify();
                        let result = {
                            let _lease = activity.enter();
                            compile(index, &graph, cap)
                        };
                        drop(graph);
                        let reuses = if full {
                            0
                        } else {
                            scratch.as_ref().unwrap().reuses().saturating_sub(before)
                        };
                        let retained = if full || result.is_err() {
                            scratch.take();
                            *scratch =
                                Some(CountingWorkspace::begin_dynamic().map_err(workspace_error)?);
                            0
                        } else {
                            scratch
                                .as_ref()
                                .unwrap()
                                .deactivate()
                                .map_err(workspace_error)?
                        };
                        Ok(Output {
                            result: Some((index, result)),
                            retained,
                            reuses,
                            trimmed,
                            preparation_ns,
                            prepared_bytes,
                        })
                    }
                }
            },
            |queue| -> Result<(), CompileError> {
                let mut state = State::new();
                loop {
                    // Reclaim all completed graph and compiler credits before
                    // preparing another graph, without waiting on a live job.
                    while let Some(done) = queue
                        .try_receive_event()
                        .map_err(|_| CompileError::Shape("native queue receive"))?
                    {
                        stats.completions_drained +=
                            u64::from(matches!(&done, cpu_queue::Event::Completed(_)));
                        state.retire(
                            done,
                            results,
                            &mut desired,
                            limits,
                            storage,
                            &prepared,
                            stats,
                        )?;
                    }
                    let pending = indices[..ready].iter().any(|&i| !state.dispatched[i]);
                    if pending && state.failure.is_none() {
                        let live = state.live(base)?;
                        let mut selected = None;
                        'jobs: for &i in &indices[..ready] {
                            if state.dispatched[i] {
                                continue;
                            }
                            // Prefer compatible public layouts and avoid shrinking a
                            // larger backing for a smaller job when another slot fits.
                            let mut best = None;
                            for slot in 0..width {
                                if !matches!(state.tasks[slot], Task::Idle) {
                                    continue;
                                }
                                let additional = desired[i].saturating_sub(state.compiler[slot]);
                                let phase = prep_bound(i)?
                                    .max(add(worker_bytes(storage[i].unwrap())?, additional)?);
                                if add(live, phase)? > budget {
                                    continue;
                                }
                                let score = (
                                    state.compiler[slot] > desired[i],
                                    state.layout[slot] != Some(storage[i].unwrap().geometry),
                                    desired[i].abs_diff(state.compiler[slot]),
                                    slot,
                                );
                                if best.as_ref().is_none_or(|&(_, _, old)| score < old) {
                                    best = Some((slot, phase, score));
                                }
                            }
                            if let Some((slot, phase, _)) = best {
                                selected = Some((i, slot, phase));
                                break 'jobs;
                            }
                        }
                        if let Some((i, slot, phase)) = selected {
                            stats.admitted_host_bytes_peak =
                                stats.admitted_host_bytes_peak.max(add(live, phase)?);
                            // Charge max(old backing + preparation,
                            // max(old backing, grant) + retained graph). Keep this
                            // conservative phase charge until the owner completes.
                            let additional = desired[i].saturating_sub(state.compiler[slot]);
                            state.graphs[slot] = phase - additional;
                            let compatible =
                                state.layout[slot] == Some(storage[i].unwrap().geometry);
                            state.layout[slot] = Some(storage[i].unwrap().geometry);
                            state.compiler[slot] = state.compiler[slot].max(desired[i]);
                            state.grants[slot] = desired[i];
                            if state.live(base)? > budget {
                                return Err(CompileError::ResourceAdmission(
                                    "native active job allowance",
                                ));
                            }
                            queue
                                .submit(
                                    slot,
                                    Job::Compile {
                                        index: i,
                                        cap: desired[i],
                                        compatible,
                                    },
                                )
                                .map_err(|_| CompileError::Shape("native queue submit"))?;
                            stats.queue_refills += u64::from(state.used[slot]);
                            state.used[slot] = true;
                            state.dispatched[i] = true;
                            state.tasks[slot] = Task::Compile(i);
                            state.preparing[slot] = true;
                            state.active += 1;
                            continue;
                        }
                        stats.admission_stalls += 1;
                        // Trim only when pending work cannot fit, and wait for
                        // actual owner-side destruction before reclaiming bytes.
                        if !state.preparing.iter().any(|&p| p)
                            && !state.tasks.iter().any(|t| matches!(t, Task::Trim))
                        {
                            if let Some(slot) = (0..width)
                                .filter(|&s| {
                                    matches!(state.tasks[s], Task::Idle) && state.compiler[s] != 0
                                })
                                .max_by_key(|&s| state.compiler[s])
                            {
                                queue
                                    .submit(slot, Job::Trim)
                                    .map_err(|_| CompileError::Shape("native trim submit"))?;
                                state.tasks[slot] = Task::Trim;
                                state.active += 1;
                                maintenance += 1;
                                continue;
                            }
                        }
                    }
                    if state.active == 0 {
                        if pending && state.failure.is_none() {
                            // A grown grant can outlive the pool's stack budget.
                            // Join owners before reducing its width; ordinary
                            // byte-cap retries keep this pool and its buffers.
                            return Ok(());
                        }
                        break;
                    }
                    let done = queue
                        .receive_event()
                        .map_err(|_| CompileError::Shape("native queue receive"))?;
                    state.retire(
                        done,
                        results,
                        &mut desired,
                        limits,
                        storage,
                        &prepared,
                        stats,
                    )?;
                }
                if let Some(error) = state.failure {
                    Err(error)
                } else {
                    Ok(())
                }
            },
        )
        .map_err(|_| CompileError::Shape("native metadata pool failed"))?;
        stats.jobs_started += (pool.jobs_started as u64)
            .checked_sub(maintenance)
            .ok_or(CompileError::Shape("native maintenance job census"))?;
        stats.maintenance_jobs += maintenance;
        stats.threads_spawned += pool.threads_spawned as u64;
        stats.pinned_workers += pool.pinned_workers as u64;
        stats.affinity_failures += pool.affinity_failures as u64;
        stats.peak_workers = stats.peak_workers.max(activity.peak.load(Ordering::SeqCst));
        stats.coordinator_wait_ns += pool.coordinator_wait_ns;
        outcome?;
    }
}
