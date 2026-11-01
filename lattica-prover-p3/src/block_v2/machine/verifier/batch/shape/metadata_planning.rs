//! CPU-only numeric planning. Concurrent compilers split the caller's original
//! reservation; only successful numeric results survive a joined cohort.
use super::{
    CompileError, ConstructionLimits, PlanningStorage, RegisteredChildShape, VerifierCoreBound,
};
use std::{
    cell::RefCell,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

pub const MAX_METADATA_WORKERS: usize = 16;
pub const METADATA_PLANNING_SCOPE_RESERVED_BYTES: usize = 64 << 10;
pub(super) const MAX_HEIGHTS: usize = 22;
// Included in PlanningStorage::helper_bytes even for sequential callers.
pub(super) const COORDINATOR_BYTES: usize = 1 << 20;
const STACK_BYTES: usize = 2 << 20;
// TLS owners (including the inactive geometry cache), OS thread bookkeeping,
// closure/return frames and allocator request slack. Symbolic arenas are already
// charged once by the shared graph reservation.
const THREAD_BYTES: usize = STACK_BYTES + (1 << 20);
pub(super) const SPLIT_BUDGET: &str = "metadata worker compiler budget";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct MetadataCpuOptions {
    pub requested_workers: Option<usize>,
    max_workers: usize,
}
impl Default for MetadataCpuOptions {
    fn default() -> Self {
        Self {
            requested_workers: None,
            max_workers: physical_ceiling(),
        }
    }
}
fn physical_ceiling() -> usize {
    crate::block_v2::machine::backend::identity_cpu::physical_core_count()
        .unwrap_or(1)
        .min(MAX_METADATA_WORKERS)
}
impl MetadataCpuOptions {
    pub fn workers(n: usize) -> Result<Self, &'static str> {
        if !(1..=MAX_METADATA_WORKERS).contains(&n) {
            return Err("metadata CPU workers must be 1..=16");
        }
        Ok(Self {
            requested_workers: Some(n),
            max_workers: n.min(physical_ceiling()),
        })
    }
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value == "auto" {
            Ok(Self::default())
        } else {
            Self::workers(value.parse().map_err(|_| "expected auto or 1..=16")?)
        }
    }
    pub fn max_workers(self) -> usize {
        self.max_workers
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MetadataPlanningStatistics {
    pub worker_ceiling: usize,
    pub peak_active_workers: usize,
    pub largest_cohort: usize,
    pub envelopes: u64,
    pub symbolic_preparations: u64,
    pub shared_symbolic_bytes_peak: usize,
    pub worker_auxiliary_bytes_peak: usize,
    pub heights_completed: u64,
    pub jobs_started: u64,
    pub cohorts: u64,
    pub budget_reductions: u64,
    pub failed_envelopes: u64,
    pub admitted_host_bytes_peak: usize,
    pub wall_ns: u128,
    pub worker_elapsed_ns: u128,
}
struct State {
    options: MetadataCpuOptions,
    statistics: MetadataPlanningStatistics,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
/// Thread-bound numerical planning controls. The full workflow reserves these
/// fixed frames inside its existing metadata allowance before opening the scope.
/// Other core callers remain sequential unless they explicitly open a scope.
pub struct MetadataPlanningScope {
    _thread: PhantomData<Rc<()>>,
}
// Includes TLS owner, options/statistic snapshots and all scope/return frames.
// Full-workflow callers keep this sublimit charged between compiler cohorts too.
const _: () = assert!(
    8 * (core::mem::size_of::<RefCell<Option<State>>>()
        + core::mem::size_of::<MetadataPlanningScope>()
        + core::mem::size_of::<MetadataCpuOptions>()
        + core::mem::size_of::<MetadataPlanningStatistics>())
        <= METADATA_PLANNING_SCOPE_RESERVED_BYTES
);
impl MetadataPlanningScope {
    pub fn begin(options: MetadataCpuOptions) -> Result<Self, CompileError> {
        STATE.with(|slot| {
            let mut state = slot.try_borrow_mut().map_err(|_| busy())?;
            if state.is_some() {
                return Err(busy());
            }
            *state = Some(State {
                options,
                statistics: MetadataPlanningStatistics {
                    worker_ceiling: options.max_workers,
                    ..Default::default()
                },
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub fn statistics(&self) -> MetadataPlanningStatistics {
        STATE.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("live metadata scope")
                .statistics
        })
    }
}
impl Drop for MetadataPlanningScope {
    fn drop(&mut self) {
        STATE.with(|slot| {
            if let Some(state) = slot.borrow_mut().take() {
                let s = state.statistics;
                use std::io::Write;
                let _ = writeln!(std::io::stderr().lock(), "metadata_planning ceiling={} peak_workers={} largest_cohort={} envelopes={} heights={} jobs={} cohorts={} budget_reductions={} failed={} admitted_host_bytes_peak={} wall_ns={} worker_elapsed_ns={}",
                    s.worker_ceiling, s.peak_active_workers, s.largest_cohort, s.envelopes,
                    s.heights_completed, s.jobs_started, s.cohorts, s.budget_reductions,
                    s.failed_envelopes, s.admitted_host_bytes_peak, s.wall_ns, s.worker_elapsed_ns);
            }
        });
    }
}
fn busy() -> CompileError {
    CompileError::ResourceAdmission("metadata planning scope unavailable")
}

/// Shared CPU ceiling for closed native metadata cohorts. Callers retain their
/// own original reservations; opening a scope never grants extra memory.
pub fn metadata_cpu_worker_ceiling() -> usize {
    STATE.with(|slot| slot.borrow().as_ref().map_or(1, |s| s.options.max_workers))
}
fn overflow() -> CompileError {
    CompileError::ResourceAdmission("metadata planning counter overflow")
}
fn record(s: MetadataPlanningStatistics) -> Result<(), CompileError> {
    STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| busy())?;
        let Some(state) = state.as_mut() else { return Ok(()); };
        let t = &mut state.statistics;
        macro_rules! add { ($($field:ident),+) => { $(t.$field = t.$field.checked_add(s.$field).ok_or_else(overflow)?;)+ }; }
        add!(envelopes, symbolic_preparations, heights_completed, jobs_started, cohorts, budget_reductions, failed_envelopes, wall_ns, worker_elapsed_ns);
        t.peak_active_workers = t.peak_active_workers.max(s.peak_active_workers);
        t.shared_symbolic_bytes_peak = t.shared_symbolic_bytes_peak.max(s.shared_symbolic_bytes_peak);
        t.worker_auxiliary_bytes_peak = t.worker_auxiliary_bytes_peak.max(s.worker_auxiliary_bytes_peak);
        t.largest_cohort = t.largest_cohort.max(s.largest_cohort);
        t.admitted_host_bytes_peak = t.admitted_host_bytes_peak.max(s.admitted_host_bytes_peak);
        Ok(())
    })
}

#[derive(Clone, Copy, Debug)]
struct Admission {
    width: usize,
    program_bytes: usize,
    total_bytes: usize,
}
fn admit(
    ceiling: usize,
    ready: usize,
    storage: PlanningStorage,
    construction: ConstructionLimits,
) -> Admission {
    // The shared graph is charged once. Each numeric worker retains its own
    // returned wires/helpers and stack, but no symbolic build workspace,
    // template or dummy witness buffers. The original caller reservation stays
    // held throughout preparation, execution and joins.
    let worker_auxiliary = storage
        .counting_worker_auxiliary_bytes()
        .expect("validated storage sum");
    for width in (2..=ceiling.min(ready)).rev() {
        let Some(overhead) = worker_auxiliary
            .checked_add(THREAD_BYTES)
            .and_then(|n| n.checked_mul(width))
            .and_then(|n| n.checked_add(COORDINATOR_BYTES))
            .and_then(|n| n.checked_add(storage.symbolic_retained_bytes))
        else {
            continue;
        };
        let Some(remaining) = storage.total_requested_bytes.checked_sub(overhead) else {
            continue;
        };
        let program_bytes = (remaining / width).min(construction.max_requested_program_bytes);
        // Scheduling heuristic only: avoid launching jobs with tiny compiler
        // shares. Every allocation still enforces the admitted cap; this floor
        // is neither a source bound nor permission to exceed the original pool.
        if program_bytes >= (128 << 20) {
            return Admission {
                width,
                program_bytes,
                total_bytes: overhead + width * program_bytes,
            };
        }
    }
    // Inline execution uses the exact original allowance and no new thread.
    Admission {
        width: 1,
        program_bytes: construction.max_requested_program_bytes,
        total_bytes: storage.total_requested_bytes,
    }
}
struct Live<'a>(&'a AtomicUsize);
impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) fn heights(
    public_values: usize,
    maximum_height: usize,
    construction: ConstructionLimits,
    auxiliary: usize,
    storage: PlanningStorage,
) -> Result<[Option<VerifierCoreBound>; MAX_HEIGHTS], CompileError> {
    let ceiling = STATE.with(|slot| {
        slot.try_borrow()
            .map(|state| state.as_ref().map_or(1, |state| state.options.max_workers))
            .map_err(|_| busy())
    })?;
    let started = Instant::now();
    let mut statistics = MetadataPlanningStatistics {
        envelopes: 1,
        ..Default::default()
    };
    let result = run_heights(
        public_values,
        maximum_height,
        construction,
        auxiliary,
        storage,
        ceiling,
        &mut statistics,
    );
    statistics.wall_ns = started.elapsed().as_nanos();
    statistics.failed_envelopes = u64::from(result.is_err());
    record(statistics)?;
    result
}
fn run_heights(
    public_values: usize,
    maximum_height: usize,
    construction: ConstructionLimits,
    auxiliary: usize,
    storage: PlanningStorage,
    ceiling: usize,
    statistics: &mut MetadataPlanningStatistics,
) -> Result<[Option<VerifierCoreBound>; MAX_HEIGHTS], CompileError> {
    let count = maximum_height.ilog2() as usize - 2;
    // The full original auxiliary bound covers this sequential preparation.
    // Its transient workspace is gone before any worker can start.
    let shared = super::RegisteredSymbolic::new(public_values)?;
    statistics.symbolic_preparations += 1;
    statistics.shared_symbolic_bytes_peak = storage.symbolic_retained_bytes;
    statistics.worker_auxiliary_bytes_peak = storage.counting_worker_auxiliary_bytes()?;
    run_jobs(
        count,
        construction,
        storage,
        ceiling,
        statistics,
        |index, program_bytes| {
            let height: usize = 1 << (index + 3);
            let shape = RegisteredChildShape {
                public_values,
                height,
                preprocessing_cap_roots: 1
                    << (height.ilog2() as usize + 1 + crate::block_v2::profile::LOG_BLOWUP)
                        .min(crate::block_v2::profile::CAP_HEIGHT),
            };
            super::verifier_core_bound_prepared(
                0,
                &[shape],
                construction,
                auxiliary,
                program_bytes,
                Some(&shared),
            )
        },
    )
}
fn run_jobs(
    count: usize,
    construction: ConstructionLimits,
    storage: PlanningStorage,
    mut ceiling: usize,
    statistics: &mut MetadataPlanningStatistics,
    compile: impl Fn(usize, usize) -> Result<VerifierCoreBound, CompileError> + Sync,
) -> Result<[Option<VerifierCoreBound>; MAX_HEIGHTS], CompileError> {
    let mut results = [None; MAX_HEIGHTS];
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    while results[..count].iter().any(Option::is_none) {
        let mut indices = [0usize; MAX_HEIGHTS];
        let mut ready = 0;
        for (i, result) in results[..count].iter().enumerate() {
            if result.is_none() {
                indices[ready] = i;
                ready += 1;
            }
        }
        let admitted = admit(ceiling, ready, storage, construction);
        statistics.largest_cohort = statistics.largest_cohort.max(admitted.width);
        statistics.admitted_host_bytes_peak = statistics
            .admitted_host_bytes_peak
            .max(admitted.total_bytes);
        statistics.cohorts += 1;
        let job = |index: usize| {
            let started = Instant::now();
            let active = live.fetch_add(1, Ordering::SeqCst) + 1;
            let _live = Live(&live);
            peak.fetch_max(active, Ordering::SeqCst);
            let result = compile(index, admitted.program_bytes);
            (index, started.elapsed().as_nanos(), result)
        };
        let mut completed: [Option<(usize, u128, Result<VerifierCoreBound, CompileError>)>;
            MAX_METADATA_WORKERS] = core::array::from_fn(|_| None);
        let mut failure = None;
        if admitted.width == 1 {
            statistics.jobs_started += 1;
            // Same unwind-to-error behavior as spawned jobs; no partial envelope
            // escapes a compiler panic, and all original owners stay in scope.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(indices[0]))) {
                Ok(result) => completed[0] = Some(result),
                Err(_) => failure = Some(CompileError::Shape("metadata compiler panicked")),
            }
        } else {
            std::thread::scope(|scope| {
                let mut handles: [Option<_>; MAX_METADATA_WORKERS] = core::array::from_fn(|_| None);
                for (slot, &index) in indices[..admitted.width].iter().enumerate() {
                    let job = &job;
                    match std::thread::Builder::new()
                        .name("ringct-metadata".into())
                        .stack_size(STACK_BYTES)
                        .spawn_scoped(scope, move || job(index))
                    {
                        Ok(handle) => {
                            handles[slot] = Some(handle);
                            statistics.jobs_started += 1;
                        }
                        Err(_) => {
                            failure = Some(CompileError::ResourceAdmission(
                                "metadata worker spawn refused",
                            ));
                            break;
                        }
                    }
                }
                // Join every successfully spawned worker, including after a
                // spawn error or panic. No detached work or early owner release.
                for (slot, handle) in handles.into_iter().enumerate() {
                    if let Some(handle) = handle {
                        match handle.join() {
                            Ok(result) => completed[slot] = Some(result),
                            Err(_) => {
                                failure = Some(CompileError::Shape("metadata compiler panicked"))
                            }
                        }
                    }
                }
            });
        }
        statistics.peak_active_workers = statistics
            .peak_active_workers
            .max(peak.load(Ordering::SeqCst));
        let mut retry = false;
        for (index, elapsed, result) in completed.into_iter().flatten() {
            statistics.worker_elapsed_ns = statistics
                .worker_elapsed_ns
                .checked_add(elapsed)
                .ok_or_else(overflow)?;
            match result {
                Ok(bound) => {
                    results[index] = Some(bound);
                    statistics.heights_completed += 1;
                }
                Err(CompileError::ResourceAdmission(SPLIT_BUDGET)) if admitted.width > 1 => {
                    retry = true
                }
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if retry {
            // Only the reduced compiler byte cap permits a retry. Numeric work
            // is discarded; the original reservation is never released/reissued.
            // Wire/input/shape/symbolic errors and full-cap refusals remain fatal.
            ceiling = (admitted.width / 2).max(1);
            statistics.budget_reductions += 1;
        }
    }
    Ok(results)
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
