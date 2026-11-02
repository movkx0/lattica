//! Joined native misses split one original planner reservation. Exact cache
//! lookups and publication happen on the coordinator; workers retain no cache.
use super::{
    cache, key,
    unchanged::{self, OtherNativeDescriptor},
    *,
};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::native_metadata_cpu_worker_ceiling;
use lattica_prover_p3::block_v2::machine::{cpu_queue, program::CountingWorkspace};

/// Ready jobs share one joined pool; execution remains capped at sixteen workers.
pub(crate) const MAX: usize = 64;
mod phase;
mod reuse;
mod scheduler;
pub(crate) use reuse::Session;
use scheduler::run_accounted;
// Cover caller/callee copies of every control array in the existing coordinator
// allowance. Prepared graph and compiler heaps have separate live reservations.
const _: () = assert!(
    8 * (std::mem::size_of::<[Request<'static>; MAX]>()
        + std::mem::size_of::<[Descriptor<'static>; MAX]>()
        + std::mem::size_of::<[Option<NativePlanningStorage>; MAX]>()
        + std::mem::size_of::<[Option<ResolvedBound>; MAX]>()
        + std::mem::size_of::<[Option<NativeCoreBound>; MAX]>()
        + std::mem::size_of::<[Option<cache::Pending>; MAX]>()
        + std::mem::size_of::<Statistics>()
        + std::mem::size_of::<[std::sync::atomic::AtomicUsize; cpu_queue::MAX_WORKERS]>()
        + std::mem::size_of::<scheduler::State>()
        + std::mem::size_of::<phase::Permit<'static>>()
        + MAX * 256)
        // Session owner, local buffers, queue stash and transfer temporary.
        // These are not copied with each of the eight descriptor frames.
        + 4 * std::mem::size_of::<Session>()
        + cpu_queue::control_bytes::<scheduler::Job, Result<scheduler::Output, CompileError>>()
        <= COORDINATOR
);
const COORDINATOR: usize = 1 << 20;
const STACK: usize = cpu_queue::STACK_BYTES;
const THREAD: usize = STACK + (1 << 20);
#[derive(Clone, Copy)]
pub(crate) enum Descriptor<'a> {
    Native(NativeDescriptor<'a>),
    Other(OtherNativeDescriptor<'a>),
}
impl Descriptor<'_> {
    pub(crate) fn storage(
        self,
        limits: ConstructionLimits,
    ) -> Result<NativePlanningStorage, CompileError> {
        match self {
            Self::Native(d) => NativePlanningStorage::for_descriptor(d, limits),
            Self::Other(d) => d.storage(limits),
        }
    }
    pub(crate) fn key(self) -> [u8; 32] {
        match self {
            Self::Native(d) => key::descriptor(0, &d),
            Self::Other(d) => key::descriptor(1, &d),
        }
    }
    fn select(
        self,
        limits: ConstructionLimits,
        auxiliary: usize,
        storage: NativePlanningStorage,
    ) -> Result<cache::Pending, CompileError> {
        match self {
            Self::Native(d) => cache::select(0, &d, limits, auxiliary, storage),
            Self::Other(d) => cache::select(1, &d, limits, auxiliary, storage),
        }
    }
    fn prepare<'a>(
        self,
        storage: NativePlanningStorage,
        aes_columns: Option<&'a [Vec<Val>]>,
    ) -> Result<PreparedCore<'a>, CompileError> {
        match self {
            Self::Native(d) => super::prepare_descriptor(d, storage, aes_columns),
            Self::Other(d) => unchanged::prepare_descriptor(d, storage),
        }
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(super) struct Statistics {
    pub cohorts: u64,
    pub jobs_started: u64,
    pub peak_workers: usize,
    pub periodic_preparations: u64,
    pub budget_reductions: u64,
    pub admitted_host_bytes_peak: usize,
    pub wall_ns: u128,
    pub threads_spawned: u64,
    pub pinned_workers: u64,
    pub affinity_failures: u64,
    pub queue_refills: u64,
    pub workspace_reuses: u64,
    pub restored_workspaces: u64,
    pub cost_hint_jobs: u64,
    pub maintenance_jobs: u64,
    pub completions_drained: u64,
    pub admission_stalls: u64,
    pub trimmed_compiler_bytes: u64,
    pub idle_compiler_bytes_peak: usize,
    pub phase_extra_bytes_peak: usize,
    pub preparation_ns: u128,
    pub coordinator_wait_ns: u128,
    pub retained_worker_bytes_peak: usize,
    pub failed_cohorts: u64,
    #[serde(skip)]
    job_ns: [u128; MAX],
}
impl Default for Statistics {
    fn default() -> Self {
        Self {
            cohorts: 0,
            jobs_started: 0,
            peak_workers: 0,
            periodic_preparations: 0,
            budget_reductions: 0,
            admitted_host_bytes_peak: 0,
            wall_ns: 0,
            threads_spawned: 0,
            pinned_workers: 0,
            affinity_failures: 0,
            queue_refills: 0,
            workspace_reuses: 0,
            restored_workspaces: 0,
            cost_hint_jobs: 0,
            maintenance_jobs: 0,
            completions_drained: 0,
            admission_stalls: 0,
            trimmed_compiler_bytes: 0,
            idle_compiler_bytes_peak: 0,
            phase_extra_bytes_peak: 0,
            preparation_ns: 0,
            coordinator_wait_ns: 0,
            retained_worker_bytes_peak: 0,
            failed_cohorts: 0,
            job_ns: [0; MAX],
        }
    }
}

fn worker_bytes(s: NativePlanningStorage) -> Result<usize, CompileError> {
    // Numeric compilation allocates neither a proof template nor dummy inputs.
    [
        s.symbolic_retained_bytes,
        s.descriptor_and_periodic_bytes,
        s.callback_and_helper_bytes,
        s.returned_wire_bytes,
    ]
    .into_iter()
    .try_fold(0, add)
}
/// The caller retains the maximum original source-planner reservation until
/// return. The fixed coordinator frames are covered inside that same budget.
pub(crate) fn bounds(
    descriptors: &[Descriptor<'_>],
    limits: ConstructionLimits,
    auxiliary: usize,
) -> Result<[Option<NativeCoreBound>; MAX], CompileError> {
    if descriptors.is_empty() || descriptors.len() > MAX {
        return Err(CompileError::Shape("native cohort length"));
    }
    let mut requests = [Request {
        descriptor: descriptors[0],
        auxiliary,
    }; MAX];
    for (r, &d) in requests.iter_mut().zip(descriptors) {
        r.descriptor = d;
    }
    bounds_exact(&requests[..descriptors.len()], limits)
}
#[derive(Clone, Copy)]
pub(crate) struct Request<'a> {
    pub descriptor: Descriptor<'a>,
    pub auxiliary: usize,
}
/// Exact numeric binding only; constructors still authenticate their original
/// source, blueprint and ledger. Private fields prevent substituting a bound
/// from a same-sized but different descriptor.
#[derive(Clone, Copy)]
pub(crate) struct ResolvedBound {
    key: [u8; 32],
    limits: ConstructionLimits,
    auxiliary: usize,
    core: NativeCoreBound,
}
impl ResolvedBound {
    pub(crate) fn for_request(
        self,
        request: Request<'_>,
        limits: ConstructionLimits,
    ) -> Result<NativeCoreBound, CompileError> {
        if self.key != request.descriptor.key()
            || self.limits != limits
            || self.auxiliary != request.auxiliary
        {
            return Err(CompileError::Shape("native resolved descriptor binding"));
        }
        Ok(self.core)
    }
}
pub(crate) fn bounds_exact(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
) -> Result<[Option<NativeCoreBound>; MAX], CompileError> {
    Ok(resolve_bounds(requests, limits)?.map(|bound| bound.map(|bound| bound.core)))
}
pub(crate) fn bounds_exact_in_ledger(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
    original: &crate::execution::retained_resources::Reservation,
    ledger: &crate::execution::retained_resources::Ledger,
) -> Result<[Option<NativeCoreBound>; MAX], CompileError> {
    Ok(
        resolve_bounds_in_ledger(requests, limits, original, ledger)?
            .map(|bound| bound.map(|bound| bound.core)),
    )
}
/// An authenticated caller may fund a bounded supplement from its existing
/// ledger. Individual compiler limits and descriptor cache identities stay fixed.
pub(crate) fn resolve_bounds_in_ledger(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
    original: &crate::execution::retained_resources::Reservation,
    ledger: &crate::execution::retained_resources::Ledger,
) -> Result<[Option<ResolvedBound>; MAX], CompileError> {
    resolve(
        requests,
        limits,
        Some(phase::Backing { original, ledger }),
        &mut Session::default(),
    )
}
/// Preserve each original caller's auxiliary allowance in the cache key.
pub(crate) fn resolve_bounds(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
) -> Result<[Option<ResolvedBound>; MAX], CompileError> {
    resolve(requests, limits, None, &mut Session::default())
}
fn resolve(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
    backing: Option<phase::Backing<'_>>,
    session: &mut Session,
) -> Result<[Option<ResolvedBound>; MAX], CompileError> {
    if requests.is_empty() || requests.len() > MAX {
        return Err(CompileError::Shape("native cohort length"));
    }
    let mut descriptor_storage = [requests[0].descriptor; MAX];
    for (d, r) in descriptor_storage.iter_mut().zip(requests) {
        *d = r.descriptor;
    }
    let descriptors = &descriptor_storage[..requests.len()];
    let started = std::time::Instant::now();
    if descriptors.is_empty() || descriptors.len() > MAX {
        return Err(CompileError::Shape("native cohort length"));
    }
    let mut storage = [None; MAX];
    let mut keys = [[0; 32]; MAX];
    let mut duplicate = [None; MAX];
    let mut pending: [Option<cache::Pending>; MAX] = core::array::from_fn(|_| None);
    let mut results = [None; MAX];
    let mut original = 0;
    for (i, &d) in descriptors.iter().enumerate() {
        let s = d.storage(limits)?;
        if s.auxiliary_peak_bytes > requests[i].auxiliary {
            return Err(CompileError::ResourceAdmission(
                "native cohort auxiliary allowance",
            ));
        }
        original = original.max(s.total_requested_bytes);
        storage[i] = Some(s);
        keys[i] = d.key();
        duplicate[i] = keys[..i]
            .iter()
            .enumerate()
            .position(|(j, k)| *k == keys[i] && requests[j].auxiliary == requests[i].auxiliary);
    }
    if let Some(backing) = &backing {
        backing.validate(original)?;
    }
    for (i, &d) in descriptors.iter().enumerate() {
        if duplicate[i].is_none() {
            let p = d.select(limits, requests[i].auxiliary, storage[i].unwrap())?;
            results[i] = p.value;
            pending[i] = Some(p);
        }
    }
    let mut stats = Statistics::default();
    let misses = results[..descriptors.len()]
        .iter()
        .zip(&duplicate)
        .filter(|(result, duplicate)| result.is_none() && duplicate.is_none())
        .count();
    let mut phase = backing
        .as_ref()
        .map(|backing| {
            session.admit(
                backing,
                original,
                misses,
                native_metadata_cpu_worker_ceiling(),
            )
        })
        .transpose()?;
    // Declared after the permit: on errors/unwind the buffers die first.
    let mut buffers = std::mem::replace(&mut session.buffers, reuse::empty());
    let budget = phase.as_ref().map_or(original, |phase| phase.budget());
    stats.phase_extra_bytes_peak = budget - original;
    // AES's periodic schedule is independent of domain, counters and segments
    // (AesLaneAir::schedule). Its constraints DO depend on these fields and are
    // always prepared separately. Share only this audited immutable table.
    let mut aes = None;
    let mut aes_misses = 0;
    for (i, d) in descriptors.iter().enumerate() {
        if duplicate[i].is_none() && results[i].is_none() {
            if let Descriptor::Native(d @ NativeDescriptor::Aes { .. }) = d {
                aes = Some(*d);
                aes_misses += 1;
            }
        }
    }
    let shared_bytes = if aes_misses > 1 {
        descriptors
            .iter()
            .enumerate()
            .filter(|(_, d)| matches!(d, Descriptor::Native(NativeDescriptor::Aes { .. })))
            .map(|(i, _)| storage[i].unwrap().descriptor_and_periodic_bytes)
            .max()
            .unwrap()
    } else {
        0
    };
    let columns = if shared_bytes != 0 {
        // Preflight above covers both construction and retained capacities.
        stats.periodic_preparations = 1;
        Some(aes.unwrap().aes()?.periodic_columns())
    } else {
        None
    };
    let result = run_accounted(
        &storage,
        &duplicate,
        descriptors.len(),
        limits,
        budget,
        shared_bytes,
        native_metadata_cpu_worker_ceiling(),
        &mut results,
        &mut stats,
        &mut buffers,
        &mut session.hints,
        phase.as_ref().map_or(0, |p| p.extra_bytes()),
        |i| descriptors[i].prepare(storage[i].unwrap(), columns.as_deref()),
        |_, prepared| prepared.retained_worker_bytes(),
        |_, prepared, cap| {
            prepared.lower(ConstructionLimits {
                max_requested_program_bytes: cap,
                ..limits
            })
        },
    );
    stats.wall_ns = started.elapsed().as_nanos();
    #[cfg(test)]
    if std::env::var("LATTICA_CPU_SCALING_PROFILE").as_deref() == Ok("1") {
        eprintln!(
            "CPU_SCALING_JOBS {}",
            serde_json::json!({
                "kind":"native", "job_ns":&stats.job_ns[..descriptors.len()],
                "compiler_peak_bytes":results[..descriptors.len()].iter().map(|r| r.map(|b| b.counts.planner_requested_program_bytes_peak)).collect::<Vec<_>>(),
                "original_host_bytes":original, "phase_host_bytes":budget, "statistics":stats,
            })
        );
    }
    stats.failed_cohorts = u64::from(result.is_err());
    cache::record_cohort(stats)?;
    // All workers have joined and their temporary owners have died. Errors
    // publish no partial cohort; successful results remain purely numerical.
    result?;
    if let Some(permit) = phase.as_mut() {
        let held = reuse::trim(&mut buffers, permit.extra_bytes())?;
        session.claim = permit.retain(held)?;
        session.buffers = buffers;
    }
    for i in 0..descriptors.len() {
        if let Some(source) = duplicate[i] {
            results[i] = results[source];
        }
        if let Some(p) = pending[i].take() {
            p.publish_cohort(Ok(results[i].unwrap()), stats.job_ns[i])?;
        }
    }
    Ok(core::array::from_fn(|i| {
        results[i].map(|core| ResolvedBound {
            key: keys[i],
            limits,
            auxiliary: requests[i].auxiliary,
            core,
        })
    }))
}

// Public geometry estimates scheduling cost only; it never grants allocation.
fn work(storage: NativePlanningStorage) -> u128 {
    geometry_work(storage.geometry)
}
fn geometry_work(g: NativeGeometry) -> u128 {
    (g.width as u128 * (g.height.ilog2() as u128 + 1)
        + g.periodic_columns as u128 * g.maximum_period as u128)
        .max(1)
}

// Initial caps are public-geometry heuristics, never allocation authority.
// Every allocation enforces its slot cap; only a byte-cap refusal can retry.
fn initial_cap(storage: NativePlanningStorage, limits: ConstructionLimits) -> usize {
    let g = storage.geometry;
    let mib = if g.width <= 320 && g.public_values <= 8 {
        48
    } else if g.width >= 600 && g.maximum_period >= 32768 {
        128
    } else if g.maximum_period >= 65536 && g.public_values > 300 {
        112
    } else {
        80
    };
    (mib << 20).min(limits.max_requested_program_bytes)
}
#[cfg(test)]
fn run<P: Send>(
    storage: &[Option<NativePlanningStorage>; MAX],
    duplicates: &[Option<usize>; MAX],
    count: usize,
    limits: ConstructionLimits,
    original: usize,
    shared: usize,
    ceiling: usize,
    results: &mut [Option<NativeCoreBound>; MAX],
    stats: &mut Statistics,
    prepare: impl Fn(usize) -> Result<P, CompileError> + Sync,
    compile: impl Fn(usize, &P, usize) -> Result<NativeCoreBound, CompileError> + Sync,
) -> Result<(), CompileError> {
    run_accounted(
        storage,
        duplicates,
        count,
        limits,
        original,
        shared,
        ceiling,
        results,
        stats,
        &mut reuse::empty(),
        &mut reuse::Hints::default(),
        0,
        prepare,
        |i, _| worker_bytes(storage[i].unwrap()),
        compile,
    )
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
