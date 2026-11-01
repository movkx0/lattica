//! Joined native misses split one original planner reservation. Exact cache
//! lookups and publication happen on the coordinator; workers retain no cache.
use super::{
    cache, key,
    unchanged::{self, OtherNativeDescriptor},
    *,
};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling;
use lattica_prover_p3::block_v2::machine::{cpu_queue, program::CountingWorkspace};

pub(crate) const MAX: usize = 16;
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
#[derive(Clone, Copy, Default, Debug, serde::Serialize)]
pub(super) struct Statistics {
    pub cohorts: u64,
    pub jobs_started: u64,
    pub peak_workers: usize,
    pub periodic_preparations: u64,
    pub budget_reductions: u64,
    pub admitted_host_bytes_peak: usize,
    pub wall_ns: u128,
    pub threads_spawned: u64,
    pub queue_refills: u64,
    pub workspace_reuses: u64,
    pub preparation_ns: u128,
    pub coordinator_wait_ns: u128,
    pub retained_worker_bytes_peak: usize,
    pub failed_cohorts: u64,
    #[serde(skip)]
    job_ns: [u128; MAX],
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
/// Preserve each original caller's auxiliary allowance in the cache key.
pub(crate) fn resolve_bounds(
    requests: &[Request<'_>],
    limits: ConstructionLimits,
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
    for (i, &d) in descriptors.iter().enumerate() {
        if duplicate[i].is_none() {
            let p = d.select(limits, requests[i].auxiliary, storage[i].unwrap())?;
            results[i] = p.value;
            pending[i] = Some(p);
        }
    }
    let mut stats = Statistics::default();
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
        original,
        shared_bytes,
        metadata_cpu_worker_ceiling(),
        &mut results,
        &mut stats,
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
    stats.failed_cohorts = u64::from(result.is_err());
    cache::record_cohort(stats)?;
    // All workers have joined and their temporary owners have died. Errors
    // publish no partial cohort; successful results remain purely numerical.
    result?;
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
    let g = storage.geometry;
    (g.width as u128 * (g.height.ilog2() as u128 + 1)
        + g.periodic_columns as u128 * g.maximum_period as u128)
        .max(1)
}

// Initial caps are public-geometry heuristics, never allocation authority.
// Every allocation enforces its slot cap; only a byte-cap refusal can retry.
fn initial_cap(storage: NativePlanningStorage, limits: ConstructionLimits) -> usize {
    let g = storage.geometry;
    let mib = if g.width <= 320 && g.public_values <= 8 {
        64
    } else if g.width >= 600 && g.maximum_period >= 32768 {
        256
    } else if g.maximum_period >= 65536 && g.public_values > 300 {
        192
    } else {
        128
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
    prepare: impl Fn(usize) -> Result<P, CompileError>,
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
        prepare,
        |i, _| worker_bytes(storage[i].unwrap()),
        compile,
    )
}
fn run_accounted<P: Send>(
    storage: &[Option<NativePlanningStorage>; MAX],
    duplicates: &[Option<usize>; MAX],
    count: usize,
    limits: ConstructionLimits,
    original: usize,
    shared: usize,
    ceiling: usize,
    results: &mut [Option<NativeCoreBound>; MAX],
    stats: &mut Statistics,
    prepare: impl Fn(usize) -> Result<P, CompileError>,
    retained: impl Fn(usize, &P) -> Result<usize, CompileError>,
    compile: impl Fn(usize, &P, usize) -> Result<NativeCoreBound, CompileError> + Sync,
) -> Result<(), CompileError> {
    let mut desired = [0; MAX];
    for i in 0..count {
        desired[i] = initial_cap(storage[i].unwrap(), limits);
    }
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
        let prep_bound = |i: usize| {
            add(
                worker_bytes(storage[i].unwrap())?,
                storage[i].unwrap().symbolic_workspace_bytes,
            )
        };
        let largest_preparation = indices[..ready]
            .iter()
            .try_fold(0usize, |n, &i| Ok(n.max(prep_bound(i)?)))?;
        let mut caps = [0; MAX];
        for (slot, &i) in indices[..ready].iter().enumerate() {
            caps[slot] = desired[i];
        }
        caps[..ready].sort_unstable_by(|a, b| b.cmp(a));
        let mut width = 1;
        let mut reserved = base;
        for n in (2..=ceiling.min(ready).min(MAX)).rev() {
            let pool = caps[..n]
                .iter()
                .try_fold(base, |sum, &cap| add(sum, add(cap, THREAD)?))?;
            if add(pool, largest_preparation)? <= original {
                width = n;
                reserved = pool;
                break;
            }
        }
        stats.cohorts += 1;
        if width == 1 {
            let i = indices[0];
            let lowered = add(
                base,
                add(
                    worker_bytes(storage[i].unwrap())?,
                    limits.max_requested_program_bytes,
                )?,
            )?;
            let peak = lowered.max(add(base, prep_bound(i)?)?);
            if peak > original {
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
        let (outcome, pool) = cpu_queue::scoped_with_state(
            width,
            |slot| {
                // A full-cap worker must stay equivalent to a fresh compiler;
                // reduced-cap workers can retry after all cached backing retires.
                if caps[slot] < limits.max_requested_program_bytes {
                    CountingWorkspace::begin(caps[slot]).map(Some)
                } else {
                    Ok(None)
                }
            },
            |scratch, (i, prepared, cap): (usize, P, usize)| {
                let result = match scratch {
                    Ok(_) => compile(i, &prepared, cap),
                    Err(_) => Err(CompileError::Shape("native workspace unavailable")),
                };
                drop(prepared);
                (
                    i,
                    result,
                    scratch
                        .as_ref()
                        .map_or(0, |s| s.as_ref().map_or(0, |s| s.reuses())),
                )
            },
            |queue| -> Result<bool, CompileError> {
                let mut dispatched = [false; MAX];
                let mut used = [false; MAX];
                let mut owner_bytes = [0; MAX];
                let mut reused = [0; MAX];
                let mut active = 0;
                let mut retained_total = 0;
                let mut retry = false;
                let mut failure = None;
                loop {
                    if !retry && failure.is_none() {
                        // Each idle slot can take the largest ready job that fits
                        // its compiler cap and the remaining preparation allowance.
                        for slot in 0..width {
                            if owner_bytes[slot] != 0 {
                                continue;
                            }
                            let mut selected = None;
                            for &i in &indices[..ready] {
                                if !dispatched[i]
                                    && desired[i] <= caps[slot]
                                    && add(add(reserved, retained_total)?, prep_bound(i)?)?
                                        <= original
                                {
                                    selected = Some(i);
                                    break;
                                }
                            }
                            let Some(i) = selected else {
                                continue;
                            };
                            let peak = add(add(reserved, retained_total)?, prep_bound(i)?)?;
                            stats.admitted_host_bytes_peak =
                                stats.admitted_host_bytes_peak.max(peak);
                            let started = std::time::Instant::now();
                            let prepared =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    prepare(i)
                                }))
                                .map_err(|_| {
                                    CompileError::Shape("native metadata preparation panic")
                                })??;
                            let elapsed = started.elapsed().as_nanos();
                            stats.preparation_ns += elapsed;
                            stats.job_ns[i] += elapsed;
                            let bytes = retained(i, &prepared)?;
                            if bytes == 0 || bytes > worker_bytes(storage[i].unwrap())? {
                                return Err(CompileError::ResourceAdmission(
                                    "native retained storage census",
                                ));
                            }
                            stats.retained_worker_bytes_peak =
                                stats.retained_worker_bytes_peak.max(bytes);
                            retained_total = add(retained_total, bytes)?;
                            owner_bytes[slot] = bytes;
                            queue
                                .submit(slot, (i, prepared, caps[slot]))
                                .map_err(|_| CompileError::Shape("native queue submit"))?;
                            stats.queue_refills += u64::from(used[slot]);
                            used[slot] = true;
                            dispatched[i] = true;
                            active += 1;
                        }
                    }
                    if active == 0 {
                        if !retry
                            && failure.is_none()
                            && indices[..ready].iter().any(|&i| !dispatched[i])
                        {
                            return Err(CompileError::ResourceAdmission(
                                "native queue made no progress",
                            ));
                        }
                        break;
                    }
                    let done = queue
                        .receive()
                        .map_err(|_| CompileError::Shape("native queue receive"))?;
                    active -= 1;
                    retained_total -= owner_bytes[done.slot];
                    owner_bytes[done.slot] = 0;
                    match done.result {
                        Ok((i, result, reuses)) => {
                            stats.job_ns[i] += done.elapsed_ns;
                            stats.workspace_reuses += reuses - reused[done.slot];
                            reused[done.slot] = reuses;
                            match result {
                                Ok(value) => results[i] = Some(value),
                                Err(CompileError::ResourceAdmission(
                                    uni::shape::NATIVE_PROGRAM_BYTE_LIMIT,
                                )) if caps[done.slot] < limits.max_requested_program_bytes => {
                                    retry = true;
                                    desired[i] = caps[done.slot]
                                        .saturating_mul(2)
                                        .min(limits.max_requested_program_bytes);
                                }
                                Err(error) => {
                                    if failure.is_none() {
                                        failure = Some(error);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            failure = Some(CompileError::Shape("native metadata worker panic"))
                        }
                    }
                }
                if let Some(error) = failure {
                    Err(error)
                } else {
                    Ok(retry)
                }
            },
        )
        .map_err(|_| CompileError::Shape("native metadata pool failed"))?;
        stats.jobs_started += pool.jobs_started as u64;
        stats.threads_spawned += pool.threads_spawned as u64;
        stats.peak_workers = stats.peak_workers.max(pool.peak_active_workers);
        stats.coordinator_wait_ns += pool.coordinator_wait_ns;
        if outcome? {
            stats.budget_reductions += 1;
        }
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
