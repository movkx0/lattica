//! Joined native misses split one original planner reservation. Exact cache
//! lookups and publication happen on the coordinator; workers retain no cache.
use super::{
    cache, key,
    unchanged::{self, OtherNativeDescriptor},
    *,
};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const MAX: usize = 16;
const COORDINATOR: usize = 1 << 20;
const STACK: usize = 2 << 20;
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
    let result = run(
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

fn run<P: Sync>(
    storage: &[Option<NativePlanningStorage>; MAX],
    duplicates: &[Option<usize>; MAX],
    count: usize,
    limits: ConstructionLimits,
    original: usize,
    shared: usize,
    mut ceiling: usize,
    results: &mut [Option<NativeCoreBound>; MAX],
    stats: &mut Statistics,
    prepare: impl Fn(usize) -> Result<P, CompileError>,
    compile: impl Fn(usize, &P, usize) -> Result<NativeCoreBound, CompileError> + Sync,
) -> Result<(), CompileError> {
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
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
        let mut width = 1;
        let mut caps = [limits.max_requested_program_bytes; MAX];
        let cap = limits.max_requested_program_bytes;
        let base = add(COORDINATOR, shared)?;
        let mut admitted = add(base, add(worker_bytes(storage[indices[0]].unwrap())?, cap)?)?;
        if admitted > original {
            return Err(CompileError::ResourceAdmission(
                "native cohort coordinator allowance",
            ));
        }
        for n in (2..=ceiling.min(ready).min(MAX)).rev() {
            let overhead = indices[..n].iter().try_fold(base, |sum, &i| {
                add(sum, add(worker_bytes(storage[i].unwrap())?, THREAD)?)
            })?;
            // Retain each prepared graph, but only one recorder is ever live.
            let preparation_peak = add(
                overhead,
                indices[..n]
                    .iter()
                    .map(|&i| storage[i].unwrap().symbolic_workspace_bytes)
                    .max()
                    .unwrap(),
            )?;
            if preparation_peak > original {
                continue;
            }
            let Some(remaining) = original.checked_sub(overhead) else {
                continue;
            };
            let per_worker = (remaining / n).min(limits.max_requested_program_bytes);
            // The metadata-only catalogue peaked at 225 MB of compiler
            // backing. A 256 MiB scheduling floor avoids a measured retry;
            // allocation limits still enforce each cap for unseen descriptors.
            if per_worker >= 256 << 20 {
                width = n;
                // Keep every initial cap above the measured 256 MiB floor.
                // Divide spare bytes by public estimated work, retaining the
                // same summed original and byte-limit-only retry policy.
                let floor = 256 << 20;
                let spare = remaining - n * floor;
                let weight: u128 = indices[..n]
                    .iter()
                    .map(|&i| work(storage[i].unwrap()))
                    .sum();
                admitted = overhead;
                for &i in &indices[..n] {
                    let extra = (spare as u128 * work(storage[i].unwrap()) / weight) as usize;
                    caps[i] = add(floor, extra)?.min(limits.max_requested_program_bytes);
                    admitted = add(admitted, caps[i])?;
                }
                break;
            }
        }
        let preparation_peak = indices[..width]
            .iter()
            .try_fold(base, |sum, &i| add(sum, worker_bytes(storage[i].unwrap())?))?;
        let preparation_peak = add(
            preparation_peak,
            indices[..width]
                .iter()
                .map(|&i| storage[i].unwrap().symbolic_workspace_bytes)
                .max()
                .unwrap(),
        )?;
        if preparation_peak > original {
            return Err(CompileError::ResourceAdmission(
                "native preparation allowance",
            ));
        }
        stats.cohorts += 1;
        stats.admitted_host_bytes_peak = stats
            .admitted_host_bytes_peak
            .max(admitted.max(preparation_peak));
        let mut prepared: [Option<P>; MAX] = core::array::from_fn(|_| None);
        for &i in &indices[..width] {
            let started = std::time::Instant::now();
            prepared[i] = Some(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(i)))
                    .unwrap_or_else(|_| {
                        Err(CompileError::Shape("native metadata preparation panic"))
                    })?,
            );
            stats.job_ns[i] += started.elapsed().as_nanos();
        }
        let job = |i| {
            struct Active<'a>(&'a AtomicUsize);
            impl Drop for Active<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
            let _active = Active(&live);
            peak.fetch_max(n, Ordering::SeqCst);
            let started = std::time::Instant::now();
            let result = compile(i, prepared[i].as_ref().unwrap(), caps[i]);
            (result, started.elapsed().as_nanos())
        };
        let mut completed: [Option<(Result<NativeCoreBound, CompileError>, u128)>; MAX] =
            core::array::from_fn(|_| None);
        let mut failure = None;
        if width == 1 {
            stats.jobs_started += 1;
            completed[0] = Some(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(indices[0])))
                    .unwrap_or_else(|_| {
                        (Err(CompileError::Shape("native metadata worker panic")), 0)
                    }),
            );
        } else {
            std::thread::scope(|scope| {
                let mut handles: [Option<_>; MAX] = core::array::from_fn(|_| None);
                for (slot, &i) in indices[..width].iter().enumerate() {
                    let job = &job;
                    match std::thread::Builder::new()
                        .name("ringct-native-metadata".into())
                        .stack_size(STACK)
                        .spawn_scoped(scope, move || job(i))
                    {
                        Ok(h) => {
                            handles[slot] = Some(h);
                            stats.jobs_started += 1;
                        }
                        Err(_) => {
                            failure = Some(CompileError::ResourceAdmission(
                                "native metadata spawn refused",
                            ));
                            break;
                        }
                    }
                }
                for (i, handle) in handles.into_iter().enumerate() {
                    if let Some(h) = handle {
                        completed[i] = Some(h.join().unwrap_or_else(|_| {
                            (Err(CompileError::Shape("native metadata worker panic")), 0)
                        }));
                    }
                }
            });
        }
        stats.peak_workers = stats.peak_workers.max(peak.load(Ordering::SeqCst));
        let mut retry = false;
        for (slot, result) in completed.into_iter().enumerate() {
            let result = result.map(|(result, ns)| {
                stats.job_ns[indices[slot]] += ns;
                result
            });
            match result {
                Some(Ok(v)) => results[indices[slot]] = Some(v),
                Some(Err(CompileError::ResourceAdmission(
                    uni::shape::NATIVE_PROGRAM_BYTE_LIMIT,
                ))) if width > 1 => retry = true,
                Some(Err(e)) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                }
                None => {}
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        if retry {
            ceiling = (width / 2).max(1);
            stats.budget_reductions += 1;
        }
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
