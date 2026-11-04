//! The case pool starts before graph construction. Stable graph outputs feed
//! registration workers; stable prepared members feed numeric continuations.
use super::*;
use super::super::native_numbers::{Binding, Job as NativeJob, Ready, TRANSIENT_LIMIT};
use crate::{execution::{retained_resources::{Bytes, Category, Requirements, Reservation},
        workflow_resources::{PreparedNativeBatch, PreparedCryptoBatch}},
    metadata_parallel::{self as workers, Error},
    graph_tree::metadata::verifier::linear_map::Cache as LinearMapCache,
    graph_crypto::metadata_readiness as crypto,
    rust_verify::committed_backend::{UnprovedRelationGraph,
        source_binding::prepared::{EncodedGraphStructure, FRAME_BYTES}}};
use std::sync::{Arc, RwLock};
const NATIVE_LIMIT: usize = 512;
// A hard additional-result sublimit. Every member's exact census is checked
// before allocation; an oversized member stays on the ordinary later path.
const CRYPTO_LIMIT: usize = 512 << 20;
enum Job<'graph, 'prepared> {
    Encode { member: usize, graph: &'graph UnprovedRelationGraph, words: usize },
    Hash { member: usize, context: bool },
    Native { member: usize, inputs: [Option<(usize, NativeJob<'prepared>)>; 2], binding: Binding },
    Crypto { member: usize, work: Arc<crypto::Member<'prepared>>, index: usize },
}
enum Done<'a> {
    Encoded,
    Hash { member: usize, context: bool, digest: [u8; 32] },
    Native { member: usize, values: Box<[Option<(usize, Ready<'a>)>; 2]> },
    Crypto { member: usize, value: crypto::Completion<'a> },
}
fn accept<'a>(done: Done<'a>, digests: &mut [[Option<[u8; 32]>; 2]; 4],
    native: &mut Option<PreparedNativeBatch<'a>>, crypto: &mut Option<PreparedCryptoBatch<'a>>)
    -> core::result::Result<(), Error> {
    match done {
        Done::Encoded => (),
        Done::Hash { member, context, digest } => {
            if digests[member][usize::from(context)].replace(digest).is_some() { return Err(Error::Publication); }
        }
        Done::Native { member, values } => for (ordinal, value) in (*values).into_iter().flatten() {
            native.as_mut().ok_or(Error::Publication)?.insert(member, ordinal, value).map_err(|_| Error::Publication)?;
        },
        Done::Crypto { member, mut value } => {
            value.absorb().map_err(|_| Error::Publication)?;
            if let Some(numbers) = value.numbers {
                crypto.as_mut().ok_or(Error::Publication)?.insert(7 * member + value.request, numbers).map_err(|_| Error::Publication)?;
            }
        }
    }
    Ok(())
}
fn host(required: Requirements) -> Result<usize> {
    usize::try_from(required.total().map_err(|_| failure("readiness requirement overflow"))?.host)
        .map_err(|_| failure("readiness host range"))
}
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or_else(|| failure("readiness size overflow")) }
pub(super) fn prepare<'source: 'graph, 'graph: 'prepared, 'prepared, const N: usize>(
    scope: &'source SourcePlanningPlan<'source>, planning: &mut WorkflowPlanning<'_>,
    graph_plans: &FixedCaseOwnerSlots<'_, GraphPlanResult<'source>, N>,
    graphs: &'graph FixedCaseOwnerSlots<'_, GraphSourceResult, N>,
    plans: &FixedCaseOwnerSlots<'_, PreparationPlanResult<'graph>, N>,
    outputs: &'prepared FixedCaseOwnerSlots<'_, PreparedSourceResult<'graph>, N>,
) -> Result<Option<EarlyNumbers<'prepared>>> {
    let ceiling = lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling();
    if ceiling < 2 || !crate::preparation_options::readiness_enabled("cpu")
        || !crate::preparation_options::concurrency_enabled("overlap")
        || !crate::preparation_options::metadata_workers_enabled("registration")
        || !crate::preparation_options::metadata_workers_enabled("native")
        || !crate::preparation_options::metadata_workers_enabled("crypto")
        || !crate::preparation_options::parallel_registration()
        || !crate::preparation_options::structural_reuse()
        || !crate::preparation_options::buffered_encoding() { return Ok(None); }
    let Some(cache) = scope.case_verifier_cache() else { return Ok(None); };
    // Allocation-free preview protects all graph outputs and the largest
    // graph phase before the pool's fixed backing/threads are admitted.
    let mut graph_outputs = [0usize; 4];
    let mut graph_phases = [0usize; 4];
    for (member, native) in scope.natives().iter().enumerate() {
        let plan = SourceGraphPlan::new(scope, native).map_err(|_| failure("readiness graph preview"))?;
        graph_outputs[member] = host(plan.output_requirements())?;
        graph_phases[member] = host(planning.graph_preparation_requirements(&plan).map_err(|_| failure("readiness graph admission"))?)?;
    }
    let graph_future = |first: usize| -> Result<usize> {
        add(graph_outputs[first..N].iter().try_fold(0usize, |s, &n| add(s, n))?,
            graph_phases[first..N].iter().copied().max().unwrap_or(0))
    };
    let remaining = usize::try_from(planning.ledger().remaining().host).unwrap_or(usize::MAX);
    let admission = match workers::Plan::new(ceiling, workers::MAX_JOBS,
        remaining.saturating_sub(graph_future(0)?), 0, FRAME_BYTES + (4 << 20)) {
        Ok(plan) if plan.width >= 2 => plan, _ => return Ok(None),
    };
    let _pool_original = planning.ledger().reserve(Category::PhaseScratch, Bytes { host: admission.host_bytes as u64, device: 0 })
        .map_err(|_| failure("readiness pool original"))?;
    // Originals precede all values that depend on them, including failure and
    // unwind paths. scoped_with_pool joins helpers before these owners drop.
    let mut registrations: [Option<Reservation>; 4] = core::array::from_fn(|_| None);
    let mut numeric_original: Option<Reservation> = None;
    let mut native = None;
    let mut crypto = None;
    let mut crypto_enabled = true;
    let cells: [RwLock<Option<Box<EncodedGraphStructure<'graph>>>>; 4] = core::array::from_fn(|_| RwLock::new(None));
    let mut digests = [[None; 2]; 4];
    #[cfg(test)] let began = std::time::Instant::now();
    #[cfg(test)] let mut graph_ready = [0u128; 4];
    #[cfg(test)] let mut source_ready = [0u128; 4];
    #[cfg(test)] let hash_ready: [std::sync::atomic::AtomicU64; 4] = core::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0));
    #[cfg(test)] let request_ready: [std::sync::atomic::AtomicU64; 28] = core::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0));
    // Workers borrow the cache through a cell; only the coordinator creates
    // it under its original before the first native job can be submitted.
    let linear_cell = RwLock::new(None::<LinearMapCache>);
    let outcome = workers::pool::scoped_with_pool(admission, |caller| Ok(caller), |caller, job, pool| match job {
        Job::Encode { member, graph, words } => {
            let value = EncodedGraphStructure::encode(graph, words).map_err(|_| Error::Worker)?;
            let mut slot = cells[member].write().map_err(|_| Error::Worker)?;
            if slot.replace(value).is_some() { return Err(Error::Publication); }
            drop(slot);
            for context in [false, true] { pool.submit(4, words, Job::Hash { member, context })?; }
            Ok(Done::Encoded)
        }
        Job::Hash { member, context } => {
            let digest = cells[member].read().map_err(|_| Error::Worker)?.as_ref().ok_or(Error::Geometry)?
                .hash(context).map_err(|_| Error::Worker)?;
            #[cfg(test)] hash_ready[member].fetch_max(u64::try_from(began.elapsed().as_nanos()).unwrap_or(u64::MAX), std::sync::atomic::Ordering::Relaxed);
            Ok(Done::Hash { member, context, digest })
        }
        Job::Native { member, inputs, binding } => {
            let maps = linear_cell.read().map_err(|_| Error::Worker)?;
            let maps = maps.as_ref().ok_or(Error::Geometry)?;
            let mut values = Box::new(core::array::from_fn(|_| None));
            for (slot, input) in values.iter_mut().zip(inputs) {
                if let Some((ordinal, input)) = input {
                    *slot = input.prepare_bounded(binding.clone(), cache, maps).map_err(|_| Error::Worker)?
                        .map(|value| (ordinal, value));
                }
            }
            Ok(Done::Native { member, values })
        }
        Job::Crypto { member, work, index } => {
            let value = work.compute(index, *caller).map_err(|_| Error::Worker)?;
            #[cfg(test)] if value.numbers.is_some() {
                request_ready[7 * member + value.request].store(u64::try_from(began.elapsed().as_nanos()).unwrap_or(u64::MAX), std::sync::atomic::Ordering::Relaxed);
            }
            Ok(Done::Crypto { member, value })
        }
    }, |pool, caller| {
        let mut all_registered = true;
        for (member, source) in scope.natives().iter().enumerate() {
            let plan_slot = graph_plans.get(member).map_err(|_| Error::Publication)?;
            plan_slot.install(SourceGraphPlan::new(scope, source)).map_err(|_| Error::Publication)?;
            let plan = plan_slot.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            let graph_slot = graphs.get(member).map_err(|_| Error::Publication)?;
            pool.publication(true, || graph_slot.install(planning.prepare_graph(plan.operation())))?
                .map_err(|_| Error::Publication)?;
            let graph = graph_slot.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            #[cfg(test)] { graph_ready[member] = began.elapsed().as_nanos(); }
            let slot = plans.get(member).map_err(|_| Error::Publication)?;
            slot.install(SourcePreparationPlan::new(scope, graph, source)).map_err(|_| Error::Publication)?;
            let plan = slot.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            let (graph, words, bytes) = plan.registration_input();
            let remaining = usize::try_from(planning.ledger().remaining().host).unwrap_or(usize::MAX);
            if bytes <= remaining.saturating_sub(graph_future(member + 1).map_err(|_| Error::Budget)?) {
                registrations[member] = Some(planning.ledger().reserve(Category::PhaseScratch,
                    Bytes { host: bytes as u64, device: 0 }).map_err(|_| Error::Budget)?);
                pool.account_admitted(bytes)?;
                pool.submit(3, words, Job::Encode { member, graph, words })?;
            } else { all_registered = false; }
            while let Some(done) = pool.try_receive()? { accept(done.value, &mut digests, &mut native, &mut crypto)?; }
        }
        super::super::driver::metadata_timing::phase(super::super::driver::metadata_timing::Phase::SourcePreparation);
        let mut future_outputs = 0usize;
        let mut largest_phase = 0usize;
        for member in 0..N {
            let plan = plans.get(member).and_then(|s| s.get()).map_err(|_| Error::Publication)?
                .as_ref().map_err(|_| Error::Publication)?;
            future_outputs = future_outputs.checked_add(host(plan.output_requirements()).map_err(|_| Error::Budget)?).ok_or(Error::Budget)?;
            largest_phase = largest_phase.max(host(planning.source_preparation_requirements(plan)
                .map_err(|_| Error::Budget)?).map_err(|_| Error::Budget)?);
        }
        let future = future_outputs.checked_add(largest_phase).ok_or(Error::Budget)?;
        let remaining = usize::try_from(planning.ledger().remaining().host).unwrap_or(usize::MAX);
        if !all_registered || future > remaining {
            // Exact later source geometry can exceed the early opportunity.
            // Join and discard speculative registration before ordinary retry.
            while pool.outstanding() != 0 {
                while let Some(done) = pool.try_receive()? { accept(done.value, &mut digests, &mut native, &mut crypto)?; }
                if pool.outstanding() != 0 && !caller.help()? { pool.wait()?; }
            }
            return Ok(false);
        }
        let native_bytes = NativeJob::maximum_retained_bytes().checked_mul(NATIVE_LIMIT)
            .and_then(|n| n.checked_add(PreparedNativeBatch::backing_bytes(NATIVE_LIMIT).ok()?)).ok_or(Error::Budget)?;
        let transient = TRANSIENT_LIMIT.checked_mul(admission.width)
            .and_then(|n| n.checked_add(LinearMapCache::allowance_bytes())).ok_or(Error::Budget)?;
        let extra = native_bytes.checked_add(CRYPTO_LIMIT).and_then(|n| n.checked_add(transient)).ok_or(Error::Budget)?;
        if extra <= remaining - future {
            let original = planning.ledger().reserve(Category::PhaseScratch, Bytes { host: native_bytes as u64, device: 0 }).map_err(|_| Error::Budget)?;
            native = Some(PreparedNativeBatch::new(original, NATIVE_LIMIT).map_err(|_| Error::Budget)?);
            crypto = Some(PreparedCryptoBatch::new(planning.ledger().reserve(Category::PhaseScratch,
                Bytes { host: CRYPTO_LIMIT as u64, device: 0 }).map_err(|_| Error::Budget)?));
            numeric_original = Some(planning.ledger().reserve(Category::PhaseScratch,
                Bytes { host: transient as u64, device: 0 }).map_err(|_| Error::Budget)?);
            *linear_cell.write().map_err(|_| Error::Publication)? = Some(LinearMapCache::new(LinearMapCache::allowance_bytes()).map_err(|_| Error::Budget)?);
            pool.account_admitted(extra)?;
        }
        let mut native_jobs = 0;
        let mut crypto_bytes = 0usize;
        for member in 0..N {
            while digests[member].iter().any(Option::is_none) {
                while let Some(done) = pool.try_receive()? { accept(done.value, &mut digests, &mut native, &mut crypto)?; }
                if digests[member].iter().any(Option::is_none) && !caller.help_matching(|job|
                    matches!(job, Job::Encode { member: ready, .. } | Job::Hash { member: ready, .. } if *ready == member))? {
                    pool.wait()?;
                }
            }
            let encoded = cells[member].write().map_err(|_| Error::Publication)?.take().ok_or(Error::Publication)?;
            let registration = (*encoded).finish(digests[member][0].ok_or(Error::Publication)?, digests[member][1].ok_or(Error::Publication)?);
            let plan = plans.get(member).and_then(|s| s.get()).map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            let output = outputs.get(member).map_err(|_| Error::Publication)?;
            pool.publication(true, || output.install(planning.prepare_sources(plan.operation_with_registration(registration))))?
                .map_err(|_| Error::Publication)?;
            let original = output.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            drop(registrations[member].take());
            #[cfg(test)] { source_ready[member] = began.elapsed().as_nanos(); }
            let mut issue = |priority, cost, job| {
                while pool.outstanding() >= workers::MAX_JOBS - 2 * N {
                    while let Some(done) = pool.try_receive()? { accept(done.value, &mut digests, &mut native, &mut crypto)?; }
                    if pool.outstanding() >= workers::MAX_JOBS - 2 * N && !caller.help()? { pool.wait()?; }
                }
                pool.submit(priority, cost, job).map(|_| ())
            };
            if let Some(scratch) = numeric_original.as_ref() {
                if crypto_enabled {
                    let plan = crypto::Plan::new(original.get().crypto().requests(), original.get().context().clone(), scope.layout(), admission.width)
                        .map_err(|_| Error::Geometry)?;
                    let bytes = plan.retained_bytes();
                    if plan.transient_bytes() <= TRANSIENT_LIMIT && bytes <= CRYPTO_LIMIT.saturating_sub(crypto_bytes) {
                        crypto_bytes += bytes;
                        if let Some(work) = plan.prepare(bytes, scratch, planning.ledger()).map_err(|_| Error::Worker)? {
                            let work = Arc::new(work);
                            for index in 0..work.jobs() {
                                issue(2, work.cost(index).map_err(|_| Error::Geometry)?, Job::Crypto { member, work: work.clone(), index })?;
                            }
                        } else { crypto_enabled = false; }
                    } else { crypto_enabled = false; }
                }
                let mut inputs = [None; 2];
                let mut count = 0;
                for ordinal in 0..original.get().algebra().batches().len() {
                    let Some(input) = NativeJob::from_original(original, ordinal).map_err(|_| Error::Publication)? else { continue; };
                    if native_jobs == NATIVE_LIMIT { continue; }
                    inputs[count] = Some((ordinal, input)); count += 1; native_jobs += 1;
                    if count == 2 {
                        let cost = inputs.iter().flatten().map(|(_, input)| input.retained_bytes()).sum();
                        issue(1, cost, Job::Native { member, inputs, binding: Binding::new(scope, original) })?;
                        inputs = [None; 2]; count = 0;
                    }
                }
                if count != 0 { issue(1, inputs[0].unwrap().1.retained_bytes(), Job::Native { member, inputs, binding: Binding::new(scope, original) })?; }
            }
        }
        while pool.outstanding() != 0 {
            while let Some(done) = pool.try_receive()? { accept(done.value, &mut digests, &mut native, &mut crypto)?; }
            if pool.outstanding() != 0 && !caller.help()? { pool.wait()?; }
        }
        Ok(true)
    });
    #[cfg(test)] if std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1") {
        eprintln!("RINGCT_METADATA_READINESS_DETAIL {}", serde_json::json!({
            "graph_ready_ns": &graph_ready[..N], "source_ready_ns": &source_ready[..N],
            "registration_ready_ns": hash_ready[..N].iter().map(|v| v.load(std::sync::atomic::Ordering::Relaxed)).collect::<Vec<_>>(),
            "request_ready_ns": request_ready[..7 * N].iter().map(|v| v.load(std::sync::atomic::Ordering::Relaxed)).collect::<Vec<_>>(),
            "joined_ns": began.elapsed().as_nanos(), "early_crypto": crypto.is_some() && crypto_enabled }));
    }
    // The cell borrows the phase cache; end that borrow before teardown.
    drop(linear_cell);
    drop(cells);
    drop(registrations);
    match outcome {
        Ok((completed, stats)) => {
            workers::report("case_readiness", stats);
            if !completed {
                drop(numeric_original);
                drop(_pool_original);
                return Ok(Some(EarlyNumbers { native: super::prepare_planned_sources(scope, planning, plans, outputs)?, crypto: None }));
            }
            if !crypto_enabled { crypto = None; }
            Ok(Some(EarlyNumbers { native, crypto }))
        }
        Err(_) => { planning.poison_numeric_preparation(); Err(failure("readiness worker or source continuation failed")) }
    }
}
