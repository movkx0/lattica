//! One bounded pool spans registration and the coordinator's GPU source phases.
//! Only immutable payload views and private numeric results enter the queue.
use super::*;
use super::super::native_numbers::{Binding, Job as NativeJob, Ready, TRANSIENT_LIMIT};
use crate::execution::{retained_resources::{Bytes, Category}, workflow_resources::PreparedNativeBatch};
use crate::metadata_parallel::{self as workers, Error};
use crate::rust_verify::committed_backend::{UnprovedRelationGraph,
    source_binding::prepared::{EncodedGraphStructure, FRAME_BYTES}};
use std::sync::RwLock;
use crate::graph_tree::metadata::verifier::linear_map::Cache as LinearMapCache;

// This is an admission sublimit, not an estimate. A larger census is left for
// its ordinary constructor before any worker executes it.
const NATIVE_LIMIT: usize = 512;
enum Job<'graph, 'a> {
    Encode { member: usize, graph: &'graph UnprovedRelationGraph, words: usize },
    Hash { member: usize, context: bool },
    Native { member: usize, inputs: [Option<(usize, NativeJob<'a>)>; 2], binding: Binding },
}
enum Done<'graph, 'a> {
    Encoded { member: usize, value: Box<EncodedGraphStructure<'graph>> },
    Hash { member: usize, context: bool, digest: [u8; 32] },
    Native { member: usize, values: Box<[Option<(usize, Ready<'a>)>; 2]> },
}
fn accept<'graph, 'a>(done: Done<'graph, 'a>, pool: &workers::pool::Pool<Job<'graph, 'a>, Done<'graph, 'a>>,
    cells: &[RwLock<Option<Box<EncodedGraphStructure<'graph>>>>; 4], costs: &[usize; 4],
    digests: &mut [[Option<[u8; 32]>; 2]; 4], batch: &mut PreparedNativeBatch<'a>) -> core::result::Result<(), Error> {
    match done {
        Done::Encoded { member, value } => {
            let mut cell = cells[member].write().map_err(|_| Error::Publication)?;
            if cell.replace(value).is_some() { return Err(Error::Publication); }
            for context in [false, true] { pool.submit(2, costs[member], Job::Hash { member, context })?; }
        }
        Done::Hash { member, context, digest } => {
            if digests[member][usize::from(context)].replace(digest).is_some() { return Err(Error::Publication); }
        }
        Done::Native { member, values } => for (ordinal, value) in (*values).into_iter().flatten() {
            batch.insert(member, ordinal, value).map_err(|_| Error::Publication)?;
        },
    }
    Ok(())
}
pub(super) fn prepare<'source: 'graph, 'graph: 'prepared, 'prepared, const N: usize>(
    scope: &SourcePlanningPlan<'source>, planning: &mut WorkflowPlanning<'_>,
    plans: &FixedCaseOwnerSlots<'_, PreparationPlanResult<'graph>, N>,
    outputs: &'prepared FixedCaseOwnerSlots<'_, PreparedSourceResult<'graph>, N>,
) -> Result<Option<PreparedNativeBatch<'prepared>>> {
    let ceiling = lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling();
    if ceiling < 2 || !crate::preparation_options::concurrency_enabled("overlap")
        || !crate::preparation_options::metadata_workers_enabled("registration")
        || !crate::preparation_options::metadata_workers_enabled("native")
        || !crate::preparation_options::parallel_registration()
        || !crate::preparation_options::structural_reuse()
        || !crate::preparation_options::buffered_encoding() { return Ok(None); }
    let Some(cache) = scope.case_verifier_cache() else { return Ok(None); };
    if !matches!(N, 3 | 4) { return Err(failure("overlap case size")); }
    let mut inputs = [None; 4];
    let mut costs = [0; 4];
    let mut registration_bytes = 0usize;
    let mut outputs_bytes = 0usize;
    let mut largest_phase = 0usize;
    let host = |requirements: crate::execution::retained_resources::Requirements| -> Result<usize> {
        usize::try_from(requirements.total().map_err(|_| failure("overlap host overflow"))?.host)
            .map_err(|_| failure("overlap host range"))
    };
    for member in 0..N {
        let plan = plans.get(member)?.get()?.as_ref().map_err(|_| failure("overlap source plan"))?;
        let input = plan.registration_input();
        costs[member] = input.1;
        registration_bytes = registration_bytes.checked_add(input.2).ok_or_else(|| failure("overlap registration overflow"))?;
        outputs_bytes = outputs_bytes.checked_add(host(plan.output_requirements())?).ok_or_else(|| failure("overlap output overflow"))?;
        largest_phase = largest_phase.max(host(planning.source_preparation_requirements(plan).map_err(|_| failure("overlap source admission"))?)?);
        inputs[member] = Some(input);
    }
    let native_bytes = NativeJob::maximum_retained_bytes().checked_mul(NATIVE_LIMIT)
        .and_then(|n| n.checked_add(PreparedNativeBatch::backing_bytes(NATIVE_LIMIT).ok()?))
        .ok_or_else(|| failure("overlap native backing"))?;
    let retained = native_bytes.checked_add(registration_bytes).and_then(|n| n.checked_add(LinearMapCache::allowance_bytes())).ok_or_else(|| failure("overlap retained overflow"))?;
    let future = outputs_bytes.checked_add(largest_phase).ok_or_else(|| failure("overlap future overflow"))?;
    let budget = usize::try_from(planning.ledger().remaining().host).unwrap_or(usize::MAX).saturating_sub(future);
    let transient = TRANSIENT_LIMIT.checked_add(FRAME_BYTES).and_then(|n| n.checked_add(4 << 20))
        .ok_or_else(|| failure("overlap transient overflow"))?;
    let admission = match workers::Plan::new(ceiling, workers::MAX_JOBS, budget, retained, transient) {
        Ok(plan) if plan.width >= 2 => plan, _ => return Ok(None),
    };
    let native_original = planning.ledger().reserve(Category::PhaseScratch, Bytes { host: native_bytes as u64, device: 0 })
        .map_err(|_| failure("overlap native original"))?;
    let _workers_original = planning.ledger().reserve(Category::PhaseScratch,
        Bytes { host: (admission.host_bytes - native_bytes) as u64, device: 0 })
        .map_err(|_| failure("overlap worker original"))?;
    let linear_maps = LinearMapCache::new(LinearMapCache::allowance_bytes()).map_err(|_| failure("overlap cache backing"))?;
    let mut batch = PreparedNativeBatch::new(native_original, NATIVE_LIMIT).map_err(|_| failure("overlap result backing"))?;
    let cells: [RwLock<Option<Box<EncodedGraphStructure<'graph>>>>; 4] = core::array::from_fn(|_| RwLock::new(None));
    let mut digests = [[None; 2]; 4];
    #[cfg(test)] let began = std::time::Instant::now();
    #[cfg(test)] let mut source_started = [0u128; 4];
    #[cfg(test)] let mut source_finished = [0u128; 4];
    #[cfg(test)] let mut dispatched = [0u128; 4];
    let outcome = workers::pool::scoped(admission, |_| Ok(()), |_, job| {
        match job {
            Job::Encode { member, graph, words } => Ok(Done::Encoded { member,
                value: EncodedGraphStructure::encode(graph, words).map_err(|_| Error::Worker)? }),
            Job::Hash { member, context } => Ok(Done::Hash { member, context, digest:
                cells[member].read().map_err(|_| Error::Worker)?.as_ref().ok_or(Error::Geometry)?
                    .hash(context).map_err(|_| Error::Worker)? }),
            Job::Native { member, inputs, binding } => {
                // The two result slots are covered by each input's existing
                // retained-result/frame allowance, including completed work.
                let mut values = Box::new(core::array::from_fn(|_| None));
                for (slot, input) in values.iter_mut().zip(inputs) {
                    if let Some((ordinal, input)) = input {
                        *slot = input.prepare_bounded(binding.clone(), cache, &linear_maps).map_err(|_| Error::Worker)?.map(|value| (ordinal, value));
                    }
                }
                Ok(Done::Native { member, values })
            },
        }
    }, |pool, caller| {
        for member in 0..N {
            let (graph, words, _) = inputs[member].ok_or(Error::Geometry)?;
            pool.submit(3, words, Job::Encode { member, graph, words })?;
        }
        let mut native_jobs = 0;
        for member in 0..N {
            while digests[member].iter().any(Option::is_none) {
                while let Some(done) = pool.try_receive()? { accept(done.value, pool, &cells, &costs, &mut digests, &mut batch)?; }
                if digests[member].iter().any(Option::is_none) && !caller.help_matching(|job| {
                    matches!(job, Job::Encode { member: ready, .. } | Job::Hash { member: ready, .. } if *ready == member)
                })? { pool.wait()?; }
            }
            let encoded = cells[member].write().map_err(|_| Error::Publication)?.take().ok_or(Error::Publication)?;
            let registration = (*encoded).finish(digests[member][0].ok_or(Error::Publication)?, digests[member][1].ok_or(Error::Publication)?);
            let plan = plans.get(member).and_then(|slot| slot.get()).map_err(|_| Error::Publication)?
                .as_ref().map_err(|_| Error::Publication)?;
            let output = outputs.get(member).map_err(|_| Error::Publication)?;
            #[cfg(test)] { source_started[member] = began.elapsed().as_nanos(); }
            pool.publication(true, || {
                output.install(planning.prepare_sources(plan.operation_with_registration(registration))).map_err(|_| Error::Publication)?;
                output.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
                Ok::<_, Error>(())
            })??;
            #[cfg(test)] { source_finished[member] = began.elapsed().as_nanos(); }
            while let Some(done) = pool.try_receive()? { accept(done.value, pool, &cells, &costs, &mut digests, &mut batch)?; }
            let original = output.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            let mut issue = |inputs: [Option<(usize, NativeJob<'prepared>)>; 2]| {
                // Keep space for hash continuations. Helpers refill themselves;
                // the coordinator can start the next GPU phase immediately.
                while pool.outstanding() >= workers::MAX_JOBS - 2 * N {
                    while let Some(done) = pool.try_receive()? { accept(done.value, pool, &cells, &costs, &mut digests, &mut batch)?; }
                    if pool.outstanding() >= workers::MAX_JOBS - 2 * N { pool.wait()?; }
                }
                let cost = inputs.iter().flatten().try_fold(0usize, |sum, (_, input)| sum.checked_add(input.retained_bytes()).ok_or(Error::Geometry))?;
                pool.submit(1, cost, Job::Native { member, inputs, binding: Binding::new(scope, original) })?;
                Ok::<_, Error>(())
            };
            let mut inputs = [None; 2];
            let mut length = 0;
            for ordinal in 0..original.get().algebra().batches().len() {
                let Some(input) = NativeJob::from_original(original, ordinal).map_err(|_| Error::Publication)? else { continue; };
                // Eligibility is decided before dispatch. Omitted work is still
                // derived by the ordinary typed constructor later in the case.
                if native_jobs == NATIVE_LIMIT { continue; }
                inputs[length] = Some((ordinal, input)); length += 1;
                if length == 2 { issue(inputs)?; inputs = [None; 2]; length = 0; }
                native_jobs += 1;
            }
            if length != 0 { issue(inputs)?; }
            #[cfg(test)] { dispatched[member] = began.elapsed().as_nanos(); }
        }
        while pool.outstanding() != 0 {
            while let Some(done) = pool.try_receive()? { accept(done.value, pool, &cells, &costs, &mut digests, &mut batch)?; }
            if pool.outstanding() != 0 && !caller.help()? { pool.wait()?; }
        }
        Ok(())
    });
    #[cfg(test)] if std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1") {
        eprintln!("RINGCT_METADATA_CASE_PIPELINE_DETAIL {}", serde_json::json!({
            "source_started_ns": &source_started[..N], "source_finished_ns": &source_finished[..N],
            "dispatched_ns": &dispatched[..N], "joined_ns": began.elapsed().as_nanos()
        }));
    }
    match outcome {
        Ok(((), statistics)) => { workers::report("case_pipeline", statistics); Ok(Some(batch)) }
        Err(_) => { planning.poison_numeric_preparation(); Err(failure("overlap worker or source continuation failed")) }
    }
}
