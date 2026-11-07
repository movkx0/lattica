//! Coordinator-owned reservations survive every worker, including failed jobs.
//! Workers own their non-Send contexts; no ledger or context crosses a thread.
use super::*;
use crate::execution::{
    retained_resources::{Bytes, Category, Ledger, Reservation, WorkerAllowance},
    ProvingContext,
};
use jobs::{Observation, Output, Spec, Task};
use std::sync::mpsc;

// Explicit native joins also wait for thread-local destructors. Scope closure
// completion and Rayon pool termination alone do not provide that boundary.
struct ComputeJoins(Vec<std::thread::JoinHandle<()>>);
impl ComputeJoins {
    fn finish(&mut self) -> Result<()> {
        let mut failed = false;
        for thread in self.0.drain(..) {
            failed |= thread.join().is_err();
        }
        ensure(!failed, "CPU compute thread panicked")
    }
}
impl Drop for ComputeJoins {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
struct OwnerJoins<'scope>(Vec<std::thread::ScopedJoinHandle<'scope, Result<()>>>);
impl OwnerJoins<'_> {
    fn finish(&mut self) -> Result<()> {
        let mut failure = None;
        for thread in self.0.drain(..) {
            let result = thread
                .join()
                .unwrap_or_else(|_| Err("CPU owner thread panicked".into()));
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for OwnerJoins<'_> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

enum Work {
    Run(Task),
    Evict,
}
enum Completion {
    Done(
        usize,
        usize,
        Result<(Output, Observation, Option<[u8; 32]>)>,
    ),
    Evicted(usize, Result<()>),
    Failed(usize, String),
}
struct Active {
    id: usize,
    work: Option<Reservation>,
    output: Reservation,
    inputs: Vec<Reservation>,
}
// The prepared program retains the same compiler input allocation. Keep
// that original reservation alongside the reusable CPU work envelope.
struct PreparedClaim {
    identity: [u8; 32],
    _work: Reservation,
    _program_originals: Vec<Reservation>,
}
pub(super) fn fixed_bytes(options: &Options) -> u64 {
    (512 << 20)
        + options.workers as u64
            * (crate::execution::PUBLIC_METADATA_LIMIT_BYTES as u64 + (8 << 20))
        + ((options.workers * (options.threads_per_proof + 1)) as u64) * (3 << 20)
}
#[derive(serde::Serialize)]
pub struct Record {
    repetition: usize,
    wall_ns: u128,
    cleanup_ns: u128,
    coordinator_wait_ns: u128,
    peak_workers: usize,
    peak_admitted_host_bytes: u64,
    admitted_device_bytes: u64,
    completed_jobs: usize,
    planned_jobs: usize,
    cache_evictions: usize,
    pub jobs: Vec<Observation>,
    cleanup_complete: bool,
}
fn reserve(ledger: &Ledger, bytes: u64) -> Result<Reservation> {
    ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: bytes,
                device: 0,
            },
        )
        .map_err(|e| format!("CPU admission: {e:?}"))
}
pub(super) fn priorities(deps: &[Vec<usize>], costs: &[u64]) -> Result<Vec<u64>> {
    ensure(deps.len() == costs.len(), "DAG cost length")?;
    let mut weights = costs.to_vec();
    let mut consumers = vec![0usize; deps.len()];
    for id in (0..deps.len()).rev() {
        for &dep in &deps[id] {
            ensure(dep < id, "DAG dependency is not an earlier node")?;
            consumers[dep] += 1;
            ensure(
                consumers[dep] == 1,
                "CPU slice requires unique consuming successor",
            )?;
            weights[dep] = weights[dep].max(
                costs[dep]
                    .checked_add(weights[id])
                    .ok_or("DAG cost overflow")?,
            );
        }
    }
    Ok(weights)
}
pub fn run(options: &Options, jobs: Vec<Spec>, repetition: usize) -> Result<Record> {
    let ledger = Ledger::new(WorkerAllowance {
        host: options.host_bytes(),
        device: 0,
    });
    run_with_ledger(options, jobs, repetition, &ledger)
}
pub(super) fn run_with_ledger(
    options: &Options,
    jobs: Vec<Spec>,
    repetition: usize,
    ledger: &Ledger,
) -> Result<Record> {
    let count = jobs.len();
    let deps: Vec<_> = jobs.iter().map(|j| j.deps.clone()).collect();
    let costs: Vec<_> = jobs.iter().map(|j| j.cost).collect();
    let mut consumed = vec![false; count];
    for inputs in &deps {
        for &id in inputs {
            if id < count {
                consumed[id] = true;
            }
        }
    }
    let priority = priorities(&deps, &costs)?;
    let fixed = reserve(&ledger, fixed_bytes(options))?;
    // These live outside the scoped thread region. Even early errors cannot
    // release claimed storage before all in-flight workers have been joined.
    let mut active: Vec<Option<Active>> = (0..options.workers).map(|_| None).collect();
    let mut cache: Vec<Option<PreparedClaim>> = (0..options.workers).map(|_| None).collect();
    let mut output_claims: Vec<Option<Reservation>> = (0..count).map(|_| None).collect();
    let mut outputs: Vec<Option<Output>> = (0..count).map(|_| None).collect();
    let mut planned: Vec<_> = jobs.into_iter().map(Some).collect();
    let mut complete = vec![false; count];
    let mut evicting = vec![false; options.workers];
    let start = Instant::now();
    let mut reports = Vec::with_capacity(count);
    let mut wait_ns = 0;
    let mut peak_workers = 0;
    let mut cache_evictions = 0;
    let mut shutdown_started = None;
    let result = std::thread::scope(|scope| -> Result<()> {
        let (done_tx, done_rx) = mpsc::channel();
        // Declared before senders so errors close all channels before joining.
        let mut owners = OwnerJoins(Vec::new());
        let mut senders = Vec::new();
        for slot in 0..options.workers {
            let (tx, rx) = mpsc::sync_channel(1);
            senders.push(tx);
            let done = done_tx.clone();
            let threads = options.threads_per_proof;
            let retain = options.retain;
            let profile = options.host_profile();
            let variant = options.cpu_variant;
            owners.0.push(
                std::thread::Builder::new()
                    .name(format!("ringct-cpu-proof-{slot}"))
                    .stack_size(2 << 20)
                    .spawn_scoped(scope, move || {
                        let worker = || -> Result<()> {
                            let mut compute_joins = ComputeJoins(Vec::new());
                            let pool = rayon::ThreadPoolBuilder::new()
                                .num_threads(threads)
                                .stack_size(2 << 20)
                                .thread_name(move |i| format!("ringct-proof-{slot}-{i}"))
                                .spawn_handler(|thread| {
                                    let mut builder = std::thread::Builder::new();
                                    if let Some(name) = thread.name() {
                                        builder = builder.name(name.to_owned());
                                    }
                                    if let Some(size) = thread.stack_size() {
                                        builder = builder.stack_size(size);
                                    }
                                    compute_joins.0.push(builder.spawn(move || thread.run())?);
                                    Ok(())
                                })
                                .build()
                                .map_err(error)?;
                            let done = done.clone();
                            let result = pool.install(move || -> Result<()> {
                                let context =
                                    ProvingContext::cpu_research_with_variant(profile, variant)?;
                                let mut identity = None;
                                while let Ok(work) = rx.recv() {
                                    match work {
                                        Work::Evict => {
                                            let result = context.release_prepared();
                                            identity = None;
                                            if done.send(Completion::Evicted(slot, result)).is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Work::Run(task) => {
                                            let id = task.id;
                                            let executed = std::panic::catch_unwind(
                                                std::panic::AssertUnwindSafe(|| {
                                                    jobs::execute(task, &context, identity)
                                                }),
                                            );
                                            let mut result = executed.unwrap_or_else(|_| {
                                                Err("CPU proof worker panicked".into())
                                            });
                                            if !retain || result.is_err() {
                                                if let Err(e) = context.release_prepared() {
                                                    result = Err(e);
                                                }
                                                if let Ok((_, _, ref mut next)) = result {
                                                    *next = None;
                                                }
                                            }
                                            identity =
                                                result.as_ref().ok().and_then(|(_, _, next)| *next);
                                            if done
                                                .send(Completion::Done(slot, id, result))
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                }
                                context.release_prepared()?;
                                drop(context);
                                Ok(())
                            });
                            drop(pool);
                            compute_joins.finish()?;
                            result
                        };
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(worker))
                                .unwrap_or_else(|_| Err("CPU worker lifecycle panicked".into()));
                        if let Err(ref e) = outcome {
                            let _ = done.send(Completion::Failed(slot, e.clone()));
                        }
                        outcome
                    })
                    .map_err(error)?,
            );
        }
        drop(done_tx);
        while reports.len() < count {
            let mut dispatched = false;
            let mut ready: Vec<_> = (0..count)
                .filter(|&id| planned[id].is_some() && deps[id].iter().all(|&d| complete[d]))
                .collect();
            // Prefer an already prepared program when remaining path costs
            // tie. Choosing only the worker would still evict A for B while
            // another ready A could reuse the same immutable preparation.
            let mut affinity = vec![false; count];
            for &id in &ready {
                let (_, _, identity) = planned[id]
                    .as_ref()
                    .unwrap()
                    .admission(&outputs, options.cpu_variant)?;
                affinity[id] = identity.is_some_and(|tag| {
                    (0..options.workers).any(|slot| {
                        active[slot].is_none()
                            && !evicting[slot]
                            && cache[slot]
                                .as_ref()
                                .is_some_and(|have| have.identity == tag)
                    })
                });
            }
            ready.sort_by_key(|&id| {
                (
                    planned[id].as_ref().unwrap().ready_phase(),
                    std::cmp::Reverse(priority[id]),
                    !affinity[id],
                    id,
                )
            });
            for id in ready {
                let spec = planned[id].as_ref().unwrap();
                let (work_bytes, output_bytes, identity) =
                    spec.admission(&outputs, options.cpu_variant)?;
                ensure(
                    work_bytes + output_bytes <= options.host_bytes(),
                    &format!(
                        "CPU job {id} admission estimate {} exceeds host allowance {}",
                        work_bytes + output_bytes,
                        options.host_bytes()
                    ),
                )?;
                let mut idle: Vec<_> = (0..options.workers)
                    .filter(|&s| active[s].is_none() && !evicting[s])
                    .collect();
                idle.sort_by_key(|&s| {
                    (
                        !identity.is_some_and(|tag| {
                            cache[s].as_ref().is_some_and(|have| have.identity == tag)
                        }),
                        s,
                    )
                });
                for slot in idle {
                    let hit = identity.is_some_and(|tag| {
                        cache[slot]
                            .as_ref()
                            .is_some_and(|have| have.identity == tag)
                    });
                    // A different registered program must retire on its owner
                    // before its reservation can fund replacement preparation.
                    if identity.is_some() && cache[slot].is_some() && !hit {
                        senders[slot].send(Work::Evict).map_err(error)?;
                        evicting[slot] = true;
                        dispatched = true;
                        continue;
                    }
                    let retained = if hit {
                        cache[slot]
                            .as_ref()
                            .unwrap()
                            ._work
                            .requirements()
                            .total()
                            .map_err(error)?
                            .host
                    } else {
                        0
                    };
                    let scratch = work_bytes.saturating_sub(retained);
                    let required = output_bytes
                        .checked_add(scratch)
                        .ok_or("CPU scratch overflow")?;
                    if ledger.remaining().host < required {
                        if hit {
                            // A hit retains the old compiler source as well
                            // as preparation. Evict it on its owner before
                            // starting more roots: otherwise new compiled
                            // programs can strand a ready proof indefinitely.
                            senders[slot].send(Work::Evict).map_err(error)?;
                            evicting[slot] = true;
                            dispatched = true;
                        }
                        continue;
                    }
                    let work = if scratch == 0 {
                        None
                    } else {
                        Some(reserve(&ledger, scratch)?)
                    };
                    let output = reserve(&ledger, output_bytes)?;
                    let spec = planned[id].take().unwrap();
                    let mut values = Vec::new();
                    let mut originals = Vec::new();
                    for dep in spec.deps {
                        values.push(
                            outputs[dep]
                                .take()
                                .ok_or("consumed/missing dependency output")?,
                        );
                        originals.push(
                            output_claims[dep]
                                .take()
                                .ok_or("missing dependency original")?,
                        );
                    }
                    active[slot] = Some(Active {
                        id,
                        work,
                        output,
                        inputs: originals,
                    });
                    senders[slot]
                        .send(Work::Run(Task {
                            id,
                            kind: spec.kind,
                            inputs: values,
                            retain_native: options.retain,
                        }))
                        .map_err(error)?;
                    peak_workers = peak_workers.max(active.iter().filter(|s| s.is_some()).count());
                    dispatched = true;
                    break;
                }
            }
            if active.iter().all(Option::is_none) && evicting.iter().all(|x| !*x) {
                // Idle cached preparation may otherwise strand a larger ready
                // job. Drop it synchronously on its owner before retrying.
                if let Some(slot) = (0..options.workers).find(|&s| cache[s].is_some()) {
                    senders[slot].send(Work::Evict).map_err(error)?;
                    evicting[slot] = true;
                } else {
                    return Err("CPU DAG cannot make progress within its memory allowance".into());
                }
            }
            let wait = Instant::now();
            let completion = done_rx.recv().map_err(error)?;
            wait_ns += wait.elapsed().as_nanos();
            match completion {
                Completion::Failed(slot, e) => return Err(format!("CPU worker {slot}: {e}")),
                Completion::Evicted(slot, result) => {
                    result?;
                    ensure(evicting[slot], "unexpected eviction completion")?;
                    evicting[slot] = false;
                    drop(cache[slot].take());
                    cache_evictions += 1;
                }
                Completion::Done(slot, id, result) => {
                    let held = active[slot].as_ref().ok_or("duplicate CPU completion")?;
                    ensure(held.id == id && !complete[id], "CPU completion identity")?;
                    let (output, mut report, next) = result?;
                    let compiled_bytes = output.compiled_output_bytes()?;
                    report.compiled_storage_bytes = compiled_bytes;
                    // Validate before taking the original: on any error all
                    // claims must survive owner/context and compute-thread joins.
                    if let (Some(tag), Some(bytes)) = (next, report.prepared_claim_bytes) {
                        let original =
                            if let Some(old) = cache[slot].as_ref().filter(|c| c.identity == tag) {
                                &old._work
                            } else {
                                held.work
                                    .as_ref()
                                    .ok_or("cache has no original reservation")?
                            };
                        ensure(
                            bytes <= original.requirements().total().map_err(error)?.host,
                            "prepared storage exceeded original CPU reservation",
                        )?;
                    }
                    if let Some(bytes) = compiled_bytes {
                        ensure(
                            bytes <= held.output.requirements().total().map_err(error)?.host,
                            "CPU compiled output exceeded original reservation",
                        )?;
                    }
                    let mut held = active[slot].take().unwrap();
                    if let Some(bytes) = compiled_bytes {
                        // Keep this original claim. Split and drop only its
                        // unused capacity after the compiler has retired scratch.
                        let reserved = held.output.requirements().total().map_err(error)?.host;
                        ensure(
                            bytes <= reserved,
                            "CPU compiled output exceeded original reservation",
                        )?;
                        let unused = held
                            .output
                            .split(crate::execution::retained_resources::Requirements::single(
                                Category::PhaseScratch,
                                Bytes {
                                    host: reserved - bytes,
                                    device: 0,
                                },
                            ))
                            .map_err(error)?;
                        drop(unused);
                    }
                    if let Some(tag) = next {
                        if cache[slot].as_ref().is_none_or(|old| old.identity != tag) {
                            drop(cache[slot].take());
                            let mut work = held
                                .work
                                .take()
                                .ok_or("cache has no original reservation")?;
                            if let Some(bytes) = report.prepared_claim_bytes {
                                let reserved = work.requirements().total().map_err(error)?.host;
                                drop(
                                    work.split(
                                        crate::execution::retained_resources::Requirements::single(
                                            Category::PhaseScratch,
                                            Bytes {
                                                host: reserved - bytes,
                                                device: 0,
                                            },
                                        ),
                                    )
                                    .map_err(error)?,
                                );
                            }
                            cache[slot] = Some(PreparedClaim {
                                identity: tag,
                                _work: work,
                                _program_originals: std::mem::take(&mut held.inputs),
                            });
                        }
                    } else {
                        drop(cache[slot].take());
                    }
                    if consumed[id] {
                        outputs[id] = Some(output);
                        output_claims[id] = Some(held.output);
                    } else {
                        // The benchmark returns observations only. Terminal
                        // proofs have already been verified and hashed; they
                        // have no DAG consumer and need no retained storage.
                        drop(output);
                        drop(held.output);
                    }
                    eprintln!(
                        "CPU_PROOF_JOB {}",
                        serde_json::to_string(&report).map_err(error)?
                    );
                    complete[id] = true;
                    reports.push(report);
                }
            }
            let _ = dispatched;
        }
        // Dropping all senders stops idle workers; scope joins them, and each
        // worker retires its context before any outside cache claim is dropped.
        shutdown_started = Some(Instant::now());
        drop(senders);
        owners.finish()
    });
    let cleanup = shutdown_started.unwrap_or_else(Instant::now);
    drop(outputs);
    drop(active);
    drop(cache);
    drop(output_claims);
    drop(fixed);
    let cleanup_ns = cleanup.elapsed().as_nanos();
    result?;
    ensure(
        ledger.snapshot().current == Bytes::ZERO,
        "CPU original reservation leak",
    )?;
    reports.sort_by_key(|r| r.id);
    Ok(Record {
        repetition,
        wall_ns: start.elapsed().as_nanos(),
        cleanup_ns,
        coordinator_wait_ns: wait_ns,
        peak_workers,
        peak_admitted_host_bytes: ledger.snapshot().peak.host,
        admitted_device_bytes: 0,
        completed_jobs: reports.len(),
        planned_jobs: count,
        cache_evictions,
        jobs: reports,
        cleanup_complete: true,
    })
}
