//! Bounded overlap for the standalone typed proof driver. The caller supplies
//! topologically ordered tasks. One proof runs on the calling thread while an
//! existing Rayon worker retires the previous output, then prepares one input.
//! A dependent input is prepared only after its producer has been retired.
use super::Error;
use std::time::Instant;

// Extra decoded children, one completed proof, verifier scratch/registry setup,
// and encoding coexist with the active prover. Subtract this from its budget;
// the enclosing cgroup and allocator caps still enforce the process total.
pub(super) const RESERVE_BYTES: u64 = 512 << 20;

#[derive(Default, serde::Serialize)]
pub(super) struct Stats {
    pub rounds: usize,
    pub dependency_barriers: usize,
    pub host_seconds: f64,
    pub proving_seconds: f64,
    pub concurrent_seconds: f64,
}

pub(super) fn run<T: Sync, I: Send, O: Send>(
    tasks: &[T],
    prepare: impl Fn(&T) -> Result<I, Error> + Sync,
    mut prove: impl FnMut(&T, I) -> Result<O, Error>,
    finish: impl Fn(&T, O) -> Result<(), Error> + Sync,
    depends: impl Fn(&T, &T) -> bool,
) -> Result<Stats, Error> {
    let mut stats = Stats::default();
    let Some(first) = tasks.first() else {
        return Ok(stats);
    };
    let mut input = prepare(first)?;
    let mut previous = None;
    for (index, task) in tasks.iter().enumerate() {
        let next = tasks.get(index + 1);
        let barrier = next.is_some_and(|next| depends(next, task));
        let prefetch = next.filter(|_| !barrier);
        let mut host_result = None;
        let mut proof_result = None;
        let mut host_interval = None;
        let mut proof_interval = None;
        // in_place_scope keeps the GPU/session and its admitted caller stack on
        // this thread. It also drains CPU work on every error or unwind. No new
        // OS thread, unbounded queue, or second GPU proof is introduced.
        rayon::in_place_scope(|scope| {
            let prepare = &prepare;
            let finish = &finish;
            let result = &mut host_result;
            let interval = &mut host_interval;
            let previous = previous.take();
            scope.spawn(move |_| {
                let started = Instant::now();
                let execute = || -> Result<Option<I>, Error> {
                    if let Some((task, output)) = previous {
                        finish(task, output)?;
                    }
                    prefetch.map(prepare).transpose()
                };
                // The project's Error is not Send; only its diagnostic crosses
                // threads. Failed retirement never releases dependent work.
                *result = Some(execute().map_err(|error| error.to_string()));
                *interval = Some((started, Instant::now()));
            });
            let started = Instant::now();
            proof_result = Some(prove(task, input));
            proof_interval = Some((started, Instant::now()));
        });
        let (host_start, host_end) = host_interval.unwrap();
        let (proof_start, proof_end) = proof_interval.unwrap();
        stats.rounds += 1;
        stats.host_seconds += (host_end - host_start).as_secs_f64();
        stats.proving_seconds += (proof_end - proof_start).as_secs_f64();
        stats.concurrent_seconds += host_end
            .min(proof_end)
            .saturating_duration_since(host_start.max(proof_start))
            .as_secs_f64();
        let prepared = host_result.unwrap()?;
        let output = proof_result.unwrap()?;
        if barrier {
            stats.dependency_barriers += 1;
            finish(task, output)?;
            input = prepare(next.unwrap())?;
        } else if let Some(prepared) = prepared {
            previous = Some((task, output));
            input = prepared;
        } else {
            finish(task, output)?;
            break;
        }
    }
    Ok(stats)
}

#[cfg(test)]
#[path = "host_pipeline_tests.rs"]
mod tests;
