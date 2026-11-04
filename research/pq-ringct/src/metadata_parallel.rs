//! Bounded numeric work. Owners, admission and ordered publication stay on the
//! caller. No worker receives a workflow ledger, runtime or proof capability.
use lattica_prover_p3::block_v2::machine::cpu_queue;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

pub(crate) const MAX_JOBS: usize = 64;
pub(crate) const CONTROL_BYTES: usize = 4 << 20;
pub(crate) mod pool;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Geometry, Budget, Worker, Publication }

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct Statistics {
    pub jobs: usize,
    pub width: usize,
    pub peak_active: usize,
    pub threads: usize,
    pub budget_reductions: usize,
    pub admitted_host_bytes: usize,
    pub worker_ns: u128,
    pub wait_ns: u128,
    pub publication_ns: u128,
    pub wall_ns: u128,
    pub queued_peak: usize,
    pub queue_ns: u128,
    pub idle_ns: u128,
    pub max_job_ns: u128,
    pub gpu_ns: u128,
    pub overlap_worker_ns: u128,
}

/// Retained results are charged for *every* job, including completed jobs that
/// await their predecessor. Transient backing and stacks are charged per lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub width: usize,
    pub host_bytes: usize,
    pub reduced: bool,
}
impl Plan {
    pub(crate) fn new(ceiling: usize, count: usize, budget: usize,
        retained: usize, transient_per_lane: usize) -> Result<Self, Error>
    {
        if !(1..=cpu_queue::MAX_WORKERS).contains(&ceiling) || count == 0 || count > MAX_JOBS {
            return Err(Error::Geometry);
        }
        let desired = ceiling.min(count);
        for width in (1..=desired).rev() {
            let host = transient_per_lane.checked_mul(width)
                .and_then(|n| n.checked_add(retained))
                .and_then(|n| n.checked_add(CONTROL_BYTES))
                .and_then(|n| n.checked_add((width - 1) * cpu_queue::THREAD_BYTES));
            if let Some(host_bytes) = host.filter(|n| *n <= budget) {
                return Ok(Self { width, host_bytes, reduced: width < desired });
            }
        }
        Err(Error::Budget)
    }
}

/// `initialize` runs on each computation lane. Its state may be thread-bound
/// (for example, a read-only numeric cache scope); it never crosses threads.
/// The caller contributes one lane and helpers use the remaining allowance.
/// The largest cost runs first, with stable ordinal tie breaking. Publication
/// always follows input order, and may submit work to the caller-owned GPU.
pub(crate) fn run<S, R: Send>(
    plan: Plan, costs: &[usize],
    initialize: impl Fn(bool) -> Result<S, Error> + Sync,
    work: impl Fn(&mut S, usize) -> Result<R, Error> + Sync,
    mut publish: impl FnMut(usize, R) -> Result<(), Error>,
) -> Result<Statistics, Error> {
    if crate::preparation_options::concurrency_enabled("overlap") {
        return pool::run(plan, costs, initialize, work, publish);
    }
    let count = costs.len();
    if count == 0 || count > MAX_JOBS || plan.width == 0 || plan.width > count
        || !cpu_queue::control_fits::<usize, (usize, Result<R, Error>, u128)>()
    { return Err(Error::Geometry); }
    let started = Instant::now();
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let compute = |state: &mut Result<S, Error>, index| {
        let now_active = active.fetch_add(1, Ordering::Relaxed) + 1;
        peak.fetch_max(now_active, Ordering::Relaxed);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Relaxed); } }
        let _active = Active(&active);
        let began = Instant::now();
        let result = match state { Ok(state) => work(state, index), Err(e) => Err(*e) };
        (index, result, began.elapsed().as_nanos())
    };
    let mut statistics = Statistics { jobs: count, width: plan.width,
        budget_reductions: usize::from(plan.reduced), admitted_host_bytes: plan.host_bytes,
        ..Default::default() };
    if plan.width == 1 {
        let mut local = initialize(true);
        for i in 0..count {
            let (_, result, elapsed) = compute(&mut local, i);
            statistics.worker_ns += elapsed;
            let began = Instant::now();
            publish(i, result?)?;
            statistics.publication_ns += began.elapsed().as_nanos();
        }
    } else {
        // Queue handles/results plus our ordered result array and initialization
        // frames fit the separately charged fixed coordinator allowance.
        if core::mem::size_of::<[Option<R>; MAX_JOBS]>().checked_mul(8)
            .and_then(|n| n.checked_add(cpu_queue::CONTROL_BYTES))
            .is_none_or(|n| n > CONTROL_BYTES) { return Err(Error::Geometry); }
        let (result, queues) = cpu_queue::scoped_with_state(plan.width - 1,
            |_| initialize(false), compute, |queue| {
                let mut order: [usize; MAX_JOBS] = core::array::from_fn(|i| i);
                order[..count].sort_unstable_by(|&a, &b| costs[b].cmp(&costs[a]).then(a.cmp(&b)));
                let mut pending: [Option<R>; MAX_JOBS] = core::array::from_fn(|_| None);
                let mut next = 0;
                let mut issued = 0;
                let mut in_flight = 0;
                let mut local = initialize(true);
                while next < count {
                    while issued < count {
                        let Some(slot) = queue.idle_slot() else { break; };
                        queue.submit(slot, order[issued]).map_err(|_| Error::Worker)?;
                        issued += 1;
                        in_flight += 1;
                    }
                    if issued < count {
                        let index = order[issued];
                        issued += 1;
                        let (_, value, elapsed) = compute(&mut local, index);
                        statistics.worker_ns += elapsed;
                        pending[index] = Some(value?);
                    } else if in_flight != 0 && pending[next].is_none() {
                        let done = queue.receive().map_err(|_| Error::Worker)?;
                        let (index, value, elapsed) = done.result.map_err(|_| Error::Worker)?;
                        in_flight -= 1;
                        statistics.worker_ns += elapsed;
                        pending[index] = Some(value?);
                    }
                    while let Some(done) = queue.try_receive().map_err(|_| Error::Worker)? {
                        let (index, value, elapsed) = done.result.map_err(|_| Error::Worker)?;
                        in_flight -= 1;
                        statistics.worker_ns += elapsed;
                        pending[index] = Some(value?);
                    }
                    // Publication may enter the caller-owned GPU. Keep helpers
                    // supplied before that potentially blocking continuation.
                    while issued < count {
                        let Some(slot) = queue.idle_slot() else { break; };
                        queue.submit(slot, order[issued]).map_err(|_| Error::Worker)?;
                        issued += 1;
                        in_flight += 1;
                    }
                    while next < count {
                        let Some(value) = pending[next].take() else { break; };
                        let began = Instant::now();
                        publish(next, value)?;
                        statistics.publication_ns += began.elapsed().as_nanos();
                        next += 1;
                    }
                }
                Ok::<_, Error>(())
            }).map_err(|_| Error::Worker)?;
        result?;
        statistics.threads = queues.threads_spawned;
        statistics.wait_ns = queues.coordinator_wait_ns;
    }
    statistics.peak_active = peak.load(Ordering::Relaxed);
    statistics.wall_ns = started.elapsed().as_nanos();
    Ok(statistics)
}

pub(crate) fn report(family: &'static str, stats: Statistics) {
    #[cfg(test)]
    if std::env::var_os("LATTICA_RINGCT_METADATA_STAGE_PROFILE").is_some()
        || std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1") {
        eprintln!("RINGCT_METADATA_PARALLEL {}", serde_json::json!({"family":family,"statistics":stats}));
    }
    #[cfg(not(test))] let _ = (family, stats);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_charges_all_results_and_reduces_before_starting() {
        let one = Plan::new(1, 9, usize::MAX, 1000, 2000).unwrap();
        assert_eq!(Plan::new(16, 9, one.host_bytes, 1000, 2000).unwrap().width, 1);
        assert_eq!(Plan::new(16, 9, one.host_bytes - 1, 1000, 2000), Err(Error::Budget));
    }
    #[test]
    fn completion_order_does_not_change_publication_or_worker_ceiling() {
        for width in [1, 2, 4, 8, 16] {
            let plan = Plan::new(width, 24, usize::MAX, 0, 0).unwrap();
            let mut output = Vec::new();
            let stats = run(plan, &[1; 24], |_| Ok(()), |_, i| {
                if i % 3 == 0 { std::thread::yield_now(); }
                Ok(i * i)
            }, |i, value| { output.push((i, value)); Ok(()) }).unwrap();
            assert_eq!(output, (0..24).map(|i| (i, i * i)).collect::<Vec<_>>());
            assert!(stats.peak_active <= width);
            assert_eq!(stats.threads, width - 1);
        }
    }
    #[test]
    fn failure_joins_workers_before_original_can_retire() {
        let live = AtomicUsize::new(0);
        struct Held<'a>(&'a AtomicUsize);
        impl Drop for Held<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
        let plan = Plan::new(4, 12, usize::MAX, 0, 0).unwrap();
        let result = run(plan, &[1; 12], |_| {
            live.fetch_add(1, Ordering::SeqCst); Ok(Held(&live))
        }, |_, i| if i == 2 { Err(Error::Worker) } else { Ok(i) }, |_, _| Ok(()));
        assert!(result.is_err());
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn worker_panic_stops_publication_and_joins_every_lane() {
        let live = AtomicUsize::new(0);
        struct Held<'a>(&'a AtomicUsize);
        impl Drop for Held<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
        let mut published = 0;
        let plan = Plan::new(4, 12, usize::MAX, 0, 0).unwrap();
        let result = run(plan, &[1; 12], |_| {
            live.fetch_add(1, Ordering::SeqCst); Ok(Held(&live))
        }, |_, i| { if i == 0 { panic!("injected numeric worker panic"); } Ok(i) },
        |_, _| { published += 1; Ok(()) });
        assert!(result.is_err());
        assert_eq!(published, 0);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}
