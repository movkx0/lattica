//! One admitted, scoped pool. Helpers refill themselves while the coordinator
//! publishes into its GPU owner. Only immutable jobs and funded data cross lanes.
use super::{Error, Plan, Statistics, CONTROL_BYTES, MAX_JOBS};
use lattica_prover_p3::block_v2::machine::cpu_queue;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

const GPU_SPANS: usize = 8;
struct Task<J> { id: usize, priority: u8, cost: usize, queued: Instant, value: J }
pub(crate) struct Completion<R> { pub id: usize, pub value: R }
struct Slot<J, R> { task: Option<Task<J>>, running: bool, done: Option<Completion<R>> }
struct State<J, R> {
    slots: [Slot<J, R>; MAX_JOBS],
    next_id: usize,
    outstanding: usize,
    active: usize,
    stopped: bool,
    error: Option<Error>,
    gpu: [Option<(Instant, Option<Instant>)>; GPU_SPANS],
    gpu_count: usize,
    stats: Statistics,
}
pub(crate) struct Pool<J, R> {
    state: Mutex<State<J, R>>,
    ready: Condvar,
    completed: Condvar,
}
impl<J, R> Pool<J, R> {
    fn lock(&self) -> MutexGuard<'_, State<J, R>> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn stop(&self) {
        self.lock().stopped = true;
        self.ready.notify_all(); self.completed.notify_all();
    }
    fn fail(&self, error: Error) {
        let mut state = self.lock();
        state.error.get_or_insert(error); state.stopped = true;
        drop(state); self.ready.notify_all(); self.completed.notify_all();
    }
    pub(crate) fn submit(&self, priority: u8, cost: usize, value: J) -> Result<usize, Error> {
        let mut state = self.lock();
        if let Some(error) = state.error { return Err(error); }
        if state.stopped { return Err(Error::Worker); }
        let slot = state.slots.iter().position(|slot| !slot.running && slot.task.is_none() && slot.done.is_none())
            .ok_or(Error::Budget)?;
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(Error::Geometry)?;
        state.slots[slot].task = Some(Task { id, priority, cost, queued: Instant::now(), value });
        state.outstanding += 1; state.stats.jobs += 1;
        state.stats.queued_peak = state.stats.queued_peak.max(state.outstanding);
        drop(state); self.ready.notify_one();
        Ok(id)
    }
    fn take(&self, wait: bool) -> Result<Option<(usize, Task<J>, Instant)>, Error> {
        self.take_matching(wait, |_| true)
    }
    fn take_matching(&self, wait: bool, eligible: impl Fn(&J) -> bool) -> Result<Option<(usize, Task<J>, Instant)>, Error> {
        let mut state = self.lock();
        loop {
            if let Some(error) = state.error { return Err(error); }
            if state.stopped { return Ok(None); }
            let index = state.slots.iter().enumerate().filter_map(|(index, slot)| slot.task.as_ref().map(|t| (index, t)))
                .filter(|(_, task)| eligible(&task.value))
                .max_by(|(_, a), (_, b)| a.priority.cmp(&b.priority).then(a.cost.cmp(&b.cost)).then(b.id.cmp(&a.id)))
                .map(|(index, _)| index);
            if let Some(index) = index {
                let task = state.slots[index].task.take().ok_or(Error::Geometry)?;
                state.slots[index].running = true;
                state.active += 1; state.stats.peak_active = state.stats.peak_active.max(state.active);
                let started = Instant::now();
                state.stats.queue_ns += started.duration_since(task.queued).as_nanos();
                return Ok(Some((index, task, started)));
            }
            if !wait { return Ok(None); }
            let began = Instant::now();
            state = self.ready.wait(state).unwrap_or_else(|error| error.into_inner());
            state.stats.idle_ns += began.elapsed().as_nanos();
        }
    }
    fn compute<S>(&self, state: &mut S, work: &(impl Fn(&mut S, J) -> Result<R, Error> + ?Sized),
        slot: usize, task: Task<J>, started: Instant)
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(state, task.value)))
            .unwrap_or(Err(Error::Worker));
        let ended = Instant::now();
        let elapsed = ended.duration_since(started).as_nanos();
        let mut state = self.lock();
        state.active -= 1; state.slots[slot].running = false;
        state.stats.worker_ns += elapsed;
        state.stats.max_job_ns = state.stats.max_job_ns.max(elapsed);
        for index in 0..state.gpu_count {
            if let Some((from, to)) = state.gpu[index] {
                let from = from.max(started); let to = to.unwrap_or(ended).min(ended);
                if to > from { state.stats.overlap_worker_ns += to.duration_since(from).as_nanos(); }
            }
        }
        match result {
            Ok(value) => state.slots[slot].done = Some(Completion { id: task.id, value }),
            Err(error) => { state.error.get_or_insert(error); state.stopped = true; }
        }
        drop(state); self.completed.notify_all(); self.ready.notify_all();
    }
    pub(crate) fn try_receive(&self) -> Result<Option<Completion<R>>, Error> {
        let mut state = self.lock();
        if let Some(error) = state.error { return Err(error); }
        let index = state.slots.iter().enumerate().filter_map(|(index, slot)| slot.done.as_ref().map(|r| (index, r.id)))
            .min_by_key(|(_, id)| *id).map(|(index, _)| index);
        Ok(match index {
            Some(index) => { state.outstanding -= 1; state.slots[index].done.take() }
            None => None,
        })
    }
    pub(crate) fn wait(&self) -> Result<(), Error> {
        let began = Instant::now();
        let mut state = self.lock();
        while state.error.is_none() && !state.stopped && state.outstanding != 0
            && !state.slots.iter().any(|slot| slot.done.is_some()) {
            state = self.completed.wait(state).unwrap_or_else(|error| error.into_inner());
        }
        state.stats.wait_ns += began.elapsed().as_nanos();
        state.error.map_or(Ok(()), Err)
    }
    pub(crate) fn outstanding(&self) -> usize { self.lock().outstanding }
    /// Statistics for extra originals admitted by the coordinator after a
    /// source becomes available. This does not grant allocation authority.
    pub(crate) fn account_admitted(&self, bytes: usize) -> Result<(), Error> {
        let mut state = self.lock();
        state.stats.admitted_host_bytes = state.stats.admitted_host_bytes.checked_add(bytes).ok_or(Error::Budget)?;
        Ok(())
    }
    pub(crate) fn publication<T>(&self, gpu: bool, work: impl FnOnce() -> T) -> Result<T, Error> {
        let started = Instant::now();
        let index = if gpu {
            let mut state = self.lock();
            if state.gpu_count == GPU_SPANS { return Err(Error::Geometry); }
            let index = state.gpu_count; state.gpu_count += 1;
            state.gpu[index] = Some((started, None)); Some(index)
        } else { None };
        struct Publication<'a, J, R> { pool: &'a Pool<J, R>, index: Option<usize>, started: Instant }
        impl<J, R> Drop for Publication<'_, J, R> {
            fn drop(&mut self) {
                let end = Instant::now(); let elapsed = end.duration_since(self.started).as_nanos();
                let mut state = self.pool.lock(); state.stats.publication_ns += elapsed;
                if let Some(index) = self.index {
                    state.gpu[index] = Some((self.started, Some(end))); state.stats.gpu_ns += elapsed;
                }
            }
        }
        let _publication = Publication { pool: self, index, started };
        Ok(work())
    }
}

pub(crate) struct Lane<'a, S, J, R> {
    pool: &'a Pool<J, R>,
    state: S,
    work: &'a (dyn Fn(&mut S, J) -> Result<R, Error> + Sync),
}
impl<S, J, R> Lane<'_, S, J, R> {
    pub(crate) fn help(&mut self) -> Result<bool, Error> {
        self.help_matching(|_| true)
    }
    /// The coordinator can restrict itself to the next publication dependency.
    /// Helpers continue taking all ready work while that dependency runs.
    pub(crate) fn help_matching(&mut self, eligible: impl Fn(&J) -> bool) -> Result<bool, Error> {
        if let Some((slot, task, started)) = self.pool.take_matching(false, eligible)? {
            self.pool.compute(&mut self.state, self.work, slot, task, started); Ok(true)
        } else { Ok(false) }
    }
}

pub(crate) fn scoped<S, J: Send, R: Send, T>(
    plan: Plan,
    initialize: impl Fn(bool) -> Result<S, Error> + Sync,
    work: impl Fn(&mut S, J) -> Result<R, Error> + Sync,
    coordinate: impl FnOnce(&Pool<J, R>, &mut Lane<'_, S, J, R>) -> Result<T, Error>,
) -> Result<(T, Statistics), Error> {
    scoped_with_pool(plan, initialize, |state, job, _| work(state, job), coordinate)
}
/// Continuations may submit bounded child jobs directly. They never carry a
/// ledger or GPU owner and cannot increase the fixed slot or lane counts.
pub(crate) fn scoped_with_pool<S, J: Send, R: Send, T>(
    plan: Plan,
    initialize: impl Fn(bool) -> Result<S, Error> + Sync,
    work: impl Fn(&mut S, J, &Pool<J, R>) -> Result<R, Error> + Sync,
    coordinate: impl FnOnce(&Pool<J, R>, &mut Lane<'_, S, J, R>) -> Result<T, Error>,
) -> Result<(T, Statistics), Error> {
    if !(1..=cpu_queue::MAX_WORKERS).contains(&plan.width)
        || core::mem::size_of::<State<J, R>>().checked_mul(8)
            .and_then(|n| n.checked_add(cpu_queue::CONTROL_BYTES)).is_none_or(|n| n > CONTROL_BYTES) {
        return Err(Error::Geometry);
    }
    let started = Instant::now();
    let pool = Pool { state: Mutex::new(State {
        slots: core::array::from_fn(|_| Slot { task: None, running: false, done: None }),
        next_id: 0, outstanding: 0, active: 0, stopped: false, error: None,
        gpu: [None; GPU_SPANS], gpu_count: 0,
        stats: Statistics { width: plan.width, admitted_host_bytes: plan.host_bytes,
            budget_reductions: usize::from(plan.reduced), ..Default::default() },
    }), ready: Condvar::new(), completed: Condvar::new() };
    let work = |state: &mut S, job: J| work(state, job, &pool);
    let initialize = |caller| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| initialize(caller)))
        .unwrap_or(Err(Error::Worker));
    let mut local = Lane { pool: &pool, state: initialize(true)?, work: &work };
    struct Stop<'a, J, R>(&'a Pool<J, R>);
    impl<J, R> Drop for Stop<'_, J, R> { fn drop(&mut self) { self.0.stop(); } }
    let (result, threads) = if plan.width == 1 {
        let _stop = Stop(&pool);
        (coordinate(&pool, &mut local), 0)
    } else {
        let (result, stats) = cpu_queue::scoped_with_state(plan.width - 1,
            |_| initialize(false), |state, ()| {
                let state = match state { Ok(state) => state, Err(error) => { pool.fail(*error); return; } };
                loop {
                    match pool.take(true) {
                        Ok(Some((slot, task, began))) => pool.compute(state, &work, slot, task, began),
                        Ok(None) | Err(_) => break,
                    }
                }
            }, |queue| {
                let _stop = Stop(&pool);
                for slot in 0..plan.width - 1 { queue.submit(slot, ()).map_err(|_| Error::Worker)?; }
                coordinate(&pool, &mut local)
            }).map_err(|_| Error::Worker)?;
        (result, stats.threads_spawned)
    };
    let value = result?;
    let state = pool.lock();
    if let Some(error) = state.error { return Err(error); }
    if state.outstanding != 0 || state.active != 0 { return Err(Error::Geometry); }
    let mut statistics = state.stats;
    statistics.threads = threads; statistics.wall_ns = started.elapsed().as_nanos();
    Ok((value, statistics))
}

pub(super) fn run<S, R: Send>(plan: Plan, costs: &[usize],
    initialize: impl Fn(bool) -> Result<S, Error> + Sync,
    work: impl Fn(&mut S, usize) -> Result<R, Error> + Sync,
    mut publish: impl FnMut(usize, R) -> Result<(), Error>,
) -> Result<Statistics, Error> {
    if costs.is_empty() || costs.len() > MAX_JOBS || plan.width > costs.len() { return Err(Error::Geometry); }
    let (_, stats) = scoped(plan, initialize, work, |pool, caller| {
        for (index, cost) in costs.iter().copied().enumerate() {
            if pool.submit(0, cost, index)? != index { return Err(Error::Geometry); }
        }
        let mut pending: [Option<R>; MAX_JOBS] = core::array::from_fn(|_| None);
        let mut next = 0;
        while next < costs.len() {
            while let Some(done) = pool.try_receive()? { pending[done.id] = Some(done.value); }
            while let Some(value) = pending.get_mut(next).and_then(Option::take) {
                pool.publication(false, || publish(next, value))??; next += 1;
            }
            if next < costs.len() && !caller.help()? { pool.wait()?; }
        }
        Ok(())
    })?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_continuations_progress_without_a_coordinator_round_trip() {
        let completed = std::sync::atomic::AtomicUsize::new(0);
        for members in [3, 4] {
            completed.store(0, std::sync::atomic::Ordering::SeqCst);
            let plan = Plan::new(4, MAX_JOBS, usize::MAX, 0, 0).unwrap();
            let (_, statistics) = scoped_with_pool(plan, |_| Ok(()), |_, (member, child), pool| {
                if child {
                    completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                } else {
                    for _ in 0..2 { pool.submit(2, 1, (member, true))?; }
                }
                Ok((member, child))
            }, |pool, _| {
                for member in 0..members { pool.submit(1, 1, (member, false))?; }
                pool.publication(true, || {
                    let until = Instant::now() + std::time::Duration::from_secs(3);
                    while completed.load(std::sync::atomic::Ordering::SeqCst) != 2 * members && Instant::now() < until {
                        std::thread::yield_now();
                    }
                    assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 2 * members);
                })?;
                while pool.outstanding() != 0 {
                    while pool.try_receive()?.is_some() {}
                    if pool.outstanding() != 0 { pool.wait()?; }
                }
                Ok(())
            }).unwrap();
            assert_eq!(statistics.jobs, 3 * members);
            assert!(statistics.overlap_worker_ns > 0);
            assert_eq!(statistics.threads, 3);
        }
    }
    #[test]
    fn publication_failure_and_panic_join_lanes_before_returning() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let live = AtomicUsize::new(0);
        struct Held<'a>(&'a AtomicUsize);
        impl Drop for Held<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
        for panic in [false, true] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let plan = Plan::new(4, MAX_JOBS, usize::MAX, 0, 0).unwrap();
                scoped(plan, |_| { live.fetch_add(1, Ordering::SeqCst); Ok(Held(&live)) }, |_, x| Ok(x), |pool, _| {
                    for x in 0..MAX_JOBS { pool.submit(0, x, x)?; }
                    pool.publication(true, || {
                        if panic { panic!("injected coordinator panic"); }
                        Err::<(), _>(Error::Publication)
                    })?
                })
            }));
            // The core queue contains a coordinator panic and reports a
            // worker failure after joining. A one-lane caller may unwind.
            assert!(!matches!(result, Ok(Ok(_))));
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }
    }
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[test]
    fn helpers_refill_while_the_coordinator_publishes() {
        let done = AtomicUsize::new(0);
        let publishing = AtomicBool::new(false);
        let plan = Plan::new(2, 12, usize::MAX, 0, 0).unwrap();
        let (_, stats) = scoped(plan, |_| Ok(()), |_, i| {
            while !publishing.load(Ordering::SeqCst) { std::thread::yield_now(); }
            done.fetch_add(1, Ordering::SeqCst); Ok(i)
        }, |pool, _| {
            for i in 0..12 { pool.submit(0, 1, i)?; }
            pool.publication(true, || {
                publishing.store(true, Ordering::SeqCst);
                let until = Instant::now() + std::time::Duration::from_secs(2);
                while done.load(Ordering::SeqCst) != 12 && Instant::now() < until { std::thread::yield_now(); }
                assert_eq!(done.load(Ordering::SeqCst), 12);
            })?;
            let mut received = 0;
            while received != 12 {
                while pool.try_receive()?.is_some() { received += 1; }
                if received != 12 { pool.wait()?; }
            }
            Ok(())
        }).unwrap();
        assert_eq!(stats.jobs, 12); assert!(stats.overlap_worker_ns > 0);
    }
    #[test]
    fn coordinator_can_wait_for_its_next_publication_dependency() {
        let plan = Plan::new(1, 2, usize::MAX, 0, 0).unwrap();
        scoped(plan, |_| Ok(()), |_, value| Ok(value), |pool, caller| {
            // Unrelated high-priority work must not delay the next publication.
            pool.submit(3, 100, 1)?;
            pool.submit(1, 1, 0)?;
            assert!(caller.help_matching(|value| *value == 0)?);
            assert_eq!(pool.try_receive()?.unwrap().value, 0);
            assert!(!caller.help_matching(|value| *value == 0)?);
            assert!(caller.help()?);
            assert_eq!(pool.try_receive()?.unwrap().value, 1);
            Ok(())
        }).unwrap();
    }
    #[test]
    fn admission_is_bounded_and_slots_can_be_reused() {
        let plan = Plan::new(1, MAX_JOBS, usize::MAX, 0, 0).unwrap();
        scoped(plan, |_| Ok(()), |_, x| Ok(x), |pool, caller| {
            for i in 0..MAX_JOBS { pool.submit(0, 1, i)?; }
            assert_eq!(pool.submit(0, 1, 99), Err(Error::Budget));
            assert!(caller.help()?); assert!(pool.try_receive()?.is_some());
            pool.submit(0, 1, 99)?;
            while pool.outstanding() != 0 {
                caller.help()?; while pool.try_receive()?.is_some() {}
            }
            Ok(())
        }).unwrap();
    }
}
