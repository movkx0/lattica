//! Fixed-storage, scoped CPU workers. The caller owns memory admission and the
//! ready-job ordering. A completion retires its job before releasing its slot.
//! Threads and queue/result slots are reused until this CPU phase ends; every
//! submitted job is joined on errors, panics and partial thread-spawn failures.
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

pub const MAX_WORKERS: usize = 16;
pub const STACK_BYTES: usize = 2 << 20;
pub const THREAD_BYTES: usize = STACK_BYTES + (1 << 20);
pub const CONTROL_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Spawn,
    WorkerPanic,
    CoordinatorPanic,
    Slot,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Statistics {
    pub threads_spawned: usize,
    pub jobs_started: usize,
    pub peak_active_workers: usize,
    pub worker_elapsed_ns: u128,
    pub coordinator_wait_ns: u128,
}

pub struct Completion<R> {
    pub slot: usize,
    pub result: Result<R, Error>,
    pub elapsed_ns: u128,
}

struct State<J, R> {
    jobs: [Option<J>; MAX_WORKERS],
    done: [Option<Completion<R>>; MAX_WORKERS],
    occupied: [bool; MAX_WORKERS],
    stop: bool,
    active: usize,
    failure: Option<Error>,
    statistics: Statistics,
}
struct Shared<J, R> {
    state: Mutex<State<J, R>>,
    changed: Condvar,
}
impl<J, R> Shared<J, R> {
    fn lock(&self) -> MutexGuard<'_, State<J, R>> {
        // No user callback runs under this mutex. Recovering poisoning lets
        // teardown wake and join workers even if the coordinator unwinds.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn stop(&self) {
        self.lock().stop = true;
        self.changed.notify_all();
    }
}

pub struct Queue<'a, J, R> {
    shared: &'a Shared<J, R>,
    width: usize,
}
impl<J, R> Queue<'_, J, R> {
    pub fn idle_slot(&self) -> Option<usize> {
        let state = self.shared.lock();
        (0..self.width).find(|&i| !state.occupied[i])
    }
    pub fn submit(&self, slot: usize, job: J) -> Result<(), Error> {
        let mut state = self.shared.lock();
        if slot >= self.width || state.stop || state.occupied[slot] {
            return Err(Error::Slot);
        }
        state.occupied[slot] = true;
        state.jobs[slot] = Some(job);
        drop(state);
        self.shared.changed.notify_all();
        Ok(())
    }
    pub fn receive(&self) -> Result<Completion<R>, Error> {
        let started = Instant::now();
        let mut state = self.shared.lock();
        loop {
            if let Some(slot) = (0..self.width).find(|&i| state.done[i].is_some()) {
                let result = state.done[slot].take().unwrap();
                state.occupied[slot] = false;
                state.statistics.coordinator_wait_ns += started.elapsed().as_nanos();
                return Ok(result);
            }
            if !state.occupied[..self.width].iter().any(|&busy| busy) {
                return Err(Error::Slot);
            }
            if let Some(error) = state.failure {
                return Err(error);
            }
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// All control arrays, handles, closures and return frames fit the caller's
/// existing 1 MiB coordinator reservation. Job-owned heap backing and per-thread
/// stacks/TLS remain separate, explicit caller charges.
pub fn control_fits<J, R>() -> bool {
    8usize
        .checked_mul(
            std::mem::size_of::<Shared<J, R>>()
                + MAX_WORKERS * std::mem::size_of::<std::thread::ScopedJoinHandle<'_, ()>>()
                + std::mem::size_of::<Queue<'_, J, R>>()
                + std::mem::size_of::<Statistics>(),
        )
        .is_some_and(|bytes| bytes <= CONTROL_BYTES)
}

pub fn scoped<J: Send, R: Send, T>(
    width: usize,
    work: impl Fn(J) -> R + Sync,
    coordinate: impl FnOnce(&Queue<'_, J, R>) -> T,
) -> Result<(T, Statistics), Error> {
    scoped_with_state(width, |_| (), |_, job| work(job), coordinate)
}

/// Worker-local scratch is created on its owner thread and dropped before the
/// phase returns. It need not be Send; callers must charge its retained backing
/// for the entire pool lifetime, including while a worker is idle.
pub fn scoped_with_state<J: Send, R: Send, S, T>(
    width: usize,
    initialize: impl Fn(usize) -> S + Sync,
    work: impl Fn(&mut S, J) -> R + Sync,
    coordinate: impl FnOnce(&Queue<'_, J, R>) -> T,
) -> Result<(T, Statistics), Error> {
    scoped_with_spawn_limit(width, initialize, work, coordinate, None)
}

fn scoped_with_spawn_limit<J: Send, R: Send, S, T>(
    width: usize,
    initialize: impl Fn(usize) -> S + Sync,
    work: impl Fn(&mut S, J) -> R + Sync,
    coordinate: impl FnOnce(&Queue<'_, J, R>) -> T,
    spawn_limit: Option<usize>,
) -> Result<(T, Statistics), Error> {
    if !(1..=MAX_WORKERS).contains(&width) || !control_fits::<J, R>() {
        return Err(Error::Geometry);
    }
    let shared = Shared {
        state: Mutex::new(State {
            jobs: core::array::from_fn(|_| None),
            done: core::array::from_fn(|_| None),
            occupied: [false; MAX_WORKERS],
            stop: false,
            active: 0,
            failure: None,
            statistics: Statistics::default(),
        }),
        changed: Condvar::new(),
    };
    std::thread::scope(|scope| {
        let mut handles: [Option<_>; MAX_WORKERS] = core::array::from_fn(|_| None);
        let mut failure = None;
        for slot in 0..width {
            if spawn_limit == Some(slot) {
                failure = Some(Error::Spawn);
                break;
            }
            let (shared, work, initialize) = (&shared, &work, &initialize);
            match std::thread::Builder::new()
                .name("ringct-cpu-queue".into())
                .stack_size(STACK_BYTES)
                .spawn_scoped(scope, move || {
                    let mut scratch =
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            initialize(slot)
                        })) {
                            Ok(scratch) => scratch,
                            Err(_) => {
                                let mut state = shared.lock();
                                state.failure = Some(Error::WorkerPanic);
                                state.stop = true;
                                drop(state);
                                shared.changed.notify_all();
                                return;
                            }
                        };
                    loop {
                        let job = {
                            let mut state = shared.lock();
                            loop {
                                if let Some(job) = state.jobs[slot].take() {
                                    state.active += 1;
                                    state.statistics.jobs_started += 1;
                                    state.statistics.peak_active_workers =
                                        state.statistics.peak_active_workers.max(state.active);
                                    break job;
                                }
                                if state.stop {
                                    return;
                                }
                                state = shared
                                    .changed
                                    .wait(state)
                                    .unwrap_or_else(|e| e.into_inner());
                            }
                        };
                        let started = Instant::now();
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            work(&mut scratch, job)
                        }))
                        .map_err(|_| Error::WorkerPanic);
                        // The work closure has returned/unwound and dropped its
                        // input owners before the coordinator can reclaim credit.
                        let elapsed_ns = started.elapsed().as_nanos();
                        let mut state = shared.lock();
                        state.active -= 1;
                        state.statistics.worker_elapsed_ns += elapsed_ns;
                        state.done[slot] = Some(Completion {
                            slot,
                            result,
                            elapsed_ns,
                        });
                        drop(state);
                        shared.changed.notify_all();
                    }
                }) {
                Ok(handle) => {
                    handles[slot] = Some(handle);
                    shared.lock().statistics.threads_spawned += 1;
                }
                Err(_) => {
                    failure = Some(Error::Spawn);
                    break;
                }
            }
        }
        let result = if failure.is_none() {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                coordinate(&Queue {
                    shared: &shared,
                    width,
                })
            }))
            .map_err(|_| Error::CoordinatorPanic)
        } else {
            Err(failure.unwrap())
        };
        shared.stop();
        for handle in handles.into_iter().flatten() {
            if handle.join().is_err() {
                failure = Some(Error::WorkerPanic);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(error) = shared.lock().failure {
            return Err(error);
        }
        let statistics = shared.lock().statistics;
        result.map(|value| (value, statistics))
    })
}

#[cfg(test)]
mod tests;
