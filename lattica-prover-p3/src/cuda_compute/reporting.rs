//! Attempt-bound completion receipts. The runtime queue serializes binding and
//! launch capture; each completion retains its original ledger until observed.
//! An active attempt owns the runtime's host submission thread. No TLS or
//! process-wide counter subtraction is used to infer proof-stage execution.
use super::{device::State, error, Result, Runtime};
use crate::proving::{Backend, Run, Stage};
use std::{
    sync::{Arc, Mutex},
    thread::{self, ThreadId},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Default)]
struct Counts {
    calls: u64,
    ns: u128,
}

#[derive(Default)]
struct Data {
    stages: [Counts; 16],
    pending: usize,
    failed: bool,
    closed: bool,
}

pub(super) struct Ledger {
    owner: ThreadId,
    run: usize,
    allowed: [bool; 16],
    data: Mutex<Data>,
}

impl Ledger {
    fn ticket(self: &Arc<Self>, stage: Option<Stage>) -> Result<Ticket> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| "CUDA reporting ledger poisoned")?;
        let index = stage.and_then(|stage| Stage::ARITHMETIC.iter().position(|&s| s == stage));
        let index = match index.filter(|&index| self.allowed[index]) {
            Some(index) if !data.closed && !data.failed => index,
            _ => {
                data.failed = true;
                return Err("CUDA kernel lacks an admitted stage in this attempt".into());
            }
        };
        data.pending = data
            .pending
            .checked_add(1)
            .ok_or("CUDA receipt count overflow")?;
        Ok(Ticket {
            ledger: self.clone(),
            index,
            completed: false,
        })
    }
}

pub(super) struct Ticket {
    ledger: Arc<Ledger>,
    index: usize,
    completed: bool,
}

impl Ticket {
    pub(super) fn complete(&mut self, ns: u64) -> Result<()> {
        let mut data = self
            .ledger
            .data
            .lock()
            .map_err(|_| "CUDA reporting ledger poisoned")?;
        if self.completed || data.closed || data.failed || data.pending == 0 {
            data.failed = true;
            return Err("CUDA completion does not belong to a live reporting attempt".into());
        }
        let count = &mut data.stages[self.index];
        let next = count
            .calls
            .checked_add(1)
            .zip(count.ns.checked_add(u128::from(ns)));
        match next {
            Some((calls, total)) => *count = Counts { calls, ns: total },
            None => {
                data.failed = true;
                return Err("CUDA stage receipt overflow".into());
            }
        }
        data.pending -= 1;
        self.completed = true;
        Ok(())
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.completed {
            let mut data = self.ledger.data.lock().unwrap_or_else(|p| p.into_inner());
            data.failed = true;
            data.pending = data.pending.saturating_sub(1);
        }
    }
}

impl State {
    pub(super) fn check_reporting_thread(&self) -> Result<()> {
        if let Some(ledger) = self
            .reporting
            .lock()
            .map_err(|_| "CUDA reporting binding poisoned")?
            .as_ref()
        {
            if ledger.owner != thread::current().id() {
                return Err("CUDA runtime is assigned to another reporting thread".into());
            }
        }
        Ok(())
    }

    /// Call under the runtime queue lock, after checking the submitting thread.
    pub(super) fn reporting_ticket(&self, stage: Option<Stage>) -> Result<Option<Ticket>> {
        self.reporting
            .lock()
            .map_err(|_| "CUDA reporting binding poisoned")?
            .as_ref()
            .map(|ledger| ledger.ticket(stage))
            .transpose()
    }
}

struct Scope<'a> {
    runtime: Runtime,
    ledger: Arc<Ledger>,
    run: &'a Run,
    closed: bool,
}

impl Runtime {
    /// Capture only this synchronous attempt's observed CUDA completions. The
    /// caller still must finalize Run before publishing its returned artifact.
    pub(crate) fn reported<T>(&self, run: &Run, body: impl FnOnce() -> Result<T>) -> Result<T> {
        let allowed = run.cuda_inventory().map_err(error)?;
        let scope = {
            let _queue = self.state.enter()?;
            let mut active = self
                .state
                .reporting
                .lock()
                .map_err(|_| "CUDA reporting binding poisoned")?;
            if active.is_some() || self.snapshot().pending_commands != 0 {
                return Err("CUDA reporting requires a fresh, quiescent attempt".into());
            }
            let ledger = Arc::new(Ledger {
                owner: thread::current().id(),
                run: run.cuda_report_identity(),
                allowed,
                data: Mutex::new(Data::default()),
            });
            *active = Some(ledger.clone());
            Scope {
                runtime: self.clone(),
                ledger,
                run,
                closed: false,
            }
        };
        let result = body();
        let observed = scope.finish(result.is_ok());
        match result {
            Ok(value) => {
                observed?;
                Ok(value)
            }
            Err(error) => {
                let _ = observed;
                Err(error)
            }
        }
    }

    /// Manual operation reporters must not send the same completion to a
    /// different Run when an encompassing native proof is being recorded.
    pub(super) fn check_report_run(&self, run: &Run) -> Result<()> {
        let _queue = self.state.enter()?;
        if let Some(ledger) = self
            .state
            .reporting
            .lock()
            .map_err(|_| "CUDA reporting binding poisoned")?
            .as_ref()
        {
            if ledger.run != run.cuda_report_identity() {
                return Err("CUDA operation belongs to a different reporting attempt".into());
            }
        }
        Ok(())
    }
}

impl Scope<'_> {
    fn close(&mut self, succeeded: bool) -> Result<()> {
        let _queue = self.runtime.state.cleanup_lock();
        let mut active = self
            .runtime
            .state
            .reporting
            .lock()
            .map_err(|_| "CUDA reporting binding poisoned")?;
        if !active
            .as_ref()
            .is_some_and(|ledger| Arc::ptr_eq(ledger, &self.ledger))
        {
            self.run.observation_failed();
            return Err("CUDA reporting attempt binding changed".into());
        }
        let mut data = self
            .ledger
            .data
            .lock()
            .map_err(|_| "CUDA reporting ledger poisoned")?;
        data.closed = true;
        let failed = !succeeded || data.failed || data.pending != 0;
        if data.pending != 0 {
            self.runtime.state.fail();
            super::cleanup(self.runtime.state.drain(), "reporting scope pending drain");
        }
        let stages = data.stages;
        drop(data);
        *active = None;
        drop(active);
        self.closed = true;
        if failed {
            self.run.observation_failed();
        }
        for (stage, count) in Stage::ARITHMETIC.into_iter().zip(stages) {
            if count.calls != 0 {
                self.run
                    .observe_device(stage, Backend::Cuda, count.calls, count.ns)
                    .map_err(error)?;
            }
        }
        if failed {
            Err("CUDA reporting attempt failed or has unobserved work".into())
        } else {
            Ok(())
        }
    }

    fn finish(mut self, succeeded: bool) -> Result<()> {
        self.close(succeeded)
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if !self.closed {
            self.run.observation_failed();
            if self.close(false).is_err() {
                // The original error or unwind is preserved. The Run cannot
                // claim coverage even if its caller incorrectly marks success.
                self.run.observation_failed();
            }
        }
    }
}
