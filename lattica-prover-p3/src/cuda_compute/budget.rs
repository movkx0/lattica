//! Reservations precede native allocations and survive until native cleanup.
use super::Result;
use serde::Serialize;
use std::sync::{Arc, Mutex};

pub(super) const MAX_PUBLIC_PROGRAM_BYTES: usize = 64 << 20;
pub(super) const MAX_PUBLIC_PROGRAMS: usize = 32;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub managed_bytes: usize,
    pub max_allocation_bytes: usize,
    pub context_reserve_bytes: usize,
    pub headroom_bytes: usize,
    pub max_allocations: usize,
    pub max_modules: usize,
    pub max_pending: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            managed_bytes: 64 << 20,
            max_allocation_bytes: 64 << 20,
            context_reserve_bytes: 4 << 30,
            headroom_bytes: 1 << 30,
            max_allocations: 4096,
            max_modules: 32,
            max_pending: 64,
        }
    }
}

impl Limits {
    pub(super) fn validate(self) -> Result<usize> {
        if self.managed_bytes == 0
            || self.max_allocation_bytes == 0
            || self.max_allocation_bytes > self.managed_bytes
            || self.context_reserve_bytes < 4 << 30
            || self.headroom_bytes == 0
            || !(1..=4096).contains(&self.max_allocations)
            || !(1..=32).contains(&self.max_modules)
            || !(1..=64).contains(&self.max_pending)
        {
            return Err("invalid bounded CUDA limits".into());
        }
        self.managed_bytes
            .checked_add(self.context_reserve_bytes)
            .and_then(|n| n.checked_add(self.headroom_bytes))
            .ok_or_else(|| "CUDA reservation overflow".into())
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub allocations: usize,
    pub modules: usize,
    /// Each pending command owns two CUDA timing events.
    pub pending_commands: usize,
    pub completed_commands: u64,
    pub device_ns: u128,
    /// Explicit u64 buffer transfers; excludes public module/driver metadata.
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub copied_bytes: u64,
    /// Host allocations retained by immutable public quotient programs. These
    /// have a separate aggregate allowance; device code buffers count above.
    pub public_program_bytes: usize,
    pub public_programs: usize,
}

pub(super) enum Transfer {
    Upload,
    Download,
    Copy,
}

pub(super) struct Budget {
    pub limits: Limits,
    state: Mutex<Snapshot>,
}

enum Kind {
    Allocation(usize),
    Module,
    Command,
    PublicProgram(usize),
}

pub(super) struct Reservation {
    budget: Arc<Budget>,
    kind: Kind,
}

impl Budget {
    pub fn transferred(&self, kind: Transfer, bytes: usize) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| "CUDA accounting poisoned")?;
        let counter = match kind {
            Transfer::Upload => &mut state.uploaded_bytes,
            Transfer::Download => &mut state.downloaded_bytes,
            Transfer::Copy => &mut state.copied_bytes,
        };
        *counter = counter
            .checked_add(
                bytes
                    .try_into()
                    .map_err(|_| "CUDA transfer size overflow")?,
            )
            .ok_or("CUDA transfer accounting overflow")?;
        Ok(())
    }
    pub fn new(limits: Limits) -> Result<Arc<Self>> {
        limits.validate()?;
        Ok(Arc::new(Self {
            limits,
            state: Mutex::new(Snapshot::default()),
        }))
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn reserve(self: &Arc<Self>, kind: Kind) -> Result<Reservation> {
        let mut state = self.state.lock().map_err(|_| "CUDA accounting poisoned")?;
        match kind {
            Kind::PublicProgram(bytes) => {
                let next = state
                    .public_program_bytes
                    .checked_add(bytes)
                    .filter(|n| *n <= MAX_PUBLIC_PROGRAM_BYTES)
                    .ok_or("CUDA public program host allowance exhausted")?;
                if bytes == 0 || state.public_programs == MAX_PUBLIC_PROGRAMS {
                    return Err("CUDA public program count or size allowance".into());
                }
                state.public_program_bytes = next;
                state.public_programs += 1;
            }
            Kind::Allocation(bytes) => {
                if bytes == 0
                    || bytes > self.limits.max_allocation_bytes
                    || state.allocations == self.limits.max_allocations
                {
                    return Err("CUDA allocation exceeds its size or count allowance".into());
                }
                let next = state
                    .live_bytes
                    .checked_add(bytes)
                    .filter(|n| *n <= self.limits.managed_bytes)
                    .ok_or("CUDA aggregate allocation allowance exhausted")?;
                state.live_bytes = next;
                state.peak_bytes = state.peak_bytes.max(next);
                state.allocations += 1;
            }
            Kind::Module => {
                if state.modules == self.limits.max_modules {
                    return Err("CUDA module allowance exhausted".into());
                }
                state.modules += 1;
            }
            Kind::Command => {
                if state.pending_commands == self.limits.max_pending {
                    return Err("CUDA pending event allowance exhausted".into());
                }
                state.pending_commands += 1;
            }
        }
        Ok(Reservation {
            budget: self.clone(),
            kind,
        })
    }

    pub fn allocation(self: &Arc<Self>, bytes: usize) -> Result<Reservation> {
        self.reserve(Kind::Allocation(bytes))
    }

    pub fn module(self: &Arc<Self>) -> Result<Reservation> {
        self.reserve(Kind::Module)
    }
    pub fn command(self: &Arc<Self>) -> Result<Reservation> {
        self.reserve(Kind::Command)
    }
    pub fn public_program(self: &Arc<Self>, bytes: usize) -> Result<Reservation> {
        self.reserve(Kind::PublicProgram(bytes))
    }

    pub fn completed(&self, ns: u64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| "CUDA accounting poisoned")?;
        let calls = state
            .completed_commands
            .checked_add(1)
            .ok_or("CUDA command count overflow")?;
        let elapsed = state
            .device_ns
            .checked_add(ns as u128)
            .ok_or("CUDA duration overflow")?;
        state.completed_commands = calls;
        state.device_ns = elapsed;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().unwrap_or_else(|p| p.into_inner());
        match self.kind {
            Kind::PublicProgram(bytes) => {
                state.public_program_bytes -= bytes;
                state.public_programs -= 1;
            }
            Kind::Allocation(bytes) => {
                state.live_bytes -= bytes;
                state.allocations -= 1;
            }
            Kind::Module => state.modules -= 1,
            Kind::Command => state.pending_commands -= 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_programs_charge_retained_host_capacity_and_count() {
        let budget = Budget::new(Limits::default()).unwrap();
        assert!(budget.public_program(0).is_err());
        assert!(budget.public_program(usize::MAX).is_err());
        let full = budget.public_program(64 << 20).unwrap();
        assert!(budget.public_program(1).is_err());
        drop(full);
        let entries: Vec<_> = (0..32).map(|_| budget.public_program(1).unwrap()).collect();
        assert!(budget.public_program(1).is_err());
        assert_eq!(budget.snapshot().public_programs, 32);
        assert_eq!(budget.snapshot().public_program_bytes, 32);
        drop(entries);
        assert_eq!(budget.snapshot().public_program_bytes, 0);
        assert_eq!(budget.snapshot().public_programs, 0);
    }

    #[test]
    fn reservations_cover_aggregate_limits_and_release_on_failure() {
        let budget = Budget::new(Limits {
            managed_bytes: 24,
            max_allocation_bytes: 16,
            max_allocations: 2,
            max_modules: 1,
            max_pending: 1,
            ..Limits::default()
        })
        .unwrap();
        for invalid in [0, 17, usize::MAX] {
            assert!(budget.allocation(invalid).is_err());
        }
        let a = budget.allocation(16).unwrap();
        assert!(budget.allocation(16).is_err());
        let b = budget.allocation(8).unwrap();
        assert!(budget.allocation(1).is_err());
        assert_eq!(budget.snapshot().live_bytes, 24);
        drop(a);
        drop(b);
        let failed_native_allocation = || -> Result<()> {
            let _reservation = budget.allocation(16)?;
            Err("injected allocation failure".into())
        };
        assert!(failed_native_allocation().is_err());
        assert_eq!(budget.snapshot().live_bytes, 0);
        assert_eq!(budget.snapshot().peak_bytes, 24);
        let module = budget.module().unwrap();
        let event = budget.command().unwrap();
        assert!(budget.module().is_err());
        assert!(budget.command().is_err());
        drop(module);
        drop(event);
        assert_eq!(budget.snapshot().modules, 0);
        assert_eq!(budget.snapshot().pending_commands, 0);
    }

    #[test]
    fn impossible_reservations_reject_before_driver_access() {
        assert!(Budget::new(Limits {
            managed_bytes: usize::MAX,
            ..Limits::default()
        })
        .is_err());
        assert!(Budget::new(Limits {
            max_pending: 65,
            ..Limits::default()
        })
        .is_err());
        assert!(Budget::new(Limits {
            context_reserve_bytes: 0,
            ..Limits::default()
        })
        .is_err());
    }
}
