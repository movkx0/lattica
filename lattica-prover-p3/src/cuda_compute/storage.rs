//! Host-only allocation schedule. Handles describe unique allocations, not
//! aliases; dropping an alias must never reduce the planned live storage.
use super::{Limits, Result, Snapshot};
use serde::Serialize;

#[derive(Debug, Default)]
pub(super) struct Live {
    bytes: usize,
    allocations: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Phase {
    pub name: &'static str,
    pub peak_bytes: usize,
    pub peak_allocations: usize,
}

pub(super) struct Schedule {
    pub state: Snapshot,
    pub limits: Limits,
    pub phases: Vec<Phase>,
}

impl Schedule {
    pub fn new(state: Snapshot, limits: Limits) -> Result<Self> {
        limits.validate()?;
        if state.live_bytes > limits.managed_bytes
            || state.allocations > limits.max_allocations
            || state.modules > limits.max_modules
            || state.pending_commands != 0
            || state.event_pairs > limits.max_pending
        {
            return Err("CUDA request requires an idle, admitted runtime".into());
        }
        Ok(Self {
            state,
            limits,
            phases: Vec::new(),
        })
    }
    pub fn phase(&mut self, name: &'static str) {
        self.phases.push(Phase {
            name,
            peak_bytes: self.state.live_bytes,
            peak_allocations: self.state.allocations,
        });
    }
    /// Include a component planner's absolute byte peak and the maximum
    /// additional allocation count on any of that component's execution paths.
    pub fn peak(&mut self, bytes: usize, additional_allocations: usize) -> Result<()> {
        let allocations = self
            .state
            .allocations
            .checked_add(additional_allocations)
            .ok_or("CUDA request allocation count overflow")?;
        if bytes > self.limits.managed_bytes || allocations > self.limits.max_allocations {
            return Err(format!(
                "CUDA request phase {} exceeds device storage",
                self.phases.last().map_or("initial", |p| p.name)
            ));
        }
        let phase = self
            .phases
            .last_mut()
            .ok_or("CUDA storage schedule has no phase")?;
        phase.peak_bytes = phase.peak_bytes.max(bytes);
        phase.peak_allocations = phase.peak_allocations.max(allocations);
        Ok(())
    }
    pub fn hold(&mut self, words: impl IntoIterator<Item = usize>) -> Result<Live> {
        let mut live = Live::default();
        for words in words.into_iter().filter(|&n| n != 0) {
            let bytes = words
                .checked_mul(8)
                .ok_or("CUDA request allocation overflow")?;
            if bytes > self.limits.max_allocation_bytes {
                return Err("CUDA request exceeds per-allocation allowance".into());
            }
            live.bytes = live
                .bytes
                .checked_add(bytes)
                .ok_or("CUDA request bytes overflow")?;
            live.allocations += 1;
        }
        let bytes = self
            .state
            .live_bytes
            .checked_add(live.bytes)
            .ok_or("CUDA request peak overflow")?;
        self.peak(bytes, live.allocations)?;
        self.state.live_bytes = bytes;
        self.state.allocations += live.allocations;
        Ok(live)
    }
    pub fn release(&mut self, live: Live) {
        self.state.live_bytes -= live.bytes;
        self.state.allocations -= live.allocations;
    }
    pub fn scratch(&mut self, words: impl IntoIterator<Item = usize>) -> Result<()> {
        let live = self.hold(words)?;
        self.release(live);
        Ok(())
    }
    pub fn sample(&mut self, words: usize) -> Result<Live> {
        let plan = crate::gpu_random::Plan::new(
            words,
            0,
            self.state.live_bytes,
            self.limits.managed_bytes,
            self.limits.max_allocation_bytes,
        )?;
        self.peak(plan.peak_bytes, 5)?;
        self.hold([words])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schedule_checks_coexistence_and_releases_unique_allocations() {
        let limits = Limits {
            managed_bytes: 128,
            max_allocation_bytes: 96,
            max_allocations: 3,
            ..Limits::default()
        };
        let mut plan = Schedule::new(Snapshot::default(), limits).unwrap();
        plan.phase("one");
        let a = plan.hold([8]).unwrap();
        plan.scratch([4, 4]).unwrap();
        assert!(plan.scratch([9]).is_err());
        assert!(plan.scratch([1, 1, 1]).is_err());
        assert_eq!(plan.state.live_bytes, 64);
        plan.release(a);
        plan.phase("two");
        plan.scratch([12]).unwrap();
        assert!(plan.scratch([13]).is_err());
        assert!(plan.scratch([usize::MAX]).is_err());
        assert_eq!(plan.phases[0].peak_bytes, 128);
        assert_eq!(plan.phases[0].peak_allocations, 3);
        assert_eq!(plan.phases[1].peak_bytes, 96);
        assert_eq!(plan.state, Snapshot::default());
    }
}
