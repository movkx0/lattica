//! Fixed observations of the exact memory-closure calculation. These
//! values never enter an admission predicate or replace an original claim.
use super::{Bytes, ClosureError, PhaseStep, Requirements};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryGate {
    Transition, Pool, FixedScratch, FixedOther, OuterResidual, Backend, ScratchMaximum,
    CombinedAdmission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CloseMemoryStage {
    pub(super) gate: MemoryGate,
    pub(super) closed_ordinal: Option<usize>,
    pub(super) allowance: Option<Bytes>,
    /// Actual current ledger, before the already-required runtime transition.
    pub(super) observed_retained: Option<Bytes>,
    /// Only the authenticated transition may subtract these original claims.
    pub(super) released_planning_scratch: Option<Bytes>,
    pub(super) transferred_startup: Option<Bytes>,
    /// The retained amount actually used by the admission predicate.
    pub(super) projected_retained: Option<Bytes>,
    pub(super) pool: Option<Bytes>,
    pub(super) pool_bookkeeping: Option<Bytes>,
    pub(super) pool_compiler: Option<Bytes>,
    pub(super) retained_compiler: Option<Bytes>,
    pub(super) compiler_scratch: Option<Bytes>,
    /// Complete category maxima before assigning any outer backend.
    pub(super) fixed_scratch: Option<Bytes>,
    /// OuterResidual: exact held amount passed to outer_residual. Other phase
    /// gates: that phase's source scratch. CombinedAdmission: full scratch max.
    pub(super) current_scratch: Option<Bytes>,
    /// OuterResidual: requested outer cap. Other phase gates: current backend.
    pub(super) requested_backend: Option<Bytes>,
    /// Combined slots, exact pool bookkeeping and category-wise scratch maxima.
    pub(super) active: Option<Bytes>,
    pub(super) required: Option<Bytes>,
    pub(super) shortfall: Option<Bytes>,
}

impl CloseMemoryStage {
    pub(super) fn new() -> Self {
        Self { gate: MemoryGate::Pool, closed_ordinal: None,
            allowance: None, observed_retained: None, released_planning_scratch: None,
            transferred_startup: None, projected_retained: None, pool: None,
            pool_bookkeeping: None, pool_compiler: None, retained_compiler: None,
            compiler_scratch: None, fixed_scratch: None,
            current_scratch: None, requested_backend: None, active: None,
            required: None, shortfall: None }
    }

    pub(super) fn at(&mut self, gate: MemoryGate, ordinal: Option<usize>) {
        self.gate = gate;
        self.closed_ordinal = ordinal;
        self.current_scratch = None;
        self.requested_backend = None;
        self.active = None;
        self.required = None;
        self.shortfall = None;
    }

    /// Observation only. Overflow remains explicit absence, never a false fit.
    pub(super) fn combined(&mut self, active: Bytes) {
        self.active = Some(active);
        self.required = self.projected_retained.and_then(|retained| Some(Bytes {
            host: retained.host.checked_add(active.host)?,
            device: retained.device.checked_add(active.device)?,
        }));
        self.shortfall = self.required.zip(self.allowance).map(|(need, limit)| Bytes {
            host: need.host.saturating_sub(limit.host),
            device: need.device.saturating_sub(limit.device),
        });
    }
}

/// Additive caller, helper, observation/result and iterator frames. Existing
/// metadata and complete-inspection censuses each apply their checked x8.
/// Observational total() errors become None, never invented zero or a new
/// failure path; the original checked closure arithmetic keeps its own error.
pub(super) const FRAME_BYTES: usize =
    8 * 2048 + // fixed test-only slot, phase-maximum and summary stream frames
    size_of::<[CloseMemoryStage; 4]>() + size_of::<[&mut CloseMemoryStage; 4]>()
    + size_of::<Option<&mut CloseMemoryStage>>() + size_of::<MemoryGate>()
    + size_of::<[Option<usize>; 4]>() + size_of::<[Option<Bytes>; 64]>()
    + size_of::<[Bytes; 24]>() + size_of::<[Requirements; 16]>()
    + size_of::<[&[crate::execution::workflow_resources::SlotSpec]; 4]>()
    + size_of::<core::result::Result<(Requirements, Requirements), ClosureError>>()
    + size_of::<core::result::Result<Requirements, crate::execution::workflow_resources::WorkflowError>>()
    + size_of::<[crate::execution::workflow_resources::PhaseFacts; 2]>()
    + size_of::<[crate::execution::retained_resources::Snapshot; 4]>()
    + size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>()
    + size_of::<core::result::Result<Bytes, ClosureError>>()
    + size_of::<core::result::Result<(), ClosureError>>()
    + size_of::<[usize; 8]>()
    + size_of::<core::iter::Enumerate<core::slice::Iter<'static, PhaseStep>>>()
    + size_of::<core::iter::Enumerate<core::slice::IterMut<'static, PhaseStep>>>();

#[cfg(test)]
fn profiling() -> bool {
    std::env::var("LATTICA_RINGCT_METADATA_STAGE_PROFILE").as_deref() == Ok("n3-paired-v1")
}
#[cfg(test)]
pub(super) fn profile_slots(slots: &[crate::execution::workflow_resources::SlotSpec]) {
    if !profiling() { return; }
    for (index, slot) in slots.iter().enumerate() {
        for category in super::Category::ALL {
            let bytes = slot.requirements.get(category);
            if bytes != Bytes::ZERO {
                eprintln!("RINGCT_MEMORY_SLOT {{\"slot\":{index},\"category\":\"{category:?}\",\"host\":{},\"device\":{}}}", bytes.host, bytes.device);
            }
        }
    }
}
#[cfg(test)]
pub(super) fn profile_retained(snapshot: &crate::execution::retained_resources::Snapshot,
    released: Requirements, transferred: Requirements) {
    if !profiling() { return; }
    for category in super::Category::ALL {
        let current = snapshot.categories[category as usize].current;
        let released = released.get(category);
        let transferred = transferred.get(category);
        if let Some(host) = current.host.checked_sub(released.host).and_then(|v| v.checked_sub(transferred.host)) {
            eprintln!("RINGCT_MEMORY_RETAINED {{\"category\":\"{category:?}\",\"host\":{host}}}");
        }
    }
}
#[cfg(test)]
pub(super) fn profile_maxima(ordinal: usize, kind: impl core::fmt::Debug, before: Requirements, after: Requirements) {
    if !profiling() { return; }
    for category in super::Category::ALL {
        let old = before.get(category);
        let new = after.get(category);
        if old != new {
            eprintln!("RINGCT_MEMORY_PHASE_MAX {{\"ordinal\":{ordinal},\"phase\":\"{kind:?}\",\"category\":\"{category:?}\",\"host\":{},\"device\":{}}}", new.host, new.device);
        }
    }
}
#[cfg(test)]
pub(super) fn profile_summary(stage: &CloseMemoryStage) {
    if !profiling() { return; }
    #[derive(serde::Serialize)]
    struct Report {
        required_host: Option<u64>, required_device: Option<u64>,
        allowance_host: Option<u64>, allowance_device: Option<u64>,
        retained_host: Option<u64>, pool_host: Option<u64>, pool_compiler_host: Option<u64>,
        scratch_host: Option<u64>, fixed_scratch_host: Option<u64>, shortfall_host: Option<u64>,
    }
    let report = Report {
        required_host: stage.required.map(|b| b.host), required_device: stage.required.map(|b| b.device),
        allowance_host: stage.allowance.map(|b| b.host), allowance_device: stage.allowance.map(|b| b.device),
        retained_host: stage.projected_retained.map(|b| b.host), pool_host: stage.pool.map(|b| b.host),
        pool_compiler_host: stage.pool_compiler.map(|b| b.host), scratch_host: stage.current_scratch.map(|b| b.host),
        fixed_scratch_host: stage.fixed_scratch.map(|b| b.host), shortfall_host: stage.shortfall.map(|b| b.host),
    };
    use std::io::Write;
    let mut out = std::io::stderr().lock();
    out.write_all(b"RINGCT_METADATA_MEMORY ").unwrap();
    serde_json::to_writer(&mut out, &report).unwrap();
    out.write_all(b"\n").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortfall_uses_projected_owners_and_includes_both_memory_domains() {
        let mut stage = CloseMemoryStage::new();
        stage.allowance = Some(Bytes { host: 100, device: 80 });
        stage.observed_retained = Some(Bytes { host: 90, device: 40 });
        stage.projected_retained = Some(Bytes { host: 20, device: 0 });
        stage.combined(Bytes { host: 81, device: 81 });
        assert_eq!(stage.required, Some(Bytes { host: 101, device: 81 }));
        assert_eq!(stage.shortfall, Some(Bytes { host: 1, device: 1 }));
        stage.combined(Bytes { host: 80, device: 80 });
        assert_eq!(stage.shortfall, Some(Bytes::ZERO));
    }

    #[test]
    fn missing_projection_and_overflow_cannot_report_zero_shortfall() {
        let mut stage = CloseMemoryStage::new();
        stage.allowance = Some(Bytes { host: u64::MAX, device: 80 });
        stage.combined(Bytes { host: 1, device: 0 });
        assert_eq!(stage.shortfall, None);
        stage.projected_retained = Some(Bytes { host: u64::MAX, device: 0 });
        stage.combined(Bytes { host: 1, device: 0 });
        assert_eq!(stage.required, None);
        assert_eq!(stage.shortfall, None);
        stage.at(MemoryGate::Backend, Some(1));
        assert_eq!(stage.active, None);
    }
}
