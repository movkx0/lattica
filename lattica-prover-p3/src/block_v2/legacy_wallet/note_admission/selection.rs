//! Exact note runtime selection with owned shared-quota storage. The enclosing
//! producer must separately own bounded immutable startup/environment storage,
//! driver/allocator/stack overhead and runtime exclusivity. No dispatch authority
//! follows from this selector payload census or the retained token.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::{add, Error, Geometry, WorkerPolicyAbsent};
use crate::block_v2::{
    gpu_hash::{
        device::{
            note_runtime::NoteDevicePlan, public_hash::PublicHashSelection, WalletProofMinimum,
        },
        engine::{retained_storage, Limits, RetainedTreeStorageMode},
    },
    resident_pcs,
};
use crate::{gpu_device::bounded, note_research_quota::Reservation};

const MANAGED: usize = 8 << 30;
const CONTEXT: usize = 4 << 30;
const NATIVE_HOST: usize = 24 << 30;

const REQUIRED: [&str; 18] = [
    "LATTICA_V2_GPU_HASH",
    "LATTICA_V2_GPU_RETAIN_TREES",
    "LATTICA_V2_GPU_QUERY_GATHER",
    "LATTICA_V2_GPU_RESIDENT_LDE",
    "LATTICA_V2_GPU_OPENINGS",
    "LATTICA_V2_QUOTIENT_FUSION",
    "LATTICA_V2_GPU_QUOTIENT_LDE",
    "LATTICA_V2_GPU_QUOTIENT_EVAL",
    "LATTICA_V2_GPU_QUOTIENT_RESIDENT",
    "LATTICA_V2_GPU_LOOKUP",
    "LATTICA_V2_GPU_OPENING_EVAL",
    "LATTICA_V2_GPU_FRI_RESIDENT",
    "LATTICA_V2_GPU_PCS_DEVICE_ONLY",
    "LATTICA_V2_GPU_WITNESS",
    "LATTICA_V2_GPU_RANDOMNESS",
    "LATTICA_V2_GPU_TRANSCRIPT",
    "LATTICA_V2_GPU_FRI_FOLD",
    "LATTICA_PROVING_REPORT",
];

// The fixed note schedule has no host-backed trees, retained transform cache,
// shared preprocessing, worker phase coordination or compact host PCS data.
const DISABLED: [&str; 4] = [
    "LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE",
    "LATTICA_V2_GPU_COMPACT_PROVER_DATA",
    "LATTICA_V2_GPU_OPENING_COMPACT",
    "LATTICA_FFT_TRACE",
];
const ABSENT: [&str; 7] = [
    "LATTICA_V2_SHARED_PREPROCESSING_DIR",
    "LATTICA_V2_PHASE_DIR",
    "LATTICA_V2_LATE_PHASE_DIR",
    "LATTICA_V2_QUERY_PHASE_DIR",
    "LATTICA_V2_LDE_SCRATCH_BYTES",
    "LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES",
    "LATTICA_V2_GPU_LDE_WORKSPACE_BYTES",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Effective {
    managed_bytes: usize,
    context_bytes: usize,
    host_output_bytes: usize,
    transfer_slots: usize,
}

pub(super) struct NoteSelection {
    physical: bounded::Snapshot,
    scratch: bounded::Scratch,
    request: bounded::Request,
    effective: Effective,
    policy: WorkerPolicyAbsent,
    // Last field: every selected identity String and scratch owner is destroyed
    // before its actual same-ledger charge. This owner cannot be cloned or sent.
    reservation: Reservation,
}

impl NoteSelection {
    pub(super) fn physical(&self) -> &bounded::Snapshot { &self.physical }

    /// Source-owned payload only; no compiler stack high-water or opaque-driver
    /// claim. The inline owner includes retained Scratch, Snapshot and token.
    /// FixedSelection and the diagnostic can overlap identity construction.
    pub(super) fn required_payload_bytes() -> Result<usize, Error> {
        Geometry::pinned()?;
        let fixed = bounded::footprint();
        let mut bytes = core::mem::size_of::<Self>();
        for temporary in [
            fixed.fixed_selection_inline,
            fixed.diagnostic_inline,
            fixed.maximum_string_requests,
        ] {
            bytes = add(bytes, temporary)?;
        }
        Ok(bytes)
    }

    /// Request borrows no environment and was parsed by the sealed startup
    /// owner. A real token is checked before any environment or driver query.
    /// Environment copies made by existing configuration helpers remain under
    /// that owner's distinct startup/configuration charge, not this token.
    pub(super) fn capture(
        request: bounded::Request,
        reservation: Reservation,
    ) -> Result<Self, Error> {
        if reservation.reserved_bytes() < Self::required_payload_bytes()? {
            return Err(Error::ResourceLimit);
        }
        let policy = WorkerPolicyAbsent::capture()?;
        let effective = Effective::capture()?;
        let mut scratch = bounded::Scratch::new();
        let physical =
            bounded::Snapshot::capture(request, &mut scratch).map_err(|_| Error::Configuration)?;
        if (MANAGED as u64 + CONTEXT as u64) > physical.identity().global_bytes {
            return Err(Error::ResourceLimit);
        }
        policy.recheck()?;
        Ok(Self {
            physical,
            scratch,
            request,
            effective,
            policy,
            reservation,
        })
    }

    /// The caller supplies its current sealed request. This refuses a changed
    /// request before configuration or device queries; bounded physical recheck
    /// does not reconstruct or clone the retained shared Identity.
    pub(super) fn recheck(&mut self, request: bounded::Request) -> Result<(), Error> {
        if request != self.request {
            return Err(Error::Configuration);
        }
        self.policy.recheck()?;
        if self.effective != Effective::capture()? {
            return Err(Error::Configuration);
        }
        self.physical
            .recheck(request, &mut self.scratch)
            .map_err(|_| Error::Configuration)
    }

    pub(super) fn policy(&self) -> &WorkerPolicyAbsent {
        &self.policy
    }

    pub(super) fn identity(&self) -> &crate::gpu_device::Identity {
        self.physical.identity()
    }

    pub(super) fn same_ledger(&self, other: &Reservation) -> bool {
        self.reservation.same_ledger(other)
    }

    pub(super) fn plan(
        &mut self,
        request: bounded::Request,
        minimum: WalletProofMinimum,
        reservation: Reservation,
    ) -> Result<NoteDevicePlan, Error> {
        if !self.same_ledger(&reservation)
            || reservation.reserved_bytes()
                < NoteDevicePlan::required_host_bytes().map_err(|_| Error::ResourceLimit)?
        {
            return Err(Error::ResourceLimit);
        }
        self.recheck(request)?;
        let limits = Limits {
            managed_bytes: self.effective.managed_bytes,
            ..Limits::default()
        };
        NoteDevicePlan::new(
            minimum,
            self.physical.device(),
            limits,
            usize::try_from(self.physical.identity().max_allocation_bytes)
                .map_err(|_| Error::ResourceLimit)?,
            self.effective.transfer_slots,
            reservation,
        )
        .map_err(|_| Error::ResourceLimit)
    }
}

impl Effective {
    fn capture() -> Result<Self, Error> {
        for name in REQUIRED {
            if !switch(name)? {
                return Err(Error::Configuration);
            }
        }
        for name in DISABLED {
            if switch(name)? {
                return Err(Error::Configuration);
            }
        }
        for name in ABSENT {
            if std::env::var_os(name).is_some() {
                return Err(Error::Configuration);
            }
        }
        match std::env::var("LATTICA_V2_GPU_TUNING") {
            Err(std::env::VarError::NotPresent) => {}
            Ok(value) if value.is_empty() => {}
            _ => return Err(Error::Configuration),
        }
        if PublicHashSelection::from_env().map_err(|_| Error::Configuration)?
            != PublicHashSelection::Baseline
        {
            return Err(Error::Configuration);
        }
        let trees = retained_storage::Selection::from_env().map_err(|_| Error::Configuration)?;
        if trees.mode != RetainedTreeStorageMode::Device || trees.host_bytes != 0 {
            return Err(Error::Configuration);
        }
        let managed_bytes = bytes("LATTICA_V2_GPU_MANAGED_BYTES", MANAGED)?;
        let context_bytes = bytes("LATTICA_V2_GPU_CONTEXT_BYTES", CONTEXT)?;
        let host_output_bytes =
            resident_pcs::try_host_output_budget().map_err(|_| Error::Configuration)?;
        if managed_bytes != MANAGED || context_bytes != CONTEXT || host_output_bytes != NATIVE_HOST
        {
            return Err(Error::ResourceLimit);
        }
        if switch("LATTICA_V2_GPU_PIPELINE")? {
            return Err(Error::Configuration);
        }
        Ok(Self {
            managed_bytes,
            context_bytes,
            host_output_bytes,
            transfer_slots: 1,
        })
    }
}

fn switch(name: &str) -> Result<bool, Error> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => Err(Error::Configuration),
    }
}

fn bytes(name: &str, default: usize) -> Result<usize, Error> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Ok(value) => value.parse().map_err(|_| Error::Configuration),
        _ => Err(Error::Configuration),
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::note_research_quota::{Quota, LEDGER_BYTES};
    use crate::spill_alloc::allocation_requests::measure;

    #[test]
    fn short_selector_token_is_refused_and_released_before_queries() {
        let required = NoteSelection::required_payload_bytes().unwrap();
        let quota = Quota::new(LEDGER_BYTES + required).unwrap();
        let request =
            bounded::Request::parse("0", "GPU-01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let short = quota.reserve(required - 1).unwrap();
        let (result, allocations) = measure(|| NoteSelection::capture(request, short));
        assert!(matches!(result, Err(Error::ResourceLimit)));
        assert_eq!(allocations.calls, 0);
        assert_eq!(allocations.bytes, 0);
        assert!(!allocations.overflow);
        assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
    }
}
