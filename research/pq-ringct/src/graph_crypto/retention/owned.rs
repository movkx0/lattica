//! Ownership prerequisite only. No current API can produce an accounted child.
//!
//! A future PreparedPairedWorkflow must issue a native dispatch permit after
//! complete workflow, native geometry, phase footprint and policy admission.
//! A generic phase lease or a memory reservation does not authorize dispatch.
//! There is deliberately no constructor attaching a token to a supplied proof.

use super::{NativeRetentionShape, Request, RetainedNativeChild, SegmentArtifact, Val};
use crate::component_tree::shake_verification_memory::{
    Plan as VerificationPlan, PROOF_BACKING_CEILING,
};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;

type Result<T> = core::result::Result<T, &'static str>;
const IDENTITY: &str = "native owner request identity";
const SHAPE: &str = "native owner unsupported source shape";
const CAPACITY: &str = "native owner source storage bound";
const AUTHORITY: &str = "native owner reservation authority";

/// Public-shape information and an exact, immutable request borrow. It carries
/// no proof receipt, dispatch authority, or reservation until claim_for succeeds.
pub(crate) struct NativeProductionPlan<'request> {
    request: &'request Request,
    index: usize,
    shape: NativeRetentionShape,
    verification: VerificationPlan,
    source_storage_bytes: usize,
}

impl<'request> NativeProductionPlan<'request> {
    pub(crate) fn new(request: &'request Request, index: usize) -> Result<Self> {
        let air = request
            .shake_partition()
            .and_then(|partition| partition.segments().get(index))
            .ok_or(SHAPE)?;
        let verification = VerificationPlan::new(air)?;
        let shape = request.segment_retention_shape(index).map_err(|_| SHAPE)?;
        // The retained shape includes its child header and every permitted
        // nested proof capacity. Additionally charge the temporary native
        // public Vec (up to twice the fixed logical public length) while it
        // becomes the retained inline array, plus both ownership headers.
        // Proving scratch, reports, endpoint calculation and verifier scratch
        // are separate whole-phase requirements, never hidden in this token.
        let public_vec = crate::shake_air::PUBLIC_VALUES
            .checked_mul(2)
            .and_then(|n| n.checked_mul(size_of::<Val>()))
            .and_then(|n| n.checked_add(size_of::<Vec<Val>>()))
            .ok_or(CAPACITY)?;
        let source_storage_bytes = shape
            .retained_bytes()
            .checked_add(public_vec)
            .and_then(|n| n.checked_add(size_of::<PendingNativeChild<'_>>()))
            .and_then(|n| n.checked_add(size_of::<ReservedNativeChild>()))
            .ok_or(CAPACITY)?;
        if source_storage_bytes > PROOF_BACKING_CEILING {
            return Err(CAPACITY);
        }
        Ok(Self {
            request,
            index,
            shape,
            verification,
            source_storage_bytes,
        })
    }

    /// A fixed conservative output reservation. It includes the source-derived
    /// storage bound above and never increases the worker's host allowance.
    pub(crate) fn requirement(&self) -> Requirements {
        Requirements::single(
            Category::NativeProof,
            Bytes {
                host: PROOF_BACKING_CEILING as u64,
                device: 0,
            },
        )
    }

    pub(crate) fn source_storage_bytes(&self) -> usize {
        self.source_storage_bytes
    }

    pub(crate) fn is_for(&self, request: &Request, index: usize) -> bool {
        core::ptr::eq(self.request, request) && self.index == index
    }

    /// Consume an exact output token split from the shared workflow admission.
    /// This reserves nothing again and must precede any production allocation.
    /// A lease alone cannot advance the returned owner to a produced child.
    pub(crate) fn claim_for(
        self,
        request: &Request,
        index: usize,
        reservation: Reservation,
        ledger: &Ledger,
    ) -> Result<PendingNativeChild<'request>> {
        if !self.is_for(request, index) {
            return Err(IDENTITY);
        }
        let allowance = ledger.snapshot().allowance;
        if allowance.host > 32u64 << 30 || allowance.device > 8u64 << 30 {
            return Err(AUTHORITY);
        }
        if !reservation.belongs_to(ledger) || reservation.requirements() != self.requirement() {
            return Err(AUTHORITY);
        }
        Ok(PendingNativeChild {
            plan: self,
            reservation,
        })
    }
}

/// An empty, reserved production slot; it cannot be retargeted or populated by
/// callers. It retains the request identity and token before a future producer
/// can allocate a proof. There is no public raw-artifact attachment method.
pub(crate) struct PendingNativeChild<'request> {
    plan: NativeProductionPlan<'request>,
    reservation: Reservation,
}

// No variants and no constructor: accounting is not native dispatch authority.
// Replace this only when PreparedPairedWorkflow can issue its reviewed permit;
// do not accept a generic PhaseLease in its place.
enum UnissuedNativeDispatchPermit {}

impl PendingNativeChild<'_> {
    fn produce(self, permit: UnissuedNativeDispatchPermit) -> Result<ReservedNativeChild> {
        match permit {}
    }
}

// Rust drops fields in declaration order. Keeping this private prevents a
// caller moving out the payload or dropping its reservation independently.
struct OwnedPayload<T> {
    payload: T,
    reservation: Reservation,
}

/// The eventual immutable produced child and its linear storage authority.
/// No current non-test constructor exists; this is not a fresh-proof receipt.
pub(crate) struct ReservedNativeChild {
    owned: OwnedPayload<RetainedNativeChild>,
}

impl ReservedNativeChild {
    pub(crate) fn index(&self) -> usize {
        self.owned.payload.index()
    }
    pub(crate) fn key(&self) -> &[u8; 32] {
        self.owned.payload.key()
    }
    pub(crate) fn shape(&self) -> NativeRetentionShape {
        self.owned.payload.shape()
    }
    pub(crate) fn artifact(&self) -> &SegmentArtifact {
        self.owned.payload.artifact()
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
