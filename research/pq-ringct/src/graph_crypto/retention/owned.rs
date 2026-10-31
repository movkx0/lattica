//! Closed native child ownership for SHAKE compiler inputs.
//!
//! The production constructor consumes an already verified original singleton
//! owner without extracting its proof or backing. PendingNativeChild remains
//! an unissued fixture path; a generic reservation never authorizes dispatch.
//! There is no constructor attaching a token to a supplied proof.

use super::{NativeRetentionShape, Request, RetainedNativeChild, SegmentArtifact, Val};
use crate::component_tree::shake_verification_memory::{
    Plan as VerificationPlan, VerificationFailure, VerificationReceipt, PROOF_BACKING_CEILING,
};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;
#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
use p3_field::PrimeCharacteristicRing;

type Result<T> = core::result::Result<T, &'static str>;
const IDENTITY: &str = "native owner request identity";
const SHAPE: &str = "native owner unsupported source shape";
const CAPACITY: &str = "native owner source storage bound";
const AUTHORITY: &str = "native owner reservation authority";

mod payload;
use payload::ChildPayload;

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
        // cache_key hashes a three-u64 SHAKE descriptor Vec; the exact request
        // payload is borrowed and the compiled-source fingerprint is inline.
        let key_scratch = 3 * size_of::<u64>() + size_of::<Vec<u64>>();
        let source_storage_bytes = shape
            .retained_bytes()
            .checked_add(public_vec)
            .and_then(|n| n.checked_add(key_scratch))
            .and_then(|n| n.checked_add(size_of::<PendingNativeChild<'_>>()))
            .and_then(|n| n.checked_add(size_of::<ReservedNativeChild<'_>>()))
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
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) || allowance.device > 8u64 << 30 {
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

impl<'request> PendingNativeChild<'request> {
    fn produce(
        self,
        permit: UnissuedNativeDispatchPermit,
    ) -> Result<ReservedNativeChild<'request>> {
        match permit {}
    }

    /// Real CPU production for the serialized correctness harness only. The
    /// harness separately guards producer scratch; this is not runtime phase
    /// admission, a GPU fallback, or an issuer of native dispatch authority.
    #[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn produce_cpu_fixture(self) -> Result<ReservedNativeChild<'request>> {
        let artifact = self
            .plan
            .request
            .prove_segment(self.plan.index)
            .map_err(|_| "test native CPU production failed")?;
        let key = self
            .plan
            .request
            .cache_key(self.plan.index)
            .map_err(|_| IDENTITY)?;
        let child =
            RetainedNativeChild::from_fresh(self.plan.index, key, self.plan.shape, artifact)
                .map_err(|_| CAPACITY)?;
        Ok(ReservedNativeChild {
            request: self.plan.request,
            owned: ChildPayload::Fixture {
                owned: OwnedPayload {
                    payload: child,
                    reservation: self.reservation,
                },
                _request: core::marker::PhantomData,
            },
        })
    }

    /// Deliberately invalid native proof, allocated after its output token, for
    /// rejection/cleanup tests. This cannot be linked into a non-test producer.
    #[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn produce_shape_fixture(self) -> Result<ReservedNativeChild<'request>> {
        let air = &self.plan.request.shake_partition().ok_or(SHAPE)?.segments()[self.plan.index];
        let proof =
            crate::component_tree::shape_diagnostic::invalid_native_template(air, air.height());
        let artifact = SegmentArtifact::Shake(crate::shake_air::lane::LaneShakeProof {
            public_values: [Val::ZERO; crate::shake_air::PUBLIC_VALUES],
            proof,
        });
        let key = self
            .plan
            .request
            .cache_key(self.plan.index)
            .map_err(|_| IDENTITY)?;
        let child =
            RetainedNativeChild::from_fresh(self.plan.index, key, self.plan.shape, artifact)
                .map_err(|_| CAPACITY)?;
        Ok(ReservedNativeChild {
            request: self.plan.request,
            owned: ChildPayload::Fixture {
                owned: OwnedPayload {
                    payload: child,
                    reservation: self.reservation,
                },
                _request: core::marker::PhantomData,
            },
        })
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
impl Request {
    /// Small exact-input request for serialized compiler-owner correctness.
    pub(crate) fn owned_compiler_fixture(input: Vec<u8>, output_len: usize) -> Self {
        use crate::graph_crypto::{Payload, Policy, RequestDescriptor};
        Self::new(
            [7; 32],
            0,
            0,
            RequestDescriptor::Shake(crate::shake_air::Descriptor {
                input_len: input.len(),
                output_len,
            }),
            Payload::Shake(input),
            Policy {
                maximum_shake_permutations: 1,
                ..Policy::default()
            },
        )
        .expect("small fixed test request")
    }
}

// Rust drops fields in declaration order. Keeping this private prevents a
// caller moving out the payload or dropping its reservation independently.
struct OwnedPayload<T> {
    payload: T,
    reservation: Reservation,
}

/// Immutable compiler child retaining its original proof storage authority.
/// Production consumes the closed verified singleton owner; fixtures remain
/// test-only and do not establish a fresh GPU production receipt.
pub(crate) struct ReservedNativeChild<'request> {
    request: &'request Request,
    owned: ChildPayload<'request>,
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod preparation;
#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(crate) use preparation::{
    FutureNativeSingleton, NativeCompletionError, NativePreparationPlan, NativeSuccessorError,
    OuterContinuationCapacity, PendingNativePreparation, PreparedNativeSingleton,
    PreparedNativeSingletonAttachment, ReadyNativeSingleton, VerifiedNativeSingleton,
    VerifiedNativeSingletonWithOriginals,
};

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(crate) use preparation::{
    ActiveHashxOuter, CompletedNativeHashx, HashxOuterStep, PendingNativeHashx,
    PreissuedHashxOuter, PreparedHashxOuter, PreparedNativeHashx, ProjectedHashxQuota,
    RetiredHashxOuter, RetiredHashxOuterOriginals,
};
