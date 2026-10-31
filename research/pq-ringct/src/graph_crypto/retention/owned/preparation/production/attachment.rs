//! Consume the complete verified singleton owner into a compiler child.
//! Additional metadata is admitted before key construction; proof/report and
//! their original claims never move out of the producer owner.
use super::*;
use crate::graph_crypto::retention::owned::ChildPayload;
use crate::graph_crypto::{NativeRetentionShape, Request, ReservedNativeChild};

const IDENTITY: &str = "native singleton attachment identity";
const AUTHORITY: &str = "native singleton attachment authority";
const SOURCE: &str = "native singleton attachment source";

// Every dynamic error below comes from the pinned retention helpers or the
// SHAKE-only cache key. Four times the longest literal covers overlapping
// String growth; no dynamic error survives its original adapter reservation.
const fn error_text_bound() -> usize {
    let messages = [
        "native retention size overflow",
        "native retention requires serial SHAKE",
        "native retention segment index",
        "native retention partition index",
        "native retention registered shape mismatch",
        "native retention geometry",
        "native retention unsupported pinned profile",
        "native retention FRI degree",
        "TryFromIntError(())",
        "native retention proof degree",
        "native retention random cap",
        "native retention preprocessing",
        "native retention quotient shape",
        "native retention random opening",
        "native retention nonbinary FRI",
        "native retention spare capacity",
        "native retention owned capacity",
        "native retention vector shape",
        "native retention cap shape",
        "crypto segment index",
    ];
    let mut longest = 8;
    let mut index = 0;
    while index < messages.len() {
        if messages[index].len() > longest {
            longest = messages[index].len();
        }
        index += 1;
    }
    longest
}

fn requirements() -> Result<Requirements> {
    let mut bytes = 0usize;
    for item in [
        size_of::<AttachmentPlan<'static>>(),
        size_of::<NativePreparationPlan<'static>>(),
        size_of::<PendingAttachment<'static>>(),
        size_of::<MetadataOwner<'static>>(),
        size_of::<NativeSingletonChild<'static>>(),
        size_of::<ChildPayload<'static>>(),
        size_of::<ReservedNativeChild<'static>>(),
        // Count the original and destination ownership headers together; do
        // not depend on move elision or a smaller observed inline layout.
        size_of::<VerifiedNativeSingleton<'static>>(),
        size_of::<NativeRetentionShape>(),
        3 * size_of::<Requirements>(),
        size_of::<Ledger>(),
        size_of::<Reservation>(),
        3 * size_of::<[u8; 32]>(),
        2 * size_of::<sha3::Sha3_256>(),
        size_of::<[usize; 5]>(),
        size_of::<[u8; 8]>(),
        size_of::<Vec<u64>>() + 3 * size_of::<u64>(),
        // A single exact public Vec during final compiler re-verification.
        size_of::<Vec<Val>>() + PUBLIC_VALUES * size_of::<Val>(),
        size_of::<VerificationPlan>(),
        size_of::<VerificationFailure>(),
        size_of::<VerificationReceipt>(),
        4 * error_text_bound() + 2 * size_of::<String>(),
        2 * size_of::<Error>(),
    ] {
        bytes = bytes.checked_add(item).ok_or(Error::Overflow)?;
    }
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

struct AttachmentPlan<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    requirements: Requirements,
}

impl<'request> AttachmentPlan<'request> {
    fn new(owner: &'request ReservedShakeRequest, index: usize) -> Result<Self> {
        let source = NativePreparationPlan::new(owner, index).map_err(|_| Error::Source)?;
        if !matches!(source.air, ShakeSegmentAir::Single(_))
            || source.census().geometry().permutations() != 1
            || source.census().geometry().rows() != 4096
            || source.census().geometry().width() != 517
        {
            return Err(Error::Source);
        }
        Ok(Self {
            owner,
            index,
            requirements: requirements()?,
        })
    }

    fn claim_for(
        self,
        owner: &ReservedShakeRequest,
        index: usize,
        original: Reservation,
        ledger: &Ledger,
    ) -> Result<PendingAttachment<'request>> {
        let allowance = ledger.snapshot().allowance;
        if !core::ptr::eq(owner, self.owner)
            || index != self.index
            || !owner.belongs_to(ledger)
            || !original.belongs_to(ledger)
            || original.requirements() != self.requirements
            || allowance.host == 0
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device != DEVICE_BYTES
        {
            return Err(Error::Authority);
        }
        Ok(PendingAttachment {
            plan: self,
            original,
        })
    }
}

struct PendingAttachment<'request> {
    plan: AttachmentPlan<'request>,
    original: Reservation,
}

impl<'request> PendingAttachment<'request> {
    fn prepare_metadata(self) -> Result<MetadataOwner<'request>> {
        // This path first acquires the adapter claim. Neither helper runs
        // during source planning or while borrowing another owner's quota.
        let shape = self
            .plan
            .owner
            .request()
            .segment_retention_shape(self.plan.index)
            .map_err(|_| Error::Source)?;
        let key = self
            .plan
            .owner
            .request()
            .cache_key(self.plan.index)
            .map_err(|_| Error::Source)?;
        Ok(MetadataOwner {
            owner: self.plan.owner,
            index: self.plan.index,
            key,
            shape,
            original: self.original,
        })
    }
}

pub(crate) struct MetadataOwner<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    key: [u8; 32],
    shape: NativeRetentionShape,
    original: Reservation,
}

impl<'request> MetadataOwner<'request> {
    fn finish(
        self,
        produced: VerifiedNativeSingleton<'request>,
        ledger: &Ledger,
    ) -> Result<ReservedNativeChild<'request>> {
        if !produced.is_for(self.owner, self.index, ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != requirements()?
        {
            return Err(Error::Authority);
        }
        self.shape
            .audit_planner_proof(&produced.artifact().proof)
            .map_err(|_| Error::Source)?;
        Ok(ReservedNativeChild {
            request: self.owner.request(),
            owned: ChildPayload::Produced(NativeSingletonChild {
                produced,
                key: self.key,
                shape: self.shape,
                original: self.original,
            }),
        })
    }
}

impl<'request> VerifiedNativeSingleton<'request> {
    /// The only production child constructor consumes an already verified
    /// opaque owner. Callers cannot provide a proof, key or detached token.
    pub(crate) fn into_reserved_child(
        self,
        ledger: &Ledger,
    ) -> Result<ReservedNativeChild<'request>> {
        if !self.is_for(self.owner, self.index, ledger) {
            return Err(Error::Authority);
        }
        let plan = AttachmentPlan::new(self.owner, self.index)?;
        let original = ledger
            .admit_phase(plan.requirements)
            .map_err(|_| Error::Admission)?;
        let pending = plan.claim_for(self.owner, self.index, original, ledger)?;
        pending.prepare_metadata()?.finish(self, ledger)
    }
}

/// Destruction drops the entire original proof/report owner before adapter
/// backing. The private enum moves this owner intact through compilation.
pub(in crate::graph_crypto::retention::owned) struct NativeSingletonChild<'request> {
    produced: VerifiedNativeSingleton<'request>,
    key: [u8; 32],
    shape: NativeRetentionShape,
    original: Reservation,
}

impl NativeSingletonChild<'_> {
    pub(in crate::graph_crypto::retention::owned) fn index(&self) -> usize {
        self.produced.index
    }
    pub(in crate::graph_crypto::retention::owned) fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub(in crate::graph_crypto::retention::owned) fn shape(&self) -> NativeRetentionShape {
        self.shape
    }
    pub(in crate::graph_crypto::retention::owned) fn artifact(&self) -> &LaneShakeProof {
        self.produced.artifact()
    }

    pub(in crate::graph_crypto::retention::owned) fn is_for(
        &self,
        request: &Request,
        index: usize,
        ledger: &Ledger,
    ) -> bool {
        core::ptr::eq(self.produced.owner.request(), request)
            && self.produced.is_for(self.produced.owner, index, ledger)
            && self.original.belongs_to(ledger)
            && requirements().is_ok_and(|r| self.original.requirements() == r)
    }

    pub(in crate::graph_crypto::retention::owned) fn verify_pre_reserved(
        &self,
        verifier: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<VerificationReceipt, VerificationFailure> {
        let configuration = VerificationFailure::Configuration;
        if !self.is_for(self.produced.owner.request(), self.index(), ledger)
            || !verifier.belongs_to(ledger)
            || verifier.requirements() != VerificationPlan::component_requirement()
        {
            return Err(configuration(AUTHORITY));
        }
        let expected_key = self
            .produced
            .owner
            .request()
            .cache_key(self.index())
            .map_err(|_| configuration(IDENTITY))?;
        if expected_key != self.key {
            return Err(configuration(IDENTITY));
        }
        let air = self
            .produced
            .owner
            .request()
            .shake_partition()
            .and_then(|partition| partition.segments().get(self.index()))
            .ok_or_else(|| configuration(SOURCE))?;
        let plan = VerificationPlan::new(air).map_err(configuration)?;
        let mut public = Vec::new();
        public
            .try_reserve_exact(PUBLIC_VALUES)
            .map_err(|_| configuration(AUTHORITY))?;
        if public.capacity() != PUBLIC_VALUES {
            return Err(configuration(AUTHORITY));
        }
        public.extend_from_slice(&self.artifact().public_values);
        plan.admit_pre_reserved(
            air,
            &self.artifact().proof,
            &public,
            self.produced.output.proof_reservation(),
            verifier,
            ledger,
        )
        .map_err(configuration)?
        .verify()
    }
}

#[cfg(test)]
mod tests;

mod preissued;
