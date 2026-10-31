//! Source-preissued exact HashX native child metadata and retained verifier.
use super::*;
use crate::graph_crypto::retention::owned::ChildPayload;
use crate::graph_crypto::{NativeRetentionShape, Request};

const AUTHORITY: &str = "HashX native child original authority";
const IDENTITY: &str = "HashX native child original identity";
const SOURCE: &str = "HashX native child source";

pub(super) struct PreparedAttachment<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    key: [u8; 32],
    shape: NativeRetentionShape,
    original: Reservation,
}

/// The original proof/report owner dies before its preissued attachment claim.
pub(in crate::graph_crypto::retention::owned) struct NativeSegmentChild<'request> {
    produced: VerifiedNativeSegment<'request>,
    key: [u8; 32],
    shape: NativeRetentionShape,
    original: Reservation,
}

pub(super) fn requirements() -> Result<Requirements> {
    let parts = [
        checked_frames::<PreparedAttachment<'static>>(8)?,
        checked_frames::<NativeSegmentChild<'static>>(8)?,
        checked_frames::<VerifiedNativeSegment<'static>>(8)?,
        checked_frames::<ReservedNativeChild<'static>>(8)?,
        checked_frames::<ChildPayload<'static>>(8)?,
        checked_frames::<Result<PreparedAttachment<'static>>>(8)?,
        checked_frames::<Result<ReservedNativeChild<'static>>>(8)?,
        checked_frames::<NativePreparationPlan<'static>>(8)?,
        checked_frames::<NativeRetentionShape>(8)?,
        checked_frames::<VerificationPlan>(8)?,
        checked_frames::<core::result::Result<VerificationPlan, &'static str>>(8)?,
        checked_frames::<
            core::result::Result<
                crate::component_tree::shake_verification_memory::AdmittedVerification<'static>,
                &'static str,
            >,
        >(8)?,
        checked_frames::<Result<Requirements>>(8)?,
        checked_frames::<
            core::result::Result<NativePreparationPlan<'static>, super::super::super::Error>,
        >(8)?,
        checked_frames::<VerificationReceipt>(8)?,
        checked_frames::<VerificationFailure>(8)?,
        checked_frames::<
            core::result::Result<(VerificationReceipt, Reservation), VerificationFailure>,
        >(8)?,
        checked_frames::<core::result::Result<VerificationReceipt, VerificationFailure>>(8)?,
        checked_frames::<Requirements>(16)?,
        checked_frames::<Reservation>(8)?,
        checked_frames::<Ledger>(8)?,
        checked_frames::<[u8; 32]>(8)?,
        checked_frames::<sha3::Sha3_256>(8)?,
        checked_frames::<Vec<u64>>(8)?,
        8 * 3 * size_of::<u64>(),
        checked_frames::<Vec<Val>>(8)?,
        PUBLIC_VALUES * size_of::<Val>(),
        VerificationPlan::retaining_original_caller_host_bytes().map_err(|_| Error::Overflow)?,
        // All closed source/key/proof-capacity helper errors are fixed strings.
        // Include overlapping bounded diagnostics, iterator and validation frames.
        32 << 10,
    ];
    let bytes = parts
        .iter()
        .try_fold(core::mem::size_of_val(&parts) * 8, |a, &b| {
            a.checked_add(b).ok_or(Error::Overflow)
        })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

impl<'request> PreparedAttachment<'request> {
    pub(super) fn reserve_before_native(
        owner: &'request ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        source(owner, ledger)?;
        if index >= SEGMENTS {
            return Err(Error::Source);
        }
        let original = ledger
            .admit_phase(requirements()?)
            .map_err(|_| Error::Admission)?;
        let preparation = NativePreparationPlan::new(owner, index).map_err(|_| Error::Source)?;
        if preparation.census().geometry().permutations() != COUNTS[index] {
            return Err(Error::Source);
        }
        // Key/shape helpers run only under the original attachment claim and
        // before the first native phase derives its remaining PCS capacity.
        let shape = owner
            .request()
            .segment_retention_shape(index)
            .map_err(|_| Error::Source)?;
        let key = owner
            .request()
            .cache_key(index)
            .map_err(|_| Error::Source)?;
        Ok(Self {
            owner,
            index,
            key,
            shape,
            original,
        })
    }

    pub(super) fn check(
        &self,
        produced: &VerifiedNativeSegment<'request>,
        ledger: &Ledger,
    ) -> Result<()> {
        if !produced.is_for(self.owner, self.index, ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != requirements()?
        {
            return Err(Error::Authority);
        }
        self.shape
            .audit_planner_proof(&produced.output.artifact().proof)
            .map_err(|_| Error::Source)?;
        Ok(())
    }

    /// Only the closed CompletedNativeHashx caller invokes this, immediately
    /// after check while both exact immutable owners remain borrowed and live.
    pub(super) fn finish(
        self,
        produced: VerifiedNativeSegment<'request>,
    ) -> ReservedNativeChild<'request> {
        ReservedNativeChild {
            request: self.owner.request(),
            owned: ChildPayload::ProducedHashx(NativeSegmentChild {
                produced,
                key: self.key,
                shape: self.shape,
                original: self.original,
            }),
        }
    }
}

impl NativeSegmentChild<'_> {
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
        self.produced.output.artifact()
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
            && requirements().is_ok_and(|required| self.original.requirements() == required)
    }

    pub(in crate::graph_crypto::retention::owned) fn verify_pre_reserved(
        &self,
        verifier: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<VerificationReceipt, VerificationFailure> {
        self.verify_retaining_original(verifier, ledger)
            .map(|(receipt, original)| {
                drop(original);
                receipt
            })
    }

    /// Success returns the actual original only after all public/configuration
    /// payloads have died. Failure is terminal cleanup, with no restore token.
    pub(in crate::graph_crypto::retention::owned) fn verify_retaining_original(
        &self,
        verifier: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<(VerificationReceipt, Reservation), VerificationFailure> {
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
        self.shape
            .audit_planner_proof(&self.artifact().proof)
            .map_err(|_| configuration(SOURCE))?;
        let air = self
            .produced
            .owner
            .request()
            .shake_partition()
            .and_then(|p| p.segments().get(self.index()))
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
        let admitted = plan
            .admit_pre_reserved(
                air,
                &self.artifact().proof,
                &public,
                self.produced.output.proof_reservation(),
                verifier,
                ledger,
            )
            .map_err(configuration)?;
        let result = admitted.verify_retaining_original();
        drop(public);
        match result {
            Ok((receipt, original)) => Ok((receipt, original)),
            Err((failure, original)) => {
                drop(original);
                Err(failure)
            }
        }
    }
}
