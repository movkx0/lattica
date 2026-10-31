//! Closed SHAKE-only child ownership. Native GPU children retain the complete
//! verified producer owner; CPU fixtures retain their original test-only path.
use super::*;
use crate::shake_air::lane::LaneShakeProof;

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
use super::preparation::{NativeSegmentChild, NativeSingletonChild};

pub(super) enum ChildPayload<'request> {
    Fixture {
        owned: OwnedPayload<RetainedNativeChild>,
        _request: core::marker::PhantomData<&'request Request>,
    },
    #[cfg(all(
        feature = "owned-native-shake",
        not(debug_assertions),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    Produced(NativeSingletonChild<'request>),
    #[cfg(all(
        feature = "owned-native-shake",
        not(debug_assertions),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    ProducedHashx(NativeSegmentChild<'request>),
}

impl ReservedNativeChild<'_> {
    pub(crate) fn index(&self) -> usize {
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => owned.payload.index(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.index(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.index(),
        }
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => owned.payload.key(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.key(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.key(),
        }
    }

    pub(crate) fn shape(&self) -> NativeRetentionShape {
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => owned.payload.shape(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.shape(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.shape(),
        }
    }

    /// No artifact wrapper, proof clone or token can escape this immutable
    /// borrow. Both closed constructors admit only the SHAKE family.
    pub(crate) fn shake_artifact(&self) -> &LaneShakeProof {
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => {
                let SegmentArtifact::Shake(proof) = owned.payload.artifact() else {
                    unreachable!("closed native child requires SHAKE")
                };
                proof
            }
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.artifact(),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.artifact(),
        }
    }

    pub(crate) fn is_for(&self, request: &Request, index: usize, ledger: &Ledger) -> bool {
        if !core::ptr::eq(self.request, request) || self.index() != index {
            return false;
        }
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => {
                owned.reservation.belongs_to(ledger)
                    && owned.reservation.requirements()
                        == Requirements::single(
                            Category::NativeProof,
                            Bytes {
                                host: PROOF_BACKING_CEILING as u64,
                                device: 0,
                            },
                        )
            }
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.is_for(request, index, ledger),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.is_for(request, index, ledger),
        }
    }

    /// Final compiler admission still performs independent numerical native
    /// verification. Its exact original verifier token predates all scratch.
    pub(crate) fn verify_pre_reserved(
        &self,
        verifier: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<VerificationReceipt, VerificationFailure> {
        let configuration = VerificationFailure::Configuration;
        if !self.is_for(self.request, self.index(), ledger)
            || !verifier.belongs_to(ledger)
            || verifier.requirements() != VerificationPlan::component_requirement()
        {
            return Err(configuration(AUTHORITY));
        }
        match &self.owned {
            ChildPayload::Fixture { owned, .. } => {
                // The unchanged CPU fixture storage envelope owns its key
                // descriptor scratch and temporary public Vec.
                let expected_key = self
                    .request
                    .cache_key(self.index())
                    .map_err(|_| configuration(IDENTITY))?;
                if self.key() != &expected_key {
                    return Err(configuration(IDENTITY));
                }
                let air = self
                    .request
                    .shake_partition()
                    .and_then(|partition| partition.segments().get(self.index()))
                    .ok_or_else(|| configuration(SHAPE))?;
                let plan = VerificationPlan::new(air).map_err(configuration)?;
                let artifact = self.shake_artifact();
                let public = artifact.public_values.to_vec();
                plan.admit_pre_reserved(
                    air,
                    &artifact.proof,
                    &public,
                    &owned.reservation,
                    verifier,
                    ledger,
                )
                .map_err(configuration)?
                .verify()
            }
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::Produced(owned) => owned.verify_pre_reserved(verifier, ledger),
            #[cfg(all(
                feature = "owned-native-shake",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            ChildPayload::ProducedHashx(owned) => owned.verify_pre_reserved(verifier, ledger),
        }
    }
}

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
impl ReservedNativeChild<'_> {
    /// Only the source-preissued HashX attachment carries the additional full
    /// retaining-verifier caller census. Older payloads retain their default
    /// drop-on-return verifier API. Failure is terminal cleanup only.
    pub(crate) fn verify_pre_reserved_retaining_original(
        &self,
        verifier: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<(VerificationReceipt, Reservation), VerificationFailure> {
        if !self.is_for(self.request, self.index(), ledger)
            || !verifier.belongs_to(ledger)
            || verifier.requirements() != VerificationPlan::component_requirement()
        {
            return Err(VerificationFailure::Configuration(AUTHORITY));
        }
        match &self.owned {
            ChildPayload::ProducedHashx(owned) => owned.verify_retaining_original(verifier, ledger),
            _ => Err(VerificationFailure::Configuration(
                "native child has no original retaining-verifier census",
            )),
        }
    }
}
