//! Fixed, research-only producer and typed PQNOTE1 handoff. Every native,
//! decoder, packet and verifier claim is acquired on the preparation ledger
//! before the first device query. Only the original encoded owner crosses
//! exact runtime retirement; the independent verifier remains in research.
use super::{core, PreparationError, PreparedNote, Reservation};
use crate::{note_gpu::*, Context};
use p3_field::PrimeField64;
use std::mem::size_of;

#[derive(Clone, Copy)]
struct HandoffPlan {
    expected_capacity: usize,
    decoder_bytes: usize,
    verifier_bytes: usize,
    inline_bytes: usize,
    total_bytes: usize,
}

impl HandoffPlan {
    fn new(expected_capacity: usize) -> Result<Self, Error> {
        let geometry = Geometry::pinned()?;
        let decoder_bytes = codec::requirements_for(
            MAX_PROOF_BYTES,
            add(ARTIFACT_HEADER_BYTES, MAX_PROOF_BYTES)?,
            expected_capacity,
            geometry,
        )?
        .reserved_bytes;
        let verifier_bytes = VerificationPlan::new()
            .map_err(|_| Error::Geometry)?
            .required_temporary_bytes();
        let mut inline_bytes = 0;
        for bytes in [
            size_of::<Self>(),
            size_of::<Admission>(),
            size_of::<ProducedNote>(),
            size_of::<RetainedProducer>(),
            size_of::<codec::PreAdmittedScratch>(),
            size_of::<VerificationPlan>(),
            size_of::<codec::ScratchGuard<'static>>(),
        ] {
            inline_bytes = add(inline_bytes, bytes)?;
        }
        let total_bytes = add(add(decoder_bytes, verifier_bytes)?, inline_bytes)?;
        if total_bytes > WORKER_HOST_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            expected_capacity,
            decoder_bytes,
            verifier_bytes,
            inline_bytes,
            total_bytes,
        })
    }
}

struct Admission {
    plan: HandoffPlan,
    runtime: Reservation,
    handoff: Reservation,
}

impl Admission {
    fn reserve(prepared: &PreparedNote<'_>) -> Result<Self, PreparationError> {
        let capacity = prepared
            .receipt
            .expected_statement_backing_bytes
            .checked_div(size_of::<u64>())
            .ok_or(PreparationError::ResourceLimit)?;
        let plan = HandoffPlan::new(capacity).map_err(PreparationError::Statement)?;
        let runtime_bytes = prepared
            .prepared
            .qualification_runtime_bytes()
            .map_err(PreparationError::Core)?;
        let total = runtime_bytes
            .checked_add(plan.total_bytes)
            .ok_or(PreparationError::ResourceLimit)?;
        // One atomic admission covers the complete continuation. Splitting
        // transfers this actual token and cannot invent replacement capacity.
        let mut handoff = prepared
            ._reservation
            .reserve_related(total)
            .map_err(|_| PreparationError::ResourceLimit)?;
        let runtime = handoff
            .split_off(runtime_bytes)
            .map_err(|_| PreparationError::ResourceLimit)?;
        Ok(Self {
            plan,
            runtime,
            handoff,
        })
    }
}

/// No constructor from bytes, Clone, token extraction or callback. The native
/// owner retires before the original preparation and handoff reservations.
pub struct ProducedNote {
    native: core::OwnedEncodedNote,
    public: [Val; 26],
    context: Context,
    plan: HandoffPlan,
    preparation: Reservation,
    handoff: Reservation,
}

/// The native encoding and original operation token stay alive through the
/// decoded artifact, including CPU verification and canonical packet borrows.
pub(in crate::note_gpu) struct RetainedProducer {
    native: core::OwnedEncodedNote,
    preparation: Reservation,
    handoff: Reservation,
}

impl RetainedProducer {
    pub(in crate::note_gpu) fn belongs_to(&self, token: &Reservation) -> bool {
        self.native.runtime_retired()
            && self.native.same_ledger(token)
            && self.preparation.same_ledger(token)
            && self.handoff.same_ledger(token)
    }
}

impl PreparedNote<'_> {
    /// Execute this one prepared research statement with fresh native proof
    /// randomness, then retire the exact owned Engine before returning output.
    /// The ordinary require_dispatch diagnostics remain unconditional refusals.
    ///
    /// # Safety
    /// Use only the dedicated immutable env-clear RTX 5080 worker whose fixed
    /// policy matches the core note qualification runtime. The external guard
    /// must enforce at most 47 GiB process, zero swap, 32 GiB worker host, 24 GiB
    /// native/output, 8 GiB managed GPU, 4 GiB context reserve and 8 threads.
    /// No other code may mutate environment variables or enter/start/retire a
    /// GPU runtime during this call. This includes parallel test execution.
    pub unsafe fn prove_owned_for_qualification(self) -> Result<ProducedNote, PreparationError> {
        let admission = Admission::reserve(&self)?;
        let Self {
            prepared,
            context,
            public,
            _reservation,
            ..
        } = self;
        // SAFETY: forwards the caller's explicit immutable guarded-worker
        // contract; every source-built owner was admitted before this call.
        let native = unsafe { prepared.prove_owned_for_qualification(admission.runtime) }
            .map_err(PreparationError::Core)?;
        if !native.runtime_retired()
            || native.public() != &public
            || !native.same_ledger(&_reservation)
            || !native.same_ledger(&admission.handoff)
        {
            return Err(PreparationError::Statement(Error::Statement));
        }
        Ok(ProducedNote {
            native,
            public,
            context,
            plan: admission.plan,
            preparation: _reservation,
            handoff: admission.handoff,
        })
    }
}

impl ProducedNote {
    pub fn runtime_retired(&self) -> bool {
        self.native.runtime_retired()
    }
    pub fn native_proof_bytes(&self) -> usize {
        self.native.encoded().len()
    }
    pub fn retained_operation_bytes(&self) -> usize {
        self.native.retained_operation_bytes()
    }
    pub fn proof_scope_ns(&self) -> u128 {
        self.native.proof_scope_ns()
    }

    /// This retired Engine's managed allocations only, excluding context,
    /// driver and other device storage measured by the external guard.
    pub fn managed_device_peak_bytes(&self) -> usize {
        self.native.managed_device_peak_bytes()
    }

    /// Preserve the PQNOTE1 envelope and existing bounded canonical decoder.
    /// The native proof is copied only through an immutable borrow while its
    /// original output charge stays retained inside the resulting artifact.
    pub fn into_decoded(mut self) -> Result<DecodedArtifact, Error> {
        if !self.native.runtime_retired()
            || self.native.public() != &self.public
            || !self.native.same_ledger(&self.handoff)
            || !self.preparation.same_ledger(&self.handoff)
        {
            return Err(Error::Statement);
        }
        let payload = self.native.encoded();
        if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
            return Err(Error::MalformedArtifact);
        }
        if self.handoff.reserved_bytes() < self.plan.total_bytes {
            return Err(Error::ResourceLimit);
        }
        let decoder = self.handoff.split_off(self.plan.decoder_bytes)?;
        let verification =
            codec::PreAdmittedScratch::new(self.handoff.split_off(self.plan.verifier_bytes)?);
        if self.handoff.reserved_bytes() < self.plan.inline_bytes {
            return Err(Error::ResourceLimit);
        }
        let length = add(ARTIFACT_HEADER_BYTES, payload.len())?;
        let mut packet = Vec::new();
        packet
            .try_reserve_exact(length)
            .map_err(|_| Error::ResourceLimit)?;
        if packet.capacity() != length {
            return Err(Error::ResourceLimit);
        }
        packet.extend_from_slice(MAGIC);
        packet.extend_from_slice(&self.context.0);
        for value in self.public {
            packet.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        }
        packet.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        packet.extend_from_slice(payload);
        let mut artifact = codec::decode_reserved(
            decoder,
            packet,
            self.public,
            self.context,
            self.plan.expected_capacity,
        )?;
        artifact.retain_producer(
            RetainedProducer {
                native: self.native,
                preparation: self.preparation,
                handoff: self.handoff,
            },
            verification,
        )?;
        Ok(artifact)
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
