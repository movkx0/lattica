//! Private fixed-fixture CPU producer for the matched seven-note experiment.
//! No arbitrary AIR, proof bytes, RNG seed, callback or dispatch fallback.
use super::*;
use crate::note_gpu::{mul, verification, Challenge, MyConfig, Proof, Val, MAGIC};
use p3_field::PrimeField64;

mod plan;
#[cfg(all(test, not(debug_assertions)))]
mod tests;

use plan::CpuPlan;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CpuTimes {
    pub fresh_configuration_ns: u128,
    pub trace_generation_ns: u128,
    pub proof_ns: u128,
    pub canonical_encoding_ns: u128,
    pub configuration_and_proof_cleanup_ns: u128,
}

impl CpuTimes {
    pub(super) const NONE: Self = Self {
        fresh_configuration_ns: 0,
        trace_generation_ns: 0,
        proof_ns: 0,
        canonical_encoding_ns: 0,
        configuration_and_proof_cleanup_ns: 0,
    };
}

pub(super) struct CpuPrepared<'a> {
    fixture: &'a Fixture,
    public: [Val; 26],
    context: Context,
    plan: CpuPlan,
    reservation: Reservation,
}

/// Encoded output and its original complete operation token have no owned
/// accessor or Clone. Both move directly into the canonical decoded artifact.
pub(super) struct CpuProduced {
    encoded: Vec<u8>,
    public: [Val; 26],
    context: Context,
    plan: CpuPlan,
    times: CpuTimes,
    reservation: Reservation,
}

pub(in crate::note_gpu) struct RetainedCpuProducer {
    encoded: Vec<u8>,
    reservation: Reservation,
}

impl RetainedCpuProducer {
    pub(in crate::note_gpu) fn belongs_to(&self, token: &Reservation) -> bool {
        !self.encoded.is_empty()
            && self.encoded.len() <= MAX_PROOF_BYTES
            && self.reservation.same_ledger(token)
    }
}

impl<'a> CpuPrepared<'a> {
    pub(super) fn reserve(
        session: &DecodeSession,
        fixture: &'a Fixture,
        context: Context,
    ) -> Result<Self, Error> {
        let plan = CpuPlan::new()?;
        // Atomic complete continuation, before public parsing/configuration,
        // trace construction, fresh entropy or any proof arithmetic.
        let reservation = session.reserve_for_producer(plan.total_bytes)?;
        let public = codec::expected_public(fixture.statement(), context)?;
        Ok(Self {
            fixture,
            public,
            context,
            plan,
            reservation,
        })
    }

    pub(super) fn prove(self) -> Result<CpuProduced, WorkflowError> {
        let started = Instant::now();
        // Exactly the independent verifier's MyConfig, including original
        // hiding,96queries,16bit query POW and FRI max log arity4. Its two
        // ChaCha RNGs are independently seeded from SysRng on every call.
        let config = verification::fresh_config().map_err(WorkflowError::Verification)?;
        let fresh_configuration_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        let trace = lattica_prover_p3::joinsplit_air::build_trace(self.fixture.witness());
        let trace_generation_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        // This concrete CPU MyConfig uses Radix2DitParallel and CPU hiding
        // MMCS. It has no environment-selected GPU implementation or retry.
        let proof = p3_uni_stark::prove(
            &config,
            &verification::air::VerifierAir,
            trace,
            &self.public,
        );
        let proof_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        let length = postcard::experimental::serialized_size(&proof)
            .map_err(|_| WorkflowError::Admission(Error::MalformedArtifact))?;
        if length == 0 || length > MAX_PROOF_BYTES {
            return Err(WorkflowError::Admission(Error::ResourceLimit));
        }
        // Size counting and serialization allocate no hidden growing buffer.
        // The maximum output was charged before this exact-capacity request.
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| WorkflowError::Admission(Error::ResourceLimit))?;
        if encoded.capacity() != length {
            return Err(WorkflowError::Admission(Error::ResourceLimit));
        }
        encoded.resize(length, 0);
        let written = postcard::to_slice(&proof, &mut encoded)
            .map_err(|_| WorkflowError::Admission(Error::MalformedArtifact))?;
        if written.len() != length {
            return Err(WorkflowError::Admission(Error::MalformedArtifact));
        }
        let canonical_encoding_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        drop(proof);
        drop(config);
        let configuration_and_proof_cleanup_ns = started.elapsed().as_nanos();
        Ok(CpuProduced {
            encoded,
            public: self.public,
            context: self.context,
            plan: self.plan,
            times: CpuTimes {
                fresh_configuration_ns,
                trace_generation_ns,
                proof_ns,
                canonical_encoding_ns,
                configuration_and_proof_cleanup_ns,
            },
            reservation: self.reservation,
        })
    }
}

impl CpuProduced {
    pub(super) fn native_proof_bytes(&self) -> usize {
        self.encoded.len()
    }
    pub(super) fn times(&self) -> CpuTimes {
        self.times
    }
    pub(super) fn into_decoded(mut self) -> Result<DecodedArtifact, Error> {
        if self.encoded.is_empty()
            || self.encoded.len() > MAX_PROOF_BYTES
            || self.reservation.reserved_bytes() != self.plan.total_bytes
        {
            return Err(Error::ResourceLimit);
        }
        let decoder = self.reservation.split_off(self.plan.decoder_bytes)?;
        let verifier =
            codec::PreAdmittedScratch::new(self.reservation.split_off(self.plan.verifier_bytes)?);
        if self.reservation.reserved_bytes()
            != add(self.plan.operation_bytes, self.plan.handoff_inline_bytes)?
        {
            return Err(Error::ResourceLimit);
        }
        let length = add(ARTIFACT_HEADER_BYTES, self.encoded.len())?;
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
        packet.extend_from_slice(&(self.encoded.len() as u64).to_le_bytes());
        packet.extend_from_slice(&self.encoded);
        let mut artifact = codec::decode_reserved(decoder, packet, self.public, self.context, 26)?;
        artifact.retain_cpu_producer(
            RetainedCpuProducer {
                encoded: self.encoded,
                reservation: self.reservation,
            },
            verifier,
        )?;
        Ok(artifact)
    }
}
