//! One opaque public-identity receipt across two fully retired GPU sessions.
//!
//! This is a research-only one-shot transfer, not a prepared-program cache.
//! The receipt is never decoded from an artifact or reconstructed from its ID.
//! The core always fingerprints the complete independently rebuilt identity
//! stream, including the freshly computed preprocessing cap, before a hit.
use super::{artifact, proving, CompilerRepresentation, Context, Error, Statement};
use artifact::ProofDescriptor;
use lattica_pq_ringct_research::opencl::Session;
use lattica_prover_p3::block_v2::{
    gpu_hash::PublicHashExecution,
    machine::backend::{RegisteredIdentityReceipt, RegisteredProgram},
};
use p3_field::PrimeField64;
use serde::Serialize;
use sha3::{Digest, Sha3_512};
use std::{mem::size_of, time::Instant};

pub(crate) const PROFILE: &str = "direct-ring-cross-session-identity-receipt-v1";
pub(crate) const METADATA_LIMIT_BYTES: usize = 64 << 20;
pub(crate) const RECEIPT_LIMIT_BYTES: usize = 1 << 20;
const DEVICE_DOMAIN: &[u8] = b"lattica/research/direct-ring/identity-device/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expected {
    context: [u8; 32],
    public: [u64; 4],
    profile: [u8; 32],
}

impl Expected {
    fn new(
        statement: &Statement,
        context: Context,
        representation: CompilerRepresentation,
    ) -> Result<Self, Error> {
        if statement.context != context {
            return Err(Error::Context);
        }
        if representation != CompilerRepresentation::FusedTernaryRangesV1 {
            return Err(Error::Profile);
        }
        Ok(Self {
            context: context.0,
            public: artifact::statement_binding(statement).map(|value| value.as_canonical_u64()),
            profile: artifact::profile_digest(representation),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Captured,
    Retired,
    Attempted,
    Refused,
}

/// Only the guarded research workflow constructs this owner. It is non-Clone
/// and has no serialized representation, heap allocation, runtime or GPU handle.
pub(crate) struct Transfer {
    expected: Expected,
    descriptor: Option<ProofDescriptor>,
    receipt: Option<RegisteredIdentityReceipt>,
    device: [u8; 64],
    phase: Phase,
    captured: Option<Instant>,
    original_public_hash: Option<PublicHashExecution>,
}

/// Bounded provenance of reused public computation. Native stage reports remain
/// the authority for the GPU work actually performed by each registration.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct ReuseReport {
    pub profile: &'static str,
    pub identity_hint_hit: bool,
    pub full_identity_stream_checked: bool,
    pub public_preprocessing_reused: bool,
    pub reused_part: &'static str,
    pub fresh_preprocessing_cap: bool,
    pub prepared_program_reused: bool,
    pub proof_reused: bool,
    pub fresh_identity_gpu_hash: bool,
    pub prover_session_retired_before_verifier_start: bool,
    pub expected_statement_reconstructed: bool,
    pub lookup_digest: &'static str,
    pub receipt_payload_bytes: usize,
    pub source_admitted_host_bytes: usize,
    pub receipt_sublimit_bytes: usize,
    pub combined_metadata_limit_bytes: usize,
    pub idle_device_bytes: usize,
    pub receipt_retained_after_setup_bytes: usize,
    pub reuse_distance_registrations: usize,
    pub receipt_lifetime_ns: u128,
    pub registered_program_id: [u64; 4],
    pub source_public_hash: PublicHashExecution,
    pub verifier_fresh_public_hash: Option<PublicHashExecution>,
}

// This policy is independent of the opaque telemetry payload: even metadata
// identical to the retired prover's observation is fresh work in the verifier's
// new engine lifetime. A successful receipt report requires an absent fresh
// observation, not merely a matching kernel/capability description.
fn checked_identity_provenance<T>(source: Option<T>, fresh: Option<T>) -> Result<T, Error> {
    if fresh.is_some() {
        return Err(Error::Profile);
    }
    source.ok_or(Error::Profile)
}

/// Additive source/move/report/hasher storage, charged by the surrounding screen
/// inside the existing 1 MiB caller charge, separately from its 32 KiB
/// orchestration slice. These limits are intersected, never added together.
/// The complete charge also fits the unchanged receipt/metadata cache ceilings.
pub(crate) fn source_host_bytes() -> Result<usize, Error> {
    let mut bytes = 0usize;
    for (count, size) in [
        // Sum all bounded move sites, even when LLVM can overlap/elide them.
        // Owning enum/result slots are separate full sizes; do not assume a
        // niche layout or hide their payload/discriminant in generic spare.
        (6, size_of::<Transfer>()),
        (8, size_of::<Option<Transfer>>()),
        (4, size_of::<Result<Transfer, Error>>()),
        // Standalone clone/core-return/drop temporaries are additional to the
        // receipt stored inline in each Transfer/owning-enum slot above.
        (4, size_of::<RegisteredIdentityReceipt>()),
        (4, size_of::<Option<RegisteredIdentityReceipt>>()),
        (8, size_of::<Option<&mut Transfer>>()),
        (4, size_of::<Result<&RegisteredIdentityReceipt, Error>>()),
        (8, size_of::<ReuseReport>()),
        (8, size_of::<Option<ReuseReport>>()),
        (4, size_of::<Result<ReuseReport, Error>>()),
        // Source/fresh arguments and returned provenance from the completion
        // policy are additional to the fields inside Transfer/ReuseReport.
        (4, size_of::<PublicHashExecution>()),
        (4, size_of::<Option<PublicHashExecution>>()),
        (4, size_of::<&Option<PublicHashExecution>>()),
        (4, size_of::<Result<PublicHashExecution, Error>>()),
        (4, size_of::<Expected>()),
        (4, size_of::<Result<Expected, Error>>()),
        (4, size_of::<ProofDescriptor>()),
        (4, size_of::<Sha3_512>()),
        (4, size_of::<[u8; 64]>()),
        (4, size_of::<Result<[u8; 64], Error>>()),
        (8, size_of::<Result<(), Error>>()),
        (4, size_of::<Instant>()),
    ] {
        bytes = size
            .checked_mul(count)
            .and_then(|n| bytes.checked_add(n))
            .ok_or(Error::ResourceLimit)?;
    }
    check_budget(bytes, RECEIPT_LIMIT_BYTES, METADATA_LIMIT_BYTES)?;
    Ok(bytes)
}

fn check_budget(bytes: usize, receipt: usize, metadata: usize) -> Result<(), Error> {
    if receipt > RECEIPT_LIMIT_BYTES
        || metadata > METADATA_LIMIT_BYTES
        || receipt > metadata
        || bytes > receipt
        || bytes > metadata
    {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

fn device_binding(session: &Session) -> Result<[u8; 64], Error> {
    device_identity_binding(session.device_identity())
}

fn device_identity_binding(
    device: &lattica_prover_p3::gpu_device::Identity,
) -> Result<[u8; 64], Error> {
    let uuid = device.uuid.as_deref().ok_or(Error::Profile)?;
    if uuid.is_empty() {
        return Err(Error::Profile);
    }
    let mut hash = Sha3_512::new();
    hash.update(DEVICE_DOMAIN);
    for value in [
        device.opencl_index as u64,
        device.global_bytes,
        device.max_allocation_bytes,
    ] {
        hash.update(value.to_le_bytes());
    }
    for value in [
        Some(uuid),
        Some(device.name.as_str()),
        device.pci.as_deref(),
        Some(device.driver.as_str()),
    ] {
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            if value.len() > 256 {
                return Err(Error::ResourceLimit);
            }
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
    }
    Ok(hash.finalize().into())
}

impl Transfer {
    pub(super) fn refuse(&mut self) {
        self.receipt = None;
        self.descriptor = None;
        self.original_public_hash = None;
        self.captured = None;
        self.phase = Phase::Refused;
    }

    #[cfg(feature = "gpu-identity-reuse-experiment")]
    pub(crate) fn new(
        statement: &Statement,
        context: Context,
        representation: CompilerRepresentation,
    ) -> Result<Self, Error> {
        proving::admit_identity_caller(statement)?;
        Ok(Self {
            expected: Expected::new(statement, context, representation)?,
            descriptor: None,
            receipt: None,
            device: [0; 64],
            phase: Phase::Empty,
            captured: None,
            original_public_hash: None,
        })
    }

    pub(super) fn check_expected(
        &self,
        statement: &Statement,
        context: Context,
        representation: CompilerRepresentation,
    ) -> Result<(), Error> {
        if self.phase != Phase::Retired
            || self.expected != Expected::new(statement, context, representation)?
        {
            return Err(Error::Profile);
        }
        Ok(())
    }

    pub(super) fn check_prover_inputs(
        &self,
        statement: &Statement,
        context: Context,
    ) -> Result<(), Error> {
        if self.phase != Phase::Empty
            || self.expected
                != Expected::new(
                    statement,
                    context,
                    CompilerRepresentation::FusedTernaryRangesV1,
                )?
        {
            return Err(Error::Profile);
        }
        Ok(())
    }

    pub(super) fn capture(
        &mut self,
        registered: &RegisteredProgram,
        descriptor: ProofDescriptor,
        session: &Session,
    ) -> Result<(), Error> {
        if self.phase != Phase::Empty
            || self.receipt.is_some()
            || registered.identity_hint_hit()
            || descriptor.registered_program_id != registered.id()
        {
            return Err(Error::Profile);
        }
        let receipt = registered
            .identity_receipt()
            .ok_or(Error::IncompleteProofCoverage)?;
        if receipt.accounted_bytes() != size_of::<RegisteredIdentityReceipt>() {
            return Err(Error::ResourceLimit);
        }
        self.device = device_binding(session)?;
        self.descriptor = Some(descriptor);
        self.receipt = Some(receipt.clone());
        self.captured = Some(Instant::now());
        self.phase = Phase::Captured;
        Ok(())
    }

    pub(super) fn retire_prover(
        &mut self,
        terminal: proving::TerminalReceipt,
        public_hash: PublicHashExecution,
    ) -> Result<(), Error> {
        if self.phase != Phase::Captured
            || !terminal.context_closed
            || !terminal.queue_drained
            || !terminal.completion_claimed
            || terminal.managed_peak_bytes > 8 << 30
            || terminal.device_allowance_bytes != 8 << 30
            || terminal.host_allowance_bytes != 32 << 30
            || terminal.gpu_context_allowance_bytes != 4 << 30
            || terminal.max_rows != 1 << 20
        {
            return Err(Error::IncompleteProofCoverage);
        }
        self.original_public_hash = Some(public_hash);
        self.phase = Phase::Retired;
        Ok(())
    }

    pub(super) fn check_reconstructed(&self, mut descriptor: ProofDescriptor) -> Result<(), Error> {
        let mut expected = self.descriptor.ok_or(Error::Profile)?;
        // The numeric artifact/old ID grants no authority. The core computes or
        // validates it only after the new cap and complete stream fingerprint.
        expected.registered_program_id = [0; 4];
        descriptor.registered_program_id = [0; 4];
        if self.phase != Phase::Retired || expected != descriptor {
            return Err(Error::Profile);
        }
        Ok(())
    }

    pub(super) fn hint(&mut self, session: &Session) -> Result<&RegisteredIdentityReceipt, Error> {
        if self.phase != Phase::Retired {
            return Err(Error::Profile);
        }
        self.phase = Phase::Attempted;
        if self.device != device_binding(session)? {
            return Err(Error::Profile);
        }
        self.receipt.as_ref().ok_or(Error::Profile)
    }

    pub(super) fn finish(
        mut self,
        registered: &RegisteredProgram,
        fresh_public_hash: Option<PublicHashExecution>,
    ) -> Result<ReuseReport, Error> {
        let source_public_hash =
            checked_identity_provenance(self.original_public_hash, fresh_public_hash)?;
        if self.phase != Phase::Attempted
            || !registered.identity_hint_hit()
            || self.descriptor.ok_or(Error::Profile)?.registered_program_id != registered.id()
        {
            // A core mismatch may compute the ordinary GPU hash, but this
            // experiment refuses that miss; it never records a successful warm
            // case or retries registration after an attempted dispatch.
            return Err(Error::Profile);
        }
        let payload = self
            .receipt
            .as_ref()
            .ok_or(Error::Profile)?
            .accounted_bytes();
        drop(self.receipt.take());
        Ok(ReuseReport {
            profile: PROFILE,
            identity_hint_hit: true,
            full_identity_stream_checked: true,
            public_preprocessing_reused: true,
            reused_part: "protocol-program-identity-only",
            fresh_preprocessing_cap: true,
            prepared_program_reused: false,
            proof_reused: false,
            fresh_identity_gpu_hash: false,
            prover_session_retired_before_verifier_start: true,
            expected_statement_reconstructed: true,
            lookup_digest: "sha3-512-over-complete-canonical-identity-stream-v1",
            receipt_payload_bytes: payload,
            source_admitted_host_bytes: source_host_bytes()?,
            receipt_sublimit_bytes: RECEIPT_LIMIT_BYTES,
            combined_metadata_limit_bytes: METADATA_LIMIT_BYTES,
            idle_device_bytes: 0,
            receipt_retained_after_setup_bytes: 0,
            reuse_distance_registrations: 0,
            receipt_lifetime_ns: self.captured.ok_or(Error::Profile)?.elapsed().as_nanos(),
            registered_program_id: registered.id(),
            source_public_hash,
            verifier_fresh_public_hash: fresh_public_hash,
        })
    }
}

#[cfg(test)]
mod tests;
