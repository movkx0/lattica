//! Fixed seven-case private-note workflow, independent of RingCT aggregation.
//! The shared verification/roundtrip helper and fixed fixtures are identical
//! for the separately guarded fresh CPU and GPU research producers.
use super::{
    add, codec,
    fixtures::{Fixture, FixtureId, FixturePlan, CASE_COUNT},
    quota::{Reservation, LEDGER_BYTES},
    DecodeSession, DecodedArtifact, Error, Geometry, VerificationError, VerificationPlan,
    ARTIFACT_HEADER_BYTES, MAX_PROOF_BYTES, WORKER_HOST_BYTES,
};
use crate::Context;
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::{mem::size_of, time::Instant};

pub(in crate::note_gpu) mod cpu;
pub use cpu::CpuTimes;
const FIXTURE_RECIPE: &str = "seven-distinct-public-fixtures-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum WorkflowError {
    Admission(Error),
    Preparation(super::proving::PreparationError),
    Verification(VerificationError),
    Lifecycle,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CaseMeasurement {
    pub id: FixtureId,
    pub fixture_generation_ns: u128,
    pub public_preparation_ns: u128,
    pub native_dispatch_and_retirement_ns: u128,
    pub reported_native_proof_scope_ns: u128,
    pub canonical_handoff_decode_ns: u128,
    pub independent_cpu_verification_ns: u128,
    pub artifact_roundtrip_ns: u128,
    pub proof_payload_destruction_ns: u128,
    pub prepare_through_payload_cleanup_ns: u128,
    pub native_proof_bytes: usize,
    /// Exact retired Engine's managed allocation peak; absent for CPU cases.
    /// This excludes context/driver storage and is not a total VRAM peak.
    pub managed_device_peak_bytes: Option<usize>,
    pub public_statement_digest: [u8; 32],
    pub canonical_packet_hash: [u8; 32],
    pub cpu: CpuTimes,
}

#[derive(Debug, Serialize)]
pub struct WorkflowMeasurement {
    pub schema: &'static str,
    pub profile: &'static str,
    pub backend: &'static str,
    pub fixture_recipe: &'static str,
    pub cases: [CaseMeasurement; CASE_COUNT],
    pub fixture_generation_and_distinctness_ns: u128,
    pub complete_note_research_workflow_ns: u128,
    pub input_count_per_case: usize,
    pub output_count_per_case: usize,
    pub value_bits: usize,
    pub distinct_statements: usize,
    pub distinct_nullifiers: usize,
    pub native_proofs: usize,
    pub native_gpu_runtimes: usize,
    pub fresh_cpu_proof_configurations: usize,
    pub recursive_proofs: usize,
    pub active_rows_per_case: usize,
    pub padded_rows_per_case: usize,
    pub fresh_public_preparations: usize,
    pub independent_cpu_verifications: usize,
    pub canonical_roundtrips: usize,
    pub host_payload_reservation_peak_bytes: usize,
    /// Maximum of the seven sequential retired Engine peaks; absent for CPU.
    pub managed_device_peak_bytes: Option<usize>,
    pub report_retained_bytes: usize,
    pub actual_process_host_peak_bytes: Option<usize>,
    pub actual_process_device_peak_bytes: Option<usize>,
    pub external_guard_memory_telemetry_required: bool,
    pub all_native_runtimes_retired: bool,
    pub all_proof_payloads_destroyed: bool,
    pub complete_ringct_workflow: bool,
    pub recursive_aggregation_performed: bool,
    pub production_acceptance: bool,
    pub cpu_baseline_qualified: bool,
}

/// Report backing remains charged after every proof, fixture and runtime dies.
/// Publishing/serializing this report is outside both workflow timing bounds.
pub struct OwnedWorkflowReport {
    measurement: WorkflowMeasurement,
    reservation: Reservation,
}

impl OwnedWorkflowReport {
    pub fn measurement(&self) -> &WorkflowMeasurement {
        &self.measurement
    }
    pub fn quota_snapshot(&self) -> super::QuotaSnapshot {
        self.reservation.snapshot()
    }
}

#[derive(Clone, Copy)]
struct WorkflowPlan {
    report_bytes: usize,
}

impl WorkflowPlan {
    fn new() -> Result<Self, Error> {
        Geometry::pinned()?;
        let report_bytes = [
            size_of::<Self>(),
            size_of::<OwnedWorkflowReport>(),
            size_of::<WorkflowMeasurement>(),
            size_of::<[Option<CaseMeasurement>; CASE_COUNT]>(),
            size_of::<[CaseMeasurement; CASE_COUNT]>(),
            size_of::<CaseMeasurement>(),
            size_of::<DecodeSession>(),
            size_of::<FixturePlan>(),
            size_of::<VerificationPlan>(),
            size_of::<RoundtripAdmission>(),
            size_of::<CompletedArtifact>(),
            size_of::<Sha3_256>(),
            8 * size_of::<Instant>(),
            2 * size_of::<super::QuotaSnapshot>(),
            2 * size_of::<Reservation>(),
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        Ok(Self { report_bytes })
    }
}

/// The complete second decode/verifier capacity is acquired before native
/// dispatch. Each original token transfers into the exact roundtrip artifact;
/// no borrowed arbitrary numeric receipt authorizes packet allocation.
struct RoundtripAdmission {
    reservation: Reservation,
    decoder_bytes: usize,
    verifier_bytes: usize,
}

impl RoundtripAdmission {
    fn reserve(session: &DecodeSession, plan: &VerificationPlan) -> Result<Self, Error> {
        let decoder_bytes = codec::requirements_for(
            MAX_PROOF_BYTES,
            add(ARTIFACT_HEADER_BYTES, MAX_PROOF_BYTES)?,
            26,
            Geometry::pinned()?,
        )?
        .reserved_bytes;
        let verifier_bytes = plan.required_temporary_bytes();
        let reservation = session.reserve_for_producer(add(decoder_bytes, verifier_bytes)?)?;
        Ok(Self {
            reservation,
            decoder_bytes,
            verifier_bytes,
        })
    }

    fn restore(
        mut self,
        artifact: &DecodedArtifact,
        fixture: &Fixture,
    ) -> Result<DecodedArtifact, Error> {
        if !artifact.same_ledger(&self.reservation)
            || artifact.context() != fixture.statement().context
            || artifact.public()
                != &codec::expected_public(fixture.statement(), artifact.context())?
        {
            return Err(Error::Statement);
        }
        let decoder = self.reservation.split_off(self.decoder_bytes)?;
        let scratch =
            codec::PreAdmittedScratch::new(self.reservation.split_off(self.verifier_bytes)?);
        let original = artifact.canonical_packet();
        if original.len() <= ARTIFACT_HEADER_BYTES
            || original.len() > add(ARTIFACT_HEADER_BYTES, MAX_PROOF_BYTES)?
        {
            return Err(Error::MalformedArtifact);
        }
        // The preceding decoder token includes this full maximum packet.
        let mut packet = Vec::new();
        packet
            .try_reserve_exact(original.len())
            .map_err(|_| Error::ResourceLimit)?;
        if packet.capacity() != original.len() {
            return Err(Error::ResourceLimit);
        }
        packet.extend_from_slice(original);
        let mut restored =
            codec::decode_reserved(decoder, packet, *artifact.public(), artifact.context(), 26)?;
        restored.retain_verification(scratch)?;
        if restored.canonical_packet() != original {
            return Err(Error::MalformedArtifact);
        }
        Ok(restored)
    }
}

struct CompletedArtifact {
    verification_ns: u128,
    roundtrip_ns: u128,
    packet_hash: [u8; 32],
}

/// Stable case identity, independent of proof randomness and measurement time.
/// Recipe length is explicit, followed by its UTF-8 bytes,32 context bytes and
/// all26 canonical public values in fixed little-endian order.
fn statement_digest(fixture: &Fixture) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/research/private-note/workflow-statement/v1");
    hash.update((FIXTURE_RECIPE.len() as u64).to_le_bytes());
    hash.update(FIXTURE_RECIPE.as_bytes());
    hash.update(fixture.statement().context.0);
    for value in &fixture.statement().public {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

/// CPU and GPU producers must enter this identical bounded path. It consumes
/// the preceding roundtrip ownership and returns only fixed-size telemetry.
fn verify_and_roundtrip(
    artifact: &DecodedArtifact,
    fixture: &Fixture,
    verifier: &VerificationPlan,
    roundtrip: RoundtripAdmission,
) -> Result<CompletedArtifact, WorkflowError> {
    let before = roundtrip.reservation.snapshot();
    let verified = verifier
        .verify(artifact)
        .map_err(WorkflowError::Verification)?;
    let verification_ns = verified.receipt().cpu_verification_ns;
    drop(verified);
    if roundtrip.reservation.snapshot() != before {
        return Err(WorkflowError::Lifecycle);
    }
    let started = Instant::now();
    let restored = roundtrip
        .restore(artifact, fixture)
        .map_err(WorkflowError::Admission)?;
    let verified = verifier
        .verify(&restored)
        .map_err(WorkflowError::Verification)?;
    drop(verified);
    drop(restored);
    let roundtrip_ns = started.elapsed().as_nanos();
    let packet_hash = Sha3_256::digest(artifact.canonical_packet()).into();
    Ok(CompletedArtifact {
        verification_ns,
        roundtrip_ns,
        packet_hash,
    })
}

/// Seven distinct fresh private-note proofs, each with a fresh owned GPU
/// runtime and preparation, two independent CPU verifications and canonical
/// roundtrip. There is no transaction aggregate or production dispatch.
///
/// # Safety
/// Requires the same dedicated immutable env-clear RTX 5080 worker and exact
/// process, thread, host, device and zero-swap guard as
/// `PreparedNote::prove_owned_for_qualification`, for this entire function.
/// No concurrent GPU work or environment mutation is permitted. The caller
/// must retain and audit the external guard's actual process memory telemetry.
pub unsafe fn run_gpu_for_qualification(
    context: Context,
) -> Result<OwnedWorkflowReport, WorkflowError> {
    let complete = Instant::now();
    let geometry = Geometry::pinned().map_err(WorkflowError::Admission)?;
    let plan = WorkflowPlan::new().map_err(WorkflowError::Admission)?;
    let session = DecodeSession::new(WORKER_HOST_BYTES).map_err(WorkflowError::Admission)?;
    let report = session
        .reserve_for_producer(plan.report_bytes)
        .map_err(WorkflowError::Admission)?;
    let fixtures = session
        .research_fixtures(context)
        .map_err(WorkflowError::Admission)?;
    if !fixtures.same_ledger(&report) {
        return Err(WorkflowError::Lifecycle);
    }
    let fixture_receipt = fixtures.receipt();
    if fixture_receipt.source != FIXTURE_RECIPE {
        return Err(WorkflowError::Lifecycle);
    }
    let verifier = VerificationPlan::new().map_err(WorkflowError::Verification)?;
    let baseline = session.snapshot().live_reserved_bytes;
    let mut cases = [None; CASE_COUNT];
    for fixture in fixtures.iter() {
        let case_started = Instant::now();
        let roundtrip =
            RoundtripAdmission::reserve(&session, &verifier).map_err(WorkflowError::Admission)?;
        let started = Instant::now();
        let prepared = session
            .prepare_note(fixture.witness(), fixture.statement(), context)
            .map_err(WorkflowError::Preparation)?;
        let public_preparation_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        // SAFETY: forwards the explicit fixed external worker contract. Both
        // decoder/verifier paths have original tokens before first device use.
        let produced = unsafe { prepared.prove_owned_for_qualification() }
            .map_err(WorkflowError::Preparation)?;
        let native_dispatch_and_retirement_ns = started.elapsed().as_nanos();
        if !produced.runtime_retired() {
            return Err(WorkflowError::Lifecycle);
        }
        let reported_native_proof_scope_ns = produced.proof_scope_ns();
        let native_proof_bytes = produced.native_proof_bytes();
        let managed_device_peak_bytes = Some(produced.managed_device_peak_bytes());
        let started = Instant::now();
        let artifact = produced.into_decoded().map_err(WorkflowError::Admission)?;
        let canonical_handoff_decode_ns = started.elapsed().as_nanos();
        let verified = verify_and_roundtrip(&artifact, fixture, &verifier, roundtrip)?;
        let started = Instant::now();
        drop(artifact);
        let proof_payload_destruction_ns = started.elapsed().as_nanos();
        if session.snapshot().live_reserved_bytes != baseline {
            return Err(WorkflowError::Lifecycle);
        }
        cases[fixture.id().ordinal()] = Some(CaseMeasurement {
            id: fixture.id(),
            fixture_generation_ns: fixture.generation_ns(),
            public_preparation_ns,
            native_dispatch_and_retirement_ns,
            reported_native_proof_scope_ns,
            canonical_handoff_decode_ns,
            independent_cpu_verification_ns: verified.verification_ns,
            artifact_roundtrip_ns: verified.roundtrip_ns,
            proof_payload_destruction_ns,
            prepare_through_payload_cleanup_ns: case_started.elapsed().as_nanos(),
            native_proof_bytes,
            managed_device_peak_bytes,
            public_statement_digest: statement_digest(fixture),
            canonical_packet_hash: verified.packet_hash,
            cpu: CpuTimes::NONE,
        });
    }
    let cases = cases.map(|case| case.expect("fixed seven successful cases"));
    for (i, case) in cases.iter().enumerate() {
        if cases[..i]
            .iter()
            .any(|prior| prior.canonical_packet_hash == case.canonical_packet_hash)
        {
            return Err(WorkflowError::Lifecycle);
        }
    }
    drop(fixtures);
    let snapshot = session.snapshot();
    if snapshot.live_reserved_bytes != LEDGER_BYTES + plan.report_bytes {
        return Err(WorkflowError::Lifecycle);
    }
    drop(session);
    let complete_note_research_workflow_ns = complete.elapsed().as_nanos();
    Ok(OwnedWorkflowReport {
        measurement: WorkflowMeasurement {
            schema: "lattica-private-note-research-seven-workflow-v2",
            profile: crate::Profile::PrivateNoteDirectV1.tag(),
            backend: "fresh_gpu_required",
            fixture_recipe: FIXTURE_RECIPE,
            managed_device_peak_bytes: cases
                .iter()
                .filter_map(|case| case.managed_device_peak_bytes)
                .max(),
            cases,
            fixture_generation_and_distinctness_ns: fixture_receipt.generation_and_distinctness_ns,
            complete_note_research_workflow_ns,
            input_count_per_case: geometry.inputs,
            output_count_per_case: geometry.outputs,
            value_bits: geometry.value_bits,
            distinct_statements: fixture_receipt.distinct_statements,
            distinct_nullifiers: fixture_receipt.distinct_nullifiers,
            native_proofs: CASE_COUNT,
            native_gpu_runtimes: CASE_COUNT,
            fresh_cpu_proof_configurations: 0,
            recursive_proofs: 0,
            active_rows_per_case: geometry.active_rows,
            padded_rows_per_case: geometry.padded_rows,
            fresh_public_preparations: CASE_COUNT,
            independent_cpu_verifications: 2 * CASE_COUNT,
            canonical_roundtrips: CASE_COUNT,
            host_payload_reservation_peak_bytes: snapshot.peak_reserved_bytes,
            report_retained_bytes: plan.report_bytes,
            actual_process_host_peak_bytes: None,
            actual_process_device_peak_bytes: None,
            external_guard_memory_telemetry_required: true,
            all_native_runtimes_retired: true,
            all_proof_payloads_destroyed: true,
            complete_ringct_workflow: false,
            recursive_aggregation_performed: false,
            production_acceptance: false,
            cpu_baseline_qualified: false,
        },
        reservation: report,
    })
}

/// The same seven statements, generation/admission boundary, canonical decoder,
/// two independent verifications per case, roundtrips and destruction checks
/// as run_gpu_for_qualification, with a fresh concrete CPU config per proof.
/// This proves standalone research notes; it performs no recursive aggregate.
///
/// # Safety
/// Requires the coordinator's dedicated immutable env-clear CPU-required
/// worker with at most47GiB process,32GiB worker host,24GiB native/output,
/// zero swap and exactly8 Rayon threads for this entire interval. No tracing
/// subscriber or concurrent benchmark may be installed. Policy must be
/// LATTICA_PROVING_POLICY=cpu-required. This entry does not inspect GPU devices,
/// construct OpenCL state or arm a spill scope. Its exact MyConfig fixes CPU
/// execution independently of environment-selected proving wrappers.
pub unsafe fn run_cpu_for_qualification(
    context: Context,
) -> Result<OwnedWorkflowReport, WorkflowError> {
    let complete = Instant::now();
    let geometry = Geometry::pinned().map_err(WorkflowError::Admission)?;
    let plan = WorkflowPlan::new().map_err(WorkflowError::Admission)?;
    let session = DecodeSession::new(WORKER_HOST_BYTES).map_err(WorkflowError::Admission)?;
    let report = session
        .reserve_for_producer(plan.report_bytes)
        .map_err(WorkflowError::Admission)?;
    let fixtures = session
        .research_fixtures(context)
        .map_err(WorkflowError::Admission)?;
    if !fixtures.same_ledger(&report) {
        return Err(WorkflowError::Lifecycle);
    }
    let fixture_receipt = fixtures.receipt();
    if fixture_receipt.source != FIXTURE_RECIPE {
        return Err(WorkflowError::Lifecycle);
    }
    let verifier = VerificationPlan::new().map_err(WorkflowError::Verification)?;
    let baseline = session.snapshot().live_reserved_bytes;
    let mut cases = [None; CASE_COUNT];
    for fixture in fixtures.iter() {
        let case_started = Instant::now();
        let roundtrip =
            RoundtripAdmission::reserve(&session, &verifier).map_err(WorkflowError::Admission)?;
        let started = Instant::now();
        let prepared = cpu::CpuPrepared::reserve(&session, fixture, context)
            .map_err(WorkflowError::Admission)?;
        let public_preparation_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        let produced = prepared.prove()?;
        let native_dispatch_and_retirement_ns = started.elapsed().as_nanos();
        let cpu = produced.times();
        let native_proof_bytes = produced.native_proof_bytes();
        let started = Instant::now();
        let artifact = produced.into_decoded().map_err(WorkflowError::Admission)?;
        let canonical_handoff_decode_ns = started.elapsed().as_nanos();
        let verified = verify_and_roundtrip(&artifact, fixture, &verifier, roundtrip)?;
        let started = Instant::now();
        drop(artifact);
        let proof_payload_destruction_ns = started.elapsed().as_nanos();
        if session.snapshot().live_reserved_bytes != baseline {
            return Err(WorkflowError::Lifecycle);
        }
        cases[fixture.id().ordinal()] = Some(CaseMeasurement {
            id: fixture.id(),
            fixture_generation_ns: fixture.generation_ns(),
            public_preparation_ns,
            native_dispatch_and_retirement_ns,
            reported_native_proof_scope_ns: cpu.proof_ns,
            canonical_handoff_decode_ns,
            independent_cpu_verification_ns: verified.verification_ns,
            artifact_roundtrip_ns: verified.roundtrip_ns,
            proof_payload_destruction_ns,
            prepare_through_payload_cleanup_ns: case_started.elapsed().as_nanos(),
            native_proof_bytes,
            managed_device_peak_bytes: None,
            public_statement_digest: statement_digest(fixture),
            canonical_packet_hash: verified.packet_hash,
            cpu,
        });
    }
    let cases = cases.map(|case| case.expect("fixed seven successful CPU cases"));
    for (i, case) in cases.iter().enumerate() {
        if cases[..i].iter().any(|prior| {
            prior.canonical_packet_hash == case.canonical_packet_hash
                || prior.public_statement_digest == case.public_statement_digest
        }) {
            return Err(WorkflowError::Lifecycle);
        }
    }
    drop(fixtures);
    let snapshot = session.snapshot();
    if snapshot.live_reserved_bytes != LEDGER_BYTES + plan.report_bytes {
        return Err(WorkflowError::Lifecycle);
    }
    drop(session);
    let complete_note_research_workflow_ns = complete.elapsed().as_nanos();
    Ok(OwnedWorkflowReport {
        measurement: WorkflowMeasurement {
            schema: "lattica-private-note-research-seven-workflow-v2",
            profile: crate::Profile::PrivateNoteDirectV1.tag(),
            backend: "fresh_cpu_required",
            fixture_recipe: FIXTURE_RECIPE,
            managed_device_peak_bytes: None,
            cases,
            fixture_generation_and_distinctness_ns: fixture_receipt.generation_and_distinctness_ns,
            complete_note_research_workflow_ns,
            input_count_per_case: geometry.inputs,
            output_count_per_case: geometry.outputs,
            value_bits: geometry.value_bits,
            distinct_statements: fixture_receipt.distinct_statements,
            distinct_nullifiers: fixture_receipt.distinct_nullifiers,
            native_proofs: CASE_COUNT,
            native_gpu_runtimes: 0,
            fresh_cpu_proof_configurations: CASE_COUNT,
            recursive_proofs: 0,
            active_rows_per_case: geometry.active_rows,
            padded_rows_per_case: geometry.padded_rows,
            fresh_public_preparations: CASE_COUNT,
            independent_cpu_verifications: 2 * CASE_COUNT,
            canonical_roundtrips: CASE_COUNT,
            host_payload_reservation_peak_bytes: snapshot.peak_reserved_bytes,
            report_retained_bytes: plan.report_bytes,
            actual_process_host_peak_bytes: None,
            actual_process_device_peak_bytes: None,
            external_guard_memory_telemetry_required: true,
            all_native_runtimes_retired: true,
            all_proof_payloads_destroyed: true,
            complete_ringct_workflow: false,
            recursive_aggregation_performed: false,
            production_acceptance: false,
            cpu_baseline_qualified: true,
        },
        reservation: report,
    })
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
