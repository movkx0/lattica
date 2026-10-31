//! Fixed-profile inventory and explicit gaps in complete lifetime admission.
//! Known payload bounds and necessary device storage are not promoted to peaks.
use super::*;
use crate::{note, Context};
use lattica_prover_p3::{config, joinsplit_air as js};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Limits {
    pub worker_host_bytes: usize,
    pub managed_device_bytes: usize,
    pub context_device_bytes: usize,
    pub native_host_bytes: usize,
    pub process_host_bytes: usize,
    pub swap_bytes: usize,
    pub max_rows: usize,
}

impl Limits {
    pub const fn campaign() -> Self {
        Self {
            worker_host_bytes: WORKER_HOST_BYTES,
            managed_device_bytes: MANAGED_DEVICE_BYTES,
            context_device_bytes: CONTEXT_DEVICE_BYTES,
            native_host_bytes: NATIVE_HOST_BYTES,
            process_host_bytes: PROCESS_HOST_BYTES,
            swap_bytes: 0,
            max_rows: MAX_ROWS,
        }
    }

    fn check(self) -> Result<(), Error> {
        if self.worker_host_bytes == 0
            || self.worker_host_bytes > WORKER_HOST_BYTES
            || self.managed_device_bytes == 0
            || self.managed_device_bytes > MANAGED_DEVICE_BYTES
            || self.context_device_bytes != CONTEXT_DEVICE_BYTES
            || self.native_host_bytes == 0
            || self.native_host_bytes > NATIVE_HOST_BYTES
            || self.native_host_bytes > self.worker_host_bytes
            || self.process_host_bytes == 0
            || self.process_host_bytes > PROCESS_HOST_BYTES
            || self.process_host_bytes < self.worker_host_bytes
            || self.swap_bytes != 0
            || !self.max_rows.is_power_of_two()
            || !(js::HEIGHT..=MAX_ROWS).contains(&self.max_rows)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Geometry {
    pub inputs: usize,
    pub outputs: usize,
    pub value_bits: usize,
    pub membership_depth: usize,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub trace_columns: usize,
    pub periodic_columns: usize,
    pub public_values: usize,
    pub challenge_degree: usize,
    pub degree_bits: usize,
    pub log_blowup: usize,
    pub queries: usize,
    pub max_log_fri_arity: usize,
    pub cap_height: usize,
    pub random_codewords: usize,
    pub query_pow_bits: usize,
    pub quotient_chunks: usize,
}

impl Geometry {
    pub fn pinned() -> Result<Self, Error> {
        // Native coefficients/types and every exposed legacy constant must
        // match the reviewed fixed profile. No untrusted artifact selects it.
        if core::mem::size_of::<usize>() != 8
            || (js::N_IN, js::M_OUT, js::BITS, js::DEPTH) != (2, 2, 52, 32)
            || (js::HEIGHT, js::WIDTH, js::N_PERIODIC, js::N_PUBLIC) != (4096, 19, 33, 26)
            || (config::LOG_BLOWUP, config::NUM_QUERIES, config::CAP_HEIGHT) != (4, 96, 6)
            || (config::NUM_RANDOM_CODEWORDS, config::QUERY_POW_BITS) != (4, 16)
            || core::mem::size_of::<Val>() != 8
            || core::mem::size_of::<Challenge>() != 16
        {
            return Err(Error::Geometry);
        }
        Ok(Self {
            inputs: 2,
            outputs: 2,
            value_bits: 52,
            membership_depth: 32,
            active_rows: (2 * (4 + 32) + 2 * 2 + 2 + 2) * 32,
            padded_rows: js::HEIGHT,
            trace_columns: js::WIDTH,
            periodic_columns: js::N_PERIODIC,
            public_values: js::N_PUBLIC,
            challenge_degree: 2,
            degree_bits: js::HEIGHT.ilog2() as usize + 1,
            log_blowup: config::LOG_BLOWUP,
            queries: config::NUM_QUERIES,
            // config::production_fri pins this literal. The reviewed legacy
            // AIR has constraint degree 8, hence 2*8 hiding quotient chunks.
            max_log_fri_arity: 4,
            cap_height: config::CAP_HEIGHT,
            random_codewords: config::NUM_RANDOM_CODEWORDS,
            query_pow_bits: config::QUERY_POW_BITS,
            quotient_chunks: 16,
        })
    }

    pub fn decoded_backing_ceiling_bytes(self) -> Result<usize, Error> {
        if self != Self::pinned()? {
            return Err(Error::Geometry);
        }
        shape::backing_ceiling(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingBound {
    CompleteProverHostLifetime,
    CompleteRandomnessStreamLifetime,
    IndependentCpuVerifierLifetime,
    ExternalProcessAndThreadAdmission,
    CurrentSourceGpuQualification,
}
const MISSING: [MissingBound; 5] = [
    MissingBound::CompleteProverHostLifetime,
    MissingBound::CompleteRandomnessStreamLifetime,
    MissingBound::IndependentCpuVerifierLifetime,
    MissingBound::ExternalProcessAndThreadAdmission,
    MissingBound::CurrentSourceGpuQualification,
];

#[derive(Debug, Serialize)]
pub struct AdmissionDiagnostic {
    schema: &'static str,
    profile: &'static str,
    proof_profile: &'static str,
    geometry: Geometry,
    limits: Limits,
    caller_statement_backing_bytes: usize,
    witness_inline_bytes: usize,
    packed_witness_staging_bytes: usize,
    public_readback_bytes: usize,
    raw_trace_device_bytes: usize,
    periodic_input_device_bytes: usize,
    periodic_transform_device_floor_bytes: usize,
    decoded_proof_backing_ceiling_bytes: usize,
    full_prover_host_peak_bytes: Option<usize>,
    full_prover_device_peak_bytes: Option<usize>,
    /// Source-derived numerical payload candidate, distinct from whole-process
    /// verification admission and not evidence that qualification has passed.
    independent_verifier_candidate_payload_bytes: Option<usize>,
    independent_verifier_peak_bytes: Option<usize>,
    dispatch_enabled: bool,
    gpu_work_performed: bool,
    cryptographic_verification_performed: bool,
    matched_ringct_workflow: bool,
    missing_bounds: [MissingBound; 5],
}

impl AdmissionDiagnostic {
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn missing_bounds(&self) -> &[MissingBound] {
        &self.missing_bounds
    }
    pub fn dispatch_enabled(&self) -> bool {
        false
    }

    /// A diagnostic cannot mint a dispatch token, even if a caller edits its
    /// serialized JSON. Closing the bounds and qualification requires a new
    /// reviewed implementation with an internal planner-issued owner.
    pub fn require_dispatch(&self) -> Result<(), Error> {
        Err(Error::IncompleteLifetimeAdmission)
    }
}

pub fn diagnose(
    expected: &note::Statement,
    context: Context,
    limits: Limits,
) -> Result<AdmissionDiagnostic, Error> {
    limits.check()?;
    let geometry = Geometry::pinned()?;
    let statement_bytes = mul(expected.public.capacity(), 8)?;
    if statement_bytes > limits.worker_host_bytes {
        return Err(Error::ResourceLimit);
    }
    codec::expected_public(expected, context)?;
    let trace = mul(mul(geometry.padded_rows, geometry.trace_columns)?, 8)?;
    let periodic = mul(mul(geometry.padded_rows, geometry.periodic_columns)?, 8)?;
    let constants = mul(2 * geometry.padded_rows.ilog2() as usize + 2, 8)?;
    let transform_floor = add(add(trace, mul(3, periodic)?)?, constants)?;
    let decoded = geometry.decoded_backing_ceiling_bytes()?;
    let staging = (2 * (9 + 32 * 5) + 2 * 10 + 6 + 28 + 1) * 8;
    let known_host = add(
        add(statement_bytes, core::mem::size_of::<note::Witness>())?,
        add(staging, add(decoded, geometry.public_values * 8)?)?,
    )?;
    if known_host > limits.worker_host_bytes || transform_floor > limits.managed_device_bytes {
        return Err(Error::ResourceLimit);
    }
    Ok(AdmissionDiagnostic {
        schema: SCHEMA,
        profile: crate::Profile::PrivateNoteDirectV1.tag(),
        proof_profile: "legacy_quadratic",
        geometry,
        limits,
        caller_statement_backing_bytes: statement_bytes,
        witness_inline_bytes: core::mem::size_of::<note::Witness>(),
        packed_witness_staging_bytes: staging,
        public_readback_bytes: geometry.public_values * 8,
        raw_trace_device_bytes: trace,
        periodic_input_device_bytes: periodic,
        periodic_transform_device_floor_bytes: transform_floor,
        decoded_proof_backing_ceiling_bytes: decoded,
        full_prover_host_peak_bytes: None,
        full_prover_device_peak_bytes: None,
        independent_verifier_candidate_payload_bytes: VerificationPlan::new()
            .ok()
            .map(|plan| plan.required_temporary_bytes()),
        independent_verifier_peak_bytes: None,
        dispatch_enabled: false,
        gpu_work_performed: false,
        cryptographic_verification_performed: false,
        matched_ringct_workflow: false,
        missing_bounds: MISSING,
    })
}
