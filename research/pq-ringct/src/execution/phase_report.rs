//! Fixed report storage for a future admitted paired phase.
//!
//! This owns copied receipts, bounded failure text and serialization backing.
//! It does not admit the borrowed source Report/String, backend temporaries,
//! graph storage, output I/O or dispatch. See phase_report/BOUNDS.md.
use super::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use lattica_prover_p3::proving::{
    Backend, CoverageScope, Observation, Policy, Profile, Report, Stage, StageCapability,
};
use std::mem::size_of;

const REPORTS: usize = 2;
const STAGES: usize = 19;
const BACKENDS: usize = 6;
const OBSERVATIONS: usize = STAGES * BACKENDS;
const COMPONENTS: usize = 16;
const LABEL_BYTES: usize = 64;
const FAILURE_BYTES: usize = 2048;
// Per-record bounds derive from the fixed keys, maximum decimal widths and
// escaped labels. The larger constants are rounded bounds, not allocations.
const ENCODED_BYTES: usize = REPORTS
    * (OBSERVATIONS * 512 + STAGES * 128 + COMPONENTS * 512 + 2048)
    + FAILURE_BYTES * 6
    + 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhaseKind {
    NativeChild,
    WrapperCompilation,
    RegisteredWrapper,
}

/// Descriptive source identity only; these numbers do not authorize execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhaseIdentity {
    pub(crate) kind: PhaseKind,
    pub(crate) ordinal: u64,
    pub(crate) first_segment: u64,
    pub(crate) segment_count: u8,
    pub(crate) profile: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureStage {
    Admission,
    NativeVerification,
    Compilation,
    Registration,
    Proving,
    PreparedRelease,
    QueueDrain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    WrongLedger,
    WrongReservation,
    InvalidIdentity,
    ReportSlotsFull,
    InventoryTooLarge,
    DuplicateCapability,
    DuplicateObservation,
    DuplicateComponent,
    LabelTooLong,
    FailureAlreadyRecorded,
    EncodingOverflow,
}

#[derive(Clone, Copy)]
struct Text<const N: usize> {
    bytes: [u8; N],
    used: usize,
}
impl<const N: usize> Text<N> {
    const EMPTY: Self = Self {
        bytes: [0; N],
        used: 0,
    };

    fn exact(value: &str) -> Result<Self, Error> {
        if value.len() > N {
            return Err(Error::LabelTooLong);
        }
        let mut result = Self::EMPTY;
        result.bytes[..value.len()].copy_from_slice(value.as_bytes());
        result.used = value.len();
        Ok(result)
    }

    fn prefix(value: &str) -> Self {
        let mut end = value.len().min(N);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        Self::exact(&value[..end]).expect("bounded UTF-8 prefix")
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.used]).expect("copied UTF-8")
    }
}

#[derive(Clone, Copy)]
struct Component {
    id: Text<LABEL_BYTES>,
    scope: CoverageScope,
    started: bool,
    cached: bool,
    succeeded: bool,
    stage_coverage_complete: bool,
}

struct Snapshot {
    schema: Text<LABEL_BYTES>,
    entry_point: Text<LABEL_BYTES>,
    policy: Policy,
    scope: CoverageScope,
    profile: Profile,
    max_log_fri_arity: u8,
    capabilities: [Option<StageCapability>; STAGES],
    elapsed_ns: u128,
    succeeded: bool,
    stage_coverage_complete: bool,
    completion_rejected: bool,
    observation_errors: u64,
    observations: [Option<Observation>; OBSERVATIONS],
    components: [Option<Component>; COMPONENTS],
}

impl Snapshot {
    fn capture(report: &Report) -> Result<Self, Error> {
        let capabilities = report.capabilities.stages();
        if capabilities.len() > STAGES
            || report.observations.len() > OBSERVATIONS
            || report.components.len() > COMPONENTS
        {
            return Err(Error::InventoryTooLarge);
        }
        // Validate all variable data before copying into the fixed output.
        if report.schema.len() > LABEL_BYTES
            || report.entry_point.len() > LABEL_BYTES
            || report.components.iter().any(|c| c.id.len() > LABEL_BYTES)
        {
            return Err(Error::LabelTooLong);
        }
        for (i, item) in capabilities.iter().enumerate() {
            if capabilities[..i]
                .iter()
                .any(|prior| prior.stage == item.stage)
            {
                return Err(Error::DuplicateCapability);
            }
        }
        for (i, item) in report.observations.iter().enumerate() {
            if report.observations[..i]
                .iter()
                .any(|prior| prior.stage == item.stage && prior.backend == item.backend)
            {
                return Err(Error::DuplicateObservation);
            }
        }
        for (i, item) in report.components.iter().enumerate() {
            if report.components[..i]
                .iter()
                .any(|prior| prior.id == item.id)
            {
                return Err(Error::DuplicateComponent);
            }
        }
        Ok(Self {
            schema: Text::exact(report.schema)?,
            entry_point: Text::exact(report.entry_point)?,
            policy: report.policy,
            scope: report.capabilities.scope(),
            profile: report.capabilities.profile(),
            max_log_fri_arity: report.capabilities.max_log_fri_arity(),
            capabilities: std::array::from_fn(|i| capabilities.get(i).cloned()),
            elapsed_ns: report.elapsed_ns,
            succeeded: report.succeeded,
            stage_coverage_complete: report.stage_coverage_complete,
            completion_rejected: report.completion_rejected,
            observation_errors: report.observation_errors,
            observations: std::array::from_fn(|i| report.observations.get(i).cloned()),
            components: std::array::from_fn(|i| {
                report.components.get(i).map(|c| Component {
                    id: Text::exact(c.id).expect("validated component label"),
                    scope: c.scope,
                    started: c.started,
                    cached: c.cached,
                    succeeded: c.succeeded,
                    stage_coverage_complete: c.stage_coverage_complete,
                })
            }),
        })
    }
}

struct Failure {
    stage: FailureStage,
    text: Text<FAILURE_BYTES>,
    original_bytes: usize,
}

struct Payload {
    identity: PhaseIdentity,
    reports: [Option<Snapshot>; REPORTS],
    failure: Option<Failure>,
}

struct Encoding {
    // Exactly one fixed request. This Vec never grows or exposes its capacity.
    bytes: Vec<u8>,
    used: usize,
}
impl Encoding {
    fn new() -> Self {
        Self {
            bytes: vec![0; ENCODED_BYTES],
            used: 0,
        }
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        let end = self
            .used
            .checked_add(value.len())
            .ok_or(Error::EncodingOverflow)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(Error::EncodingOverflow)?
            .copy_from_slice(value);
        self.used = end;
        Ok(())
    }
    fn decimal(&mut self, mut value: u128) -> Result<(), Error> {
        let mut digits = [0; 39];
        let mut first = digits.len();
        loop {
            first -= 1;
            digits[first] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.bytes(&digits[first..])
    }
    fn boolean(&mut self, value: bool) -> Result<(), Error> {
        self.bytes(if value { b"true" } else { b"false" })
    }
    fn string(&mut self, value: &str) -> Result<(), Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.bytes(b"\"")?;
        for &byte in value.as_bytes() {
            match byte {
                b'\"' => self.bytes(b"\\\"")?,
                b'\\' => self.bytes(b"\\\\")?,
                0..=31 => self.bytes(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 15) as usize],
                ])?,
                _ => self.bytes(&[byte])?,
            }
        }
        self.bytes(b"\"")
    }
}

/// Payload and encoding drop before the token, including after a move/unwind.
/// No Clone, payload extraction or unreserved constructor is provided. The
/// checked consuming reclamation path returns only the original quota after
/// destroying this payload and its encoding.
pub(crate) struct PhaseReportOwner {
    payload: Box<Payload>,
    encoding: Encoding,
    reservation: Reservation,
}

impl PhaseReportOwner {
    /// Source-derived requested backing plus explicit construction/copy scratch.
    /// Allocator metadata, OS stacks, borrowed source reports/errors and I/O
    /// remain outside this bound; this is not a process-RSS measurement.
    pub(crate) const fn requirements() -> Requirements {
        Requirements::single(
            Category::Report,
            Bytes {
                host: (2 * size_of::<Payload>()
                    + 2 * size_of::<Snapshot>()
                    + ENCODED_BYTES
                    + size_of::<Self>()
                    + 39
                    + 6) as u64,
                device: 0,
            },
        )
    }

    /// Accept only the exact pre-split report charge in this same ledger.
    /// Rejection returns the unchanged token; no backing has been allocated.
    pub(crate) fn from_reservation(
        reservation: Reservation,
        ledger: &Ledger,
        identity: PhaseIdentity,
    ) -> Result<Self, (Error, Reservation)> {
        let error = if !reservation.belongs_to(ledger) {
            Some(Error::WrongLedger)
        } else if reservation.requirements() != Self::requirements() {
            Some(Error::WrongReservation)
        } else if !(1..=2).contains(&identity.segment_count)
            || (identity.kind == PhaseKind::NativeChild && identity.segment_count != 1)
            || identity
                .first_segment
                .checked_add(u64::from(identity.segment_count))
                .is_none()
        {
            Some(Error::InvalidIdentity)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((error, reservation));
        }
        Ok(Self {
            payload: Box::new(Payload {
                identity,
                reports: [None, None],
                failure: None,
            }),
            encoding: Encoding::new(),
            reservation,
        })
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.reservation.belongs_to(ledger)
    }

    /// The source receipt must already have its own preceding admission.
    /// Failed capture leaves all earlier records intact and uses no heap.
    pub(crate) fn record_proving(&mut self, report: &Report) -> Result<(), Error> {
        let limit = match self.payload.identity.kind {
            PhaseKind::WrapperCompilation => 0,
            PhaseKind::NativeChild => 1,
            PhaseKind::RegisteredWrapper => 2,
        };
        let slot = self.payload.reports[..limit]
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(Error::ReportSlotsFull)?;
        *slot = Some(Snapshot::capture(report)?);
        Ok(())
    }

    /// Copy a UTF-8 prefix without formatting or cloning the original error.
    /// The caller must separately admit that original error's construction.
    pub(crate) fn record_failure(
        &mut self,
        stage: FailureStage,
        message: &str,
    ) -> Result<(), Error> {
        if self.payload.failure.is_some() {
            return Err(Error::FailureAlreadyRecorded);
        }
        self.payload.failure = Some(Failure {
            stage,
            text: Text::prefix(message),
            original_bytes: message.len(),
        });
        Ok(())
    }

    /// Return a borrow of owned, fixed encoding storage. No JSON tree/String,
    /// arbitrary serializer or output callback can allocate in this operation.
    pub(crate) fn encode(&mut self) -> Result<&[u8], Error> {
        self.encoding.used = 0;
        if let Err(error) = encode_payload(&self.payload, &mut self.encoding) {
            self.encoding.used = 0;
            return Err(error);
        }
        Ok(&self.encoding.bytes[..self.encoding.used])
    }
}

fn stage_name(value: Stage) -> &'static str {
    match value {
        Stage::PublicValues => "public_values",
        Stage::WitnessTrace => "witness_trace",
        Stage::Preprocessing => "preprocessing",
        Stage::Lookup => "lookup",
        Stage::Transform => "transform",
        Stage::Quotient => "quotient",
        Stage::Randomness => "randomness",
        Stage::Hiding => "hiding",
        Stage::Commitment => "commitment",
        Stage::Opening => "opening",
        Stage::FriFold => "fri_fold",
        Stage::FriQuery => "fri_query",
        Stage::FinalPolynomial => "final_polynomial",
        Stage::Scalar => "scalar",
        Stage::Transcript => "transcript",
        Stage::Grinding => "grinding",
        Stage::UpstreamProver => "upstream_prover",
        Stage::ConstraintAudit => "constraint_audit",
        Stage::Serialization => "serialization",
    }
}
fn backend_name(value: Backend) -> &'static str {
    match value {
        Backend::Cpu => "cpu",
        Backend::OpenCl => "open_cl",
        Backend::Metal => "metal",
        Backend::Cuda => "cuda",
        Backend::Mixed => "mixed",
        Backend::Unknown => "unknown",
    }
}
fn scope_name(value: CoverageScope) -> &'static str {
    match value {
        CoverageScope::ProofRequest => "proof_request",
        CoverageScope::Statement => "statement",
        CoverageScope::RegistryCompilation => "registry_compilation",
        CoverageScope::Preprocessing => "preprocessing",
        CoverageScope::RegisteredProof => "registered_proof",
        CoverageScope::Operation => "operation",
    }
}
fn policy_name(value: Policy) -> &'static str {
    match value {
        Policy::Compatible => "compatible",
        Policy::CpuRequired => "cpu_required",
        Policy::GpuRequired => "gpu_required",
    }
}
fn profile_name(value: Profile) -> &'static str {
    match value {
        Profile::LegacyQuadratic => "legacy_quadratic",
        Profile::BlockV2Cubic => "block_v2_cubic",
        Profile::MatrictN10 => "matrict_n10",
    }
}
fn failure_name(value: FailureStage) -> &'static str {
    match value {
        FailureStage::Admission => "admission",
        FailureStage::NativeVerification => "native_verification",
        FailureStage::Compilation => "compilation",
        FailureStage::Registration => "registration",
        FailureStage::Proving => "proving",
        FailureStage::PreparedRelease => "prepared_release",
        FailureStage::QueueDrain => "queue_drain",
    }
}

fn encode_snapshot(r: &Snapshot, out: &mut Encoding) -> Result<(), Error> {
    out.bytes(b"{\"schema\":")?;
    out.string(r.schema.as_str())?;
    out.bytes(b",\"entry_point\":")?;
    out.string(r.entry_point.as_str())?;
    out.bytes(b",\"policy\":")?;
    out.string(policy_name(r.policy))?;
    out.bytes(b",\"capabilities\":{\"scope\":")?;
    out.string(scope_name(r.scope))?;
    out.bytes(b",\"profile\":")?;
    out.string(profile_name(r.profile))?;
    out.bytes(b",\"max_log_fri_arity\":")?;
    out.decimal(u128::from(r.max_log_fri_arity))?;
    out.bytes(b",\"stages\":[")?;
    let mut first = true;
    for c in r.capabilities.iter().flatten() {
        if !first {
            out.bytes(b",")?;
        }
        first = false;
        out.bytes(b"{\"stage\":")?;
        out.string(stage_name(c.stage))?;
        out.bytes(b",\"backend\":")?;
        out.string(backend_name(c.backend))?;
        out.bytes(b"}")?;
    }
    out.bytes(b"]},\"elapsed_ns\":")?;
    out.decimal(r.elapsed_ns)?;
    out.bytes(b",\"succeeded\":")?;
    out.boolean(r.succeeded)?;
    out.bytes(b",\"stage_coverage_complete\":")?;
    out.boolean(r.stage_coverage_complete)?;
    out.bytes(b",\"completion_rejected\":")?;
    out.boolean(r.completion_rejected)?;
    out.bytes(b",\"observation_errors\":")?;
    out.decimal(u128::from(r.observation_errors))?;
    out.bytes(b",\"observations\":[")?;
    first = true;
    for o in r.observations.iter().flatten() {
        if !first {
            out.bytes(b",")?;
        }
        first = false;
        out.bytes(b"{\"stage\":")?;
        out.string(stage_name(o.stage))?;
        out.bytes(b",\"backend\":")?;
        out.string(backend_name(o.backend))?;
        out.bytes(b",\"calls\":")?;
        out.decimal(u128::from(o.calls))?;
        out.bytes(b",\"completed_calls\":")?;
        out.decimal(u128::from(o.completed_calls))?;
        out.bytes(b",\"device_calls\":")?;
        out.decimal(u128::from(o.device_calls))?;
        out.bytes(b",\"inclusive_ns\":")?;
        out.decimal(o.inclusive_ns)?;
        out.bytes(b",\"device_ns\":")?;
        out.decimal(o.device_ns)?;
        out.bytes(b"}")?;
    }
    out.bytes(b"],\"components\":[")?;
    first = true;
    for c in r.components.iter().flatten() {
        if !first {
            out.bytes(b",")?;
        }
        first = false;
        out.bytes(b"{\"id\":")?;
        out.string(c.id.as_str())?;
        out.bytes(b",\"scope\":")?;
        out.string(scope_name(c.scope))?;
        out.bytes(b",\"started\":")?;
        out.boolean(c.started)?;
        out.bytes(b",\"cached\":")?;
        out.boolean(c.cached)?;
        out.bytes(b",\"succeeded\":")?;
        out.boolean(c.succeeded)?;
        out.bytes(b",\"stage_coverage_complete\":")?;
        out.boolean(c.stage_coverage_complete)?;
        out.bytes(b"}")?;
    }
    out.bytes(b"]}")
}

fn encode_payload(payload: &Payload, out: &mut Encoding) -> Result<(), Error> {
    out.bytes(b"{\"schema\":\"pq-bounded-phase-reports-v1\",\"phase\":")?;
    out.string(match payload.identity.kind {
        PhaseKind::NativeChild => "native_child",
        PhaseKind::WrapperCompilation => "wrapper_compilation",
        PhaseKind::RegisteredWrapper => "registered_wrapper",
    })?;
    out.bytes(b",\"ordinal\":")?;
    out.decimal(u128::from(payload.identity.ordinal))?;
    out.bytes(b",\"first_segment\":")?;
    out.decimal(u128::from(payload.identity.first_segment))?;
    out.bytes(b",\"segment_count\":")?;
    out.decimal(u128::from(payload.identity.segment_count))?;
    out.bytes(b",\"profile\":[")?;
    for (i, byte) in payload.identity.profile.iter().enumerate() {
        if i != 0 {
            out.bytes(b",")?;
        }
        out.decimal(u128::from(*byte))?;
    }
    out.bytes(b"],\"proving_reports\":[")?;
    let mut first = true;
    for r in payload.reports.iter().flatten() {
        if !first {
            out.bytes(b",")?;
        }
        first = false;
        encode_snapshot(r, out)?;
    }
    out.bytes(b"],\"failure\":")?;
    if let Some(failure) = &payload.failure {
        out.bytes(b"{\"stage\":")?;
        out.string(failure_name(failure.stage))?;
        out.bytes(b",\"message\":")?;
        out.string(failure.text.as_str())?;
        out.bytes(b",\"original_bytes\":")?;
        out.decimal(failure.original_bytes as u128)?;
        out.bytes(b",\"truncated\":")?;
        out.boolean(failure.text.used != failure.original_bytes)?;
        out.bytes(b",\"retry_attempted\":false}")?;
    } else {
        out.bytes(b"null")?;
    }
    out.bytes(b",\"dispatch_authorized\":false,\"source_transients_admitted\":false}")
}

#[cfg(test)]
mod tests;

mod reclamation;
