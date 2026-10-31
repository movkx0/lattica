//! Failure-only observations of the original native issuer. These fixed scalar
//! projections neither move an error/owner nor grant admission or a retry.
use super::*;
use crate::execution::retained_resources::Error as QuotaError;
use crate::execution::{phase_lifecycle, report_transport};
use crate::opencl::RuntimeError;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::Error as NativeError;
use lattica_prover_p3::block_v2::native_gpu::shake_preparation::{
    ShakePreparationGeometry, ShakePreparationPlan,
};

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct Failure {
    domain: &'static str,
    code: &'static str,
    category: Option<usize>,
    requested: Option<[u64; 2]>,
    available: Option<[u64; 2]>,
    status: Option<&'static str>,
}
impl Failure {
    fn new(domain: &'static str, code: &'static str) -> Self {
        Self {
            domain,
            code,
            category: None,
            requested: None,
            available: None,
            status: None,
        }
    }
    fn quota(error: &QuotaError) -> Self {
        match error {
            QuotaError::Overflow => Self::new("quota", "Overflow"),
            QuotaError::DifferentLedger => Self::new("quota", "DifferentLedger"),
            QuotaError::ExceedsWorkerAllowance {
                requested,
                remaining,
            } => Self {
                requested: Some([requested.host, requested.device]),
                available: Some([remaining.host, remaining.device]),
                ..Self::new("quota", "ExceedsWorkerAllowance")
            },
            QuotaError::SplitExceedsReservation {
                category,
                requested,
                available,
            } => Self {
                category: Some(*category as usize),
                requested: Some([requested.host, requested.device]),
                available: Some([available.host, available.device]),
                ..Self::new("quota", "SplitExceedsReservation")
            },
        }
    }
    fn lifecycle(error: &phase_lifecycle::Error) -> Self {
        use phase_lifecycle::Error as E;
        let code = match error {
            E::AlreadyBound => "AlreadyBound",
            E::WorkAlreadyStarted => "WorkAlreadyStarted",
            E::CpuReferenceRequired => "CpuReferenceRequired",
            E::ContextBusy => "ContextBusy",
            E::PreparedStatePresent => "PreparedStatePresent",
            E::EnclosingAllowance => "EnclosingAllowance",
            E::EmptyPhase => "EmptyPhase",
            E::GenerationExhausted => "GenerationExhausted",
            E::NotReady(status) => {
                return Self {
                    status: Some(match status {
                        phase_lifecycle::Status::Unbound => "Unbound",
                        phase_lifecycle::Status::Ready => "Ready",
                        phase_lifecycle::Status::Active => "Active",
                        phase_lifecycle::Status::Poisoned => "Poisoned",
                        phase_lifecycle::Status::Retired => "Retired",
                    }),
                    ..Self::new("lifecycle", "NotReady")
                }
            }
            E::StalePhase => "StalePhase",
            E::BackendReservationCannotEscape => "BackendReservationCannotEscape",
            E::OutstandingOwnedPartition => "OutstandingOwnedPartition",
            E::IncompleteOwnedPartition => "IncompleteOwnedPartition",
            E::Reservation(error) => return Self::quota(error),
            E::Cleanup(error) => match error {
                phase_lifecycle::CleanupFailure::PreparedRelease => "CleanupPreparedRelease",
                phase_lifecycle::CleanupFailure::QueueDrain => "CleanupQueueDrain",
            },
        };
        Self::new("lifecycle", code)
    }
    fn workflow(error: &WorkflowError) -> Self {
        let code = match error {
            WorkflowError::Policy => "Policy",
            WorkflowError::Source => "Source",
            #[cfg(all(
                feature = "full-workflow-experiment",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            WorkflowError::AuxiliarySource(_) => "AuxiliarySource",
            #[cfg(all(
                feature = "full-workflow-experiment",
                not(debug_assertions),
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            WorkflowError::CompleteSource { .. } => "CompleteSource",
            WorkflowError::Identity => "Identity",
            WorkflowError::Enclosing => "Enclosing",
            WorkflowError::Planning => "Planning",
            WorkflowError::Allocation => "Allocation",
            WorkflowError::Empty => "Empty",
            WorkflowError::Slot => "Slot",
            WorkflowError::SlotBusy => "SlotBusy",
            WorkflowError::SlotAuthority => "SlotAuthority",
            WorkflowError::Sequence => "Sequence",
            WorkflowError::Incomplete => "Incomplete",
            WorkflowError::Retired => "Retired",
            WorkflowError::Poisoned => "Poisoned",
            WorkflowError::BackendAllowance => "BackendAllowance",
            WorkflowError::Overflow => "Overflow",
            WorkflowError::Quota(error) => return Self::quota(error),
            WorkflowError::Lifecycle(error) => return Self::lifecycle(error),
        };
        Self::new("workflow", code)
    }
    fn paired(error: PairedFailure) -> Self {
        let code = match error {
            PairedFailure::Unsupported => "Unsupported",
            PairedFailure::Resource => "Resource",
            PairedFailure::Authority => "Authority",
            PairedFailure::Source => "Source",
            PairedFailure::SourceDrift => "SourceDrift",
            PairedFailure::Coverage => "Coverage",
            PairedFailure::Context => "Context",
            PairedFailure::Order => "Order",
            PairedFailure::Overflow => "Overflow",
            PairedFailure::Rows => "Rows",
            PairedFailure::Capacity => "Capacity",
            PairedFailure::Preparation => "Preparation",
            PairedFailure::Native => "Native",
            PairedFailure::Compilation => "Compilation",
            PairedFailure::Proof => "Proof",
            PairedFailure::Verification => "Verification",
            PairedFailure::Cleanup => "Cleanup",
        };
        Self::new("paired", code)
    }
    fn runtime(error: RuntimeError) -> Self {
        let code = match error {
            RuntimeError::Configuration => "Configuration",
            RuntimeError::Admission => "Admission",
            RuntimeError::WrongLedger => "WrongLedger",
            RuntimeError::Selection => "Selection",
            RuntimeError::ActiveSession => "ActiveSession",
            RuntimeError::MissingOwner => "MissingOwner",
            RuntimeError::Initialization => "Initialization",
            RuntimeError::Lifecycle => "Lifecycle",
        };
        Self::new("runtime", code)
    }
    fn native(error: NativeError) -> Self {
        let code = match error {
            NativeError::Authority => "Authority",
            NativeError::Geometry => "Geometry",
            NativeError::Preparation => "Preparation",
            NativeError::Planner => "Planner",
            NativeError::Admission => "Admission",
            NativeError::Runtime => "Runtime",
            NativeError::AlreadyAttempted => "AlreadyAttempted",
            NativeError::Configuration => "Configuration",
            NativeError::Entropy => "Entropy",
            NativeError::Normalization => "Normalization",
            NativeError::Trace => "Trace",
            NativeError::Public => "Public",
            NativeError::Proof => "Proof",
            NativeError::Report => "Report",
            NativeError::Output => "Output",
        };
        Self::new("native_shake", code)
    }
}

#[derive(serde::Serialize)]
struct PublicGeometry {
    backend_host_bytes: u64,
    backend_device_bytes: u64,
    rows: usize,
    width: usize,
    public_values: usize,
    periodic_columns: usize,
    periodic_length: usize,
    pcs_host_bytes: u64,
    startup_host_bytes: u64,
    startup_device_bytes: u64,
}
pub(super) struct Diagnostic {
    ordinal: usize,
    cursor: usize,
    pub(super) closed_index: Option<usize>,
    pub(super) stage: &'static str,
    cause: Option<Failure>,
    restoration: Option<Failure>,
    geometry: Option<PublicGeometry>,
}
#[derive(serde::Serialize)]
struct Entry<'a> {
    schema: &'static str,
    family: &'static str,
    request_step: usize,
    native_cursor: usize,
    closed_index: Option<usize>,
    stage: &'static str,
    workflow_cause: Failure,
    source_cause: &'a Option<Failure>,
    restoration_cause: &'a Option<Failure>,
    public_geometry: &'a Option<PublicGeometry>,
}
impl report_transport::FixedPayload for Entry<'_> {}
impl Diagnostic {
    pub(super) fn new(ordinal: usize, cursor: usize) -> Self {
        Self {
            ordinal,
            cursor,
            closed_index: None,
            stage: "admission_state",
            cause: None,
            restoration: None,
            geometry: None,
        }
    }
    pub(super) fn geometry(&mut self, partition: &NativePartitionPlan, backend: Bytes) {
        // Read only getters on the already constructed source plan. No second
        // planner, source payload, witness value, key, or proof is inspected.
        let geometry = partition.native.preparation().geometry();
        let startup = partition.startup.get(Category::PhaseScratch);
        self.geometry = Some(PublicGeometry {
            backend_host_bytes: backend.host,
            backend_device_bytes: backend.device,
            rows: geometry.rows(),
            width: geometry.width(),
            public_values: geometry.public_values(),
            periodic_columns: geometry.periodic_columns(),
            periodic_length: geometry.periodic_length(),
            pcs_host_bytes: partition.pcs.get(Category::PhaseScratch).host,
            startup_host_bytes: startup.host,
            startup_device_bytes: startup.device,
        });
    }
    pub(super) fn paired(&mut self, error: PairedFailure) {
        self.cause = Some(Failure::paired(error));
    }
    pub(super) fn runtime(&mut self, error: RuntimeError) {
        self.cause = Some(Failure::runtime(error));
    }
    pub(super) fn native(&mut self, error: NativeError) {
        self.cause = Some(Failure::native(error));
    }
    pub(super) fn restoration(&mut self, error: PairedFailure) {
        self.restoration = Some(Failure::paired(error));
    }
    fn entry<'a>(&'a self, error: &WorkflowError) -> Entry<'a> {
        Entry {
            schema: "ringct-native-preissue-failure-v1",
            family: "shake",
            request_step: self.ordinal,
            native_cursor: self.cursor,
            closed_index: self.closed_index,
            stage: self.stage,
            workflow_cause: Failure::workflow(error),
            source_cause: &self.cause,
            restoration_cause: &self.restoration,
            public_geometry: &self.geometry,
        }
    }
    pub(super) fn emit(&self, error: &WorkflowError) -> Result<(), report_transport::Error> {
        report_transport::emit(b"owned_native_preissue_failure ", &self.entry(error))
    }
}
// This query is entirely const: no additional WorkflowError-sized Result or
// temporary query frame can exist before the issuer's scratch is admitted.
// Const arithmetic overflow is a compile error; the caller checks addition
// into its complete source-derived scratch requirement.
pub(super) const HOST_BYTES: usize = {
    use core::mem::size_of;
    8 * (size_of::<Diagnostic>()
        + size_of::<Entry<'static>>()
        + size_of::<Failure>()
        + size_of::<Option<Failure>>()
        + size_of::<PublicGeometry>()
        + size_of::<Option<PublicGeometry>>()
        + size_of::<&NativePartitionPlan>()
        + size_of::<NativeShakeReservationPlan>()
        + size_of::<ShakePreparationPlan>()
        + size_of::<ShakePreparationGeometry>()
        + size_of::<Requirements>()
        + size_of::<Bytes>()
        + size_of::<&Diagnostic>()
        + size_of::<&Entry<'static>>()
        + size_of::<&WorkflowError>()
        + size_of::<&QuotaError>()
        + size_of::<&phase_lifecycle::Error>()
        + size_of::<RuntimeError>()
        + size_of::<NativeError>()
        + size_of::<PairedFailure>()
        + size_of::<Option<usize>>()
        + size_of::<usize>()
        + size_of::<&str>()
        + size_of::<bool>()
        + size_of::<Result<(), report_transport::Error>>())
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Ledger, WorkerAllowance};
    #[test]
    fn maximum_numeric_failure_record_fits_the_documented_bound() {
        let quota = QuotaError::SplitExceedsReservation {
            category: Category::IndependentVerifier,
            requested: Bytes {
                host: u64::MAX,
                device: u64::MAX,
            },
            available: Bytes {
                host: u64::MAX,
                device: u64::MAX,
            },
        };
        let mut diagnostic = Diagnostic::new(usize::MAX, usize::MAX);
        diagnostic.closed_index = Some(usize::MAX);
        diagnostic.stage = "partition_source_subset";
        diagnostic.cause = Some(Failure::quota(&quota));
        diagnostic.restoration = Some(Failure::quota(&quota));
        diagnostic.geometry = Some(PublicGeometry {
            backend_host_bytes: u64::MAX,
            backend_device_bytes: u64::MAX,
            rows: usize::MAX,
            width: usize::MAX,
            public_values: usize::MAX,
            periodic_columns: usize::MAX,
            periodic_length: usize::MAX,
            pcs_host_bytes: u64::MAX,
            startup_host_bytes: u64::MAX,
            startup_device_bytes: u64::MAX,
        });
        let encoded = serde_json::to_vec(&diagnostic.entry(&WorkflowError::Quota(quota))).unwrap();
        assert!(encoded.len() + b"owned_native_preissue_failure ".len() + 1 <= 2048);
    }
    #[test]
    fn retained_error_and_original_credit_survive_diagnostic_projection() {
        let ledger = Ledger::new(WorkerAllowance {
            host: 4096,
            device: 0,
        });
        let owner = ledger
            .admit_phase(Requirements::single(
                Category::Report,
                Bytes {
                    host: 512,
                    device: 0,
                },
            ))
            .unwrap();
        let error = WorkflowError::Lifecycle(phase_lifecycle::Error::Reservation(
            QuotaError::SplitExceedsReservation {
                category: Category::IndependentVerifier,
                requested: Bytes {
                    host: 8192,
                    device: 16,
                },
                available: Bytes {
                    host: 4096,
                    device: 0,
                },
            },
        ));
        let slot = Some(Err::<(), _>((error, owner)));
        let diagnostic = Diagnostic::new(1, 0);
        let before = ledger.snapshot().current;
        let (error, owner) = slot.as_ref().unwrap().as_ref().unwrap_err();
        let entry = diagnostic.entry(error);
        assert_eq!(entry.workflow_cause.domain, "quota");
        assert_eq!(entry.workflow_cause.code, "SplitExceedsReservation");
        assert_eq!(
            entry.workflow_cause.category,
            Some(Category::IndependentVerifier as usize)
        );
        assert_eq!(entry.workflow_cause.requested, Some([8192, 16]));
        assert_eq!(entry.workflow_cause.available, Some([4096, 0]));
        assert!(owner.belongs_to(&ledger));
        assert_eq!(ledger.snapshot().current, before);
        drop(slot);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    #[test]
    fn original_preflight_failure_survives_a_distinct_restoration_failure() {
        let mut diagnostic = Diagnostic::new(1, 0);
        diagnostic.closed_index = Some(18);
        diagnostic.stage = "runtime_preflight";
        diagnostic.runtime(RuntimeError::Selection);
        diagnostic.restoration(PairedFailure::Authority);
        let entry = diagnostic.entry(&WorkflowError::Planning);
        assert_eq!(entry.stage, "runtime_preflight");
        assert_eq!(entry.closed_index, Some(18));
        assert_eq!(entry.source_cause.as_ref().unwrap().code, "Selection");
        assert_eq!(entry.restoration_cause.as_ref().unwrap().code, "Authority");
    }
    #[test]
    fn error_projection_distinguishes_planner_admission_and_lifecycle_refusals() {
        let mut diagnostic = Diagnostic::new(1, 0);
        diagnostic.native(NativeError::Planner);
        assert_eq!(
            diagnostic
                .entry(&WorkflowError::Planning)
                .source_cause
                .as_ref()
                .unwrap()
                .code,
            "Planner"
        );
        diagnostic.native(NativeError::Admission);
        assert_eq!(
            diagnostic
                .entry(&WorkflowError::Planning)
                .source_cause
                .as_ref()
                .unwrap()
                .code,
            "Admission"
        );
        let error = WorkflowError::Lifecycle(phase_lifecycle::Error::NotReady(
            phase_lifecycle::Status::Poisoned,
        ));
        assert_eq!(
            diagnostic.entry(&error).workflow_cause.status,
            Some("Poisoned")
        );
        assert!(HOST_BYTES >= 8 * core::mem::size_of::<Diagnostic>());
    }
}
