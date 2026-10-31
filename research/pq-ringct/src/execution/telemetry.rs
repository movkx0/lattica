//! Bounded public observations. These are measurements, never cache admission.
use super::*;

const MAX_ACCESSES: usize = 4096;
// A report row owns 15 JSON values, two 64-byte hex strings and one outer
// value. Reserve more than their backing capacity before collecting any rows.
// Allocator overhead remains excluded, as for the existing public cache.
const REPORT_RESERVATION_BYTES: usize = MAX_ACCESSES * 1024 + (64 << 10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegistrationTelemetry {
    #[default]
    Disabled,
    Bounded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessOutcome {
    Pending = 0,
    Registered = 1,
    PreparedHit = 2,
    DrainFailed = 3,
    AdmissionFailed = 4,
    SetupFailed = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseReason {
    IdentityChanged = 0,
    HostBudgetChanged = 1,
    ProgramMismatch = 2,
    PhaseBoundary = 3,
    SessionRetired = 4,
    Cleanup = 5,
}

struct Access {
    identity: Identity,
    host_allowance_bytes: u64,
    setup_seconds: f64,
    outcome: AccessOutcome,
    reuse_distance: Option<u64>,
    released_after: Option<ReleaseReason>,
    public_host_bytes: usize,
    managed_device_bytes: Option<u64>,
    metadata_payload_bytes: Option<usize>,
    metadata_hit: Option<bool>,
    receipt_hit: Option<bool>,
    callback_ok: Option<bool>,
    active_rows: usize,
    padded_rows: usize,
}

pub(super) struct RegistrationTrace {
    mode: RegistrationTelemetry,
    accesses: Vec<Access>,
    attempted: u64,
    dropped: u64,
    releases: [u64; 6],
}

impl RegistrationTrace {
    pub(super) fn new(mode: RegistrationTelemetry) -> Self {
        const { assert!(16 * std::mem::size_of::<Value>() + 128 <= 1024) };
        let accesses = if mode == RegistrationTelemetry::Bounded {
            Vec::with_capacity(MAX_ACCESSES)
        } else {
            Vec::new()
        };
        assert!(accesses.capacity() <= MAX_ACCESSES);
        Self {
            mode,
            accesses,
            attempted: 0,
            dropped: 0,
            releases: [0; 6],
        }
    }

    pub(super) fn accounted_bytes(&self) -> usize {
        self.accesses.capacity() * std::mem::size_of::<Access>()
            + if self.mode == RegistrationTelemetry::Bounded {
                REPORT_RESERVATION_BYTES
            } else {
                0
            }
    }

    pub(super) fn enabled(&self) -> bool {
        self.mode == RegistrationTelemetry::Bounded
    }
    pub(super) fn attempted(&self) -> u64 {
        self.attempted
    }

    pub(super) fn begin(
        &mut self,
        identity: Identity,
        host_allowance_bytes: u64,
        program: &Program,
    ) -> Option<usize> {
        self.attempted += 1;
        if !self.enabled() {
            return None;
        }
        if self.accesses.len() == MAX_ACCESSES {
            self.dropped += 1;
            return None;
        }
        let index = self.accesses.len();
        let reuse_distance = self
            .accesses
            .iter()
            .rposition(|a| a.identity == identity && a.host_allowance_bytes == host_allowance_bytes)
            .map(|previous| (index - previous - 1) as u64);
        self.accesses.push(Access {
            identity,
            host_allowance_bytes,
            setup_seconds: 0.0,
            outcome: AccessOutcome::Pending,
            reuse_distance,
            released_after: None,
            public_host_bytes: 0,
            managed_device_bytes: None,
            metadata_payload_bytes: None,
            metadata_hit: None,
            receipt_hit: None,
            callback_ok: None,
            active_rows: program.active_rows(),
            padded_rows: program.height(),
        });
        Some(index)
    }

    pub(super) fn outcome(&mut self, index: Option<usize>, outcome: AccessOutcome, seconds: f64) {
        if let Some(index) = index {
            self.accesses[index].outcome = outcome;
            self.accesses[index].setup_seconds = seconds;
        }
    }

    pub(super) fn retained(
        &mut self,
        index: Option<usize>,
        public_host_bytes: usize,
        managed_device_bytes: Option<u64>,
        metadata_payload_bytes: usize,
        metadata_hit: bool,
        receipt_hit: bool,
    ) {
        if let Some(index) = index {
            let access = &mut self.accesses[index];
            access.public_host_bytes = public_host_bytes;
            access.managed_device_bytes = managed_device_bytes;
            access.metadata_payload_bytes = Some(metadata_payload_bytes);
            access.metadata_hit = Some(metadata_hit);
            access.receipt_hit = Some(receipt_hit);
        }
    }

    pub(super) fn callback(&mut self, index: Option<usize>, ok: bool) {
        if let Some(index) = index {
            self.accesses[index].callback_ok = Some(ok);
        }
    }

    pub(super) fn release(&mut self, index: Option<usize>, reason: ReleaseReason) {
        self.releases[reason as usize] += 1;
        if let Some(index) = index {
            self.accesses[index].released_after = Some(reason);
        }
    }

    pub(super) fn report(&self) -> Value {
        let rows: Vec<Value> = self
            .accesses
            .iter()
            .map(|a| {
                json!([
                    hex(&a.identity.registration),
                    hex(&a.identity.manifest),
                    a.host_allowance_bytes,
                    a.setup_seconds,
                    a.outcome as u8,
                    a.reuse_distance,
                    a.released_after.map(|r| r as u8),
                    a.public_host_bytes,
                    a.managed_device_bytes,
                    a.metadata_payload_bytes,
                    a.metadata_hit,
                    a.receipt_hit,
                    a.callback_ok,
                    a.active_rows,
                    a.padded_rows
                ])
            })
            .collect();
        let mut report = json!({
            "schema":"pq-registration-access-trace-v1",
            "enabled":self.enabled(), "maximum_accesses":MAX_ACCESSES,
            "attempted_accesses":self.attempted, "recorded_accesses":rows.len(),
            "dropped_accesses":self.dropped,
            "complete":self.enabled() && self.dropped == 0 && self.accesses.iter().all(|a| a.outcome != AccessOutcome::Pending),
            "reserved_host_bytes":self.accounted_bytes(),
            "report_reservation_bytes":if self.enabled() { REPORT_RESERVATION_BYTES } else { 0 },
            "reservation_charged_to":"shared_public_metadata_allowance",
            "prepared_retained_host_bytes":null, "prepared_retained_device_bytes":null,
            "prepared_footprint_status":"complete immutable prepared-state footprint unavailable; observations do not authorize retention",
            "reuse_distance_unit":"intervening registration accesses with identical identity and host allowance",
            "outcomes":["pending","registered","prepared_hit","drain_failed","admission_failed","setup_failed"],
            "release_reasons":["identity_changed","host_budget_changed","program_mismatch","phase_boundary","session_retired","cleanup"],
            "release_counts":self.releases,
            "fields":["registration","manifest","host_allowance_bytes","setup_seconds","outcome","reuse_distance","released_after","public_host_bytes","managed_device_live_bytes","metadata_payload_bytes","metadata_hit","receipt_hit","callback_ok","active_rows","padded_rows"]
        });
        // Move the complete array. json! would serialize an expression by
        // reference and momentarily duplicate all event backing.
        report["rows"] = Value::Array(rows);
        report
    }
}
