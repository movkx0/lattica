//! Host-approved local pool timings. Worker messages cannot install these.
//! Estimates never grant proof, resource, lease or deadline admission.
use super::*;
use lattica_prover_p3::block_v2::execution::{
    pool::PoolCoordinator,
    scheduler::{TimingCalibration, TimingIdentity},
    worker::typed::process::configuration_digest,
};
use std::mem::size_of;

pub(super) const SERVICE_MS: u64 = 180_000;
pub(super) const SHUTDOWN_MS: u64 = 30_000;
pub(super) const DISPATCH_MS: u64 = SERVICE_MS - SHUTDOWN_MS;
pub(super) const CANDIDATE_MS: u64 = 600_000;
const MAX_RECORDS: usize = 64;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Window {
    pub schema_version: u32,
    pub boot_id: String,
    pub issued_monotonic_ms: u64,
    pub dispatch_deadline_monotonic_ms: u64,
}

impl Window {
    pub fn validate_shape(&self) -> Result<(), Error> {
        self.validate_at(&self.boot_id, self.issued_monotonic_ms)
    }
    pub fn validate_at(&self, boot_id: &str, monotonic_ms: u64) -> Result<(), Error> {
        if self.schema_version != 1
            || self.boot_id != boot_id
            || self.boot_id.len() != 36
            || self.issued_monotonic_ms > monotonic_ms
            || self.issued_monotonic_ms.checked_add(DISPATCH_MS)
                != Some(self.dispatch_deadline_monotonic_ms)
            || self.dispatch_deadline_monotonic_ms <= monotonic_ms
        {
            return Err("pool timing window is expired or belongs to another launch/boot".into());
        }
        Ok(())
    }

    /// Translate once into the coordinator's clock. Capture its clock first so
    /// the translation can only shorten the host's pre-launch dispatch window.
    pub fn deadline(&self, coordinator_ms: u64) -> Result<u64, Error> {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let now = monotonic_ms()?;
        self.validate_at(boot.trim(), now)?;
        coordinator_ms
            .checked_add(self.dispatch_deadline_monotonic_ms - now)
            .ok_or_else(|| "pool timing window overflow".into())
    }
}

/// One host-issued workflow horizon, retained verbatim by every service phase.
/// Journal times in this mode are elapsed milliseconds from this origin.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workflow {
    pub schema_version: u32,
    pub boot_id: String,
    pub started_monotonic_ms: u64,
    pub deadline_monotonic_ms: u64,
}

impl Workflow {
    pub fn validate_at(&self, boot: &str, now: u64) -> Result<(), Error> {
        if self.schema_version != 1
            || self.boot_id.len() != 36
            || self.boot_id != boot
            || self.started_monotonic_ms > now
            || self.started_monotonic_ms.checked_add(CANDIDATE_MS)
                != Some(self.deadline_monotonic_ms)
            || now >= self.deadline_monotonic_ms
        {
            return Err("pool workflow clock changed or original deadline expired".into());
        }
        Ok(())
    }

    pub fn check_window(&self, window: &Window) -> Result<(), Error> {
        self.validate_at(&self.boot_id, self.started_monotonic_ms)?;
        window.validate_shape()?;
        if window.boot_id != self.boot_id
            || window.issued_monotonic_ms < self.started_monotonic_ms
            || window.issued_monotonic_ms >= self.deadline_monotonic_ms
        {
            return Err("pool service window is outside its original workflow".into());
        }
        Ok(())
    }

    pub fn validate_live(&self) -> Result<(), Error> {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        self.validate_at(boot.trim(), monotonic_ms()?)
    }
}

pub(super) struct Clock {
    anchor: Instant,
    offset_ms: u64,
}

impl Clock {
    pub fn new(workflow: Option<&Workflow>, legacy_start: Instant) -> Result<Self, Error> {
        let Some(workflow) = workflow else {
            return Ok(Self {
                anchor: legacy_start,
                offset_ms: 0,
            });
        };
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        // Capture Instant first and round the monotonic sample upward. Sampling
        // and millisecond quantization may shorten, never renew, the horizon.
        let anchor = Instant::now();
        let now = monotonic_ms()?;
        workflow.validate_at(boot.trim(), now)?;
        Ok(Self {
            anchor,
            offset_ms: now - workflow.started_monotonic_ms + 1,
        })
    }

    pub fn now(&self) -> u64 {
        self.offset_ms
            .saturating_add(u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

fn monotonic_ms() -> Result<u64, Error> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    u64::try_from(value.tv_sec)?
        .checked_mul(1_000)
        .and_then(|ms| ms.checked_add(u64::try_from(value.tv_nsec).ok()? / 1_000_000))
        .ok_or_else(|| "pool monotonic clock overflow".into())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    schema_version: u32,
    gpu_uuid: String,
    executable: [u8; 32],
    identity: [[u8; 32]; 5],
    #[serde(deserialize_with = "records")]
    records: Vec<Record>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

fn records<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Record>, D::Error> {
    input::bounded::<D, Record, MAX_RECORDS>(d)
}

pub(super) struct Loaded {
    pub identity: TimingIdentity,
    records: Vec<(TimingCalibration, [u8; 32])>,
}

impl Loaded {
    pub fn load(path: &Path, executable: [u8; 32], uuid: &str) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err("pool timing approval path must be absolute".into());
        }
        let approval: Approval = read_json(path)?;
        if approval.schema_version != 1
            || approval.gpu_uuid != uuid
            || approval.executable != executable
            || approval.records.is_empty()
        {
            return Err("pool timing approval image/device/record mismatch".into());
        }
        let [backend, kernels, device, driver, settings] = approval.identity;
        let identity = TimingIdentity::new(backend, kernels, executable, device, driver, settings)?;
        let mut records = input::exact(approval.records.len())?;
        for record in approval.records {
            if !record.path.is_absolute() || record.evidence == [0; 32] {
                return Err("pool timing record needs an absolute path and host evidence".into());
            }
            let bytes = read_bytes(&record.path, TimingCalibration::ENCODED_BYTES)?;
            if bytes.len() != TimingCalibration::ENCODED_BYTES
                || configuration_digest(&bytes)? != record.content_identity
            {
                return Err("pool timing record content changed".into());
            }
            records.push((TimingCalibration::decode_host(&bytes)?, record.evidence));
        }
        Ok(Self { identity, records })
    }

    /// Validate the complete import before the supervised process is started.
    /// Binding to its actual immutable descriptor also checks resource classes.
    pub fn check(&self, worker: &ProcessWorker) -> Result<(), Error> {
        let capabilities = worker.scheduling_capabilities_with_timing(self.identity)?;
        self.check_capabilities(&capabilities)
    }

    fn check_capabilities(&self, capabilities: &WorkerCapabilities) -> Result<(), Error> {
        let mut costs = CostModel::new(SERVICE_MS)?;
        for (record, evidence) in &self.records {
            costs.import_calibration(capabilities, record, *evidence)?;
        }
        Ok(())
    }

    pub fn install(self, pool: &mut PoolCoordinator, worker: WorkerId) -> Result<(), Error> {
        for (record, evidence) in self.records {
            pool.import_worker_calibration(worker, &record, evidence)?;
        }
        Ok(())
    }
}

/// Known payloads only: bounded JSON bytes, decoder scratch, path strings and
/// record metadata, one record read, and retained decoded worker approvals.
/// Moving approvals from slots to the import list can overlap their headers.
pub(super) fn storage_bytes(workers: usize) -> Result<u64, Error> {
    if !(1..=16).contains(&workers) {
        return Err("pool timing worker count".into());
    }
    let bytes = 3 * JSON_LIMIT
        + 2 * (size_of::<Option<Workflow>>() + 36)
        + size_of::<Clock>()
        + MAX_RECORDS * size_of::<Record>()
        + size_of::<Approval>()
        + TimingCalibration::ENCODED_BYTES
        + workers
            * (2 * size_of::<Option<Loaded>>()
                + size_of::<WorkerId>()
                + size_of::<Option<u64>>()
                + MAX_RECORDS * size_of::<(TimingCalibration, [u8; 32])>());
    Ok(u64::try_from(bytes)?)
}

#[cfg(test)]
#[path = "execution_pool_timing_tests.rs"]
mod tests;
