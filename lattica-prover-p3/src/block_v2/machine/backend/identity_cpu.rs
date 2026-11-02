//! Bounded CPU identity hashing. GPU preprocessing and proof policy are separate.
use super::{identity_stream, MachineAir};
use crate::block_v2::{
    commitment::{self, stream::State},
    machine::{analysis, fingerprint, program::Program},
    profile,
};
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Report, Request, Run, Stage};
use p3_field::PrimeField64;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};

const DOMAIN: u64 = 0x4c42563210;
pub const MAX_IDENTITY_STREAMS: usize = 16;
pub const WORKER_STACK_BYTES: u64 = 2 << 20;
pub const IDENTITY_PREFIX_HOST_BYTES: u64 = fingerprint::bounded::RETAINED_BYTES as u64 + 4096;
const IDENTITY_PREFIX_CONSTRUCTION_BYTES: u64 = fingerprint::bounded::HOST_BYTES as u64 + 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct IdentityCpuOptions {
    pub requested_workers: Option<usize>,
    max_streams: usize,
}
impl Default for IdentityCpuOptions {
    fn default() -> Self {
        Self {
            requested_workers: None,
            max_streams: physical_core_count().unwrap_or(1).min(MAX_IDENTITY_STREAMS),
        }
    }
}
impl IdentityCpuOptions {
    pub fn workers(n: usize) -> Result<Self, &'static str> {
        if !(1..=MAX_IDENTITY_STREAMS).contains(&n) {
            return Err("identity CPU workers must be 1..=16");
        }
        Ok(Self {
            requested_workers: Some(n),
            max_streams: n.min(physical_core_count().unwrap_or(1)),
        })
    }
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value == "auto" {
            Ok(Self::default())
        } else {
            Self::workers(value.parse().map_err(|_| "expected auto or 1..=16")?)
        }
    }
    pub fn max_streams(self) -> usize {
        self.max_streams
    }
    /// Largest independent cohort whose incremental CPU storage fits the
    /// supplied original reservation. Program owners stay charged separately.
    pub fn fit_ready(self, ready: usize, host_allowance: u64) -> Result<Self, String> {
        for count in (1..=ready.min(self.max_streams)).rev() {
            if IdentityBatchFootprint::for_borrowed_program_bounds(count, 0)?.host_bytes
                <= host_allowance
            {
                return self.limited_to(count).map_err(str::to_owned);
            }
        }
        Err("one CPU identity job does not fit the original reservation".into())
    }
    pub fn parallel(self) -> bool {
        self.max_streams > 1
    }
    /// Lower a pre-dispatch cohort without changing the user's requested ceiling.
    pub fn limited_to(mut self, n: usize) -> Result<Self, &'static str> {
        if n == 0 || n > self.max_streams {
            return Err("invalid CPU cohort limit");
        }
        self.max_streams = n;
        Ok(self)
    }
}

/// Count distinct allowed (socket, core) pairs, never SMT siblings. Unknown
/// topology conservatively admits only one worker. The guard records affinity.
pub fn physical_core_count() -> Result<usize, String> {
    #[cfg(target_os = "linux")]
    {
        let status =
            std::fs::read_to_string("/proc/self/status").map_err(|_| "CPU affinity unavailable")?;
        let allowed = status
            .lines()
            .find_map(|s| s.strip_prefix("Cpus_allowed_list:\t"))
            .ok_or("CPU affinity missing")?;
        let mut cores = std::collections::BTreeSet::new();
        for range in allowed.trim().split(',') {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            let first: usize = first.parse().map_err(|_| "CPU affinity range")?;
            let last: usize = last.parse().map_err(|_| "CPU affinity range")?;
            if last < first || last > 65535 {
                return Err("CPU affinity range".into());
            }
            for cpu in first..=last {
                let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
                let socket = std::fs::read_to_string(format!("{base}/physical_package_id"))
                    .map_err(|_| "CPU socket topology")?;
                let core = std::fs::read_to_string(format!("{base}/core_id"))
                    .map_err(|_| "CPU core topology")?;
                cores.insert((socket.trim().to_owned(), core.trim().to_owned()));
            }
        }
        if cores.is_empty() {
            return Err("empty CPU affinity".into());
        }
        Ok(cores.len())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(1)
    }
}

#[derive(serde::Serialize)]
pub struct RegistrationReports {
    pub preprocessing: Report,
    pub identity: Report,
}
pub(super) fn cpu_run(entry: &'static str) -> Result<Run, String> {
    cpu_run_with_report(entry, false)
}
pub(super) fn cpu_run_with_report(entry: &'static str, emit_report: bool) -> Result<Run, String> {
    Run::new(
        entry,
        Request {
            policy: Policy::CpuRequired,
            emit_report,
        },
        Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, false)
            .scoped(CoverageScope::Operation, &[Stage::Preprocessing]),
    )
    .map_err(|e| e.to_string())
}
fn prefix_len(
    air: &MachineAir,
    analysis: &analysis::MachineAnalysis,
    fingerprint: &[u64],
) -> Result<usize, String> {
    identity_stream::Cursor::new(air, analysis, fingerprint).try_fold(0usize, |n, word| {
        if word? >= commitment::MODULUS {
            return Err("noncanonical identity field".into());
        }
        n.checked_add(1)
            .ok_or_else(|| "identity length overflow".into())
    })
}
pub(super) fn hash(
    air: &MachineAir,
    analysis: &analysis::MachineAnalysis,
    fingerprint: &[u64],
    common: &p3_batch_stark::CommonData<profile::Config>,
) -> Result<[u64; 4], String> {
    let roots = common
        .preprocessed
        .as_ref()
        .ok_or("identity commitment missing")?
        .commitment
        .roots();
    let count = prefix_len(air, analysis, fingerprint)?
        .checked_add(roots.len().checked_mul(4).ok_or("identity cap size")?)
        .ok_or("identity size")?;
    let mut state = State::new(DOMAIN, count).map_err(|e| format!("{e:?}"))?;
    for field in identity_stream::Cursor::new(air, analysis, fingerprint) {
        state.push(field?).map_err(|e| format!("{e:?}"))?;
    }
    for field in roots.iter().flatten() {
        state
            .push(field.as_canonical_u64())
            .map_err(|e| format!("{e:?}"))?;
    }
    state.finish().map_err(|e| format!("{e:?}"))
}

pub struct IdentityCpuContext {
    authority: Arc<()>,
    next_batch: AtomicU64,
}
impl Default for IdentityCpuContext {
    fn default() -> Self {
        Self::new()
    }
}
impl IdentityCpuContext {
    pub fn new() -> Self {
        Self {
            authority: Arc::new(()),
            next_batch: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityProgramStorage {
    Borrowed,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct IdentityBatchFootprint {
    pub program_storage: IdentityProgramStorage,
    pub borrowed_program_host_bytes: u64,
    pub host_bytes: u64,
    pub retained_host_bytes: u64,
    pub managed_bytes: u64,
    pub max_allocation_bytes: u64,
}
impl IdentityBatchFootprint {
    pub fn for_borrowed_program_bounds(streams: usize, source: u64) -> Result<Self, String> {
        if !(1..=MAX_IDENTITY_STREAMS).contains(&streams) {
            return Err("CPU identity cohort width".into());
        }
        let retained_host_bytes = (streams as u64)
            .checked_mul(IDENTITY_PREFIX_HOST_BYTES)
            .ok_or("CPU identity retained overflow")?;
        // Keep the entire previous construction allowance. Only completed
        // prefixes use the tighter encoded-field bound in retained slots.
        let host_bytes = (streams as u64 * IDENTITY_PREFIX_CONSTRUCTION_BYTES)
            .checked_add(crate::block_v2::machine::symbolic::HOST_BYTES)
            .and_then(|n| n.checked_add(streams as u64 * WORKER_STACK_BYTES + (1 << 20)))
            .ok_or("CPU identity footprint overflow")?;
        host_bytes
            .checked_add(source)
            .ok_or("CPU identity enclosing overflow")?;
        Ok(Self {
            program_storage: IdentityProgramStorage::Borrowed,
            borrowed_program_host_bytes: source,
            host_bytes,
            retained_host_bytes,
            managed_bytes: 0,
            max_allocation_bytes: 0,
        })
    }
}

pub struct CompletedIdentityPrefix {
    authority: Arc<()>,
    batch: u64,
    job: u64,
    program: Arc<Program>,
    header: [u64; 10],
    trailer: [u64; 18],
    fingerprint: Vec<u64>,
    cap_fields: usize,
    state: State,
}
impl CompletedIdentityPrefix {
    pub fn job(&self) -> u64 {
        self.job
    }
    pub fn batch(&self) -> u64 {
        self.batch
    }
    pub fn retained_host_bytes(&self) -> u64 {
        (std::mem::size_of::<Self>()
            + self.fingerprint.capacity() * 8
            + self.state.retained_heap_bytes()) as u64
    }
    pub(super) fn check_owner(
        &self,
        context: &IdentityCpuContext,
        job: u64,
        air: &MachineAir,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&self.authority, &context.authority)
            || self.job != job
            || !std::ptr::eq(self.program.as_ref(), air.program())
        {
            return Err("CPU identity workflow, job or original program mismatch".into());
        }
        Ok(())
    }
    pub(super) fn finish(
        mut self,
        air: &MachineAir,
        analysis: &analysis::MachineAnalysis,
        fingerprint: &[u64],
        common: &p3_batch_stark::CommonData<profile::Config>,
    ) -> Result<[u64; 4], String> {
        let roots = common
            .preprocessed
            .as_ref()
            .ok_or("identity commitment missing")?
            .commitment
            .roots();
        if !std::ptr::eq(self.program.as_ref(), air.program())
            || self.header != identity_stream::header(air)
            || self.trailer != identity_stream::trailer(analysis)
            || self.fingerprint != fingerprint
            || roots.len().checked_mul(4) != Some(self.cap_fields)
        {
            return Err("CPU identity metadata or cap geometry changed".into());
        }
        for field in roots.iter().flatten() {
            self.state
                .push(field.as_canonical_u64())
                .map_err(|e| format!("{e:?}"))?;
        }
        self.state.finish().map_err(|e| format!("{e:?}"))
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod cohort;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub use cohort::{
    BorrowedIdentityBatchPlan, CpuWorkerReport, IdentityBatchReport, PendingBorrowedIdentityBatch,
};
#[cfg(test)]
mod tests;
