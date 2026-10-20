//! Proving policy and bounded, per-operation stage reports.
//!
//! A compiled GPU feature is not evidence that a proof was generated on GPU.
//! Admission uses the selected implementation's complete stage inventory. Actual
//! observations remain separate: an opaque upstream call never establishes stage
//! coverage. Reports contain code metadata and timings, never inputs or RNG state.
use serde::Serialize;
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

mod composition;
pub(crate) use composition::CachedScope;
pub use composition::ComponentObservation;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    Compatible,
    CpuRequired,
    GpuRequired,
}

impl Policy {
    pub fn parse(value: Option<&str>) -> Result<Self, Error> {
        match value {
            None | Some("compatible") => Ok(Self::Compatible),
            Some("cpu-required") => Ok(Self::CpuRequired),
            Some("gpu-required") => Ok(Self::GpuRequired),
            _ => Err(Error::InvalidPolicy),
        }
    }
    fn allows(self, backend: Backend) -> bool {
        match self {
            Self::Compatible => true,
            Self::CpuRequired => backend == Backend::Cpu,
            Self::GpuRequired => {
                matches!(backend, Backend::OpenCl | Backend::Metal | Backend::Cuda)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Cpu,
    OpenCl,
    Metal,
    Cuda,
    Mixed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    PublicValues,
    WitnessTrace,
    Preprocessing,
    Lookup,
    Transform,
    Quotient,
    Randomness,
    Hiding,
    Commitment,
    Opening,
    FriFold,
    FriQuery,
    FinalPolynomial,
    Scalar,
    Transcript,
    Grinding,
    /// Timing envelope only. It proves nothing about the individual stages.
    UpstreamProver,
    /// Explicit host-side constraint validation in debug proving builds.
    /// This is not part of the arithmetic inventory and cannot satisfy it.
    ConstraintAudit,
    Serialization,
}

impl Stage {
    pub const ARITHMETIC: [Self; 16] = [
        Self::PublicValues,
        Self::WitnessTrace,
        Self::Preprocessing,
        Self::Lookup,
        Self::Transform,
        Self::Quotient,
        Self::Randomness,
        Self::Hiding,
        Self::Commitment,
        Self::Opening,
        Self::FriFold,
        Self::FriQuery,
        Self::FinalPolynomial,
        Self::Scalar,
        Self::Transcript,
        Self::Grinding,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    LegacyQuadratic,
    BlockV2Cubic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StageCapability {
    pub stage: Stage,
    pub backend: Backend,
}

/// What the operation receives as input and therefore promises to compute.
/// Component coverage does not establish coverage of its caller's whole request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageScope {
    ProofRequest,
    Statement,
    RegistryCompilation,
    Preprocessing,
    RegisteredProof,
    Operation,
}

#[derive(Clone, Debug, Serialize)]
pub struct Capabilities {
    scope: CoverageScope,
    profile: Profile,
    max_log_fri_arity: u8,
    stages: Vec<StageCapability>,
}

impl Capabilities {
    pub fn cpu(profile: Profile, preprocessing: bool, lookup: bool) -> Self {
        Self {
            scope: CoverageScope::ProofRequest,
            profile,
            max_log_fri_arity: match profile {
                Profile::LegacyQuadratic => 4,
                Profile::BlockV2Cubic => 1,
            },
            stages: Stage::ARITHMETIC
                .into_iter()
                .filter(|s| {
                    (*s != Stage::Preprocessing || preprocessing) && (*s != Stage::Lookup || lookup)
                })
                .map(|stage| StageCapability {
                    stage,
                    backend: Backend::Cpu,
                })
                .collect(),
        }
    }
    pub(crate) fn set(&mut self, stage: Stage, backend: Backend) {
        let slot = self
            .stages
            .iter_mut()
            .find(|s| s.stage == stage)
            .expect("stage must belong to this proving path");
        slot.backend = backend;
    }
    pub fn stages(&self) -> &[StageCapability] {
        &self.stages
    }
    pub fn scope(&self) -> CoverageScope {
        self.scope
    }
    pub(crate) fn scoped(mut self, scope: CoverageScope, stages: &[Stage]) -> Self {
        assert!(stages
            .iter()
            .all(|stage| self.stages.iter().any(|s| s.stage == *stage)));
        self.stages.retain(|entry| stages.contains(&entry.stage));
        self.scope = scope;
        self
    }
    #[cfg(debug_assertions)]
    pub(crate) fn with_constraint_audit(mut self) -> Self {
        self.stages.push(StageCapability {
            stage: Stage::ConstraintAudit,
            backend: Backend::Cpu,
        });
        self
    }
    pub fn admit(&self, policy: Policy) -> Result<(), Error> {
        // Empty inventories must never admit a strict request vacuously.
        if self.stages.is_empty() {
            return Err(Error::MissingInventory);
        }
        let gaps: Vec<_> = self
            .stages
            .iter()
            .filter(|s| !policy.allows(s.backend))
            .cloned()
            .collect();
        if gaps.is_empty() {
            Ok(())
        } else {
            Err(Error::Unsupported { policy, gaps })
        }
    }
}

pub fn legacy_cpu() -> Capabilities {
    Capabilities::cpu(Profile::LegacyQuadratic, false, false)
}

#[cfg(feature = "gpu")]
pub(crate) fn legacy_opencl(hiding: bool) -> Capabilities {
    let mut capabilities = legacy_cpu();
    // Host conversion/domain preparation remains in the current DFT adapter.
    capabilities.set(Stage::Transform, Backend::Mixed);
    if hiding {
        capabilities.set(Stage::Commitment, Backend::Mixed);
        capabilities.set(Stage::Hiding, Backend::Mixed);
        capabilities.set(Stage::FriQuery, Backend::Mixed);
    }
    capabilities
}

/// The legacy ABI preserves its error code and never initializes a GPU here.
pub(crate) fn legacy_abi_admission() -> bool {
    legacy_cpu_admission().is_ok()
}

pub(crate) fn legacy_cpu_admission() -> Result<(), Error> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() {
        return Err(Error::ComponentRejected);
    }
    Request::from_env().and_then(|r| r.admit(&legacy_cpu()))
}

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub policy: Policy,
    pub emit_report: bool,
}

impl Request {
    pub fn compatible() -> Self {
        Self {
            policy: Policy::Compatible,
            emit_report: false,
        }
    }
    pub fn from_env() -> Result<Self, Error> {
        let policy = match std::env::var("LATTICA_PROVING_POLICY") {
            Ok(value) => Policy::parse(Some(&value))?,
            Err(std::env::VarError::NotPresent) => Policy::Compatible,
            Err(_) => return Err(Error::InvalidPolicy),
        };
        let emit_report = match std::env::var("LATTICA_PROVING_REPORT") {
            Err(std::env::VarError::NotPresent) => false,
            Ok(value) if value == "0" => false,
            Ok(value) if value == "1" => true,
            _ => return Err(Error::InvalidReportSwitch),
        };
        Ok(Self {
            policy,
            emit_report,
        })
    }
    pub fn admit(self, capabilities: &Capabilities) -> Result<(), Error> {
        let assigned = std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_some();
        #[cfg(all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda")))]
        let assigned = assigned || crate::block_v2::wallet_worker::is_assigned();
        // A local wallet assignment cannot be downgraded through a Rust request,
        // a changed environment, or a CPU ABI that bypasses GPU selection.
        if assigned && self.policy != Policy::GpuRequired {
            return Err(Error::ComponentRejected);
        }
        capabilities.admit(self.policy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidPolicy,
    InvalidReportSwitch,
    MissingInventory,
    Unsupported {
        policy: Policy,
        gaps: Vec<StageCapability>,
    },
    StageRejected {
        policy: Policy,
        stage: Stage,
        backend: Backend,
    },
    Finished,
    ObservationOverflow,
    ComponentRejected,
    IncompleteCoverage {
        missing: Vec<StageCapability>,
        missing_components: Vec<&'static str>,
        unaccounted: Vec<StageCapability>,
        observation_errors: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str(
                "LATTICA_PROVING_POLICY must be compatible, cpu-required or gpu-required",
            ),
            Self::InvalidReportSwitch => f.write_str("LATTICA_PROVING_REPORT must be 0 or 1"),
            Self::MissingInventory => f.write_str("proving stage inventory is empty"),
            Self::Unsupported { policy, gaps } => write!(
                f,
                "proving policy {policy:?} is not supported by the selected path: {gaps:?}"
            ),
            Self::StageRejected {
                policy,
                stage,
                backend,
            } => write!(
                f,
                "proving policy {policy:?} rejected {stage:?} on {backend:?}"
            ),
            Self::Finished => f.write_str("proving stage recorded after report completion"),
            Self::ObservationOverflow => f.write_str("proving device observation counter overflow"),
            Self::ComponentRejected => f.write_str("proving component receipt rejected"),
            Self::IncompleteCoverage { missing, missing_components, unaccounted, observation_errors } => write!(
                f,
                "GPU proving completion rejected: missing {missing:?}, missing components {missing_components:?}, unaccounted {unaccounted:?}, observation errors {observation_errors}"
            ),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub stage: Stage,
    pub backend: Backend,
    pub calls: u64,
    pub completed_calls: u64,
    /// Completed operations reported by a device executor, excluding wall-time envelopes.
    pub device_calls: u64,
    /// Inclusive wall time; nested/concurrent entries must not be summed.
    pub inclusive_ns: u128,
    /// Device event time, independent of inclusive CPU wall intervals.
    pub device_ns: u128,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub entry_point: &'static str,
    pub policy: Policy,
    pub capabilities: Capabilities,
    pub elapsed_ns: u128,
    pub succeeded: bool,
    pub stage_coverage_complete: bool,
    /// A successful computation was withheld because strict GPU coverage failed.
    pub completion_rejected: bool,
    /// Lost or inconsistent executor observations prevent a coverage claim.
    pub observation_errors: u64,
    pub observations: Vec<Observation>,
    /// Explicit child completions; cached scopes never add fresh device work.
    pub components: Vec<ComponentObservation>,
}

struct State {
    observations: Vec<Observation>,
    components: Vec<ComponentObservation>,
    /// Authenticated setup provenance, never a synthetic device observation.
    cached_preprocessing: bool,
    finished: bool,
    observation_errors: u64,
}

/// One operation, with a bounded (stage, backend) table shared by its closures.
/// Pass a reference explicitly to parallel work; do not rely on thread-local state.
pub struct Run {
    request: Request,
    entry_point: &'static str,
    capabilities: Capabilities,
    started: Instant,
    state: Arc<Mutex<State>>,
    parent: Option<composition::Parent>,
}

impl Run {
    /// Process-local identity for a CUDA attempt. This never enters a report or
    /// worker payload; the borrowing scope keeps the underlying state alive.
    #[cfg(feature = "gpu-cuda")]
    pub(crate) fn cuda_report_identity(&self) -> usize {
        Arc::as_ptr(&self.state) as usize
    }

    #[cfg(feature = "gpu-cuda")]
    pub(crate) fn cuda_require_capabilities(&self, expected: &Capabilities) -> Result<(), Error> {
        if self.capabilities.scope != expected.scope
            || self.capabilities.profile != expected.profile
            || self.capabilities.max_log_fri_arity != expected.max_log_fri_arity
            || self.capabilities.stages != expected.stages
        {
            return Err(Error::ComponentRejected);
        }
        self.cuda_inventory()?;
        Ok(())
    }

    #[cfg(feature = "gpu-cuda")]
    pub(crate) fn cuda_inventory(&self) -> Result<[bool; 16], Error> {
        if self.state.lock().map_err(|_| Error::Finished)?.finished {
            return Err(Error::Finished);
        }
        let mut stages = [false; 16];
        for (index, stage) in Stage::ARITHMETIC.into_iter().enumerate() {
            if self
                .capabilities
                .stages
                .iter()
                .any(|s| s.stage == stage && s.backend == Backend::Cuda)
            {
                self.check_device_stage(stage, Backend::Cuda)?;
                stages[index] = true;
            }
        }
        if !stages.iter().any(|&enabled| enabled) {
            return Err(Error::MissingInventory);
        }
        Ok(stages)
    }

    pub fn new(
        entry_point: &'static str,
        request: Request,
        capabilities: Capabilities,
    ) -> Result<Self, Error> {
        request.admit(&capabilities)?;
        #[cfg(all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda")))]
        if crate::block_v2::wallet_worker::is_assigned() {
            crate::block_v2::wallet_worker::admit(request).map_err(|_| Error::ComponentRejected)?;
        }
        #[cfg(not(all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda"))))]
        if std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_some() {
            return Err(Error::ComponentRejected);
        }
        Ok(Self {
            request,
            entry_point,
            capabilities,
            started: Instant::now(),
            state: Arc::new(Mutex::new(State {
                observations: Vec::new(),
                components: Vec::new(),
                cached_preprocessing: false,
                finished: false,
                observation_errors: 0,
            })),
            parent: None,
        })
    }
    pub fn measure<T>(
        &self,
        stage: Stage,
        backend: Backend,
        body: impl FnOnce() -> T,
    ) -> Result<T, Error> {
        // Serialization is host byte movement. An opaque upstream call is not
        // evidence that required-GPU arithmetic ran on device, even if so labeled.
        if (stage == Stage::UpstreamProver && self.request.policy == Policy::GpuRequired)
            || (stage != Stage::Serialization && !self.request.policy.allows(backend))
        {
            return Err(Error::StageRejected {
                policy: self.request.policy,
                stage,
                backend,
            });
        }
        let index = {
            let mut state = self.state.lock().unwrap();
            if state.finished {
                return Err(Error::Finished);
            }
            let index = state
                .observations
                .iter()
                .position(|o| o.stage == stage && o.backend == backend)
                .unwrap_or_else(|| {
                    state.observations.push(Observation {
                        stage,
                        backend,
                        calls: 0,
                        completed_calls: 0,
                        device_calls: 0,
                        inclusive_ns: 0,
                        device_ns: 0,
                    });
                    state.observations.len() - 1
                });
            state.observations[index].calls += 1;
            index
        };
        let mut timer = Timer {
            run: self,
            index,
            started: Instant::now(),
            completed: false,
        };
        let value = body();
        timer.completed = true;
        Ok(value)
    }
    #[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
    pub(crate) fn check_device_stage(&self, stage: Stage, backend: Backend) -> Result<(), Error> {
        if stage == Stage::UpstreamProver
            || !matches!(backend, Backend::OpenCl | Backend::Metal | Backend::Cuda)
            || !self.request.policy.allows(backend)
        {
            return Err(Error::StageRejected {
                policy: self.request.policy,
                stage,
                backend,
            });
        }
        Ok(())
    }

    /// Record successful device operations from session counters, including
    /// operations completed before a later proof failure. No wall time is
    /// inferred from a whole-proof envelope or a capability declaration.
    #[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
    pub(crate) fn observe_device(
        &self,
        stage: Stage,
        backend: Backend,
        completed_calls: u64,
        device_ns: u128,
    ) -> Result<(), Error> {
        self.check_device_stage(stage, backend)?;
        let Ok(mut state) = self.state.lock() else {
            return Err(Error::Finished);
        };
        if state.finished {
            return Err(Error::Finished);
        }
        if completed_calls == 0 && device_ns == 0 {
            return Ok(());
        }
        if let Some(observation) = state
            .observations
            .iter_mut()
            .find(|o| o.stage == stage && o.backend == backend)
        {
            let next = (
                observation.calls.checked_add(completed_calls),
                observation.completed_calls.checked_add(completed_calls),
                observation.device_calls.checked_add(completed_calls),
                observation.device_ns.checked_add(device_ns),
            );
            let (Some(calls), Some(completed), Some(device_calls), Some(ns)) = next else {
                state.observation_errors = state.observation_errors.saturating_add(1);
                return Err(Error::ObservationOverflow);
            };
            observation.calls = calls;
            observation.completed_calls = completed;
            observation.device_calls = device_calls;
            observation.device_ns = ns;
        } else {
            state.observations.push(Observation {
                stage,
                backend,
                calls: completed_calls,
                completed_calls,
                device_calls: completed_calls,
                inclusive_ns: 0,
                device_ns,
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
    pub(crate) fn observation_failed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.observation_errors = state.observation_errors.saturating_add(1);
        }
    }

    /// Finalize before releasing the operation's output. Strict GPU requests
    /// require completed device receipts for the admitted inventory; a successful
    /// computation with incomplete coverage must not escape as a successful proof.
    pub fn finish(self, succeeded: bool) -> Result<Report, Error> {
        let mut state = self.state.lock().unwrap();
        state.finished = true;
        // A composed request can reuse numerical preprocessing only alongside
        // a fresh, fully accounted registered proof. Cache-only requests and
        // missing/failed components still cannot complete the parent inventory.
        let reused_preprocessing = self.capabilities.scope == CoverageScope::ProofRequest
            && state.cached_preprocessing
            && state.components.iter().any(|component| {
                component.scope == CoverageScope::RegisteredProof
                    && !component.cached
                    && component.succeeded
                    && component.stage_coverage_complete
            });
        let missing: Vec<_> = self
            .capabilities
            .stages
            .iter()
            .filter(|s| {
                if s.stage == Stage::Preprocessing && reused_preprocessing {
                    return false;
                }
                !state.observations.iter().any(|o| {
                    o.stage == s.stage
                        && o.backend == s.backend
                        && o.completed_calls > 0
                        && (!matches!(s.backend, Backend::OpenCl | Backend::Metal | Backend::Cuda)
                            || o.device_calls > 0)
                })
            })
            .cloned()
            .collect();
        let unaccounted: Vec<_> = state
            .observations
            .iter()
            .filter(|o| {
                o.stage == Stage::UpstreamProver
                    || matches!(o.backend, Backend::Mixed | Backend::Unknown)
                    || o.calls != o.completed_calls
                    || (o.stage != Stage::Serialization
                        && !self
                            .capabilities
                            .stages
                            .iter()
                            .any(|s| s.stage == o.stage && s.backend == o.backend))
            })
            .map(|o| StageCapability {
                stage: o.stage,
                backend: o.backend,
            })
            .collect();
        let missing_components: Vec<_> = state
            .components
            .iter()
            .filter(|c| !c.succeeded || !c.stage_coverage_complete)
            .map(|c| c.id)
            .collect();
        let complete = succeeded
            && missing_components.is_empty()
            && state.observation_errors == 0
            && missing.is_empty()
            && unaccounted.is_empty();
        let completion_rejected =
            succeeded && self.request.policy == Policy::GpuRequired && !complete;
        let report = Report {
            schema: "lattica-proving-stages-v1",
            entry_point: self.entry_point,
            policy: self.request.policy,
            capabilities: self.capabilities.clone(),
            elapsed_ns: self.started.elapsed().as_nanos(),
            succeeded: succeeded && !completion_rejected,
            stage_coverage_complete: complete,
            completion_rejected,
            observation_errors: state.observation_errors,
            observations: std::mem::take(&mut state.observations),
            components: std::mem::take(&mut state.components),
        };
        drop(state);
        self.publish(&report);
        if completion_rejected {
            Err(Error::IncompleteCoverage {
                missing,
                missing_components,
                unaccounted,
                observation_errors: report.observation_errors,
            })
        } else {
            Ok(report)
        }
    }
}

impl Run {
    fn publish(&self, report: &Report) {
        if let Some(parent) = &self.parent {
            parent.record(report);
        }
        if self.request.emit_report {
            if let Ok(json) = serde_json::to_string(report) {
                eprintln!("proving_stage_report {json}");
            }
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        // Preserve partial receipts on early return/unwind, including child work
        // whose optional JSON report is disabled. Never panic during unwinding.
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.finished {
            return;
        }
        state.finished = true;
        let report = Report {
            schema: "lattica-proving-stages-v1",
            entry_point: self.entry_point,
            policy: self.request.policy,
            capabilities: self.capabilities.clone(),
            elapsed_ns: self.started.elapsed().as_nanos(),
            succeeded: false,
            stage_coverage_complete: false,
            completion_rejected: false,
            observation_errors: state.observation_errors,
            observations: std::mem::take(&mut state.observations),
            components: std::mem::take(&mut state.components),
        };
        drop(state);
        self.publish(&report);
    }
}

struct Timer<'a> {
    run: &'a Run,
    index: usize,
    started: Instant,
    completed: bool,
}
impl Drop for Timer<'_> {
    fn drop(&mut self) {
        let mut state = self.run.state.lock().unwrap();
        let observation = &mut state.observations[self.index];
        observation.inclusive_ns += self.started.elapsed().as_nanos();
        observation.completed_calls += u64::from(self.completed);
    }
}

#[cfg(test)]
mod tests;

// Request-boundary regressions must see CPU witness-oracle calls even when
// they happen outside an inner prover's stage-report scope. Test only: no
// production counter, environment switch or additional proving work is added.
#[cfg(test)]
thread_local! {
    static CPU_WITNESS_ORACLE_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn record_cpu_witness_oracle() {
    CPU_WITNESS_ORACLE_CALLS.with(|calls| calls.set(calls.get() + 1));
}

#[cfg(test)]
pub(crate) fn cpu_witness_oracle_calls() -> u64 {
    CPU_WITNESS_ORACLE_CALLS.with(std::cell::Cell::get)
}
