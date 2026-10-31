//! Validate the exact native scope. In particular, this never re-labels a
//! registered proof as GPU execution of public-statement compilation.
use super::*;
use lattica_prover_p3::proving::{Backend, CoverageScope, Observation, Profile, Stage};

const MAX_OBSERVATION_CAPACITY: usize = 128;
const MAX_COMPONENT_CAPACITY: usize = 16;
const SETUP_STAGES: [Stage; 4] = [
    Stage::Preprocessing,
    Stage::Randomness,
    Stage::Transform,
    Stage::Commitment,
];

/// Public device identity with individually bounded retained strings. These
/// are copied from the actual selected Session, never from caller metadata.
#[derive(Debug, Serialize)]
pub struct DeviceReceipt {
    pub opencl_index: usize,
    pub uuid: Option<String>,
    pub name: String,
    pub pci: Option<String>,
    pub global_bytes: u64,
    pub max_allocation_bytes: u64,
    pub driver: String,
}

impl DeviceReceipt {
    pub(super) fn from_session(session: &Session) -> Result<Self, Error> {
        fn text(value: &str) -> Result<String, Error> {
            if value.len() > 256 {
                return Err(Error::ResourceLimit);
            }
            Ok(value.to_owned())
        }
        let device = session.device_identity();
        Ok(Self {
            opencl_index: device.opencl_index,
            uuid: device.uuid.as_deref().map(text).transpose()?,
            name: text(&device.name)?,
            pci: device.pci.as_deref().map(text).transpose()?,
            global_bytes: device.global_bytes,
            max_allocation_bytes: device.max_allocation_bytes,
            driver: text(&device.driver)?,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum NativeScope {
    Registration,
    Proof,
}

impl NativeScope {
    fn scope(self) -> CoverageScope {
        match self {
            Self::Registration => CoverageScope::Preprocessing,
            Self::Proof => CoverageScope::RegisteredProof,
        }
    }
    fn entry(self) -> &'static str {
        match self {
            Self::Registration => "block_v2_preprocessing",
            Self::Proof => "block_v2_registered_program",
        }
    }
    fn includes(self, stage: Stage) -> bool {
        match self {
            Self::Registration => SETUP_STAGES.contains(&stage),
            Self::Proof => Stage::ARITHMETIC.contains(&stage) && stage != Stage::PublicValues,
        }
    }
    fn stage_count(self) -> usize {
        match self {
            Self::Registration => 4,
            Self::Proof => 15,
        }
    }
}

pub(super) fn validate(report: &Report, expected: NativeScope) -> Result<(), Error> {
    if report.schema != "lattica-proving-stages-v1"
        || report.entry_point != expected.entry()
        || report.policy != Policy::GpuRequired
        || report.capabilities.scope() != expected.scope()
        || report.capabilities.profile() != Profile::BlockV2Cubic
        || report.capabilities.max_log_fri_arity() != 1
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || report.observations.capacity() > MAX_OBSERVATION_CAPACITY
        || report.components.capacity() > MAX_COMPONENT_CAPACITY
        || !report.components.is_empty()
    {
        return Err(Error::IncompleteProofCoverage);
    }
    let inventory = report.capabilities.stages();
    if inventory.len() != expected.stage_count()
        || inventory.iter().enumerate().any(|(i, entry)| {
            entry.backend != Backend::OpenCl
                || !expected.includes(entry.stage)
                || inventory[..i]
                    .iter()
                    .any(|prior| prior.stage == entry.stage)
        })
    {
        return Err(Error::IncompleteProofCoverage);
    }
    observations(&report.observations, expected)
}

fn observations(observed: &[Observation], expected: NativeScope) -> Result<(), Error> {
    if observed.iter().enumerate().any(|(i, observation)| {
        // The chosen core entry points do not serialize a proof, execute an
        // opaque upstream prover, or compose cached child scopes. A new entry
        // requires explicit requalification instead of loosening this check.
        !expected.includes(observation.stage)
            || observation.backend != Backend::OpenCl
            || observation.calls == 0
            || observation.calls != observation.completed_calls
            || observation.device_calls == 0
            || observed[..i].iter().any(|prior| {
                prior.stage == observation.stage && prior.backend == observation.backend
            })
    }) || Stage::ARITHMETIC
        .into_iter()
        .filter(|&stage| expected.includes(stage))
        .any(|stage| {
            !observed
                .iter()
                .any(|observation| observation.stage == stage)
        })
    {
        return Err(Error::IncompleteProofCoverage);
    }
    Ok(())
}

/// A fixed-size subset of session telemetry. A JSON receipt is only accepted
/// after Session has drained the queue and released the engine. It is not a
/// cryptographic proof or a substitute for the native stage reports.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TerminalReceipt {
    pub host_allowance_bytes: u64,
    pub device_allowance_bytes: u64,
    pub gpu_context_allowance_bytes: u64,
    pub max_rows: u64,
    pub commits: u64,
    pub allocations: u64,
    pub managed_peak_bytes: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub context_closed: bool,
    pub queue_drained: bool,
    pub completion_claimed: bool,
}

impl TerminalReceipt {
    pub(super) fn parse(value: &serde_json::Value, completed: bool) -> Result<Self, Error> {
        fn number(value: &serde_json::Value, name: &str) -> Result<u64, Error> {
            value
                .get(name)
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::IncompleteProofCoverage)
        }
        let receipt = Self {
            host_allowance_bytes: number(value, "host_allowance_bytes")?,
            device_allowance_bytes: number(value, "device_allowance_bytes")?,
            gpu_context_allowance_bytes: number(value, "gpu_context_allowance_bytes")?,
            max_rows: number(value, "max_rows")?,
            commits: number(value, "commits")?,
            allocations: number(value, "allocations")?,
            managed_peak_bytes: number(value, "managed_peak_bytes")?,
            uploaded_bytes: number(value, "uploaded_bytes")?,
            downloaded_bytes: number(value, "downloaded_bytes")?,
            context_closed: value
                .get("context_closed")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            queue_drained: value
                .get("queue_drained")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            completion_claimed: completed,
        };
        if receipt.host_allowance_bytes != HOST_BYTES
            || receipt.device_allowance_bytes != DEVICE_BYTES
            || receipt.gpu_context_allowance_bytes != CONTEXT_BYTES
            || receipt.max_rows != MAX_ROWS as u64
            || receipt.managed_peak_bytes > DEVICE_BYTES
            || !receipt.context_closed
            || !receipt.queue_drained
            || (completed && (receipt.commits == 0 || receipt.allocations == 0))
            || (!completed
                && (value
                    .get("completion_claimed")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
                    || value
                        .get("stark_completion_claimed")
                        .and_then(serde_json::Value::as_bool)
                        != Some(false)))
        {
            return Err(Error::IncompleteProofCoverage);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(scope: NativeScope) -> Vec<Observation> {
        Stage::ARITHMETIC
            .into_iter()
            .filter(|&stage| scope.includes(stage))
            .map(|stage| Observation {
                stage,
                backend: Backend::OpenCl,
                calls: 1,
                completed_calls: 1,
                device_calls: 1,
                inclusive_ns: 1,
                device_ns: 1,
            })
            .collect()
    }

    #[test]
    fn every_required_stage_needs_fresh_completed_device_observations() {
        for scope in [NativeScope::Registration, NativeScope::Proof] {
            let good = complete(scope);
            assert!(observations(&good, scope).is_ok());
            for i in 0..good.len() {
                let mut missing = good.clone();
                missing.remove(i);
                assert_eq!(
                    observations(&missing, scope),
                    Err(Error::IncompleteProofCoverage)
                );
                let mut incomplete = good.clone();
                incomplete[i].completed_calls = 0;
                assert!(observations(&incomplete, scope).is_err());
                let mut host = good.clone();
                host[i].backend = Backend::Cpu;
                assert!(observations(&host, scope).is_err());
                let mut timing_only = good.clone();
                timing_only[i].device_calls = 0;
                assert!(observations(&timing_only, scope).is_err());
            }
            let mut duplicate = good.clone();
            duplicate.push(duplicate[0].clone());
            assert!(observations(&duplicate, scope).is_err());
        }
    }

    fn terminal() -> serde_json::Value {
        serde_json::json!({
            "host_allowance_bytes": HOST_BYTES, "device_allowance_bytes": DEVICE_BYTES,
            "gpu_context_allowance_bytes": CONTEXT_BYTES, "max_rows": MAX_ROWS,
            "commits": 1, "allocations": 1, "managed_peak_bytes": 1,
            "uploaded_bytes": 1, "downloaded_bytes": 1,
            "context_closed": true, "queue_drained": true,
            "completion_claimed": false, "stark_completion_claimed": false,
        })
    }

    #[test]
    fn terminal_receipt_requires_limits_drain_and_actual_context_closure() {
        assert!(TerminalReceipt::parse(&terminal(), true).is_ok());
        assert!(TerminalReceipt::parse(&terminal(), false).is_ok());
        for key in [
            "host_allowance_bytes",
            "device_allowance_bytes",
            "gpu_context_allowance_bytes",
            "max_rows",
            "commits",
            "allocations",
            "context_closed",
            "queue_drained",
        ] {
            let mut bad = terminal();
            bad.as_object_mut().unwrap().remove(key);
            assert!(TerminalReceipt::parse(&bad, true).is_err(), "{key}");
        }
        let mut bad = terminal();
        bad["managed_peak_bytes"] = (DEVICE_BYTES + 1).into();
        assert!(TerminalReceipt::parse(&bad, true).is_err());
        let mut bad = terminal();
        bad["completion_claimed"] = true.into();
        assert!(TerminalReceipt::parse(&bad, false).is_err());
    }
}
