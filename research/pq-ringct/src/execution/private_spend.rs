//! Native private-spend creation on the worker's owned GPU session.
//!
//! This operation has its own receipt and diagnostics. It is not a STARK or
//! recursive proof, and never contributes to their coverage or call totals.
use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::private_spend::{
        self as native_spend, PrivateSpendOutput, PrivateSpendRequest, SpendEvidence, SpendLimits,
        ENTRY_POINT,
    },
    proving::{Backend, CoverageScope, Profile, Report, Stage},
};

const REQUIRED_PRELUDE_STEPS: u32 = 0x0000_003f;
const REQUIRED_ACCEPTED_ATTEMPT_STEPS: u32 = 0x03ff_ffc0;

#[cfg(feature = "native-spend-oracle")]
struct OracleKey([u8; 32]);

#[cfg(feature = "native-spend-oracle")]
fn wipe_oracle_key(key: &mut [u8; 32]) {
    for byte in key {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(feature = "native-spend-oracle")]
impl OracleKey {
    fn copy_for_oracle(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(feature = "native-spend-oracle")]
impl Drop for OracleKey {
    fn drop(&mut self) {
        wipe_oracle_key(&mut self.0);
    }
}

fn validate_spend_report(report: &Report) -> Result<(), String> {
    if report.entry_point != ENTRY_POINT
        || report.policy != Policy::GpuRequired
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || !report.components.is_empty()
        || report.capabilities.profile() != Profile::MatrictN10
        || report.capabilities.scope() != CoverageScope::Operation
        || report.capabilities.stages().len() != 1
        || report.observations.len() != 1
    {
        return Err("native spend returned an incomplete MatRiCT operation report".into());
    }
    let capability = &report.capabilities.stages()[0];
    let observation = &report.observations[0];
    if capability.stage != Stage::WitnessTrace
        || capability.backend != Backend::OpenCl
        || observation.stage != Stage::WitnessTrace
        || observation.backend != Backend::OpenCl
        || observation.calls == 0
        || observation.calls != observation.completed_calls
        || observation.device_calls == 0
        || observation.device_calls > observation.completed_calls
    {
        return Err("native spend lacks completed OpenCL witness-operation receipts".into());
    }
    Ok(())
}

fn validate_spend_evidence(evidence: &SpendEvidence, device_bytes: u64) -> Result<(), String> {
    if evidence.prelude_steps != REQUIRED_PRELUDE_STEPS
        || evidence.accepted_attempt_steps != REQUIRED_ACCEPTED_ATTEMPT_STEPS
    {
        return Err("native spend lacks the complete prelude or accepted-attempt schedule".into());
    }
    // Managed GPU bytes and host staging bytes are separate allowances.
    let managed_bytes = u64::try_from(evidence.managed_bytes)
        .map_err(|_| "native spend managed-byte count exceeds the device budget type")?;
    if managed_bytes == 0 || managed_bytes > device_bytes {
        return Err("native spend managed bytes exceed the owned device allowance".into());
    }
    if evidence.kernel_source_sha256.len() != 64
        || !evidence
            .kernel_source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("native spend lacks a complete kernel source digest".into());
    }
    Ok(())
}

impl ProvingContext {
    /// Create the native MatRiCT spend under the worker's owned GPU session.
    /// The device controller samples and rejects privately; the returned report
    /// covers native spend creation only. This does not create a STARK proof.
    pub fn create_matrict_spend_on_gpu(
        &self,
        input: PrivateSpendRequest,
        limits: SpendLimits,
    ) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
        self.with_matrict_spend(limits, |request| {
            native_spend::create_spend(input, limits, request)
        })
    }

    /// Deterministic test-oracle entry point. Explicit feature gating keeps a
    /// caller-supplied private seed out of the production spend API.
    #[cfg(feature = "native-spend-oracle")]
    pub fn create_matrict_spend_on_gpu_for_oracle(
        &self,
        input: PrivateSpendRequest,
        limits: SpendLimits,
        mut key: [u8; 32],
    ) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
        let oracle_key = OracleKey(key);
        wipe_oracle_key(&mut key);
        self.with_matrict_spend(limits, |request| {
            native_spend::create_spend_for_oracle(
                input,
                limits,
                request,
                oracle_key.copy_for_oracle(),
            )
        })
    }

    fn with_matrict_spend(
        &self,
        limits: SpendLimits,
        operation: impl FnOnce(Request) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String>,
    ) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
        if self.policy() != Policy::GpuRequired {
            return Err("native spend requires an owned GPU-required context".into());
        }
        let session = self
            .session
            .as_ref()
            .ok_or("native spend requires an owned OpenCL session")?;
        let host_bytes = u64::try_from(limits.host_bytes)
            .map_err(|_| "native spend host allowance exceeds the worker budget type")?;
        if host_bytes == 0 || host_bytes > self.host_bytes {
            return Err("native spend host allowance exceeds worker allowance".into());
        }
        let device_bytes = session.limits().device_bytes;
        self.release_prepared()?;
        let _serial = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant native spend operation")?;
        let started = Instant::now();
        let result = operation(self.request).and_then(|(output, report, evidence)| {
            validate_spend_report(&report)?;
            validate_spend_evidence(&evidence, device_bytes)?;
            Ok((output, report, evidence))
        });
        self.diagnostics.native_spend_finished(
            started.elapsed().as_secs_f64(),
            result.as_ref().ok().map(|(_, report, evidence)| (report, evidence)),
        );
        if let Err(ref message) = result {
            self.diagnostics
                .failure("native_spend", Value::Null, message, None);
        }
        result
    }
}
