//! Native MatRiCT n10 private-spend creation on an owned OpenCL context.
//!
//! This is a separate operation from proving the spend verification relation.
//! Its receipt must never be counted as a STARK or recursive aggregate proof.
//! CPU input checks, fresh OS entropy and independent verification are explicit
//! host boundaries. Sampling, rejection, proof equations and transcripts are
//! submitted by the device controller, with no CPU implementation fallback.
mod types;

#[cfg(feature = "native-spend-oracle")]
pub mod oracle;
#[cfg(feature = "native-spend-oracle")]
pub mod rng_rejection_oracle;

#[cfg(feature = "native-spend-oracle")]
pub mod phase_oracle;
pub(crate) use types::{input_layout, status, PackedSpendInputs};
pub use types::{
    CanonicalPoly, PrivateOutputKeys, PrivateSpendOutput, PrivateSpendRequest, PrivateSpendWitness,
    PublicSpendInputs, SignedPoly,
};
pub(crate) use types::{PROOF_BYTES, STATEMENT_BYTES, STATUS_U32_WORDS};

use crate::block_v2::gpu_hash::device::DeviceSession;
use crate::proving::{
    Backend, Capabilities, CoverageScope, Policy, Profile, Report, Request, Run, Stage,
};

pub const ENTRY_POINT: &str = "native_matrict_spend";

/// Public resource limits fixed before private sampling starts. Exhaustion is
/// an error, never a truncated distribution, reseed, or CPU fallback.
#[derive(Clone, Copy, Debug)]
pub struct SpendLimits {
    pub host_bytes: usize,
    pub max_attempts: u64,
    pub random_call_limit: u64,
    pub proposal_limit: u64,
}
impl SpendLimits {
    pub fn bounded(host_bytes: usize) -> Self {
        Self {
            host_bytes,
            max_attempts: 1024,
            random_call_limit: 1 << 24,
            proposal_limit: 1 << 28,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.host_bytes == 0
            || self.host_bytes as u64 > 32u64 << 30
            || !(1..=65_536).contains(&self.max_attempts)
            || !(1..=1u64 << 32).contains(&self.random_call_limit)
            || !(1..=1u64 << 32).contains(&self.proposal_limit)
        {
            return Err("native spend resource limits are outside the bounded profile".into());
        }
        Ok(())
    }
}

/// Public execution metadata only; no witnesses, seeds or private RNG cursors.
/// The schedule masks describe the prelude and the accepted attempt, never
/// rejected intermediate values. The generic receipt has operation scope.
#[derive(Debug, serde::Serialize)]
pub struct SpendEvidence {
    pub prelude_steps: u32,
    pub accepted_attempt_steps: u32,
    pub managed_bytes: usize,
    pub kernel_source_sha256: &'static str,
}

/// Caller must serialize this operation against its prepared-program registry.
/// The capacity owner prevents another proof from borrowing this arena's budget.
pub fn create_spend(
    input: PrivateSpendRequest,
    limits: SpendLimits,
    request: Request,
) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
    create_spend_inner(input, limits, request, None)
}

/// Deterministic qualification only. This API does not exist in normal builds.
/// Reusing a key across spends is unsafe; the production entry always uses OS
/// entropy. The supplied live key copy and its owned staging are wiped.
#[cfg(feature = "native-spend-oracle")]
pub fn create_spend_for_oracle(
    input: PrivateSpendRequest,
    limits: SpendLimits,
    request: Request,
    mut key: [u8; 32],
) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
    let entropy = types::PrivateEntropy::for_oracle(key);
    for byte in &mut key {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    create_spend_inner(input, limits, request, Some(entropy))
}

fn create_spend_inner(
    input: PrivateSpendRequest,
    limits: SpendLimits,
    request: Request,
    entropy: Option<types::PrivateEntropy>,
) -> Result<(PrivateSpendOutput, Report, SpendEvidence), String> {
    limits.validate()?;
    if request.policy != Policy::GpuRequired {
        return Err("native spend creation requires explicit GPU-required policy".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::MatrictN10, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    let run = Run::new(ENTRY_POINT, request, capabilities).map_err(|e| e.to_string())?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let packed = match entropy {
        Some(entropy) => input.pack_with_entropy(limits.host_bytes, entropy)?,
        None => input.pack(limits.host_bytes)?,
    };
    let (output, evidence) = session.create_native_private_spend(packed, limits, &run)?;
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok((output, report, evidence))
}
