//! Feature-only, deterministic private sampler qualification.
//!
//! This operation is diagnostic: it cannot complete a native spend or a STARK.
//! Callers must hold the admitted OpenCL session and serialize it against other
//! prepared/proving work. Secret results and RNG cursors must never be logged.

use super::{
    Backend, Capabilities, CoverageScope, DeviceSession, Policy, Profile, Report, Request, Run,
    Stage,
};
use std::sync::atomic::{compiler_fence, Ordering};

pub const ENTRY_POINT: &str = "native_matrict_sampler_probe";

/// Public bounds fixed before sampling; exhaustion never falls back to CPU.
#[derive(Clone, Copy)]
pub struct SamplerLimits {
    pub host_bytes: usize,
    pub random_call_limit: u64,
    pub proposal_limit: u64,
}

impl SamplerLimits {
    pub fn bounded(host_bytes: usize) -> Self {
        Self {
            host_bytes,
            random_call_limit: 1 << 24,
            proposal_limit: 1 << 28,
        }
    }

    pub(crate) fn validate(&self, rows: usize) -> Result<(), String> {
        if !(1..=11).contains(&rows) {
            return Err(
                "sampler diagnostic resource limits are outside the bounded profile".into(),
            );
        }
        // Output plus simultaneous post-scrub readback, RNG/key/status staging
        // and a conservative fixed allowance. No private allocation precedes
        // this check except the fixed 32-byte key owner.
        let staging = (2 * rows * 256 + 2 * 36 + 32 + 8) * 8 + 64 * 1024;
        if self.host_bytes < staging
            || self.host_bytes as u64 > 32u64 << 30
            || !(1..=1u64 << 32).contains(&self.random_call_limit)
            || !(1..=1u64 << 32).contains(&self.proposal_limit)
        {
            return Err(
                "sampler diagnostic resource limits are outside the bounded profile".into(),
            );
        }
        Ok(())
    }
}

fn wipe<T: Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: initialized, exclusively owned live staging storage.
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct SecretKey([u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) struct SamplerKeyWords(pub(crate) Vec<u64>);
impl Drop for SamplerKeyWords {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Diagnostic ownership only. Deliberately no Debug/Clone/serde implementation.
pub struct PrivateSamples {
    pub(crate) words: Vec<u64>,
    pub(crate) counters: [u64; 3],
}

impl PrivateSamples {
    pub fn words(&self) -> &[u64] {
        &self.words
    }
    pub fn private_blocks(&self) -> u64 {
        self.counters[0]
    }
    pub fn private_calls(&self) -> u64 {
        self.counters[1]
    }
    pub fn private_proposals(&self) -> u64 {
        self.counters[2]
    }
}

impl Drop for PrivateSamples {
    fn drop(&mut self) {
        wipe(&mut self.words);
        wipe(&mut self.counters);
    }
}

/// Public geometry and scrub result only; no private diagnostic values.
pub struct SamplerEvidence {
    pub profile: u32,
    pub rows: usize,
    pub managed_bytes: usize,
    pub scrub_verified: bool,
    pub kernel_source_sha256: &'static str,
}

/// Compare deterministic outputs to the separately gated native C reference.
/// Profiles 0..4 require one_rows=0; profile 5 is sample_1 with rows 1..11.
/// The live key copy, packed key, device state and returned owner are wiped.
/// This is not a guarantee about compiler copies, registers or all stack bytes.
pub fn samples(
    mut key: [u8; 32],
    profile: u32,
    one_rows: u32,
    limits: SamplerLimits,
    request: Request,
) -> Result<(PrivateSamples, Report, SamplerEvidence), String> {
    let key_owner = SecretKey(key);
    wipe(&mut key);
    let rows = match (profile, one_rows) {
        (0, 0) => 9,
        (1 | 4, 0) => 11,
        (2, 0) => 10,
        (3, 0) => 8,
        (5, 1..=11) => one_rows as usize,
        _ => return Err("sampler diagnostic profile or row count is invalid".into()),
    };
    limits.validate(rows)?;
    if request.policy != Policy::GpuRequired {
        return Err("sampler diagnostic requires explicit GPU-required policy".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::MatrictN10, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    let run = Run::new(ENTRY_POINT, request, capabilities).map_err(|e| e.to_string())?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let mut packed = SamplerKeyWords(vec![0; 32]);
    for (word, byte) in packed.0.iter_mut().zip(&key_owner.0) {
        *word = u64::from(*byte);
    }
    drop(key_owner);
    let (output, evidence) =
        session.probe_native_private_sampler(packed, profile, rows, limits, &run)?;
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok((output, report, evidence))
}
