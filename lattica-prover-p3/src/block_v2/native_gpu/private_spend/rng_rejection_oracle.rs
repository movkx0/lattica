//! Feature-only AES-call and rejection qualification against the original C.
//! These operation receipts establish neither native-spend nor STARK completion.
//! Callers serialize probes inside an admitted OpenCL context. Secret outputs
//! and RNG cursors must never be logged; borrowed coefficient inputs are owned
//! and retired by the caller.
use super::{
    Backend, Capabilities, CoverageScope, DeviceSession, Policy, Profile, Report, Request, Run,
    Stage,
};
use std::sync::atomic::{compiler_fence, Ordering};

pub const RNG_ENTRY_POINT: &str = "native_matrict_rng_calls_probe";
pub const REJECTION_ENTRY_POINT: &str = "native_matrict_rejection_probe";
pub const MAX_RNG_CALLS: usize = 256;
pub const MAX_RNG_BYTES: usize = 1 << 20;
/// Narrower than the C reference adapter; larger calls are refused, never split.
pub const MAX_RNG_CALL_BYTES: u32 = 4096;
pub const COUNTER_END: u64 = 1 << 32;
pub const REJECTION_F_WORDS: usize = 22 * 256;
pub const REJECTION_Z_WORDS: usize = 16 * 256;
pub const REJECTION_OP_WORDS: usize = 118 * 256;

#[derive(Clone, Copy)]
pub struct ProbeLimits {
    pub host_bytes: usize,
    pub random_call_limit: u64,
}
impl ProbeLimits {
    pub fn bounded(host_bytes: usize) -> Self {
        Self { host_bytes, random_call_limit: 1 << 24 }
    }
    pub(crate) fn validate(&self, data_bytes: usize, progress_words: usize) -> Result<(), String> {
        // Conservative simultaneous owned staging, returned outputs and verified
        // scrub readback. Borrowed caller inputs remain outside this owned bound.
        let required = data_bytes.checked_mul(3)
            .and_then(|n| progress_words.checked_mul(3 * 8).and_then(|p| n.checked_add(p)))
            .and_then(|n| n.checked_add(128 * 1024))
            .ok_or("RNG/rejection probe staging size overflow")?;
        if self.host_bytes < required || self.host_bytes as u64 > 32u64 << 30
            || !(1..=COUNTER_END).contains(&self.random_call_limit)
        {
            return Err("RNG/rejection probe resource limits are outside the bounded profile".into());
        }
        Ok(())
    }
}
fn wipe<T: Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: live, exclusively owned initialized storage.
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}
struct SecretKey([u8; 32]);
impl Drop for SecretKey { fn drop(&mut self) { wipe(&mut self.0); } }
pub(crate) struct ProbeWords(pub(crate) Vec<u64>);
impl Drop for ProbeWords { fn drop(&mut self) { wipe(&mut self.0); } }

/// No Debug, Clone or serialization implementation for private diagnostics.
pub struct PrivateRngCalls {
    pub(crate) bytes: Vec<u8>,
    pub(crate) progress: Vec<u64>,
}
impl PrivateRngCalls {
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    /// Per-call [absolute next AES counter, cumulative calls]. With the normal
    /// zero start this exactly matches the C adapter's [blocks,calls] records.
    pub fn progress(&self) -> &[u64] { &self.progress }
}
impl Drop for PrivateRngCalls {
    fn drop(&mut self) { wipe(&mut self.bytes); wipe(&mut self.progress); }
}
pub struct PrivateRejection { pub(crate) result: [u64; 3] }
impl PrivateRejection {
    pub fn rejected(&self) -> bool { self.result[0] == 1 }
    pub fn private_blocks(&self) -> u64 { self.result[1] }
    pub fn private_calls(&self) -> u64 { self.result[2] }
}
impl Drop for PrivateRejection { fn drop(&mut self) { wipe(&mut self.result); } }

/// Public admission/cleanup information only. No private values or decisions.
pub struct ProbeEvidence {
    pub managed_bytes: usize,
    pub scrub_verified: bool,
    pub kernel_source_sha256: &'static str,
    pub diagnostic_source_sha256: &'static str,
}
pub(crate) enum ProbeInput {
    Rng { lengths: Vec<u64>, total: usize, initial_counter: u64 },
    Rejection { kind: u32, words: ProbeWords },
}
pub(crate) enum ProbeOutput {
    Rng(PrivateRngCalls),
    Rejection(PrivateRejection),
}
fn run(entry: &'static str, request: Request) -> Result<Run, String> {
    if request.policy != Policy::GpuRequired {
        return Err("RNG/rejection probe requires explicit GPU-required policy".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::MatrictN10, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    Run::new(entry, request, capabilities).map_err(|e| e.to_string())
}
fn packed_key(key: &SecretKey) -> ProbeWords {
    let mut words = ProbeWords(vec![0; 32]);
    for (word, &byte) in words.0.iter_mut().zip(&key.0) { *word = u64::from(byte); }
    words
}

pub fn rng_calls(
    mut key: [u8; 32], lengths: &[u32], limits: ProbeLimits, request: Request,
) -> Result<(PrivateRngCalls, Report, ProbeEvidence), String> {
    let key_owner = SecretKey(key);
    wipe(&mut key);
    rng_calls_from_counter(key_owner.0, lengths, 0, limits, request)
}

/// Diagnostic-only direct terminal-counter qualification. A nonzero start has
/// no native adapter counterpart and must not be represented as C stream parity.
/// 2^32 permits zero-byte calls; a positive-byte request then fails closed.
pub fn rng_calls_from_counter(
    mut key: [u8; 32], lengths: &[u32], initial_counter: u64,
    limits: ProbeLimits, request: Request,
) -> Result<(PrivateRngCalls, Report, ProbeEvidence), String> {
    let key_owner = SecretKey(key);
    wipe(&mut key);
    if lengths.is_empty() || lengths.len() > MAX_RNG_CALLS
        || lengths.iter().any(|&n| n > MAX_RNG_CALL_BYTES)
        || initial_counter > COUNTER_END
    {
        return Err("RNG probe call shape is outside the bounded profile".into());
    }
    let total = lengths.iter().try_fold(0usize, |sum, &n| {
        sum.checked_add(n as usize).filter(|&v| v <= MAX_RNG_BYTES)
    }).ok_or("RNG probe call shape is outside the bounded profile")?;
    limits.validate(total.div_ceil(8).max(1) * 8, lengths.len() * 2)?;
    let run = run(RNG_ENTRY_POINT, request)?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let key = packed_key(&key_owner);
    drop(key_owner);
    let input = ProbeInput::Rng {
        lengths: lengths.iter().map(|&n| u64::from(n)).collect(), total, initial_counter,
    };
    let (output, evidence) = session.probe_native_rng_rejection(key, input, limits, &run)?;
    let ProbeOutput::Rng(output) = output else {
        return Err("RNG probe returned the wrong diagnostic type".into());
    };
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok((output, report, evidence))
}

/// kind 0: z[11],c[11]; kind 1: z[8],c[8]; kind 2: original OP's ten
/// components, row offsets [0,18,29,40,49,59,77,88,99,108], 118 rows total.
/// Coefficient bitpatterns are copied unchanged, without reduction or clamping.
pub fn rejection(
    mut key: [u8; 32], kind: u32, inputs: &[u64], limits: ProbeLimits, request: Request,
) -> Result<(PrivateRejection, Report, ProbeEvidence), String> {
    let key_owner = SecretKey(key);
    wipe(&mut key);
    let words = match kind {
        0 => REJECTION_F_WORDS, 1 => REJECTION_Z_WORDS, 2 => REJECTION_OP_WORDS,
        _ => return Err("rejection probe input shape is invalid".into()),
    };
    if inputs.len() != words { return Err("rejection probe input shape is invalid".into()); }
    limits.validate(words * 8, 3)?;
    let run = run(REJECTION_ENTRY_POINT, request)?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let key = packed_key(&key_owner);
    drop(key_owner);
    let input = ProbeInput::Rejection { kind, words: ProbeWords(inputs.to_vec()) };
    let (output, evidence) = session.probe_native_rng_rejection(key, input, limits, &run)?;
    let ProbeOutput::Rejection(output) = output else {
        return Err("rejection probe returned the wrong diagnostic type".into());
    };
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok((output, report, evidence))
}
