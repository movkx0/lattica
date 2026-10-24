//! Feature-gated private reference diagnostics for RNG calls and rejection.
//! Borrowed seeds/input coefficients remain caller-owned and caller-wiped.
//! Returned bytes, decisions and consumption counters must not be logged.
//! No native spend proof, transcript or sampling distribution is substituted.
use super::{available, NativeError, NATIVE_LOCK};
use std::sync::atomic::{compiler_fence, Ordering};

pub const MAX_RNG_CALLS: usize = 256;
pub const MAX_RNG_BYTES: usize = 1 << 20;
pub const REJECTION_F_WORDS: usize = 22 * 256;
pub const REJECTION_Z_WORDS: usize = 16 * 256;
pub const REJECTION_OP_WORDS: usize = 118 * 256;

fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) { wipe(&mut self.0); }
}
struct SecretWords(Vec<u64>);
impl Drop for SecretWords {
    fn drop(&mut self) { wipe(&mut self.0); }
}

/// Owns all reference bytes and per-call private consumption records.
pub struct ReferenceRngCalls {
    bytes: SecretBytes,
    progress: SecretWords,
}
impl ReferenceRngCalls {
    pub fn bytes(&self) -> &[u8] { &self.bytes.0 }
    /// Consecutive [cumulative blocks, cumulative calls] pairs; no serialization.
    pub fn progress(&self) -> &[u64] { &self.progress.0 }
}

/// Owns [decision, consumed blocks, consumed calls] until volatile retirement.
pub struct ReferenceRejection {
    result: SecretWords,
}
impl ReferenceRejection {
    pub fn rejected(&self) -> bool { self.result.0[0] == 1 }
    pub fn private_blocks(&self) -> u64 { self.result.0[1] }
    pub fn private_calls(&self) -> u64 { self.result.0[2] }
}

extern "C" {
    fn lattica_matrict_rng_calls_oracle(
        private_seed: *const u8, lengths: *const u32, count: usize,
        out: *mut u8, out_bytes: usize, progress: *mut u64, progress_words: usize,
    ) -> i32;
    fn lattica_matrict_rejection_oracle(
        private_seed: *const u8, kind: u32, inputs: *const u64, input_words: usize,
        result_words: *mut u64, result_count: usize,
    ) -> i32;
}

/// Reset the private reference AES stream, preserving every requested call
/// boundary. A zero-length call consumes no AES block and still counts as a call.
pub fn rng_calls(
    private_seed: &[u8; 32], lengths: &[u32],
) -> Result<ReferenceRngCalls, NativeError> {
    if !available() { return Err(NativeError::UnsupportedHardware); }
    if lengths.is_empty() || lengths.len() > MAX_RNG_CALLS {
        return Err(NativeError::InvalidWitness);
    }
    let count = lengths.iter().try_fold(0usize, |sum, &length| {
        sum.checked_add(length as usize).filter(|&n| n <= MAX_RNG_BYTES)
    }).ok_or(NativeError::InvalidWitness)?;
    let mut output = ReferenceRngCalls {
        bytes: SecretBytes(vec![0; count]),
        progress: SecretWords(vec![0; 2 * lengths.len()]),
    };
    let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
    let status = unsafe {
        lattica_matrict_rng_calls_oracle(
            private_seed.as_ptr(), lengths.as_ptr(), lengths.len(),
            output.bytes.0.as_mut_ptr(), output.bytes.0.len(),
            output.progress.0.as_mut_ptr(), output.progress.0.len(),
        )
    };
    match status {
        1 => Ok(output),
        0 => Err(NativeError::InvalidWitness),
        _ => Err(NativeError::NativeFailure),
    }
}

/// Run the original rej_f (0), rej_z (1), or rej_op (2) with a fresh private
/// reference stream. Coefficients use the exact C row-major u64 bitpattern ABI.
/// Pathological inputs may trigger the reference guard and return NativeFailure;
/// they must never be converted into an acceptance or a changed distribution.
pub fn rejection(
    private_seed: &[u8; 32], kind: u32, inputs: &[u64],
) -> Result<ReferenceRejection, NativeError> {
    if !available() { return Err(NativeError::UnsupportedHardware); }
    let expected = match kind {
        0 => REJECTION_F_WORDS,
        1 => REJECTION_Z_WORDS,
        2 => REJECTION_OP_WORDS,
        _ => return Err(NativeError::InvalidWitness),
    };
    if inputs.len() != expected { return Err(NativeError::InvalidWitness); }
    let mut output = ReferenceRejection { result: SecretWords(vec![0; 3]) };
    let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
    let status = unsafe {
        lattica_matrict_rejection_oracle(
            private_seed.as_ptr(), kind, inputs.as_ptr(), inputs.len(),
            output.result.0.as_mut_ptr(), output.result.0.len(),
        )
    };
    match status {
        1 if output.result.0[0] <= 1 => Ok(output),
        0 => Err(NativeError::InvalidWitness),
        _ => Err(NativeError::NativeFailure),
    }
}
