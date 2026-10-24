//! Opt-in adapter to the pinned, locally patched MatRiCT+ research reference.
//!
//! This is a real private-spend fixture and public-verifier experiment, not a
//! wallet or consensus acceptance API. Its ten-member ring contains pairs of
//! accounts with a shared hidden selection index. It implements no HTLCs,
//! recipient note delivery, authenticated ledger lookup, fees, or recursion.
//! The C reference uses global mutable state; every operation is serialized.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{fmt, sync::Mutex, time::Instant};

static NATIVE_LOCK: Mutex<()> = Mutex::new(());
const MAX_NATIVE_PACKET: usize = 16 * 1024 * 1024;
pub const RING_PAIRS: u64 = 10;
pub const VALUE_LIMIT: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureAmounts {
    pub input: [u64; 2],
    pub output: [u64; 2],
}

pub struct NativeFixture {
    /// Full public verifier statement; not an on-chain transaction encoding.
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
    /// Includes setup, key generation and minting; excludes verification.
    pub generation_ns: u64,
    pub verification_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    UnsupportedHardware,
    InvalidWitness,
    PacketLength,
    Poisoned,
    NativeFailure,
    GeneratedProofRejected,
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedHardware => "native research backend requires Linux x86_64 with AVX2, AES and FMA",
            Self::InvalidWitness => "fixture requires a ring index below ten, 52-bit amounts and exact zero-fee conservation",
            Self::PacketLength => "noncanonical or excessive native packet size",
            Self::Poisoned => "native reference state lock is poisoned",
            Self::NativeFailure => "native reference operation failed",
            Self::GeneratedProofRejected => "fresh native proof failed public verification",
        })
    }
}
impl std::error::Error for NativeError {}

extern "C" {
    fn lattica_matrict_statement_bytes() -> usize;
    fn lattica_matrict_proof_bytes() -> usize;
    fn lattica_matrict_fixture_with_setup_seed(
        context: *const u8,
        setup_seed: *const u8,
        index: u64,
        in0: u64,
        in1: u64,
        out0: u64,
        out1: u64,
        statement: *mut u8,
        statement_len: usize,
        proof: *mut u8,
        proof_len: usize,
    ) -> i32;
    fn lattica_matrict_verify(
        context: *const u8,
        statement: *const u8,
        statement_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
}

pub fn available() -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("fma")
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        false
    }
}

fn sizes() -> Result<(usize, usize), NativeError> {
    if !available() {
        return Err(NativeError::UnsupportedHardware);
    }
    // These return constants and do not read or mutate C state.
    let (statement, proof) = unsafe {
        (
            lattica_matrict_statement_bytes(),
            lattica_matrict_proof_bytes(),
        )
    };
    if statement == 0 || proof == 0 || statement > MAX_NATIVE_PACKET || proof > MAX_NATIVE_PACKET {
        return Err(NativeError::PacketLength);
    }
    Ok((statement, proof))
}

pub fn generate_fixture(
    context: [u8; 32],
    index: u64,
    amounts: FixtureAmounts,
) -> Result<NativeFixture, NativeError> {
    generate_with_optional_seed(context, None, index, amounts)
}

/// Use a fixed, caller-selected public setup seed, as a network registry would.
/// Spending keys, commitment randomness and private prover entropy remain fresh.
/// The seed is included in the public statement and must be bound by the caller's
/// verifier configuration; this function does not establish a network policy.
pub fn generate_fixture_with_setup_seed(
    context: [u8; 32],
    setup_seed: [u8; 32],
    index: u64,
    amounts: FixtureAmounts,
) -> Result<NativeFixture, NativeError> {
    generate_with_optional_seed(context, Some(setup_seed), index, amounts)
}

fn generate_with_optional_seed(
    context: [u8; 32],
    setup_seed: Option<[u8; 32]>,
    index: u64,
    amounts: FixtureAmounts,
) -> Result<NativeFixture, NativeError> {
    if index >= RING_PAIRS
        || amounts
            .input
            .iter()
            .chain(&amounts.output)
            .any(|&v| v >= VALUE_LIMIT)
        || amounts.input.iter().sum::<u64>() != amounts.output.iter().sum::<u64>()
    {
        return Err(NativeError::InvalidWitness);
    }
    let (statement_size, proof_size) = sizes()?;
    let mut statement = vec![0; statement_size];
    let mut proof = vec![0; proof_size];
    let guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
    let start = Instant::now();
    // Exact lengths and witness bounds are checked here and again at the C boundary.
    let status = unsafe {
        lattica_matrict_fixture_with_setup_seed(
            context.as_ptr(),
            setup_seed
                .as_ref()
                .map_or(std::ptr::null(), |seed| seed.as_ptr()),
            index,
            amounts.input[0],
            amounts.input[1],
            amounts.output[0],
            amounts.output[1],
            statement.as_mut_ptr(),
            statement.len(),
            proof.as_mut_ptr(),
            proof.len(),
        )
    };
    let generation_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    drop(guard);
    if status != 1 {
        return Err(NativeError::NativeFailure);
    }
    let start = Instant::now();
    if !verify(&context, &statement, &proof)? {
        return Err(NativeError::GeneratedProofRejected);
    }
    let verification_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    Ok(NativeFixture {
        statement,
        proof,
        generation_ns,
        verification_ns,
    })
}

/// Only public artifacts are accepted: no amounts, secret ring index, openings,
/// spending keys or private RNG seeds are passed through this interface.
pub fn verify(context: &[u8; 32], statement: &[u8], proof: &[u8]) -> Result<bool, NativeError> {
    let (statement_size, proof_size) = sizes()?;
    if statement.len() != statement_size || proof.len() != proof_size {
        return Err(NativeError::PacketLength);
    }
    let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
    let status = unsafe {
        lattica_matrict_verify(
            context.as_ptr(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    };
    match status {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(NativeError::NativeFailure),
    }
}

/// Internal XKCP-compatible primitive, supplied by the pinned RustCrypto SHAKE.
/// The C reference calls it only with bounded owned buffers. No Rust unwind may
/// cross this boundary. Native callers must treat a nonzero return as failure.
#[no_mangle]
unsafe extern "C" fn SHAKE256(
    output: *mut u8,
    output_len: usize,
    input: *const u8,
    input_len: usize,
) -> i32 {
    if output_len > MAX_NATIVE_PACKET
        || input_len > MAX_NATIVE_PACKET
        || (output_len != 0 && output.is_null())
        || (input_len != 0 && input.is_null())
    {
        return 1;
    }
    std::panic::catch_unwind(|| {
        let mut state = Shake256::default();
        if input_len != 0 {
            state.update(unsafe { std::slice::from_raw_parts(input, input_len) });
        }
        let mut reader = state.finalize_xof();
        if output_len != 0 {
            reader.read(unsafe { std::slice::from_raw_parts_mut(output, output_len) });
        }
    })
    .map(|_| 0)
    .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_expansion_binds_seed_and_repeats_deterministically() {
        if !available() {
            return;
        }
        extern "C" {
            fn lattica_matrict_challenge_selftest() -> i32;
        }
        let _guard = NATIVE_LOCK.lock().unwrap();
        // The unpatched upstream initializes a different AES key schedule from
        // the one read by challenge expansion, making distinct seeds collide.
        assert_eq!(unsafe { lattica_matrict_challenge_selftest() }, 1);
    }

    #[test]
    fn prover_negative_carry_reduction_is_canonical_and_matches_modulo() {
        if !available() {
            return;
        }
        extern "C" {
            fn lattica_matrict_reduction_selftest() -> i32;
        }
        let _guard = NATIVE_LOCK.lock().unwrap();
        // Compare the optimized reducer with integer remainder at bucket and
        // modulus boundaries, including the negative-carry range up to 7Q.
        assert_eq!(unsafe { lattica_matrict_reduction_selftest() }, 1);
    }

    #[test]
    fn shake_callback_matches_fips202_empty_input_and_rejects_bad_buffers() {
        let mut output = [0_u8; 32];
        assert_eq!(
            unsafe { SHAKE256(output.as_mut_ptr(), output.len(), std::ptr::null(), 0) },
            0
        );
        assert_eq!(
            output,
            [
                0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
                0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
                0x6e, 0xd5, 0x76, 0x2f,
            ]
        );
        assert_eq!(
            unsafe { SHAKE256(std::ptr::null_mut(), 1, std::ptr::null(), 0) },
            1
        );
        assert_eq!(
            unsafe { SHAKE256(output.as_mut_ptr(), output.len(), std::ptr::null(), 1) },
            1
        );
        assert_eq!(
            unsafe {
                SHAKE256(
                    output.as_mut_ptr(),
                    MAX_NATIVE_PACKET + 1,
                    std::ptr::null(),
                    0,
                )
            },
            1
        );
    }
}

/// Owns actual fixture witnesses for the GPU spend path; does not call spend().
#[cfg(feature = "opencl")]
pub mod private_spend_fixture;

/// Private reference diagnostics only; never part of production proving.
#[cfg(feature = "native-spend-oracle")]
pub mod private_rng_rejection_oracle;
