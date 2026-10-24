//! Research-only ASK witness preparation, without CPU spend-proof generation.
//!
//! The fixture creates a synthetic ring and recipients using the reference
//! keygen/mint routines. Real wallets supply their own ring and ASK witnesses.
//! All private owned buffers below deliberately lack Debug, Clone and serde.
use super::{available, FixtureAmounts, NativeError, NATIVE_LOCK};
use lattica_prover_p3::block_v2::native_gpu::private_spend::{
    PrivateSpendRequest, PrivateSpendWitness, PublicSpendInputs,
};
use std::sync::atomic::{compiler_fence, Ordering};

const DEGREE: usize = 256;
const WORDS: usize = 56_965;
const RING: usize = 64;
const RECIPIENTS: usize = 46_144;
const SPENDING_KEYS: usize = 48_192;
const COMMITMENT_KEYS: usize = 52_288;
const SERIALS: usize = 56_896;
const SCALARS: usize = 56_960;
#[cfg(feature = "native-spend-oracle")]
const STATEMENT_BYTES: usize = 202_848;
#[cfg(feature = "native-spend-oracle")]
const PROOF_BYTES: usize = 53_600;

extern "C" {
    fn lattica_matrict_export_spend_fixture(
        context: *const u8,
        setup_seed: *const u8,
        index: u64,
        in0: u64,
        in1: u64,
        out0: u64,
        out1: u64,
        out: *mut u64,
        words: usize,
    ) -> i32;
}

fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: exclusively owned initialized live storage, including failures.
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}
struct SecretWords(Vec<u64>);
impl Drop for SecretWords {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Owns the actual ASK witnesses and public inputs. This is never a wire codec.
/// Explicit owned storage is wiped; arbitrary compiler copies are not covered.
pub struct NativeSpendFixture {
    words: SecretWords,
}

/// Only ring setup, key generation and input coin minting execute here on CPU.
/// No native spend proof, output coin, mask or rejection result is created.
/// Private key generation uses fresh OS entropy; the optional seed is public.
pub fn generate_spend_fixture(
    context: [u8; 32],
    setup_seed: Option<[u8; 32]>,
    index: u64,
    amounts: FixtureAmounts,
) -> Result<NativeSpendFixture, NativeError> {
    if !available() {
        return Err(NativeError::UnsupportedHardware);
    }
    if index >= super::RING_PAIRS
        || amounts
            .input
            .iter()
            .chain(&amounts.output)
            .any(|&v| v >= super::VALUE_LIMIT)
        || amounts.input.iter().sum::<u64>() != amounts.output.iter().sum::<u64>()
    {
        return Err(NativeError::InvalidWitness);
    }
    let mut fixture = NativeSpendFixture {
        words: SecretWords(vec![0; WORDS]),
    };
    let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
    // All output storage is initialized, owned, and retired on every error path.
    let status = unsafe {
        lattica_matrict_export_spend_fixture(
            context.as_ptr(),
            setup_seed.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            index,
            amounts.input[0],
            amounts.input[1],
            amounts.output[0],
            amounts.output[1],
            fixture.words.0.as_mut_ptr(),
            fixture.words.0.len(),
        )
    };
    match status {
        1 => Ok(fixture),
        0 => Err(NativeError::InvalidWitness),
        _ => Err(NativeError::NativeFailure),
    }
}

struct DecodedWitness {
    spending_keys: Vec<[i64; DEGREE]>,
    commitment_keys: Vec<[i64; DEGREE]>,
    serials: [[u8; 32]; 2],
    selected: u64,
    inputs: [u64; 2],
    outputs: [u64; 2],
}
impl Drop for DecodedWitness {
    fn drop(&mut self) {
        for p in self
            .spending_keys
            .iter_mut()
            .chain(&mut self.commitment_keys)
        {
            wipe(p);
        }
        for serial in &mut self.serials {
            wipe(serial);
        }
        wipe(std::slice::from_mut(&mut self.selected));
        wipe(&mut self.inputs);
        wipe(&mut self.outputs);
    }
}
impl NativeSpendFixture {
    pub fn into_gpu_request(self) -> Result<PrivateSpendRequest, NativeError> {
        let words = &self.words.0;
        if words.len() != WORDS {
            return Err(NativeError::PacketLength);
        }
        let mut setup_seed = [0; 32];
        let mut context = [0; 32];
        for i in 0..32 {
            setup_seed[i] = u8::try_from(words[i]).map_err(|_| NativeError::InvalidWitness)?;
            context[i] = u8::try_from(words[32 + i]).map_err(|_| NativeError::InvalidWitness)?;
        }
        let mut public = PublicSpendInputs {
            setup_seed,
            context,
            ring: vec![[0; DEGREE]; 180],
            recipients: vec![[0; DEGREE]; 8],
        };
        for (poly, chunk) in public
            .ring
            .iter_mut()
            .zip(words[RING..RECIPIENTS].chunks_exact(DEGREE))
        {
            poly.copy_from_slice(chunk);
        }
        for (poly, chunk) in public
            .recipients
            .iter_mut()
            .zip(words[RECIPIENTS..SPENDING_KEYS].chunks_exact(DEGREE))
        {
            poly.copy_from_slice(chunk);
        }
        let mut owned = DecodedWitness {
            spending_keys: vec![[0; DEGREE]; 16],
            commitment_keys: vec![[0; DEGREE]; 18],
            serials: [[0; 32]; 2],
            selected: words[SCALARS],
            inputs: [words[SCALARS + 1], words[SCALARS + 2]],
            outputs: [words[SCALARS + 3], words[SCALARS + 4]],
        };
        for (poly, chunk) in owned
            .spending_keys
            .iter_mut()
            .zip(words[SPENDING_KEYS..COMMITMENT_KEYS].chunks_exact(DEGREE))
        {
            for (dst, &src) in poly.iter_mut().zip(chunk) {
                *dst = src as i64;
            }
        }
        for (poly, chunk) in owned
            .commitment_keys
            .iter_mut()
            .zip(words[COMMITMENT_KEYS..SERIALS].chunks_exact(DEGREE))
        {
            for (dst, &src) in poly.iter_mut().zip(chunk) {
                *dst = src as i64;
            }
        }
        for (dst, &src) in owned
            .serials
            .iter_mut()
            .flatten()
            .zip(&words[SERIALS..SCALARS])
        {
            *dst = u8::try_from(src).map_err(|_| NativeError::InvalidWitness)?;
        }
        let witness = PrivateSpendWitness::new(
            std::mem::take(&mut owned.spending_keys),
            std::mem::take(&mut owned.commitment_keys),
            owned.serials,
            owned.selected,
            owned.inputs,
            owned.outputs,
        )
        .map_err(|_| NativeError::InvalidWitness)?;
        PrivateSpendRequest::new(public, witness).map_err(|_| NativeError::InvalidWitness)
    }
}

/// Deterministic diagnostics are separately opt-in and never change fresh RNG
/// behavior of the normal GPU request path. Values must not be logged/serialized.
#[cfg(feature = "native-spend-oracle")]
pub mod oracle {
    use super::*;

    #[repr(C)]
    #[derive(Default)]
    pub struct PhaseRecord {
        pub phase: u32,
        pub component: u32,
        pub bytes: u64,
        pub digest: [u8; 32],
        pub private_blocks: u64,
    }
    const _: () = assert!(std::mem::size_of::<PhaseRecord>() == 56);
    struct SecretRecords(Vec<PhaseRecord>);
    impl Drop for SecretRecords {
        fn drop(&mut self) {
            for record in &mut self.0 {
                // SAFETY: the record has only integer fields and owns no resource.
                unsafe { std::ptr::write_volatile(record, PhaseRecord::default()) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
    pub struct ReferenceSpend {
        pub statement: Vec<u8>,
        pub proof: Vec<u8>,
        keys: SecretWords,
        records: SecretRecords,
        record_count: usize,
    }
    impl Drop for ReferenceSpend {
        fn drop(&mut self) {
            wipe(std::slice::from_mut(&mut self.record_count));
        }
    }
    impl ReferenceSpend {
        pub fn output_keys_equal(&self, keys: &[[i64; DEGREE]]) -> bool {
            keys.len() == 18
                && self
                    .keys
                    .0
                    .iter()
                    .copied()
                    .eq(keys.iter().flatten().map(|&v| v as u64))
        }
        pub fn phases(&self) -> &[PhaseRecord] {
            &self.records.0[..self.record_count]
        }
    }
    pub struct ReferenceSamples {
        words: SecretWords,
        blocks: u64,
        calls: u64,
    }
    impl ReferenceSamples {
        pub fn words(&self) -> &[u64] {
            &self.words.0
        }
        pub fn private_blocks(&self) -> u64 {
            self.blocks
        }
        pub fn private_calls(&self) -> u64 {
            self.calls
        }
    }
    impl Drop for ReferenceSamples {
        fn drop(&mut self) {
            wipe(std::slice::from_mut(&mut self.blocks));
            wipe(std::slice::from_mut(&mut self.calls));
        }
    }
    extern "C" {
        fn lattica_matrict_spend_oracle(
            inputs: *const u64,
            words: usize,
            private_seed: *const u8,
            attempt_limit: u64,
            statement: *mut u8,
            statement_len: usize,
            proof: *mut u8,
            proof_len: usize,
            output_keys: *mut u64,
            key_words: usize,
            records: *mut PhaseRecord,
            capacity: usize,
            record_count: *mut usize,
        ) -> i32;
        fn lattica_matrict_sampler_oracle(
            private_seed: *const u8,
            kind: u32,
            one_rows: u32,
            out: *mut u64,
            words: usize,
            blocks: *mut u64,
            calls: *mut u64,
        ) -> i32;
    }

    /// At most 8192 attempts and 131074 private checkpoint records (~7 MiB).
    /// Caller retains/wipes its private seed; this function makes no seed copy.
    pub fn spend(
        fixture: &NativeSpendFixture,
        private_seed: &[u8; 32],
        attempt_limit: u64,
    ) -> Result<ReferenceSpend, NativeError> {
        if !available() {
            return Err(NativeError::UnsupportedHardware);
        }
        if !(1..=8192).contains(&attempt_limit) {
            return Err(NativeError::InvalidWitness);
        }
        // Two mint records and at most sixteen records for each reference attempt.
        let capacity = 2 + attempt_limit as usize * 16;
        let mut records = Vec::with_capacity(capacity);
        records.resize_with(capacity, PhaseRecord::default);
        let mut output = ReferenceSpend {
            statement: vec![0; STATEMENT_BYTES],
            proof: vec![0; PROOF_BYTES],
            keys: SecretWords(vec![0; 18 * DEGREE]),
            records: SecretRecords(records),
            record_count: 0,
        };
        let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
        let status = unsafe {
            lattica_matrict_spend_oracle(
                fixture.words.0.as_ptr(),
                fixture.words.0.len(),
                private_seed.as_ptr(),
                attempt_limit,
                output.statement.as_mut_ptr(),
                output.statement.len(),
                output.proof.as_mut_ptr(),
                output.proof.len(),
                output.keys.0.as_mut_ptr(),
                output.keys.0.len(),
                output.records.0.as_mut_ptr(),
                output.records.0.len(),
                &mut output.record_count,
            )
        };
        match status {
            1 if output.record_count <= capacity => Ok(output),
            0 => Err(NativeError::InvalidWitness),
            _ => Err(NativeError::NativeFailure),
        }
    }
    /// Profile0..4: nk1,nk3,nhatkhat,brs13nbark,ba_n1; profile5: sample_1.
    pub fn samples(
        private_seed: &[u8; 32],
        profile: u32,
        one_rows: u32,
    ) -> Result<ReferenceSamples, NativeError> {
        if !available() {
            return Err(NativeError::UnsupportedHardware);
        }
        let rows = match profile {
            0 => 9,
            1 | 4 => 11,
            2 => 10,
            3 => 8,
            5 if (1..=11).contains(&one_rows) => one_rows as usize,
            _ => return Err(NativeError::InvalidWitness),
        };
        let mut output = ReferenceSamples {
            words: SecretWords(vec![0; rows * DEGREE]),
            blocks: 0,
            calls: 0,
        };
        let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
        let status = unsafe {
            lattica_matrict_sampler_oracle(
                private_seed.as_ptr(),
                profile,
                one_rows,
                output.words.0.as_mut_ptr(),
                output.words.0.len(),
                &mut output.blocks,
                &mut output.calls,
            )
        };
        if status == 1 {
            Ok(output)
        } else {
            Err(NativeError::NativeFailure)
        }
    }
}
