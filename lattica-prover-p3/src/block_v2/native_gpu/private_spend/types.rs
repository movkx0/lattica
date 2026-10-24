//! Research MatRiCT n10 private-spend ownership and packed device input ABI.
//!
//! This module performs shape/input admission and serialization, never spend
//! arithmetic. It does not implement or claim a GPU prover by itself. Secret
//! types intentionally have no Clone, Debug, or serde implementation.
use rand::TryRng;
use std::sync::atomic::{compiler_fence, Ordering};

pub const DEGREE: usize = 256;
pub const RING_PAIRS: usize = 10;
pub const INPUTS: usize = 2;
pub const OUTPUTS: usize = 2;
pub const PUBLIC_KEY_POLYS: usize = 4;
pub const COIN_POLYS: usize = 5;
pub const SPENDING_KEY_POLYS: usize = 8;
pub const COMMITMENT_KEY_POLYS: usize = 9;
pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;
pub const VALUE_LIMIT: u64 = 1 << 52;
pub const STATEMENT_BYTES: usize = 202_848;
pub const PROOF_BYTES: usize = 53_600;
pub const STATUS_U32_WORDS: usize = 16;
pub const STATUS_BYTES: usize = STATUS_U32_WORDS * 4;

pub type CanonicalPoly = [u64; DEGREE];
pub type SignedPoly = [i64; DEGREE];

pub(crate) mod input_layout {
    use super::*;
    pub const SEED: usize = 0;
    pub const CONTEXT: usize = SEED + 32;
    pub const RING: usize = CONTEXT + 32;
    pub const RING_POLYS: usize = RING_PAIRS * INPUTS * (PUBLIC_KEY_POLYS + COIN_POLYS);
    pub const RECIPIENTS: usize = RING + RING_POLYS * DEGREE;
    pub const RECIPIENT_POLYS: usize = OUTPUTS * PUBLIC_KEY_POLYS;
    pub const SPENDING_KEYS: usize = RECIPIENTS + RECIPIENT_POLYS * DEGREE;
    pub const COMMITMENT_KEYS: usize = SPENDING_KEYS + INPUTS * SPENDING_KEY_POLYS * DEGREE;
    pub const SERIALS: usize = COMMITMENT_KEYS + INPUTS * COMMITMENT_KEY_POLYS * DEGREE;
    /// Selected ring-pair index, input amounts[2], output amounts[2].
    pub const PRIVATE_SCALARS: usize = SERIALS + INPUTS * 32;
    pub const ENTROPY_KEY: usize = PRIVATE_SCALARS + 1 + INPUTS + OUTPUTS;
    pub const WORDS: usize = ENTROPY_KEY + 32;
    pub const BYTES: usize = WORDS * 8;
}

pub(crate) mod status {
    pub const ERROR: usize = 0;
    pub const OUTCOME: usize = 1;
    pub const PHASE: usize = 2;
    pub const PENDING: u32 = 0;
    pub const REJECTED: u32 = 1;
    pub const ACCEPTED: u32 = 2;
    pub const INVALID_STATE: u32 = 1;
    pub const NONCANONICAL: u32 = 2;
    pub const BOUND: u32 = 4;
    pub const ARITHMETIC_OVERFLOW: u32 = 8;
    pub const RNG_EXHAUSTED: u32 = 16;
    pub const SAMPLER_BUDGET: u32 = 32;
    pub const ATTEMPT_LIMIT: u32 = 64;
    pub const INTERNAL: u32 = 128;
}

fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: the slice exclusively owns initialized live storage. This
        // protects the explicitly owned buffers, not arbitrary compiler copies.
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn wipe_polys(polys: &mut [SignedPoly]) {
    for poly in polys {
        wipe(poly);
    }
}

/// Public input layout is explicit and independent of the reference C ABI.
pub struct PublicSpendInputs {
    pub setup_seed: [u8; 32],
    pub context: [u8; 32],
    /// Pair-major, account-major; each account has pk[4] followed by cn[5].
    pub ring: Vec<CanonicalPoly>,
    /// Recipient-major, four public-key polynomials per recipient.
    pub recipients: Vec<CanonicalPoly>,
}

impl PublicSpendInputs {
    fn validate(&self) -> Result<(), String> {
        if self.ring.len() != input_layout::RING_POLYS
            || self.recipients.len() != input_layout::RECIPIENT_POLYS
        {
            return Err("native spend public geometry differs from the n10 profile".into());
        }
        if self
            .ring
            .iter()
            .chain(&self.recipients)
            .flatten()
            .any(|&v| v >= Q)
        {
            return Err("native spend public coefficient is noncanonical".into());
        }
        Ok(())
    }
}

/// Actual spending witnesses, not an already-produced native spend proof.
pub struct PrivateSpendWitness {
    spending_keys: Vec<SignedPoly>,
    commitment_keys: Vec<SignedPoly>,
    serials: [[u8; 32]; INPUTS],
    selected_pair: u64,
    input_amounts: [u64; INPUTS],
    output_amounts: [u64; OUTPUTS],
}

impl PrivateSpendWitness {
    /// Takes ownership before validation, so rejected secret inputs are wiped.
    pub fn new(
        spending_keys: Vec<SignedPoly>,
        commitment_keys: Vec<SignedPoly>,
        serials: [[u8; 32]; INPUTS],
        selected_pair: u64,
        input_amounts: [u64; INPUTS],
        output_amounts: [u64; OUTPUTS],
    ) -> Result<Self, String> {
        let witness = Self {
            spending_keys,
            commitment_keys,
            serials,
            selected_pair,
            input_amounts,
            output_amounts,
        };
        witness.validate()?;
        Ok(witness)
    }

    fn validate(&self) -> Result<(), String> {
        if self.spending_keys.len() != INPUTS * SPENDING_KEY_POLYS
            || self.commitment_keys.len() != INPUTS * COMMITMENT_KEY_POLYS
        {
            return Err("native spend private geometry differs from the n10 profile".into());
        }
        if self.selected_pair >= RING_PAIRS as u64
            || self
                .input_amounts
                .iter()
                .chain(&self.output_amounts)
                .any(|&v| v >= VALUE_LIMIT)
            || self.input_amounts[0] + self.input_amounts[1]
                != self.output_amounts[0] + self.output_amounts[1]
            || self.serials[0] == self.serials[1]
        {
            return Err("native spend witness violates the pinned input contract".into());
        }
        if self
            .spending_keys
            .iter()
            .chain(&self.commitment_keys)
            .flatten()
            .any(|&v| !(-1..=1).contains(&v))
        {
            return Err("native spend key coefficient exceeds the reference sample_1 range".into());
        }
        Ok(())
    }
}

impl Drop for PrivateSpendWitness {
    fn drop(&mut self) {
        wipe_polys(&mut self.spending_keys);
        wipe_polys(&mut self.commitment_keys);
        for serial in &mut self.serials {
            wipe(serial);
        }
        wipe(std::slice::from_mut(&mut self.selected_pair));
        wipe(&mut self.input_amounts);
        wipe(&mut self.output_amounts);
    }
}

/// One fresh OS-derived key. The device performs AES expansion and sampling.
pub(crate) struct PrivateEntropy([u8; 32]);
impl PrivateEntropy {
    #[cfg(feature = "native-spend-oracle")]
    pub(crate) fn for_oracle(mut key: [u8; 32]) -> Self {
        let owned = Self(key);
        wipe(&mut key);
        owned
    }
    fn fresh() -> Result<Self, String> {
        let mut value = Self([0; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(&mut value.0)
            .map_err(|_| "native spend entropy acquisition failed".to_owned())?;
        Ok(value)
    }
}
impl Drop for PrivateEntropy {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Owned host staging; the worker must retire it immediately after upload.
pub(crate) struct PackedSpendInputs {
    words: Vec<u64>,
}
impl PackedSpendInputs {
    pub(crate) fn words(&self) -> &[u64] {
        &self.words
    }
}
impl Drop for PackedSpendInputs {
    fn drop(&mut self) {
        wipe(&mut self.words);
    }
}

pub struct PrivateSpendRequest {
    public: PublicSpendInputs,
    witness: PrivateSpendWitness,
}
impl PrivateSpendRequest {
    pub fn new(public: PublicSpendInputs, witness: PrivateSpendWitness) -> Result<Self, String> {
        public.validate()?;
        witness.validate()?;
        Ok(Self { public, witness })
    }

    /// No caller-selectable production RNG key or precomputed private masks.
    pub(crate) fn pack(self, host_bytes: usize) -> Result<PackedSpendInputs, String> {
        self.pack_with_entropy(host_bytes, PrivateEntropy::fresh()?)
    }

    pub(crate) fn pack_with_entropy(
        self,
        host_bytes: usize,
        entropy: PrivateEntropy,
    ) -> Result<PackedSpendInputs, String> {
        // Account simultaneously for owned input vectors and packed staging.
        let original = self
            .public
            .ring
            .capacity()
            .checked_add(self.public.recipients.capacity())
            .and_then(|n| n.checked_add(self.witness.spending_keys.capacity()))
            .and_then(|n| n.checked_add(self.witness.commitment_keys.capacity()))
            .and_then(|n| n.checked_mul(DEGREE * 8))
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
            .ok_or("native spend host ownership overflow")?;
        let admitted = original
            .checked_add(input_layout::BYTES)
            .and_then(|n| n.checked_add(32))
            .ok_or("native spend staging overflow")?;
        if admitted > host_bytes {
            return Err("native spend inputs and staging exceed host admission".into());
        }
        let mut packed = PackedSpendInputs {
            words: vec![0; input_layout::WORDS],
        };
        let mut cursor = 0;
        let mut push = |value| {
            packed.words[cursor] = value;
            cursor += 1;
        };
        for &byte in self.public.setup_seed.iter().chain(&self.public.context) {
            push(byte as u64);
        }
        for &word in self
            .public
            .ring
            .iter()
            .chain(&self.public.recipients)
            .flatten()
        {
            push(word);
        }
        for &word in self
            .witness
            .spending_keys
            .iter()
            .chain(&self.witness.commitment_keys)
            .flatten()
        {
            push(word as u64);
        }
        for &byte in self.witness.serials.iter().flatten() {
            push(byte as u64);
        }
        push(self.witness.selected_pair);
        for &amount in self
            .witness
            .input_amounts
            .iter()
            .chain(&self.witness.output_amounts)
        {
            push(amount);
        }
        for &byte in &entropy.0 {
            push(byte as u64);
        }
        debug_assert_eq!(cursor, input_layout::WORDS);
        Ok(packed)
    }
}

/// A separate secret result channel; never part of a public proof/report codec.
pub struct PrivateOutputKeys {
    polynomials: Vec<SignedPoly>,
}
impl PrivateOutputKeys {
    pub(crate) fn new(polynomials: Vec<SignedPoly>) -> Result<Self, String> {
        let keys = Self { polynomials };
        if keys.polynomials.len() != OUTPUTS * COMMITMENT_KEY_POLYS
            || keys
                .polynomials
                .iter()
                .flatten()
                .any(|&v| !(-1..=1).contains(&v))
        {
            return Err("GPU native spend returned invalid output-key geometry or bounds".into());
        }
        Ok(keys)
    }
    pub fn polynomials(&self) -> &[SignedPoly] {
        &self.polynomials
    }
}
impl Drop for PrivateOutputKeys {
    fn drop(&mut self) {
        wipe_polys(&mut self.polynomials);
    }
}

pub struct PrivateSpendOutput {
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
    pub output_keys: PrivateOutputKeys,
}
