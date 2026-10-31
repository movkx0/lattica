//! Constrained byte primitives for the MatRiCT+ verifier.
//!
//! These are ordinary arithmetic/Boolean machine programs, not host hash
//! oracles. Inputs are byte-valued field witnesses; internal bit hints are
//! constrained by Booleanity and exact reconstruction. Program shape depends
//! only on fixed lengths and public protocol constants, never witness values.
//! The incremental permutation and reusable key schedule permit segmentation;
//! callers must authenticate every intermediate state when doing so.

use super::program::{ScopedProgramBuilder as Builder, Val, Wire};
use p3_field::PrimeCharacteristicRing;

/// A byte whose little-endian bits are constrained to be Boolean.
#[derive(Clone, Copy, Debug)]
pub struct Byte([Wire; 8]);

pub const SHAKE_INPUT_DOMAIN: u64 = 0x5348_414b_455f_494e;
pub const SHAKE_OUTPUT_DOMAIN: u64 = 0x5348_414b_455f_4f55;

/// Domain-separated commitment used to bind SHAKE component proofs. Pack
/// little-endian pairs of bytes into field elements, with a zero high byte
/// for an odd final length. The byte length is part of the initial state.
/// This is distinct from `hash_fields`, whose length is a field-element count.
pub fn poseidon_commit_bytes(b: &mut Builder<'_>, domain: u64, bytes: &[Byte]) -> [Wire; 4] {
    let zero = b.constant(Val::ZERO);
    let mut state = [
        b.constant(Val::from_u64(domain)),
        b.constant(Val::from_usize(bytes.len())),
        zero,
        zero,
    ];
    let weight = b.constant(Val::from_u64(256));
    let fields: Vec<_> = bytes
        .chunks(2)
        .map(|pair| {
            let low = pair[0].to_wire(b);
            if pair.len() == 1 {
                return low;
            }
            let high = pair[1].to_wire(b);
            let high = b.mul(high, weight);
            b.add(low, high)
        })
        .collect();
    for chunk in fields.chunks(4) {
        let mut input = [zero; 8];
        input[..4].copy_from_slice(&state);
        input[4..4 + chunk.len()].copy_from_slice(chunk);
        state.copy_from_slice(&b.poseidon(input)[..4]);
    }
    state
}

impl Byte {
    /// Allocate one field witness. Append its integer byte value to the host
    /// witness vector in allocation order; no auxiliary witness is required.
    pub fn input(b: &mut Builder<'_>) -> Self {
        let value = b.input();
        Self::from_wire(b, value)
    }

    /// Constrain `value` to [0,256) and decompose it. Reconstruction is unique
    /// because 255 is below the Goldilocks modulus.
    pub fn from_wire(b: &mut Builder<'_>, value: Wire) -> Self {
        let bits = core::array::from_fn(|i| b.bit_hint(value, i));
        let result = Self::from_bits(b, bits);
        let reconstructed = result.to_wire(b);
        b.assert_equal(reconstructed, value);
        result
    }

    pub fn from_bits(b: &mut Builder<'_>, bits: [Wire; 8]) -> Self {
        for bit in bits {
            b.assert_bool(bit);
        }
        Self(bits)
    }

    pub fn constant(b: &mut Builder<'_>, value: u8) -> Self {
        Self(core::array::from_fn(|i| {
            b.constant(Val::from_u8((value >> i) & 1))
        }))
    }

    pub fn bits(self) -> [Wire; 8] {
        self.0
    }

    pub fn to_wire(self, b: &mut Builder<'_>) -> Wire {
        let mut result = b.constant(Val::ZERO);
        for (i, bit) in self.0.into_iter().enumerate() {
            let weight = b.constant(Val::from_u64(1 << i));
            let term = b.mul(bit, weight);
            result = b.add(result, term);
        }
        result
    }

    pub fn xor(self, b: &mut Builder<'_>, other: Self) -> Self {
        Self(core::array::from_fn(|i| bit_xor(b, self.0[i], other.0[i])))
    }
}

fn bit_not(b: &mut Builder<'_>, a: Wire) -> Wire {
    let one = b.constant(Val::ONE);
    let zero = b.constant(Val::ZERO);
    b.select(a, one, zero)
}

fn bit_xor(b: &mut Builder<'_>, a: Wire, c: Wire) -> Wire {
    if a == c {
        return b.constant(Val::ZERO);
    }
    let not_c = bit_not(b, c);
    b.select(a, c, not_c)
}

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROT: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Full 24-round Keccak-f[1600], with standard little-endian lane encoding.
/// A caller splitting permutations across proofs must bind all 200 state
/// bytes between proofs; exposing only the rate is insufficient.
pub fn keccak_f1600(b: &mut Builder<'_>, state: &mut [Byte; 200]) {
    let zero = b.constant(Val::ZERO);
    let mut a: [Wire; 1600] = core::array::from_fn(|i| state[i / 8].0[i % 8]);
    for round_constant in KECCAK_RC {
        let mut c = [[zero; 64]; 5];
        for x in 0..5 {
            for z in 0..64 {
                let mut parity = a[x * 64 + z];
                for y in 1..5 {
                    parity = bit_xor(b, parity, a[(x + 5 * y) * 64 + z]);
                }
                c[x][z] = parity;
            }
        }
        for x in 0..5 {
            for z in 0..64 {
                let d = bit_xor(b, c[(x + 4) % 5][z], c[(x + 1) % 5][(z + 63) % 64]);
                for y in 0..5 {
                    let index = (x + 5 * y) * 64 + z;
                    a[index] = bit_xor(b, a[index], d);
                }
            }
        }
        let mut rotated = [zero; 1600];
        for x in 0..5 {
            for y in 0..5 {
                let lane = x + 5 * y;
                let destination = y + 5 * ((2 * x + 3 * y) % 5);
                for z in 0..64 {
                    rotated[destination * 64 + (z + KECCAK_ROT[lane]) % 64] = a[lane * 64 + z];
                }
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let index = (x + 5 * y) * 64 + z;
                    let next = rotated[((x + 1) % 5 + 5 * y) * 64 + z];
                    let after = rotated[((x + 2) % 5 + 5 * y) * 64 + z];
                    let and_not = b.select(next, after, zero);
                    a[index] = bit_xor(b, rotated[index], and_not);
                }
            }
        }
        for (z, bit) in a[..64].iter_mut().enumerate() {
            if (round_constant >> z) & 1 != 0 {
                *bit = bit_not(b, *bit);
            }
        }
    }
    *state = core::array::from_fn(|i| Byte(core::array::from_fn(|j| a[8 * i + j])));
}

/// SHAKE256 with fixed input/output lengths. Handles empty input, exact-rate
/// input, the suffix/final-bit overlap at byte 135, and multiple squeeze blocks.
pub fn shake256(b: &mut Builder<'_>, input: &[Byte], output_len: usize) -> Vec<Byte> {
    const RATE: usize = 136;
    let zero = Byte::constant(b, 0);
    let mut state = [zero; 200];
    let mut chunks = input.chunks_exact(RATE);
    for chunk in chunks.by_ref() {
        for i in 0..RATE {
            state[i] = state[i].xor(b, chunk[i]);
        }
        keccak_f1600(b, &mut state);
    }
    let rest = chunks.remainder();
    for (i, byte) in rest.iter().enumerate() {
        state[i] = state[i].xor(b, *byte);
    }
    let suffix = Byte::constant(b, 0x1f);
    state[rest.len()] = state[rest.len()].xor(b, suffix);
    let final_bit = Byte::constant(b, 0x80);
    state[RATE - 1] = state[RATE - 1].xor(b, final_bit);
    keccak_f1600(b, &mut state);
    let mut result = Vec::with_capacity(output_len);
    while result.len() < output_len {
        let take = (output_len - result.len()).min(RATE);
        result.extend_from_slice(&state[..take]);
        if result.len() < output_len {
            keccak_f1600(b, &mut state);
        }
    }
    result
}

fn xtime(b: &mut Builder<'_>, a: Byte) -> Byte {
    let zero = b.constant(Val::ZERO);
    Byte(core::array::from_fn(|i| {
        let shifted = if i == 0 { zero } else { a.0[i - 1] };
        if (0x1bu8 >> i) & 1 != 0 {
            bit_xor(b, shifted, a.0[7])
        } else {
            shifted
        }
    }))
}

fn gf_mul(b: &mut Builder<'_>, mut a: Byte, c: Byte) -> Byte {
    let mut result = Byte::constant(b, 0);
    for i in 0..8 {
        let term = Byte(core::array::from_fn(|j| b.mul(a.0[j], c.0[i])));
        result = result.xor(b, term);
        if i != 7 {
            a = xtime(b, a);
        }
    }
    result
}

fn gf_square(b: &mut Builder<'_>, a: Byte) -> Byte {
    // Squaring is linear over GF(2). These are x^(2*i) mod (x^8+x^4+x^3+x+1).
    const BASIS: [u8; 8] = [0x01, 0x04, 0x10, 0x40, 0x1b, 0x6c, 0xab, 0x9a];
    Byte(core::array::from_fn(|i| {
        let mut bit = b.constant(Val::ZERO);
        for (j, basis) in BASIS.into_iter().enumerate() {
            if (basis >> i) & 1 != 0 {
                bit = bit_xor(b, bit, a.0[j]);
            }
        }
        bit
    }))
}

fn aes_sbox(b: &mut Builder<'_>, a: Byte) -> Byte {
    // a^254 is the multiplicative inverse for nonzero bytes and maps zero to
    // zero, exactly as required by the AES S-box. Four field multiplications;
    // squarings are linear and all GF operations are Boolean constraints.
    let a2 = gf_square(b, a);
    let a3 = gf_mul(b, a2, a);
    let a6 = gf_square(b, a3);
    let a12 = gf_square(b, a6);
    let a15 = gf_mul(b, a12, a3);
    let a30 = gf_square(b, a15);
    let a60 = gf_square(b, a30);
    let a120 = gf_square(b, a60);
    let a240 = gf_square(b, a120);
    let a252 = gf_mul(b, a240, a12);
    let inverse = gf_mul(b, a252, a2);
    Byte(core::array::from_fn(|i| {
        let mut bit = inverse.0[i];
        for offset in [4, 5, 6, 7] {
            bit = bit_xor(b, bit, inverse.0[(i + offset) % 8]);
        }
        if (0x63u8 >> i) & 1 != 0 {
            bit_not(b, bit)
        } else {
            bit
        }
    }))
}

/// Expanded AES-256 key. Reuse one constrained schedule for every block with
/// the same seed, as the author implementation does.
pub struct Aes256Key {
    rounds: [[Byte; 16]; 15],
}

impl Aes256Key {
    pub fn expand(b: &mut Builder<'_>, key: &[Byte; 32]) -> Self {
        let zero = Byte::constant(b, 0);
        let mut words = [[zero; 4]; 60];
        for i in 0..8 {
            words[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in 8..60 {
            let mut temp = words[i - 1];
            if i % 8 == 0 {
                temp.rotate_left(1);
                temp = temp.map(|byte| aes_sbox(b, byte));
                let round_constant = Byte::constant(b, rcon);
                temp[0] = temp[0].xor(b, round_constant);
                rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x1b } else { 0 };
            } else if i % 8 == 4 {
                temp = temp.map(|byte| aes_sbox(b, byte));
            }
            words[i] = core::array::from_fn(|j| words[i - 8][j].xor(b, temp[j]));
        }
        Self {
            rounds: core::array::from_fn(|i| core::array::from_fn(|j| words[4 * i + j / 4][j % 4])),
        }
    }

    pub fn encrypt(&self, b: &mut Builder<'_>, input: &[Byte; 16]) -> [Byte; 16] {
        let mut state = core::array::from_fn(|i| input[i].xor(b, self.rounds[0][i]));
        for round in 1..=14 {
            state = state.map(|byte| aes_sbox(b, byte));
            let shifted = core::array::from_fn(|i| {
                let row = i % 4;
                let column = i / 4;
                state[4 * ((column + row) % 4) + row]
            });
            state = shifted;
            if round != 14 {
                for column in 0..4 {
                    let c: [Byte; 4] = core::array::from_fn(|row| state[4 * column + row]);
                    let t01 = c[0].xor(b, c[1]);
                    let t23 = c[2].xor(b, c[3]);
                    let total = t01.xor(b, t23);
                    for row in 0..4 {
                        let adjacent = c[row].xor(b, c[(row + 1) % 4]);
                        let doubled = xtime(b, adjacent);
                        let base = c[row].xor(b, total);
                        state[4 * column + row] = base.xor(b, doubled);
                    }
                }
            }
            state = core::array::from_fn(|i| state[i].xor(b, self.rounds[round][i]));
        }
        state
    }

    /// Author-compatible counter stream: LE u32 counter, four zero bytes,
    /// then LE u64 domain. A partial block's unused tail is discarded; the
    /// next call must advance its start counter by ceil(output_len / 16).
    pub fn ctr(
        &self,
        b: &mut Builder<'_>,
        domain: u64,
        start_counter: u32,
        output_len: usize,
    ) -> Vec<Byte> {
        let mut result = Vec::with_capacity(output_len);
        let blocks = output_len / 16 + usize::from(output_len % 16 != 0);
        for block in 0..blocks {
            let counter = start_counter.wrapping_add(block as u32);
            let mut encoded = [0u8; 16];
            encoded[..4].copy_from_slice(&counter.to_le_bytes());
            encoded[8..].copy_from_slice(&domain.to_le_bytes());
            let input = encoded.map(|v| Byte::constant(b, v));
            let encrypted = self.encrypt(b, &input);
            let take = (output_len - result.len()).min(16);
            result.extend_from_slice(&encrypted[..take]);
        }
        result
    }
}

#[cfg(test)]
mod tests;
