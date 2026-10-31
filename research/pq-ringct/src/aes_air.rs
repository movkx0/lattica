//! Fixed-request AES-256-CTR AIR with commitments to every input/output byte.
//!
//! This component proves AES itself; native encryption only supplies trace
//! witnesses. A consuming recursive verifier must bind both public commitments
//! to the arithmetic component's matching PendingAes request and pin descriptor
//! periodic schedule. Successful native encryption is never an acceptance flag.

pub use crate::rust_verify::constraints_crypto::{AES_INPUT_DOMAIN, AES_OUTPUT_DOMAIN};
use crate::shake_air::{
    absorb_commitment, round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

pub(crate) mod constraints;
#[cfg(test)]
mod tests;
pub(crate) mod witness;
#[cfg(feature = "opencl")]
mod gpu;
pub use witness::AesWitness;

pub const PUBLIC_VALUES: usize = 8;
const ROOT_KEY: usize = 0;
const KEY: usize = ROOT_KEY + 256;
const STATE: usize = KEY + 256;
const CIPHER: usize = STATE + 128;
const SBOX_WIDTH: usize = 66;
const INV: usize = 0;
const GF_CARRY: usize = 8;
const ZERO: usize = 40;
const FIELD_INV: usize = 41;
const SBOX_OUT: usize = 42;
const AFFINE_CARRY: usize = 50;
const STATE_SBOX: usize = CIPHER + 128;
const KEY_SBOX: usize = STATE_SBOX + 16 * SBOX_WIDTH;
const NEXT_KEY: usize = KEY_SBOX + 4 * SBOX_WIDTH;
const KEY_CARRY: usize = NEXT_KEY + 128;
const STATE_OUT: usize = KEY_CARRY + 128;
const STATE_CARRY: usize = STATE_OUT + 128;
const COUNTER_BITS: usize = STATE_CARRY + 128 * 3;
const INPUT_ACC: usize = COUNTER_BITS + 32;
const OUTPUT_ACC: usize = INPUT_ACC + 4;
const INPUT_POSEIDON: usize = OUTPUT_ACC + 4;
const OUTPUT_POSEIDON: usize = INPUT_POSEIDON + POSEIDON_WIDTH;
pub const WIDTH: usize = OUTPUT_POSEIDON + POSEIDON_WIDTH;

const ACTIVE: usize = 0;
const FIRST: usize = 1;
const LAST: usize = 2;
const MIDDLE: usize = 3;
const END: usize = 4;
const GLOBAL_LINK: usize = 5;
const ROTATE: usize = 6;
const RCON: usize = 7;
const COUNTER: usize = RCON + 8;
const INPUT_CHUNK: usize = COUNTER + 1;
const OUTPUT_CHUNK: usize = INPUT_CHUNK + 7;
const FULL_BLOCK: usize = OUTPUT_CHUNK + 2;
pub const PERIODIC_COLUMNS: usize = FULL_BLOCK + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub domain: u64,
    pub start_counter: u32,
    pub output_len: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Overflow,
}
impl Descriptor {
    pub fn blocks(self) -> usize {
        self.output_len.div_ceil(16)
    }
    pub fn input_bytes(self, key: &[u8; 32]) -> [u8; 52] {
        let mut result = [0; 52];
        result[..32].copy_from_slice(key);
        result[32..40].copy_from_slice(&self.domain.to_le_bytes());
        result[40..44].copy_from_slice(&self.start_counter.to_le_bytes());
        result[44..].copy_from_slice(&(self.output_len as u64).to_le_bytes());
        result
    }
    fn counter(self, block: usize) -> [u8; 16] {
        let mut result = [0; 16];
        result[..4].copy_from_slice(&self.start_counter.wrapping_add(block as u32).to_le_bytes());
        result[8..].copy_from_slice(&self.domain.to_le_bytes());
        result
    }
}
#[derive(Clone, Debug)]
pub struct AesAir {
    pub descriptor: Descriptor,
    pub height: usize,
}
impl AesAir {
    pub fn new(descriptor: Descriptor) -> Result<Self, Error> {
        if descriptor.output_len == 0 || descriptor.output_len > u32::MAX as usize {
            return Err(Error::Length);
        }
        let height = descriptor
            .blocks()
            .checked_mul(14)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Overflow)?;
        height.checked_mul(WIDTH).ok_or(Error::Overflow)?;
        Ok(Self { descriptor, height })
    }
    fn metadata(&self) -> RowMajorMatrix<Val> {
        let mut values = Val::zero_vec(self.height * PERIODIC_COLUMNS);
        let rows = self.descriptor.blocks() * 14;
        for (index, row) in values
            .chunks_exact_mut(PERIODIC_COLUMNS)
            .enumerate()
            .take(rows)
        {
            let round = index % 14;
            let block = index / 14;
            row[ACTIVE] = Val::ONE;
            row[FIRST] = Val::from_bool(round == 0);
            row[LAST] = Val::from_bool(round == 13);
            row[MIDDLE] = Val::from_bool(round < 13);
            row[END] = Val::from_bool(index + 1 == rows);
            row[GLOBAL_LINK] = Val::from_bool(index + 1 < rows);
            row[ROTATE] = Val::from_bool(round % 2 == 0);
            let rcon = if round % 2 == 0 {
                gf_pow(2, (round / 2) as u16)
            } else {
                0
            };
            for bit in 0..8 {
                row[RCON + bit] = Val::from_u8((rcon >> bit) & 1);
            }
            row[COUNTER] = Val::from_u32(self.descriptor.start_counter.wrapping_add(block as u32));
            row[FULL_BLOCK] = Val::from_bool(block + 1 < self.descriptor.blocks());
            if block == 0 && round < 7 {
                row[INPUT_CHUNK + round] = Val::ONE;
            }
            let take = self
                .descriptor
                .output_len
                .saturating_sub(block * 16)
                .min(16);
            if round < 2 && round * 8 < take {
                row[OUTPUT_CHUNK + round] = Val::ONE;
            }
        }
        RowMajorMatrix::new(values, PERIODIC_COLUMNS)
    }
}
impl BaseAir<Val> for AesAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        let metadata = self.metadata();
        (0..PERIODIC_COLUMNS)
            .map(|column| {
                (0..self.height)
                    .map(|row| metadata.values[row * PERIODIC_COLUMNS + column])
                    .collect()
            })
            .collect()
    }
}

pub(crate) fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            out ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    out
}
pub(crate) fn gf_pow(a: u8, mut power: u16) -> u8 {
    let mut value = 1;
    let mut base = a;
    while power != 0 {
        if power & 1 != 0 {
            value = gf_mul(value, base);
        }
        base = gf_mul(base, base);
        power >>= 1;
    }
    value
}
pub(crate) fn reduction(power: usize) -> u8 {
    let mut value = 1_u16 << power;
    for bit in (8..=14).rev() {
        if value & (1 << bit) != 0 {
            value ^= 0x11b << (bit - 8);
        }
    }
    value as u8
}
pub(crate) fn shifted_byte(byte: usize) -> usize {
    let column = byte / 4;
    let row = byte % 4;
    4 * ((column + row) % 4) + row
}
