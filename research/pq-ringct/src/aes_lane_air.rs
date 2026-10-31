//! Serial AES-256-CTR component with small trace width and fixed schedules.
//! All state/key banks are copied or updated by AIR constraints on every row.
//! Native encryption generates hints only. Segments bind the same complete
//! request key/metadata commitment and expose chained output accumulators.
use crate::aes_air::{gf_mul, gf_pow, shifted_byte};
pub use crate::aes_air::{Descriptor, AES_INPUT_DOMAIN, AES_OUTPUT_DOMAIN};
use crate::shake_air::{
    absorb_commitment, round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

mod constraints;
#[cfg(test)]
mod degree_tests;
pub mod join;
#[cfg(test)]
mod tests;
mod witness;
#[cfg(feature = "opencl")]
mod gpu;
pub use witness::SegmentWitness;

pub const PUBLIC_VALUES: usize = 12;
pub const INPUT_COMMITMENT: usize = 0;
pub const OUTPUT_START: usize = 4;
pub const OUTPUT_END: usize = 8;
pub const ROWS_PER_BLOCK: usize = 1024;
pub const SCHEDULE_PERIOD: usize = 64;
const ROOT_KEY: usize = 0;
const KEY: usize = ROOT_KEY + 32;
const STATE: usize = KEY + 32;
const SCRATCH: usize = STATE + 16;
const READ: usize = SCRATCH + 16;
const SBOX: usize = READ + 64;
const RESULT: usize = SBOX + 66;
const CARRY: usize = RESULT + 8;
const COUNTER_BITS: usize = CARRY + 24;
const COUNTER_CARRY: usize = COUNTER_BITS + 32;
const BLOCK_INDEX: usize = COUNTER_CARRY + 1;
const REMAINING: usize = BLOCK_INDEX + 1;
const ACTIVE: usize = REMAINING + 1;
const ACTIVE_INV: usize = ACTIVE + 1;
const FIRST: usize = ACTIVE_INV + 1;
const FIRST_INV: usize = FIRST + 1;
const LAST: usize = FIRST_INV + 1;
const LAST_INV: usize = LAST + 1;
const INPUT_ACC: usize = LAST_INV + 1;
const OUTPUT_ACC: usize = INPUT_ACC + 4;
const PHASE_BITS: usize = OUTPUT_ACC + 4;
const PRELUDE: usize = PHASE_BITS + 4;
const ROUNDS: usize = PRELUDE + 1;
const FINAL_ROUND: usize = ROUNDS + 1;
const OUTPUT_PHASE: usize = FINAL_ROUND + 1;
const RCON_BITS: usize = OUTPUT_PHASE + 1;
const POSEIDON: usize = RCON_BITS + 8;
pub const WIDTH: usize = POSEIDON + POSEIDON_WIDTH;

const SLOT: usize = 0;
const SUB: usize = SLOT + 16;
const MIX: usize = SUB + 1;
const KEY_SUB: usize = MIX + 1;
const KEY_XOR: usize = KEY_SUB + 1;
const KEY_ROTATE: usize = KEY_XOR + 1;
const PHASE_END: usize = KEY_ROTATE + 1;
const HEADER: usize = PHASE_END + 1;
const OUTPUT_CHUNK: usize = HEADER + 7;
pub const PERIODIC_COLUMNS: usize = OUTPUT_CHUNK + 2;

// Exact under p3-air 0.6.1 symbolic degrees: the serial selectors/gadgets are
// at most seven, and the unconditional embedded Poseidon2 S-box attains seven.
// Update the admitted raw-symbolic tests whenever constraints or dependencies change.
const MAX_CONSTRAINT_DEGREE: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Segment,
    Overflow,
}

#[derive(Clone, Debug)]
pub struct AesLaneAir {
    pub descriptor: Descriptor,
    pub first_block: usize,
    pub blocks: usize,
    pub height: usize,
}
impl AesLaneAir {
    pub fn new(descriptor: Descriptor) -> Result<Self, Error> {
        Self::segment(descriptor, 0, descriptor.blocks())
    }
    pub fn segment(
        descriptor: Descriptor,
        first_block: usize,
        blocks: usize,
    ) -> Result<Self, Error> {
        if descriptor.output_len == 0 || descriptor.output_len > u32::MAX as usize {
            return Err(Error::Length);
        }
        if blocks == 0
            || first_block.checked_add(blocks).ok_or(Error::Overflow)? > descriptor.blocks()
        {
            return Err(Error::Segment);
        }
        let height = blocks
            .checked_mul(ROWS_PER_BLOCK)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Overflow)?;
        height.checked_mul(WIDTH).ok_or(Error::Overflow)?;
        Ok(Self {
            descriptor,
            first_block,
            blocks,
            height,
        })
    }
    fn schedule() -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(SCHEDULE_PERIOD); PERIODIC_COLUMNS];
        for row in 0..SCHEDULE_PERIOD {
            let i = row % 16;
            columns[SLOT + i][row] = Val::ONE;
            if row < 48 {
                let op = if row < 16 {
                    SUB
                } else if row < 32 {
                    MIX
                } else if i < 4 {
                    KEY_SUB
                } else {
                    KEY_XOR
                };
                columns[op][row] = Val::ONE;
            }
        }
        for i in 0..7 {
            columns[HEADER + i][i] = Val::ONE;
        }
        columns[KEY_ROTATE][47] = Val::ONE;
        columns[PHASE_END][63] = Val::ONE;
        columns[OUTPUT_CHUNK][0] = Val::ONE;
        columns[OUTPUT_CHUNK + 1][1] = Val::ONE;
        columns
    }
}
impl BaseAir<Val> for AesLaneAir {
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(MAX_CONSTRAINT_DEGREE)
    }
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
        Self::schedule()
    }
}
