//! Lane-serialized SHAKE component, with the same 216 authenticated endpoints
//! as `ShakeAir`. Every state/scratch register is carried by AIR constraints;
//! there are no memory lookups or native cryptographic acceptance oracles.
//!
//! One component covers one permutation. A constrained five-bit block counter
//! selects the prelude, 24 Keccak rounds, squeeze and idle blocks. All trusted
//! periodic schedules have period 128, independent of the 4096-row trace.

use super::*;

pub mod batch;
mod constraints;
mod join;
pub use join::{verify_request, LaneShakeProof};
#[cfg(test)]
mod tests;
#[cfg(test)]
mod degree_tests;
mod witness;
#[cfg(feature = "opencl")]
mod gpu;

pub const HEIGHT: usize = 4096;
pub const SCHEDULE_PERIOD: usize = 128;
// Exact in pinned p3-air symbolic degree units: selected (2) * round
// selector (2) * theta/chi (3), and embedded Poseidon2 with degree 7.
// Batch RC resets also reach 7. Keep degree_tests in sync with AIR changes.
const MAX_CONSTRAINT_DEGREE: usize = 7;
const STATE: usize = 0;
const SCRATCH: usize = 100;
const BITS: usize = 200;
const INPUT_ACC: usize = BITS + 192;
const OUTPUT_ACC: usize = INPUT_ACC + 4;
const COUNTER: usize = OUTPUT_ACC + 4;
const PRELUDE: usize = COUNTER + 5;
const ROUNDS: usize = PRELUDE + 1;
const FINAL_ROUND: usize = ROUNDS + 1;
const RC: usize = FINAL_ROUND + 1;
const POSEIDON: usize = RC + 15;
pub const WIDTH: usize = POSEIDON + POSEIDON_WIDTH;

const SX: usize = 0;
const SY: usize = 5;
const C_RESET: usize = 10;
const C_UPDATE: usize = 11;
const THETA: usize = 12;
const RHO: usize = 13;
const CHI: usize = 14;
const IOTA: usize = 15;
const BYTES: usize = 16;
const BLOCK_END: usize = 17;
const INPUT_RAW: usize = 18;
const SUFFIX: usize = INPUT_RAW + 8;
const OUTPUT_RAW: usize = SUFFIX + 8;
pub const PERIODIC_COLUMNS: usize = OUTPUT_RAW + 8;

const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

#[derive(Clone, Debug)]
pub struct LaneShakeAir {
    pub descriptor: Descriptor,
    pub permutation: usize,
}

impl LaneShakeAir {
    pub fn new(descriptor: Descriptor, permutation: usize) -> Result<Self, Error> {
        ShakeAir::new(descriptor, permutation, 1)?;
        Ok(Self {
            descriptor,
            permutation,
        })
    }

    fn absorbs(&self) -> bool {
        self.permutation < self.descriptor.absorb_permutations()
    }

    fn last_absorption(&self) -> bool {
        self.permutation + 1 == self.descriptor.absorb_permutations()
    }

    fn fixed_schedule(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(SCHEDULE_PERIOD); PERIODIC_COLUMNS];
        let input_bytes = self.descriptor.input_bytes(self.permutation);
        let output_bytes = self.descriptor.output_bytes(self.permutation);
        for step in 0..SCHEDULE_PERIOD {
            let (x, y, op) = match step {
                0..=24 => (
                    step / 5,
                    step % 5,
                    if step % 5 == 0 { C_RESET } else { C_UPDATE },
                ),
                25..=49 => ((step - 25) % 5, (step - 25) / 5, THETA),
                50..=74 => ((step - 50) % 5, (step - 50) / 5, RHO),
                75..=99 => ((step - 75) % 5, (step - 75) / 5, CHI),
                100 => (0, 0, IOTA),
                101..=117 => ((step - 101) % 5, (step - 101) / 5, BYTES),
                _ => (0, 0, BLOCK_END),
            };
            columns[SX + x][step] = Val::ONE;
            columns[SY + y][step] = Val::ONE;
            if step <= 117 || step == 127 {
                columns[op][step] = Val::ONE;
            }
            if (101..=117).contains(&step) {
                for byte in 0..8 {
                    let position = (step - 101) * 8 + byte;
                    columns[INPUT_RAW + byte][step] = Val::from_bool(position < input_bytes);
                    columns[SUFFIX + byte][step] =
                        Val::from_bool(self.last_absorption() && position == input_bytes);
                    columns[OUTPUT_RAW + byte][step] = Val::from_bool(position < output_bytes);
                }
            }
        }
        columns
    }
}

impl BaseAir<Val> for LaneShakeAir {
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
        self.fixed_schedule()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(MAX_CONSTRAINT_DEGREE)
    }
}
