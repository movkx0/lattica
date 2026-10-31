//! Segmented SHAKE256 relation with authenticated input/output commitments.
//!
//! A segment proves actual Keccak rounds, absorption, padding, squeezing and
//! Poseidon commitments to the corresponding ordered bytes. Adjacent segment
//! publics MUST be equated inside the consuming proof. Merely checking them
//! on the host does not establish a recursively aggregated SHAKE relation.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use std::borrow::Borrow;

mod constraints;
pub mod lane;
#[cfg(test)]
mod tests;
mod witness;
#[cfg(feature = "opencl")]
mod gpu;

pub use lattica_prover_p3::block_v2::machine::pq_bytes::{SHAKE_INPUT_DOMAIN, SHAKE_OUTPUT_DOMAIN};
pub use witness::SegmentWitness;

pub const RATE: usize = 136;
pub const PUBLIC_VALUES: usize = 216;
pub const START_STATE: usize = 0;
pub const END_STATE: usize = 100;
pub const INPUT_START: usize = 200;
pub const INPUT_END: usize = 204;
pub const OUTPUT_START: usize = 208;
pub const OUTPUT_END: usize = 212;

pub(crate) type PoseidonCols<T> = Poseidon2Cols<T, 8, 7, 0, 4, 22>;
pub(crate) type PoseidonAir = Poseidon2Air<Val, Linear, 8, 7, 0, 4, 22>;
pub(crate) const POSEIDON_WIDTH: usize = p3_poseidon2_air::num_cols::<8, 7, 0, 4, 22>();
const MESSAGE: usize = NUM_KECCAK_COLS;
const OUTPUT: usize = MESSAGE + 1088;
const ODD_BITS: usize = OUTPUT + 100;
const INPUT_ACC: usize = ODD_BITS + 16;
const OUTPUT_ACC: usize = INPUT_ACC + 4;
const INPUT_POSEIDON: usize = OUTPUT_ACC + 4;
const OUTPUT_POSEIDON: usize = INPUT_POSEIDON + POSEIDON_WIDTH;
pub const WIDTH: usize = OUTPUT_POSEIDON + POSEIDON_WIDTH;

const FULL_INPUT: usize = 0;
const LAST_INPUT: usize = 1;
const FULL_OUTPUT: usize = 2;
const LAST_OUTPUT: usize = 3;
const LINK: usize = 4;
const END: usize = 5;
pub const PERIODIC_COLUMNS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub input_len: usize,
    pub output_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Segment,
    Overflow,
}

impl Descriptor {
    pub fn permutations(self) -> Result<usize, Error> {
        let absorb = self.input_len / RATE + 1;
        let squeeze = self.output_len.saturating_sub(1) / RATE;
        absorb.checked_add(squeeze).ok_or(Error::Overflow)
    }
    fn absorb_permutations(self) -> usize {
        self.input_len / RATE + 1
    }
    fn input_bytes(self, permutation: usize) -> usize {
        self.input_len
            .saturating_sub(permutation.saturating_mul(RATE))
            .min(RATE)
    }
    fn output_bytes(self, permutation: usize) -> usize {
        let first = self.absorb_permutations() - 1;
        if permutation < first {
            return 0;
        }
        self.output_len
            .saturating_sub((permutation - first).saturating_mul(RATE))
            .min(RATE)
    }
}

/// `first_permutation` and `permutations` are trusted AIR metadata, not witness
/// values. The same descriptor and exact contiguous partition must be fixed
/// by the consuming recursive program and authenticated periodic-column schedule.
#[derive(Clone, Debug)]
pub struct ShakeAir {
    pub descriptor: Descriptor,
    pub first_permutation: usize,
    pub permutations: usize,
    pub height: usize,
}

impl ShakeAir {
    pub fn new(
        descriptor: Descriptor,
        first_permutation: usize,
        permutations: usize,
    ) -> Result<Self, Error> {
        // Protect native allocation products as well as field-valued lengths.
        if descriptor.input_len > u32::MAX as usize || descriptor.output_len > u32::MAX as usize {
            return Err(Error::Length);
        }
        let end = first_permutation
            .checked_add(permutations)
            .ok_or(Error::Overflow)?;
        if permutations == 0 || end > descriptor.permutations()? {
            return Err(Error::Segment);
        }
        let height = permutations
            .checked_mul(24)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Overflow)?;
        height.checked_mul(WIDTH).ok_or(Error::Overflow)?;
        Ok(Self {
            descriptor,
            first_permutation,
            permutations,
            height,
        })
    }

    pub fn whole(descriptor: Descriptor) -> Result<Self, Error> {
        Self::new(descriptor, 0, descriptor.permutations()?)
    }

    fn fixed_schedule(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(self.height); PERIODIC_COLUMNS];
        let last_absorb = self.descriptor.absorb_permutations() - 1;
        let full_output_end = last_absorb + self.descriptor.output_len / RATE;
        for row in 0..self.permutations * 24 {
            let local_perm = row / 24;
            let global_perm = self.first_permutation + local_perm;
            columns[FULL_INPUT][row] = Val::from_bool(global_perm < last_absorb);
            columns[LAST_INPUT][row] = Val::from_bool(global_perm == last_absorb);
            columns[FULL_OUTPUT][row] =
                Val::from_bool(global_perm >= last_absorb && global_perm < full_output_end);
            columns[LAST_OUTPUT][row] = Val::from_bool(
                self.descriptor.output_len % RATE != 0 && global_perm == full_output_end,
            );
            columns[LINK][row] =
                Val::from_bool(row % 24 == 23 && local_perm + 1 < self.permutations);
            columns[END][row] = Val::from_bool(row + 1 == self.permutations * 24);
        }
        columns
    }

    fn odd_output_limb(&self) -> usize {
        let remainder = self.descriptor.output_len % RATE;
        if remainder % 2 != 0 {
            remainder / 2
        } else {
            0
        }
    }
}

impl BaseAir<Val> for ShakeAir {
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
}

pub(crate) fn round_constants() -> RoundConstants<Val, 8, 4, 22> {
    RoundConstants::new(INITIAL, INTERNAL, FINAL)
}

/// Native companion to `pq_bytes::poseidon_commit_bytes`, for witness
/// generation and differential tests. It is never used as a proof oracle.
pub fn commit_bytes(domain: u64, bytes: &[u8]) -> [Val; 4] {
    let mut state = [
        Val::from_u64(domain),
        Val::from_usize(bytes.len()),
        Val::ZERO,
        Val::ZERO,
    ];
    for chunk in bytes.chunks(8) {
        let _ = absorb_commitment(&mut state, chunk);
    }
    state
}

pub(crate) fn absorb_commitment(state: &mut [Val; 4], bytes: &[u8]) -> [Val; 8] {
    assert!(bytes.len() <= 8);
    let mut input = [Val::ZERO; 8];
    input[..4].copy_from_slice(state);
    for (i, pair) in bytes.chunks(2).enumerate() {
        input[4 + i] =
            Val::from_u16(u16::from(pair[0]) + (u16::from(*pair.get(1).unwrap_or(&0)) << 8));
    }
    let original = input;
    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut input);
    state.copy_from_slice(&input[..4]);
    original
}

#[derive(Clone)]
pub(crate) struct SubWindow<W> {
    window: W,
    start: usize,
    width: usize,
}
impl<T, W: WindowAccess<T>> WindowAccess<T> for SubWindow<W> {
    fn current_slice(&self) -> &[T] {
        &self.window.current_slice()[self.start..self.start + self.width]
    }
    fn next_slice(&self) -> &[T] {
        &self.window.next_slice()[self.start..self.start + self.width]
    }
}

pub(crate) struct SubBuilder<'a, AB: AirBuilder> {
    pub parent: &'a mut AB,
    pub start: usize,
    pub width: usize,
}
impl<AB: AirBuilder> AirBuilder for SubBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type MainWindow = SubWindow<AB::MainWindow>;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        SubWindow {
            window: self.parent.main(),
            start: self.start,
            width: self.width,
        }
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.parent.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.parent.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.parent.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.parent.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.parent.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.parent.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.parent.periodic_values()
    }
}
