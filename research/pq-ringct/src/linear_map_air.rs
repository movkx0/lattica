//! Fixed coefficientwise linear maps, compiled from the exact immutable DAG.
//!
//! Source roots and every coefficient bound are proved, not supplied as native
//! acceptance hints. A registration pins all scalar coefficients and constants.
use crate::{
    ntt_air::constraints::canonical_range,
    rust_verify::{
        committed_backend::PolynomialKind,
        constraints_ntt::{POLYNOMIAL_DOMAIN, SIGNED_POLYNOMIAL_DOMAIN},
        D, Q, QHAT,
    },
    shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

mod constraints;
mod descriptor;
#[cfg(feature = "opencl")]
mod gpu;
mod join;
#[cfg(test)]
mod tests;
mod witness;
pub use descriptor::{graph_operation, GraphLinearMap, LinearMapDescriptor};
pub use join::{LinearMapProof, PendingLinearMap, RegisteredLinearMapAir};
pub use witness::{LinearMapInput, LinearMapWitness};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Descriptor,
    NonCanonical,
    IntegerBound,
    Length,
}
#[derive(Clone, Debug)]
pub struct LinearMapAir {
    descriptor: LinearMapDescriptor,
}
fn field_signed(value: i64) -> Val {
    if value < 0 {
        -Val::from_u64(value.unsigned_abs())
    } else {
        Val::from_u64(value as u64)
    }
}
impl LinearMapAir {
    pub fn new(descriptor: LinearMapDescriptor) -> Self {
        Self { descriptor }
    }
    pub fn descriptor(&self) -> &LinearMapDescriptor {
        &self.descriptor
    }
    fn inputs(&self) -> usize {
        self.descriptor.inputs.len()
    }
    fn stride(&self) -> usize {
        (self.inputs() + 1).next_power_of_two()
    }
    pub fn height(&self) -> usize {
        64 * self.stride()
    }
    pub fn public_values(&self) -> usize {
        4 * (self.inputs() + 1)
    }
    fn acc(&self) -> usize {
        4 * self.inputs()
    }
    fn ranges(&self) -> usize {
        self.acc() + self.public_values()
    }
    fn bits(&self) -> usize {
        self.descriptor.bits
    }
    fn range_width(bits: usize) -> usize {
        1 + bits + bits / 4
    }
    fn range(&self, lane: usize) -> usize {
        self.ranges() + lane * Self::range_width(self.bits())
    }
    fn quotient_bits(&self) -> usize {
        let limit = 2 * self.descriptor.quotient_bound + 1;
        (64 - limit.leading_zeros() as usize).max(1).div_ceil(4) * 4
    }
    fn quotient(&self, lane: usize) -> usize {
        self.range(4) + lane * Self::range_width(self.quotient_bits())
    }
    fn poseidon(&self) -> usize {
        if matches!(self.descriptor.output, PolynomialKind::Canonical { .. }) {
            self.quotient(4)
        } else {
            self.range(4)
        }
    }
    pub fn width(&self) -> usize {
        self.poseidon() + POSEIDON_WIDTH
    }
    fn link(&self) -> usize {
        self.inputs() + 1
    }
    fn coefficient(&self, input: usize, lane: usize) -> usize {
        self.link() + 1 + 4 * input + lane
    }
    fn constant(&self, lane: usize) -> usize {
        self.coefficient(self.inputs(), lane)
    }
    fn bound_selector(&self, index: usize) -> usize {
        self.constant(4) + index
    }
    fn periodic_count(&self) -> usize {
        self.bound_selector(self.descriptor.bounds.len())
    }
    fn initial(&self, which: usize) -> [Val; 4] {
        let kind = if which == self.inputs() {
            self.descriptor.output
        } else {
            self.descriptor.inputs[which]
        };
        match kind {
            PolynomialKind::Canonical { modulus } => [
                Val::from_u64(POLYNOMIAL_DOMAIN),
                Val::from_u64(modulus),
                Val::from_usize(D),
                Val::ZERO,
            ],
            PolynomialKind::Signed { .. } => [
                Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
                Val::ZERO,
                Val::from_usize(D),
                Val::ZERO,
            ],
        }
    }
    fn metadata(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(self.height()); self.periodic_count()];
        for chunk in 0..64 {
            for phase in 0..self.stride() {
                let row = chunk * self.stride() + phase;
                if phase <= self.inputs() {
                    columns[phase][row] = Val::ONE;
                }
                columns[self.link()][row] = Val::from_bool(phase + 1 < self.stride());
                for input in 0..self.inputs() {
                    for lane in 0..4 {
                        columns[self.coefficient(input, lane)][row] =
                            field_signed(self.descriptor.coefficients[input][4 * chunk + lane]);
                    }
                }
                for lane in 0..4 {
                    columns[self.constant(lane)][row] =
                        field_signed(self.descriptor.constant[4 * chunk + lane]);
                }
                if !self.descriptor.bounds.is_empty() {
                    let bound = if phase < self.inputs() {
                        let PolynomialKind::Signed { bound } = self.descriptor.inputs[phase] else {
                            unreachable!()
                        };
                        bound
                    } else if phase == self.inputs() {
                        let PolynomialKind::Signed { bound } = self.descriptor.output else {
                            unreachable!()
                        };
                        bound
                    } else {
                        0
                    };
                    let position = self.descriptor.bounds.binary_search(&bound).unwrap();
                    columns[self.bound_selector(position)][row] = Val::ONE;
                }
            }
        }
        // Compress trusted schedules to their exact minimal power-of-two period.
        // Constant coefficients use period one; source phases use only stride.
        for column in &mut columns {
            while column.len() > 1 && column[..column.len() / 2] == column[column.len() / 2..] {
                column.truncate(column.len() / 2);
            }
        }
        columns
    }
}
impl BaseAir<Val> for LinearMapAir {
    fn width(&self) -> usize {
        self.width()
    }
    fn num_public_values(&self) -> usize {
        self.public_values()
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic_count()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.metadata()
    }
}
