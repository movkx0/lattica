use super::*;
pub use crate::rust_verify::committed_backend::PolynomialValues as LinearMapInput;
use crate::rust_verify::constraints_ntt::{commit_signed_values, commit_values};
use p3_symmetric::Permutation;
pub struct LinearMapWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: Vec<Val>,
    pub output: LinearMapInput,
}
fn value(input: &LinearMapInput, index: usize) -> i128 {
    match input {
        LinearMapInput::Canonical(values) => i128::from(values[index]),
        LinearMapInput::Signed(values) => i128::from(values[index]),
    }
}
fn range(row: &mut [Val], start: usize, bits: usize, upper: u64, value: u64) {
    row[start] = Val::from_u64(value);
    for bit in 0..bits {
        row[start + 1 + bit] = Val::from_u64((value >> bit) & 1);
    }
    let mut equal = true;
    for step in 0..bits / 4 {
        let shift = 4 * (bits / 4 - 1 - step);
        equal &= ((value >> shift) & 15) == ((upper >> shift) & 15);
        row[start + 1 + bits + step] = Val::from_bool(equal);
    }
}
impl LinearMapAir {
    pub fn generate(&self, inputs: &[LinearMapInput]) -> Result<LinearMapWitness, Error> {
        if inputs.len() != self.inputs() {
            return Err(Error::Length);
        }
        for (input, kind) in inputs.iter().zip(&self.descriptor.inputs) {
            match (input, kind) {
                (LinearMapInput::Canonical(values), PolynomialKind::Canonical { modulus })
                    if values.iter().all(|v| v < modulus) => {}
                (LinearMapInput::Signed(values), PolynomialKind::Signed { bound })
                    if values.iter().all(|v| v.unsigned_abs() <= u64::from(*bound)) => {}
                _ => return Err(Error::NonCanonical),
            }
        }
        let sums: [i128; D] = core::array::from_fn(|index| {
            self.descriptor.coefficients.iter().zip(inputs).fold(
                i128::from(self.descriptor.constant[index]),
                |sum, (coefficient, input)| {
                    sum + i128::from(coefficient[index]) * value(input, index)
                },
            )
        });
        let output = match self.descriptor.output {
            PolynomialKind::Canonical { modulus } => LinearMapInput::Canonical(
                sums.map(|sum| sum.rem_euclid(i128::from(modulus)) as u64),
            ),
            PolynomialKind::Signed { bound } => {
                if sums
                    .iter()
                    .any(|sum| sum.unsigned_abs() > u128::from(bound))
                {
                    return Err(Error::NonCanonical);
                }
                LinearMapInput::Signed(sums.map(|sum| sum as i64))
            }
        };
        let mut public_values = Vec::with_capacity(self.public_values());
        for (values, kind) in inputs.iter().chain(std::iter::once(&output)).zip(
            self.descriptor
                .inputs
                .iter()
                .chain(std::iter::once(&self.descriptor.output)),
        ) {
            let root = match (values, kind) {
                (LinearMapInput::Canonical(values), PolynomialKind::Canonical { modulus }) => {
                    commit_values(POLYNOMIAL_DOMAIN, *modulus, values)
                }
                (LinearMapInput::Signed(values), PolynomialKind::Signed { .. }) => {
                    commit_signed_values(values)
                }
                _ => unreachable!(),
            };
            public_values.extend(root);
        }
        let width = self.width();
        let mut trace = Val::zero_vec(self.height() * width);
        let mut poses = Vec::with_capacity(self.height());
        let mut accumulators: Vec<_> = (0..=self.inputs())
            .map(|which| self.initial(which))
            .collect();
        for chunk in 0..64 {
            for phase in 0..self.stride() {
                let row_index = chunk * self.stride() + phase;
                let row = &mut trace[row_index * width..(row_index + 1) * width];
                for (input, values) in inputs.iter().enumerate() {
                    for lane in 0..4 {
                        row[4 * input + lane] =
                            field_signed(value(values, 4 * chunk + lane) as i64);
                    }
                }
                for (which, acc) in accumulators.iter().enumerate() {
                    row[self.acc() + 4 * which..self.acc() + 4 * which + 4].copy_from_slice(acc);
                }
                let mut message = [Val::ZERO; 8];
                if phase <= self.inputs() {
                    message[..4].copy_from_slice(&accumulators[phase]);
                }
                for lane in 0..4 {
                    let index = 4 * chunk + lane;
                    let (current, kind) = if phase < self.inputs() {
                        (
                            value(&inputs[phase], index),
                            Some(self.descriptor.inputs[phase]),
                        )
                    } else if phase == self.inputs() {
                        (value(&output, index), Some(self.descriptor.output))
                    } else {
                        (0, None)
                    };
                    let (encoded, upper) = match kind {
                        Some(PolynomialKind::Canonical { modulus }) => {
                            (current as u64, modulus - 1)
                        }
                        Some(PolynomialKind::Signed { bound }) => {
                            ((current + i128::from(bound)) as u64, u64::from(bound) * 2)
                        }
                        None => (
                            0,
                            if let PolynomialKind::Canonical { modulus } = self.descriptor.output {
                                modulus - 1
                            } else {
                                0
                            },
                        ),
                    };
                    range(row, self.range(lane), self.bits(), upper, encoded);
                    if let PolynomialKind::Canonical { modulus } = self.descriptor.output {
                        let quotient = if phase == self.inputs() {
                            let quotient = (sums[index] - value(&output, index))
                                / i128::from(modulus)
                                + i128::from(self.descriptor.quotient_bound);
                            if quotient < 0
                                || quotient > i128::from(self.descriptor.quotient_bound) * 2
                            {
                                return Err(Error::IntegerBound);
                            }
                            quotient as u64
                        } else {
                            0
                        };
                        range(
                            row,
                            self.quotient(lane),
                            self.quotient_bits(),
                            2 * self.descriptor.quotient_bound,
                            quotient,
                        );
                    }
                    message[4 + lane] = field_signed(current as i64);
                }
                poses.push(message);
                p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut message);
                if phase <= self.inputs() {
                    accumulators[phase].copy_from_slice(&message[..4]);
                }
            }
        }
        let pose_trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poses,
            &round_constants(),
            0,
        );
        for (index, row) in trace.chunks_exact_mut(width).enumerate() {
            row[self.poseidon()..].copy_from_slice(
                &pose_trace.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
            );
        }
        Ok(LinearMapWitness {
            trace: RowMajorMatrix::new(trace, width),
            public_values,
            output,
        })
    }
}
