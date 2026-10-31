use super::*;
use p3_field::PrimeField64;
use p3_symmetric::Permutation;

#[derive(Clone, Debug)]
pub enum PermutationInput {
    Canonical([u64; D]),
    Signed([i64; D]),
}
pub struct PermutationWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub output: PermutationInput,
}
fn signed(value: i64) -> Val {
    if value < 0 {
        -Val::from_u64(value.unsigned_abs())
    } else {
        Val::from_u64(value as u64)
    }
}
fn range(row: &mut [Val], start: usize, bits: usize, modulus: u64, value: u64) {
    row[start] = Val::from_u64(value);
    for bit in 0..bits {
        row[start + 1 + bit] = Val::from_u64((value >> bit) & 1);
    }
    let mut equal = true;
    for step in 0..bits / 4 {
        let shift = 4 * (bits / 4 - 1 - step);
        equal &= ((value >> shift) & 15) == (((modulus - 1) >> shift) & 15);
        row[start + 1 + bits + step] = Val::from_bool(equal);
    }
}
impl PermutationAir {
    pub fn generate(&self, input: &PermutationInput) -> Result<PermutationWitness, Error> {
        let (bank, output) = match (self.kind, input) {
            (PermutationKind::AutomorphismQ, PermutationInput::Canonical(input)) => {
                if input.iter().any(|&v| v >= Q) {
                    return Err(Error::NonCanonical);
                }
                (
                    input.map(Val::from_u64),
                    PermutationInput::Canonical(arithmetic::aut(input)),
                )
            }
            (PermutationKind::InverseChallenge, PermutationInput::Signed(input)) => {
                if input.iter().any(|v| v.unsigned_abs() > 1) {
                    return Err(Error::NonCanonical);
                }
                (
                    input.map(signed),
                    PermutationInput::Signed(arithmetic::inverse_aut(input)),
                )
            }
            _ => return Err(Error::Descriptor),
        };
        let width = self.width();
        let mut values = Val::zero_vec(HEIGHT * width);
        let mut poses = Vec::with_capacity(HEIGHT);
        let mut acc = [self.initial(); 2];
        for row_index in 0..HEIGHT {
            let row = &mut values[row_index * width..(row_index + 1) * width];
            row[BANK..BANK + D].copy_from_slice(&bank);
            for which in 0..2 {
                row[ACC + 4 * which..ACC + 4 * which + 4].copy_from_slice(&acc[which]);
            }
            let mut message = [Val::ZERO; 8];
            if row_index < 128 {
                let which = row_index / 64;
                message[..4].copy_from_slice(&acc[which]);
                for lane in 0..4 {
                    let target = 4 * (row_index % 64) + lane;
                    let source = if which == 0 {
                        target
                    } else {
                        self.source_index(target)
                    };
                    row[READ + lane] = bank[source];
                    let data = if which == 0 { input } else { &output };
                    let (magnitude, negative, encoded) = match data {
                        PermutationInput::Canonical(values) => {
                            (values[target], false, Val::from_u64(values[target]))
                        }
                        PermutationInput::Signed(values) => (
                            values[target].unsigned_abs(),
                            values[target] < 0,
                            signed(values[target]),
                        ),
                    };
                    row[SIGN + lane] = Val::from_bool(negative);
                    range(
                        row,
                        self.range(lane),
                        self.bits(),
                        self.modulus(),
                        magnitude,
                    );
                    if self.kind == PermutationKind::AutomorphismQ {
                        let quotient = if which == 1 {
                            bank[source].as_canonical_u64() * self.factor(target).as_canonical_u64()
                                / Q
                        } else {
                            0
                        };
                        range(row, self.quotient(lane), self.bits(), Q, quotient);
                    }
                    message[4 + lane] = encoded;
                }
                poses.push(message);
                p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut message);
                acc[which].copy_from_slice(&message[..4]);
            } else {
                for lane in 0..4 {
                    range(row, self.range(lane), self.bits(), self.modulus(), 0);
                    if self.kind == PermutationKind::AutomorphismQ {
                        range(row, self.quotient(lane), self.bits(), Q, 0);
                    }
                }
                poses.push(message);
            }
        }
        let pose_trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poses,
            &round_constants(),
            0,
        );
        for (index, row) in values.chunks_exact_mut(width).enumerate() {
            row[self.poseidon()..].copy_from_slice(
                &pose_trace.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
            );
        }
        let public_values = core::array::from_fn(|i| acc[i / 4][i % 4]);
        Ok(PermutationWitness {
            trace: RowMajorMatrix::new(values, width),
            public_values,
            output,
        })
    }
}
