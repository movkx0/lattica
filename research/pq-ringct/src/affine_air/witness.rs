use super::*;
use crate::rust_verify::{
    arithmetic,
    constraints_ntt::{commit_signed_values, commit_values},
};

#[derive(Clone, Debug)]
pub enum AffineInput {
    Binary { left: [u64; D], right: [u64; D] },
    Signed([i64; D]),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffineRoots {
    pub left: [Val; 4],
    pub right: Option<[Val; 4]>,
    pub output: [Val; 4],
}
pub struct AffineWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub roots: Vec<AffineRoots>,
    pub output: Vec<[u64; D]>,
}

fn absorb(state: &mut [Val; 4], values: &[Val; 4]) {
    let mut input = [Val::ZERO; 8];
    input[..4].copy_from_slice(state);
    input[4..].copy_from_slice(values);
    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut input);
    state.copy_from_slice(&input[..4]);
}
fn range_witness(row: &mut [Val], start: usize, bits: usize, modulus: u64, value: u64) {
    row[start] = Val::from_u64(value);
    for bit in 0..bits {
        row[start + 1 + bit] = Val::from_u64((value >> bit) & 1);
    }
    let mut equal = true;
    for step in 0..bits / 4 {
        let nibble = bits / 4 - 1 - step;
        equal &= ((value >> (4 * nibble)) & 15) == (((modulus - 1) >> (4 * nibble)) & 15);
        row[start + 1 + bits + step] = Val::from_bool(equal);
    }
}
fn signed_value(value: i64) -> Val {
    if value < 0 {
        -Val::from_u64(value.unsigned_abs())
    } else {
        Val::from_u64(value as u64)
    }
}

impl AffineAir {
    /// Native digest helper; producing this root is not proof acceptance.
    pub fn bundle_roots(&self, roots: &[AffineRoots]) -> Result<[Val; 4], Error> {
        if roots.len() != self.count
            || roots
                .iter()
                .any(|r| r.right.is_some() == self.kind.is_conversion())
        {
            return Err(Error::Length);
        }
        let mut state = self.bundle_initial();
        for roots in roots {
            absorb(&mut state, &roots.left);
            if let Some(right) = roots.right {
                absorb(&mut state, &right);
            }
            absorb(&mut state, &roots.output);
        }
        Ok(state)
    }

    pub fn generate(&self, inputs: &[AffineInput]) -> Result<AffineWitness, Error> {
        if inputs.len() != self.count {
            return Err(Error::Length);
        }
        let width = self.width();
        let mut values = Val::zero_vec(self.height * width);
        let mut poses = Vec::with_capacity(self.height);
        let metadata = self.metadata();
        let mut bundle = self.bundle_initial();
        let mut roots = Vec::with_capacity(self.count);
        let mut output = Vec::with_capacity(self.count);
        for (polynomial, input) in inputs.iter().enumerate() {
            let (left, right, signs, magnitudes, result, native_roots) = match (self.kind, input) {
                (AffineKind::Add | AffineKind::Sub, AffineInput::Binary { left, right }) => {
                    if left.iter().chain(right).any(|&v| v >= self.modulus) {
                        return Err(Error::NonCanonical);
                    }
                    let result = core::array::from_fn(|i| {
                        if self.kind == AffineKind::Add {
                            arithmetic::add(left[i], right[i], self.modulus)
                        } else {
                            arithmetic::sub(left[i], right[i], self.modulus)
                        }
                    });
                    let roots = AffineRoots {
                        left: commit_values(POLYNOMIAL_DOMAIN, self.modulus, left),
                        right: Some(commit_values(POLYNOMIAL_DOMAIN, self.modulus, right)),
                        output: commit_values(POLYNOMIAL_DOMAIN, self.modulus, &result),
                    };
                    (
                        left.map(Val::from_u64),
                        right.map(Val::from_u64),
                        [false; D],
                        [0; D],
                        result,
                        roots,
                    )
                }
                (AffineKind::SignedToCanonical { bound }, AffineInput::Signed(signed)) => {
                    if signed.iter().any(|v| v.unsigned_abs() > u64::from(bound)) {
                        return Err(Error::NonCanonical);
                    }
                    let result = signed.map(|v| arithmetic::signed(v, self.modulus));
                    let roots = AffineRoots {
                        left: commit_signed_values(signed),
                        right: None,
                        output: commit_values(POLYNOMIAL_DOMAIN, self.modulus, &result),
                    };
                    (
                        signed.map(signed_value),
                        [Val::ZERO; D],
                        signed.map(|v| v < 0),
                        signed.map(|v| v.unsigned_abs()),
                        result,
                        roots,
                    )
                }
                _ => return Err(Error::Descriptor),
            };
            let mut accumulators = core::array::from_fn::<_, 3, _>(|which| self.initial(which));
            for local in 0..ROWS_PER_POLYNOMIAL {
                let index = polynomial * ROWS_PER_POLYNOMIAL + local;
                let row = &mut values[index * width..(index + 1) * width];
                let phase = local % 4;
                let chunk = local / 4;
                if local < 256 {
                    for lane in 0..4 {
                        let i = 4 * chunk + lane;
                        row[LEFT + lane] = left[i];
                        row[RIGHT + lane] = right[i];
                        row[SIGN + lane] = Val::from_bool(signs[i]);
                        let canonical = if phase == 2 {
                            result[i]
                        } else if !self.kind.is_conversion() && phase < 2 {
                            // Canonical coefficients were validated before trace allocation.
                            let AffineInput::Binary { left, right } = input else {
                                unreachable!()
                            };
                            if phase == 0 {
                                left[i]
                            } else {
                                right[i]
                            }
                        } else {
                            0
                        };
                        range_witness(row, self.range(lane), self.bits(), self.modulus, canonical);
                        if self.kind.is_conversion() {
                            range_witness(
                                row,
                                self.magnitude(lane),
                                self.magnitude_bits(),
                                u64::from(self.kind.bound()) + 1,
                                if phase == 0 { magnitudes[i] } else { 0 },
                            );
                        } else if phase == 2 {
                            let AffineInput::Binary { left, right } = input else {
                                unreachable!()
                            };
                            row[CARRY + lane] = Val::from_bool(if self.kind == AffineKind::Add {
                                left[i] + right[i] >= self.modulus
                            } else {
                                left[i] < right[i]
                            });
                        }
                    }
                } else {
                    for lane in 0..4 {
                        range_witness(row, self.range(lane), self.bits(), self.modulus, 0);
                        if self.kind.is_conversion() {
                            range_witness(
                                row,
                                self.magnitude(lane),
                                self.magnitude_bits(),
                                u64::from(self.kind.bound()) + 1,
                                0,
                            );
                        }
                    }
                }
                for which in 0..3 {
                    row[ACC + 4 * which..ACC + 4 * which + 4].copy_from_slice(&accumulators[which]);
                }
                row[BUNDLE..BUNDLE + 4].copy_from_slice(&bundle);
                let mut pose = [Val::ZERO; 8];
                for which in 0..3 {
                    if metadata[HASH_A + which][local] == Val::ONE {
                        pose[..4].copy_from_slice(&accumulators[which]);
                        for lane in 0..4 {
                            pose[4 + lane] = match which {
                                0 => row[LEFT + lane],
                                1 => row[RIGHT + lane],
                                _ => row[self.range(lane)],
                            };
                        }
                    }
                    if metadata[BUNDLE_A + which][local] == Val::ONE {
                        pose[..4].copy_from_slice(&bundle);
                        pose[4..].copy_from_slice(&accumulators[which]);
                    }
                }
                poses.push(pose);
                p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut pose);
                for which in 0..3 {
                    if metadata[HASH_A + which][local] == Val::ONE {
                        accumulators[which].copy_from_slice(&pose[..4]);
                    }
                    if metadata[BUNDLE_A + which][local] == Val::ONE {
                        bundle.copy_from_slice(&pose[..4]);
                    }
                }
            }
            roots.push(native_roots);
            output.push(result);
        }
        let poseidon_trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poses,
            &round_constants(),
            0,
        );
        for (index, row) in values.chunks_exact_mut(width).enumerate() {
            row[self.poseidon()..].copy_from_slice(
                &poseidon_trace.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
            );
        }
        Ok(AffineWitness {
            trace: RowMajorMatrix::new(values, width),
            public_values: bundle,
            roots,
            output,
        })
    }
}
