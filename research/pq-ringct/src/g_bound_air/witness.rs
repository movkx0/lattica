use super::*;

pub struct GBoundWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub output: [i64; D],
}
fn recovered(value: Val) -> i64 {
    let n = value.as_canonical_u64();
    if n <= (GOLDILOCKS_MODULUS / 2) as u64 {
        n as i64
    } else {
        -((GOLDILOCKS_MODULUS as u64 - n) as i64)
    }
}
impl GBoundAir {
    pub fn generate(&self, f: &[i64; D], x: &[i64; D]) -> Result<GBoundWitness, Error> {
        let schedule = self.schedule();
        let psi = Val::two_adic_generator(9);
        let mut left = f.map(signed);
        let mut right = x.map(signed);
        let mut acc = initial();
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        let mut output = [0i64; D];
        let mut trace = Val::zero_vec(HEIGHT * WIDTH);
        let mut permutation_inputs = Vec::with_capacity(HEIGHT);
        for row_index in 0..HEIGHT {
            let phase = row_index / SCHEDULE_PERIOD;
            let row = row_index % SCHEDULE_PERIOD;
            let data = &mut trace[row_index * WIDTH..(row_index + 1) * WIDTH];
            data[LEFT..RIGHT].copy_from_slice(&left);
            data[RIGHT..ADDRESS_BITS].copy_from_slice(&right);
            data[PHASE + phase] = Val::ONE;
            data[ACC..POSEIDON].copy_from_slice(&acc);
            let (a, b) = match phase {
                0 => (4 * (row % 64), 0),
                1 | 11 | 21 => (row, 0),
                2 | 12 | 22 => (row + 128, 0),
                3..=10 => (
                    (schedule[ADDRESS_A + phase - 3][row].as_canonical_u64()) as usize,
                    (schedule[ADDRESS_B + phase - 3][row].as_canonical_u64()) as usize,
                ),
                13..=20 => (
                    (schedule[ADDRESS_A + 20 - phase][row].as_canonical_u64()) as usize,
                    (schedule[ADDRESS_B + 20 - phase][row].as_canonical_u64()) as usize,
                ),
                23 if row < 64 => (4 * row, 0),
                _ => (0, 0),
            };
            for (which, index) in [a, b].into_iter().enumerate() {
                for bit in 0..8 {
                    data[ADDRESS_BITS + 8 * which + bit] = Val::from_bool(index & (1 << bit) != 0);
                }
                data[ADDRESS_PREFIX + which * 32 + index % 16] = Val::ONE;
                data[ADDRESS_PREFIX + which * 32 + 16 + index / 16] = Val::ONE;
            }
            data[READS..RANGES].copy_from_slice(&[left[a], left[b], right[a], right[b]]);
            let (values, bound) = if phase == 0 && row < 64 {
                (core::array::from_fn(|i| left[a + i]), self.f_bound)
            } else if phase == 0 {
                (core::array::from_fn(|i| right[a + i]), 1)
            } else if phase == 23 && row < 64 {
                (core::array::from_fn(|i| left[a + i]), self.g_bound)
            } else {
                ([Val::ZERO; 4], 0)
            };
            for slot in 0..4 {
                let range = RANGES + slot * RANGE_WIDTH;
                let encoded = (values[slot] + Val::from_u32(bound)).as_canonical_u64();
                if encoded >= 1 << RANGE_BITS {
                    return Err(Error::Encoding);
                }
                data[range] = Val::from_u64(encoded);
                for bit in 0..RANGE_BITS {
                    data[range + 1 + bit] = Val::from_u64((encoded >> bit) & 1);
                }
                let mut prefix = true;
                for step in 0..6 {
                    let shift = 4 * (5 - step);
                    prefix &= ((encoded >> shift) & 15) == (((2 * bound as u64) >> shift) & 15);
                    data[range + 1 + RANGE_BITS + step] = Val::from_bool(prefix);
                }
            }
            let mut updated = acc;
            permutation_inputs.push(absorb(
                &mut updated,
                if phase == 0 { values } else { [Val::ZERO; 4] },
            ));
            if phase == 0 {
                acc = updated;
                if row == 63 {
                    public_values[..4].copy_from_slice(&acc);
                    acc = initial();
                }
                if row == 127 {
                    public_values[4..].copy_from_slice(&acc);
                }
            }
            match phase {
                1 | 2 => {
                    let factor = schedule[TWIST_FACTOR][row]
                        * if phase == 2 {
                            psi.exp_u64(128)
                        } else {
                            Val::ONE
                        };
                    right[a] = (right[a] - left[a]) * factor;
                    left[a] *= factor;
                }
                3..=10 => {
                    let factor = schedule[FORWARD_FACTOR + phase - 3][row];
                    for bank in [&mut left, &mut right] {
                        let (u, v) = (bank[a], bank[b]);
                        bank[a] = u + v;
                        bank[b] = (u - v) * factor;
                    }
                }
                11 | 12 => left[a] *= right[a],
                13..=20 => {
                    let factor = schedule[INVERSE_FACTOR + 20 - phase][row];
                    let (u, v) = (left[a], left[b] * factor);
                    left[a] = u + v;
                    left[b] = u - v;
                }
                21 | 22 => {
                    let factor = schedule[UNTWIST_FACTOR][row]
                        * if phase == 22 {
                            psi.inverse().exp_u64(128)
                        } else {
                            Val::ONE
                        };
                    left[a] *= factor;
                    output[a] = recovered(left[a]);
                }
                _ => {}
            }
        }
        let poseidon = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            permutation_inputs,
            &round_constants(),
            0,
        );
        for (i, row) in trace.chunks_exact_mut(WIDTH).enumerate() {
            row[POSEIDON..]
                .copy_from_slice(&poseidon.values[i * POSEIDON_WIDTH..(i + 1) * POSEIDON_WIDTH]);
        }
        Ok(GBoundWitness {
            trace: RowMajorMatrix::new(trace, WIDTH),
            public_values,
            output,
        })
    }
}
