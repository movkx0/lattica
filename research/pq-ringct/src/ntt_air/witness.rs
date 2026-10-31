use super::*;
use p3_symmetric::Permutation;

pub struct NttWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: Vec<Val>,
    pub output: Vec<[u64; D]>,
}

fn put_bits(row: &mut [Val], start: usize, value: u64, count: usize) {
    for bit in 0..count {
        row[start + bit] = Val::from_u64((value >> bit) & 1);
    }
}
impl NttAir {
    pub fn generate(&self, input: &[[u64; D]]) -> Result<NttWitness, Error> {
        if input.len() != self.count {
            return Err(Error::Length);
        }
        if input.iter().flatten().any(|&value| value >= self.modulus) {
            return Err(Error::NonCanonical);
        }
        let width = self.width();
        let mut values = Val::zero_vec(self.height * width);
        let mut public_values = Val::zero_vec(self.public_values());
        let mut output = Vec::with_capacity(self.count);
        let steps = self.steps();
        let mut poseidon_inputs = Vec::with_capacity(self.height);
        let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
        let initial = |domain| {
            [
                Val::from_u64(domain),
                Val::from_u64(self.modulus),
                Val::from_usize(D),
                Val::ZERO,
            ]
        };
        let mut acc = initial(INPUT_DOMAIN);
        for (polynomial, original) in input.iter().enumerate() {
            let mut state = *original;
            acc = initial(INPUT_DOMAIN);
            for local in 0..ROWS_PER_POLYNOMIAL {
                let index = polynomial * ROWS_PER_POLYNOMIAL + local;
                let row = &mut values[index * width..(index + 1) * width];
                for i in 0..D {
                    row[STATE + i] = Val::from_u64(state[i]);
                }
                let mut ranges = [0_u64; 6];
                let mut reads = [0_u64; 4];
                let hash = local < 64 || local >= 832;
                let (a, b) = if hash {
                    let group = if local < 64 {
                        local
                    } else {
                        let block = local - 832;
                        if self.modulus == Q {
                            PERM_NTT[block] as usize
                        } else {
                            block
                        }
                    };
                    let base = group * 4;
                    reads.copy_from_slice(&state[base..base + 4]);
                    ranges[..4].copy_from_slice(&reads);
                    (base, 0)
                } else {
                    let step = steps[local - 64];
                    reads[0] = state[step.a];
                    reads[1] = state[step.b];
                    let u = u128::from(reads[0]) * u128::from(step.factor_u);
                    let v = u128::from(reads[1]) * u128::from(step.factor_v);
                    let q = u128::from(self.modulus);
                    ranges[0] = (u % q) as u64;
                    ranges[1] = (v % q) as u64;
                    ranges[2] = (u / q) as u64;
                    ranges[3] = (v / q) as u64;
                    let add = ranges[0] + ranges[1];
                    let sub = ranges[0] + self.modulus - ranges[1];
                    ranges[4] = add % self.modulus;
                    ranges[5] = sub % self.modulus;
                    row[self.carries()] = Val::from_u64(add / self.modulus);
                    row[self.carries() + 1] = Val::from_u64(sub / self.modulus);
                    state[step.a] = ranges[4];
                    state[step.b] = ranges[5];
                    (step.a, step.b)
                };
                self.range_witness(row, &ranges);
                index_witness(row, a, b);
                for i in 0..4 {
                    row[READS + i] = Val::from_u64(reads[i]);
                }
                row[self.acc()..self.poseidon()].copy_from_slice(&acc);
                let mut block = [Val::ZERO; 8];
                block[..4].copy_from_slice(&acc);
                if hash {
                    for i in 0..4 {
                        block[4 + i] = Val::from_u64(reads[i]);
                    }
                }
                poseidon_inputs.push(block);
                permutation.permute_mut(&mut block);
                if hash {
                    acc.copy_from_slice(&block[..4]);
                }
                if local == 63 {
                    public_values[polynomial * 8..polynomial * 8 + 4].copy_from_slice(&acc);
                    acc = initial(OUTPUT_DOMAIN);
                }
                if local + 1 == ROWS_PER_POLYNOMIAL {
                    public_values[polynomial * 8 + 4..polynomial * 8 + 8].copy_from_slice(&acc);
                }
            }
            let transformed = if self.modulus == Q {
                core::array::from_fn(|i| state[PERM_NTT[i / 4] as usize * 4 + i % 4])
            } else {
                state
            };
            assert_eq!(
                transformed,
                arithmetic::ntt(&original.map(|value| value as i64), self.modulus),
                "serial NTT witness must match independent native translation"
            );
            output.push(transformed);
        }
        for index in self.count * ROWS_PER_POLYNOMIAL..self.height {
            let row = &mut values[index * width..(index + 1) * width];
            self.range_witness(row, &[0; 6]);
            index_witness(row, 0, 0);
            row[self.acc()..self.poseidon()].copy_from_slice(&acc);
            let mut block = [Val::ZERO; 8];
            block[..4].copy_from_slice(&acc);
            poseidon_inputs.push(block);
        }
        let trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poseidon_inputs,
            &round_constants(),
            0,
        );
        for (row, fields) in values.chunks_exact_mut(width).enumerate() {
            fields[self.poseidon()..]
                .copy_from_slice(&trace.values[row * POSEIDON_WIDTH..(row + 1) * POSEIDON_WIDTH]);
        }
        Ok(NttWitness {
            trace: RowMajorMatrix::new(values, width),
            public_values,
            output,
        })
    }
    fn range_witness(&self, row: &mut [Val], values: &[u64; 6]) {
        for (slot, &value) in values.iter().enumerate() {
            assert!(value < self.modulus);
            let start = self.range(slot);
            row[start] = Val::from_u64(value);
            put_bits(row, start + 1, value, self.bits());
            let mut prefix = true;
            for step in 0..self.nibbles() {
                let nibble = self.nibbles() - 1 - step;
                prefix &=
                    ((value >> (nibble * 4)) & 15) == (((self.modulus - 1) >> (nibble * 4)) & 15);
                row[start + 1 + self.bits() + step] = Val::from_bool(prefix);
            }
        }
    }
}
fn index_witness(row: &mut [Val], a: usize, b: usize) {
    put_bits(row, INDEX_BITS, a as u64, 8);
    put_bits(row, INDEX_BITS + 8, b as u64, 8);
    for (nibble, value) in [a & 15, a >> 4, b & 15, b >> 4].into_iter().enumerate() {
        for candidate in 0..16 {
            row[PREFIX + nibble * 16 + candidate] = Val::from_bool(candidate == value);
        }
    }
}
