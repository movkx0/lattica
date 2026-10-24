use super::*;
use p3_symmetric::Permutation;
pub struct MulWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: Vec<Val>,
    pub output: Vec<[u64; D]>,
}
impl MulAir {
    pub fn generate(&self, left: &[[u64; D]], right: &[[u64; D]]) -> Result<MulWitness, Error> {
        if left.len() != self.count || right.len() != self.count {
            return Err(Error::Length);
        }
        if left
            .iter()
            .chain(right)
            .flatten()
            .any(|&v| v >= self.modulus)
        {
            return Err(Error::NonCanonical);
        }
        let width = self.width();
        let mut values = Val::zero_vec(self.height * width);
        let mut public_values = Vec::with_capacity(self.public_values());
        let mut output = Vec::with_capacity(self.count);
        let mut poseidon_inputs = Vec::with_capacity(self.height);
        let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
        let mut accumulators = [self.initial(); 3];
        for polynomial in 0..self.count {
            accumulators = [self.initial(); 3];
            let mut product = [0; D];
            for block in 0..64 {
                let a = &left[polynomial][4 * block..4 * block + 4];
                let c = &right[polynomial][4 * block..4 * block + 4];
                let mut state = [0_u64; 4];
                for local in 0..ROWS_PER_BLOCK {
                    let index = polynomial * ROWS_PER_POLYNOMIAL + block * ROWS_PER_BLOCK + local;
                    let row = &mut values[index * width..(index + 1) * width];
                    for lane in 0..4 {
                        row[LEFT + lane] = Val::from_u64(a[lane]);
                        row[RIGHT + lane] = Val::from_u64(c[lane]);
                        row[STATE + lane] = Val::from_u64(state[lane]);
                    }
                    let mut ranges = [0_u64; 5];
                    let which = match local {
                        0 => Some(0),
                        1 => Some(1),
                        18 => Some(2),
                        _ => None,
                    };
                    if let Some(which) = which {
                        ranges[..4].copy_from_slice(match which {
                            0 => a,
                            1 => c,
                            _ => &state,
                        });
                    } else {
                        let term = local - 2;
                        let i = term / 4;
                        let j = term % 4;
                        let target = (i + j) % 4;
                        let (factor, negative) = self.term(block, i, j);
                        let q = u128::from(self.modulus);
                        let first = u128::from(a[i]) * u128::from(c[j]);
                        ranges[0] = (first % q) as u64;
                        ranges[1] = (first / q) as u64;
                        let second = u128::from(ranges[0]) * u128::from(factor);
                        ranges[2] = (second % q) as u64;
                        ranges[3] = (second / q) as u64;
                        let sum = if negative {
                            state[target] + self.modulus - ranges[2]
                        } else {
                            state[target] + ranges[2]
                        };
                        ranges[4] = sum % self.modulus;
                        row[self.carry()] = Val::from_u64(sum / self.modulus);
                        row[READS] = Val::from_u64(a[i]);
                        row[READS + 1] = Val::from_u64(c[j]);
                        row[READS + 2] = Val::from_u64(state[target]);
                        state[target] = ranges[4];
                    }
                    self.range_witness(row, &ranges);
                    for which in 0..3 {
                        row[self.acc() + 4 * which..self.acc() + 4 * which + 4]
                            .copy_from_slice(&accumulators[which]);
                    }
                    let mut hash = [Val::ZERO; 8];
                    if let Some(which) = which {
                        hash[..4].copy_from_slice(&accumulators[which]);
                        for lane in 0..4 {
                            hash[4 + lane] = Val::from_u64(ranges[lane]);
                        }
                    }
                    poseidon_inputs.push(hash);
                    if let Some(which) = which {
                        permutation.permute_mut(&mut hash);
                        accumulators[which].copy_from_slice(&hash[..4]);
                    }
                }
                product[block * 4..block * 4 + 4].copy_from_slice(&state);
            }
            assert_eq!(
                product,
                arithmetic::mul(&left[polynomial], &right[polynomial], self.modulus),
                "serial product must match native verifier"
            );
            for accumulator in accumulators {
                public_values.extend(accumulator);
            }
            output.push(product);
        }
        for index in self.count * ROWS_PER_POLYNOMIAL..self.height {
            let row = &mut values[index * width..(index + 1) * width];
            self.range_witness(row, &[0; 5]);
            for which in 0..3 {
                row[self.acc() + 4 * which..self.acc() + 4 * which + 4]
                    .copy_from_slice(&accumulators[which]);
            }
            poseidon_inputs.push([Val::ZERO; 8]);
        }
        let poses = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poseidon_inputs,
            &round_constants(),
            0,
        );
        for (index, row) in values.chunks_exact_mut(width).enumerate() {
            row[self.poseidon()..].copy_from_slice(
                &poses.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
            );
        }
        Ok(MulWitness {
            trace: RowMajorMatrix::new(values, width),
            public_values,
            output,
        })
    }
    fn range_witness(&self, row: &mut [Val], values: &[u64; 5]) {
        for (slot, &value) in values.iter().enumerate() {
            assert!(value < self.modulus);
            let start = self.range(slot);
            row[start] = Val::from_u64(value);
            for bit in 0..self.bits() {
                row[start + 1 + bit] = Val::from_u64((value >> bit) & 1);
            }
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
