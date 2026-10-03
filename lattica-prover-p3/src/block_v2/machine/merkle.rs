//! Fixed-shape salted MMCS authentication. This gadget handles the equal-height
//! matrices used by a single-instance candidate proof, not arbitrary MMCS trees.
use super::circuit::Extension;
use super::program::Val;
use super::{ExecutionError, ProgramBuilder, Wire};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};

pub type Digest = [Wire; 4];

impl ProgramBuilder {
    /// Upstream PaddingFreeSponge: partial final blocks retain the previous
    /// state in untouched rate slots. Length MUST be fixed by the program.
    pub fn mmcs_leaf_hash(&mut self, fields: &[Wire]) -> Digest {
        let zero = self.constant(Val::ZERO);
        let mut state = [zero; 8];
        for chunk in fields.chunks(4) {
            state[..chunk.len()].copy_from_slice(chunk);
            state = self.poseidon(state);
        }
        state[..4].try_into().unwrap()
    }
    pub fn compress(&mut self, left: Digest, right: Digest) -> Digest {
        let input = [
            left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
        ];
        self.poseidon(input)[..4].try_into().unwrap()
    }
    pub fn assert_digest(&mut self, a: Digest, b: Digest) {
        for i in 0..4 {
            self.assert_equal(a[i], b[i]);
        }
    }
    pub fn select_digest(&mut self, bit: Wire, a: Digest, b: Digest) -> Digest {
        core::array::from_fn(|i| self.select(bit, a[i], b[i]))
    }
    pub fn authenticate_equal_height_mmcs(
        &mut self,
        cap: &[Digest],
        index_bits: &[Wire],
        rows: &[Vec<Wire>],
        salts: &[[Wire; 4]],
        siblings: &[Digest],
    ) -> Result<(), ExecutionError> {
        if cap.is_empty()
            || !cap.len().is_power_of_two()
            || rows.is_empty()
            || rows.len() != salts.len()
            || rows.iter().any(Vec::is_empty)
            || index_bits.len() > 32
            || siblings.len() + cap.len().ilog2() as usize != index_bits.len()
        {
            return Err(ExecutionError::InvalidHeight);
        }
        for &bit in index_bits {
            self.assert_bool(bit);
        }
        let mut fields = Vec::new();
        for (row, salt) in rows.iter().zip(salts) {
            fields.extend_from_slice(row);
            fields.extend_from_slice(salt);
        }
        let mut digest = self.mmcs_leaf_hash(&fields);
        for (depth, &sibling) in siblings.iter().enumerate() {
            let left = self.select_digest(index_bits[depth], digest, sibling);
            let right = self.select_digest(index_bits[depth], sibling, digest);
            digest = self.compress(left, right);
        }
        // Authenticate against the full tree above the cap instead of selecting
        // one of 64 digests with a large mux for every query. The full cap tree
        // is constrained once and shared by Poseidon CSE across queries. Upper
        // path values are witness hints, NEVER trusted selectors: every value is
        // checked by the compression chain ending at that constrained cap root.
        // This uses the same Merkle collision-resistance assumption as MMCS.
        let cap_bits = &index_bits[siblings.len()..];
        let mut entries = cap.to_vec();
        for (depth, &bit) in cap_bits.iter().enumerate() {
            let sibling: Digest = core::array::from_fn(|column| {
                let swapped = (0..entries.len()).map(|i| entries[i ^ 1][column]).collect();
                self.select_hint(swapped, &cap_bits[depth..])
            });
            let left = self.select_digest(bit, digest, sibling);
            let right = self.select_digest(bit, sibling, digest);
            digest = self.compress(left, right);
            entries = entries
                .chunks_exact(2)
                .map(|pair| self.compress(pair[0], pair[1]))
                .collect();
        }
        self.assert_digest(digest, entries[0]);
        Ok(())
    }
    /// g^reverse_bits(index), with bit zero first. Used by binary FRI.
    pub fn subgroup_point(
        &mut self,
        index_bits: &[Wire],
        log_order: usize,
    ) -> Result<Wire, ExecutionError> {
        if log_order > 32 || index_bits.len() > log_order {
            return Err(ExecutionError::InvalidHeight);
        }
        let generator = Val::two_adic_generator(log_order);
        let one = self.constant(Val::ONE);
        let mut point = one;
        for (i, &bit) in index_bits.iter().enumerate() {
            let factor = self.constant(generator.exp_u64(1 << (index_bits.len() - 1 - i)));
            let selected = self.select(bit, one, factor);
            point = self.mul(point, selected);
        }
        Ok(point)
    }
    /// Fold an already authenticated, ordered pair at points x and -x.
    pub fn binary_fri_fold(
        &mut self,
        even: Extension,
        odd: Extension,
        beta: Extension,
        x: Wire,
    ) -> Extension {
        let half = self.constant(Val::ONE.halve());
        let sum = self.ext_add(even, odd);
        let average = self.ext_scale(sum, half);
        let difference = self.ext_sub(even, odd);
        let inv_x = self.inverse(x);
        let half_inv_x = self.mul(half, inv_x);
        let slope = self.ext_scale(difference, half_inv_x);
        let scaled = self.ext_mul(beta, slope);
        self.ext_add(average, scaled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MyCompress, MyHash, ValMmcs};
    use p3_commit::Mmcs;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::CryptographicHasher;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn padding_free_sponge_matches_native_partial_blocks() {
        let hash = MyHash::new(default_goldilocks_poseidon2_8());
        for len in 0..19 {
            let values: Vec<_> = (0..len).map(|i| Val::from_usize(30 + i)).collect();
            let mut b = ProgramBuilder::new(4).unwrap();
            let inputs: Vec<_> = values.iter().map(|&v| b.constant(v)).collect();
            let digest = b.mmcs_leaf_hash(&inputs);
            for (i, w) in digest.into_iter().enumerate() {
                let p = b.public(i).unwrap();
                b.assert_equal(w, p);
            }
            let expected = hash.hash_iter(values);
            b.finish(None).unwrap().evaluate(&expected, &[]).unwrap();
        }
    }

    #[test]
    fn salted_multi_matrix_merkle_matches_native() {
        let perm = default_goldilocks_poseidon2_8();
        let mmcs = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm),
            3,
            ChaCha20Rng::from_seed([5; 32]),
        );
        let matrices = [3, 5].map(|width| {
            RowMajorMatrix::new(
                (0..128 * width)
                    .map(|i| Val::from_usize(i + width))
                    .collect(),
                width,
            )
        });
        let (commit, data) = mmcs.commit(matrices.to_vec());
        for index in [0, 1, 31, 64, 127] {
            let opening = mmcs.open_batch(index, &data);
            let mut b = ProgramBuilder::new(0).unwrap();
            let mut witness = Vec::new();
            let cap: Vec<_> = commit
                .roots()
                .iter()
                .map(|d| d.map(|v| b.constant(v)))
                .collect();
            let bits: Vec<_> = (0..7)
                .map(|i| b.constant(Val::from_usize((index >> i) & 1)))
                .collect();
            let rows: Vec<Vec<_>> = opening
                .opened_values
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|&v| {
                            witness.push(v);
                            b.input()
                        })
                        .collect()
                })
                .collect();
            let salts: Vec<[Wire; 4]> = opening
                .opening_proof
                .0
                .iter()
                .map(|salt| {
                    core::array::from_fn(|i| {
                        witness.push(salt[i]);
                        b.input()
                    })
                })
                .collect();
            let siblings: Vec<_> = opening
                .opening_proof
                .1
                .iter()
                .map(|digest| {
                    digest.map(|v| {
                        witness.push(v);
                        b.input()
                    })
                })
                .collect();
            b.authenticate_equal_height_mmcs(&cap, &bits, &rows, &salts, &siblings)
                .unwrap();
            let program = b.finish(None).unwrap();
            program.evaluate(&[], &witness).unwrap();
            witness[0] += Val::ONE;
            assert_eq!(
                program.evaluate(&[], &witness).unwrap_err(),
                ExecutionError::Unsatisfied
            );
        }
    }
}
