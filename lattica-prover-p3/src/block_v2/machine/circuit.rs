//! Circuit-building helpers. All equalities are emitted as AIR operations.
use super::program::{ProgramBuilder, Val, Wire};
use p3_field::PrimeCharacteristicRing;

pub type Extension = [Wire; 3];

impl ProgramBuilder {
    /// Canonical 64-bit decomposition, including the Goldilocks < p check.
    /// Reconstruction alone would allow the alias x + p.
    pub fn bits(&mut self, value: Wire) -> [Wire; 64] {
        let bits = core::array::from_fn(|i| self.bit_hint(value, i));
        self.assert_canonical_bits(value, bits);
        bits
    }
    pub fn assert_canonical_bits(&mut self, value: Wire, bits: [Wire; 64]) {
        for bit in bits {
            self.assert_bool(bit);
        }
        let zero = self.constant(Val::ZERO);
        let one = self.constant(Val::ONE);
        let mut reconstructed = zero;
        for (i, &bit) in bits.iter().enumerate() {
            let weight = self.constant(Val::from_u64(1u64 << i));
            let term = self.mul(bit, weight);
            reconstructed = self.add(reconstructed, term);
        }
        self.assert_equal(reconstructed, value);
        // p - 1 = 0xffffffff00000000. If high 32 bits are all one,
        // every low bit must be zero; otherwise the 64-bit integer is < p.
        let mut high_all_ones = one;
        for &bit in &bits[32..] {
            high_all_ones = self.mul(high_all_ones, bit);
        }
        for &bit in &bits[..32] {
            let forbidden = self.mul(high_all_ones, bit);
            self.assert_zero(forbidden);
        }
    }
    pub fn ext_constant(&mut self, coefficients: [Val; 3]) -> Extension {
        coefficients.map(|v| self.constant(v))
    }
    pub fn ext_scale(&mut self, a: Extension, b: Wire) -> Extension {
        a.map(|v| self.mul(v, b))
    }
    pub fn ext_select(&mut self, bit: Wire, a: Extension, b: Extension) -> Extension {
        core::array::from_fn(|i| self.select(bit, a[i], b[i]))
    }
    pub fn ext_inverse(&mut self, a: Extension) -> Extension {
        self.cubic_inverse(a)
    }
    pub fn ext_pow(&mut self, mut a: Extension, mut exponent: u64) -> Extension {
        let mut out = self.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
        while exponent != 0 {
            if exponent & 1 != 0 {
                out = self.ext_mul(out, a);
            }
            exponent >>= 1;
            if exponent != 0 {
                a = self.ext_mul(a, a);
            }
        }
        out
    }
    pub fn sub(&mut self, a: Wire, b: Wire) -> Wire {
        let minus_one = self.constant(-Val::ONE);
        let negative = self.mul(b, minus_one);
        self.add(a, negative)
    }
    pub fn assert_zero(&mut self, a: Wire) {
        let zero = self.constant(Val::ZERO);
        self.assert_equal(a, zero);
    }
    pub fn ext_add(&mut self, a: Extension, b: Extension) -> Extension {
        core::array::from_fn(|i| self.add(a[i], b[i]))
    }
    pub fn ext_sub(&mut self, a: Extension, b: Extension) -> Extension {
        core::array::from_fn(|i| self.sub(a[i], b[i]))
    }
    pub fn ext_mul(&mut self, a: Extension, b: Extension) -> Extension {
        self.cubic_mul(a, b)
    }
    pub fn ext_assert_equal(&mut self, a: Extension, b: Extension) {
        for i in 0..3 {
            self.assert_equal(a[i], b[i]);
        }
    }
    pub fn hash_fields(&mut self, domain: u64, fields: &[Wire]) -> [Wire; 4] {
        let zero = self.constant(Val::ZERO);
        let mut state = [
            self.constant(Val::from_u64(domain)),
            self.constant(Val::from_usize(fields.len())),
            zero,
            zero,
        ];
        for chunk in fields.chunks(4) {
            let mut input = [zero; 8];
            input[..4].copy_from_slice(&state);
            input[4..4 + chunk.len()].copy_from_slice(chunk);
            state.copy_from_slice(&self.poseidon(input)[..4]);
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::{commitment, profile::Challenge};
    use p3_field::{BasedVectorSpace, Field, PrimeField64};

    #[test]
    fn cubic_arithmetic_and_inversion_match_native() {
        for seed in 1..12u64 {
            let mut b = ProgramBuilder::new(0).unwrap();
            let a = [seed, seed + 11, seed * 3].map(Val::from_u64);
            let c = [seed + 31, seed * 7, seed + 111].map(Val::from_u64);
            let wa = b.ext_constant(a);
            let wc = b.ext_constant(c);
            let a = Challenge::from_basis_coefficients_slice(&a).unwrap();
            let c = Challenge::from_basis_coefficients_slice(&c).unwrap();
            for (actual, expected) in [
                (b.ext_mul(wa, wc), a * c),
                (b.ext_inverse(wa), a.inverse()),
                (b.ext_add(wa, wc), a + c),
                (b.ext_sub(wa, wc), a - c),
                (b.ext_pow(wa, 13), a.exp_u64(13)),
            ] {
                let expected =
                    b.ext_constant(expected.as_basis_coefficients_slice().try_into().unwrap());
                b.ext_assert_equal(actual, expected);
            }
            b.finish(None).unwrap().evaluate(&[], &[]).unwrap();
        }
    }

    #[test]
    fn canonical_bits_reject_modulus_aliases() {
        let mut b = ProgramBuilder::new(1).unwrap();
        let value = b.public(0).unwrap();
        let bits = core::array::from_fn(|_| b.input());
        b.assert_canonical_bits(value, bits);
        let p = b.finish(None).unwrap();
        for number in [0, 1, 1 << 32, commitment::MODULUS - 1] {
            let input: Vec<_> = (0..64).map(|i| Val::from_u64((number >> i) & 1)).collect();
            p.evaluate(&[Val::from_u64(number)], &input).unwrap();
        }
        for number in [commitment::MODULUS, commitment::MODULUS + 1, u64::MAX] {
            let input: Vec<_> = (0..64).map(|i| Val::from_u64((number >> i) & 1)).collect();
            assert!(p.evaluate(&[Val::from_u64(number)], &input).is_err());
        }
    }

    #[test]
    fn ordered_statement_hash_matches_native() {
        for count in 0..10 {
            let values: Vec<u64> = (0..count).map(|i| i * 71 + 33).collect();
            let expected = commitment::hash_fields(commitment::LEAF, &values).unwrap();
            let mut b = ProgramBuilder::new(4).unwrap();
            let fields: Vec<_> = values
                .into_iter()
                .map(|v| b.constant(Val::from_u64(v)))
                .collect();
            let digest = b.hash_fields(commitment::LEAF, &fields);
            for (i, &w) in digest.iter().enumerate() {
                let public = b.public(i).unwrap();
                b.assert_equal(public, w);
            }
            b.finish(None)
                .unwrap()
                .evaluate(&expected.map(Val::from_u64), &[])
                .unwrap();
        }
        assert_eq!(Val::NEG_ONE.as_canonical_u64(), commitment::MODULUS - 1);
    }

    #[test]
    fn binary_fold_matches_interpolation() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let even = [2, 3, 5].map(Val::from_u64);
        let odd = [7, 11, 13].map(Val::from_u64);
        let beta = [17, 19, 23].map(Val::from_u64);
        let x = Val::from_u64(29);
        let we = b.ext_constant(even);
        let wo = b.ext_constant(odd);
        let wb = b.ext_constant(beta);
        let wx = b.constant(x);
        let actual = b.binary_fri_fold(we, wo, wb, wx);
        let even = Challenge::from_basis_coefficients_slice(&even).unwrap();
        let odd = Challenge::from_basis_coefficients_slice(&odd).unwrap();
        let beta = Challenge::from_basis_coefficients_slice(&beta).unwrap();
        let expected = (even + odd) * Val::ONE.halve() + beta * (even - odd) * x.double().inverse();
        let expected = b.ext_constant(expected.as_basis_coefficients_slice().try_into().unwrap());
        b.ext_assert_equal(actual, expected);
        b.finish(None).unwrap().evaluate(&[], &[]).unwrap();
    }
}
