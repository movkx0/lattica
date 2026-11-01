//! Read-only Goldilocks FFT setup shared across CPU compilations. No heap,
//! columns, coefficients or builder wires are retained. Tests bind the root to
//! the field implementation; source qualification includes this module.
use super::super::program::Val;
const P: u64 = 0xffff_ffff_0000_0001;
// Goldilocks::TWO_ADIC_GENERATORS[32].
const ROOT: u64 = 1753635133440165772;
const fn multiply(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}
const fn power(mut x: u64, mut e: u64) -> u64 {
    let mut y = 1;
    while e != 0 {
        if e & 1 != 0 {
            y = multiply(y, x);
        }
        x = multiply(x, x);
        e >>= 1;
    }
    y
}
const fn setup() -> [[u64; 2]; 33] {
    let mut table = [[1; 2]; 33];
    table[32][0] = power(ROOT, P - 2);
    let mut k = 32;
    while k > 0 {
        table[k - 1][0] = multiply(table[k][0], table[k][0]);
        k -= 1;
    }
    k = 1;
    while k <= 32 {
        table[k][1] = multiply(table[k - 1][1], P / 2 + 1);
        k += 1;
    }
    table
}
const SETUP: [[u64; 2]; 33] = setup();
pub(super) fn get(log_n: u32) -> (Val, Val) {
    let [root, scale] = SETUP[log_n as usize];
    (Val::new(root), Val::new(scale))
}
#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
    #[test]
    fn every_fft_setup_matches_the_field_roots_and_normalization() {
        for log in 0..=32 {
            let (root, scale) = get(log);
            assert_eq!(root, Val::two_adic_generator(log as usize).inverse());
            assert_eq!(scale, Val::from_u64(1u64 << log).inverse());
        }
        assert_eq!(core::mem::size_of_val(&SETUP), 528);
    }
}
