//! Immutable public transform roots shared by GPU transports.
use crate::config::Val;
use p3_field::PrimeField64;

// The pinned Goldilocks two-adic root (Plonky3 0.6.1). Build inverse roots
// at compile time; a fold needs only a lookup, never a host field inversion.
const INVERSE_ROOTS: [u64; 33] = {
    const P: u128 = 0xffff_ffff_0000_0001;
    let mut root = 0x1856_29dc_da58_878cu128;
    let mut exponent = P - 2;
    let mut inverse = 1u128;
    while exponent != 0 {
        if exponent & 1 != 0 {
            inverse = inverse * root % P;
        }
        root = root * root % P;
        exponent >>= 1;
    }
    let mut roots = [0u64; 33];
    roots[32] = inverse as u64;
    let mut i = 32;
    while i > 0 {
        roots[i - 1] = (roots[i] as u128 * roots[i] as u128 % P) as u64;
        i -= 1;
    }
    roots
};

pub(crate) fn inverse_root(log_rows: u32) -> u64 {
    INVERSE_ROOTS[log_rows as usize]
}

pub(crate) fn root(log_rows: u32) -> u64 {
    Val::TWO_ADIC_GENERATORS[log_rows as usize].as_canonical_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_transform_roots_match_all_reference_domains() {
        use p3_field::{Field, TwoAdicField};
        for bits in 0..=32 {
            let expected = Val::two_adic_generator(bits);
            assert_eq!(root(bits as u32), expected.as_canonical_u64());
            assert_eq!(
                inverse_root(bits as u32),
                expected.inverse().as_canonical_u64()
            );
        }
    }
}
