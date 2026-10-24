//! Shared CPU-oracle Poseidon2 constants for GPU transports.
use p3_field::PrimeField64;
use p3_goldilocks::{
    Goldilocks, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
    MATRIX_DIAG_8_GOLDILOCKS,
};

#[cfg(feature = "gpu")]
fn opencl_diagonal_prefix(diagonal: [u64; 8]) -> &'static str {
    const P: u64 = 0xffff_ffff_0000_0001;
    // A dependency update with a different diagonal must use the generic
    // multiplication path, not silently change the permutation being proved.
    if diagonal == [P - 2, 1, 2, P / 2 + 1, 3, P / 2, P - 3, P - 4] {
        "#define LATTICA_POSEIDON2_FAST_DIAGONAL 1\n"
    } else {
        ""
    }
}

#[cfg(feature = "gpu")]
pub(crate) fn opencl_poseidon2_prefix() -> &'static str {
    opencl_diagonal_prefix(MATRIX_DIAG_8_GOLDILOCKS.map(|value| value.as_canonical_u64()))
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;

    #[test]
    fn opencl_fast_diagonal_requires_every_matching_coefficient() {
        let diagonal = MATRIX_DIAG_8_GOLDILOCKS.map(|value| value.as_canonical_u64());
        assert!(!opencl_poseidon2_prefix().is_empty());
        for index in 0..8 {
            let mut changed = diagonal;
            changed[index] ^= 1;
            assert!(opencl_diagonal_prefix(changed).is_empty());
        }
        assert!(opencl_diagonal_prefix([0; 8]).is_empty());
    }
}
pub(crate) fn poseidon2_consts() -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let flat = |rows: &[[Goldilocks; 8]]| {
        rows.iter()
            .flatten()
            .map(|x| x.as_canonical_u64())
            .collect()
    };
    (
        flat(&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL),
        GOLDILOCKS_POSEIDON2_RC_8_INTERNAL
            .iter()
            .map(|x| x.as_canonical_u64())
            .collect(),
        flat(&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL),
        MATRIX_DIAG_8_GOLDILOCKS
            .iter()
            .map(|x| x.as_canonical_u64())
            .collect(),
    )
}
