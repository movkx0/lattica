//! Shared CPU-oracle Poseidon2 constants for GPU transports.
use p3_field::PrimeField64;
use p3_goldilocks::{
    Goldilocks, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
    MATRIX_DIAG_8_GOLDILOCKS,
};
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
