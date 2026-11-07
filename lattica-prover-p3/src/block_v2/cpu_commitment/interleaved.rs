//! Independent packed Poseidon2-8 sponges, interleaved at each round.
//! Constants and the optimized diagonal are from p3-goldilocks 0.6.1
//! (MIT OR Apache-2.0). This changes instruction scheduling, not the hash.
use super::Packed;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
    GenericPoseidon2LinearLayersGoldilocks as Layers,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;

#[inline(always)]
fn pow7(x: Packed) -> Packed {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x2 * x
}

#[inline(always)]
fn internal(s: &mut [Packed; 8]) {
    let sum: Packed = s.iter().copied().sum();
    let old = *s;
    s[0] = sum - old[0].double();
    s[1] = sum + old[1];
    s[2] = sum + old[2].double();
    s[3] = sum + old[3].halve();
    s[4] = sum + old[4].double() + old[4];
    s[5] = sum - old[5].halve();
    s[6] = sum - old[6].double() - old[6];
    s[7] = sum - old[7].double().double();
}

#[inline]
fn permute<const N: usize>(states: &mut [[Packed; 8]; N]) {
    for state in states.iter_mut() {
        <Layers as GenericPoseidon2LinearLayers<8>>::external_linear_layer(state);
    }
    for constants in INITIAL {
        for col in 0..8 {
            for state in states.iter_mut() {
                state[col] = pow7(state[col] + constants[col]);
            }
        }
        for state in states.iter_mut() {
            <Layers as GenericPoseidon2LinearLayers<8>>::external_linear_layer(state);
        }
    }
    for constant in INTERNAL {
        for state in states.iter_mut() {
            state[0] = pow7(state[0] + constant);
        }
        for state in states.iter_mut() {
            internal(state);
        }
    }
    for constants in FINAL {
        for col in 0..8 {
            for state in states.iter_mut() {
                state[col] = pow7(state[col] + constants[col]);
            }
        }
        for state in states.iter_mut() {
            <Layers as GenericPoseidon2LinearLayers<8>>::external_linear_layer(state);
        }
    }
}

/// Inputs are consecutive packed rows, each with exactly `columns` fields.
/// A final partial rate block leaves the other rate fields unchanged, exactly
/// as PaddingFreeSponge does. Missing tail rows are never read or published.
pub(super) fn hash<const N: usize>(rows: &[Packed], columns: usize) -> [[Packed; 4]; N] {
    assert!(columns > 0 && rows.len() % columns == 0);
    let count = rows.len() / columns;
    assert!(count > 0 && count <= N);
    let mut states = [[Packed::ZERO; 8]; N];
    for first in (0..columns).step_by(4) {
        for row in 0..count {
            for col in 0..4.min(columns - first) {
                states[row][col] = rows[row * columns + first + col];
            }
        }
        permute(&mut states);
    }
    std::array::from_fn(|row| std::array::from_fn(|col| states[row][col]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MyHash, Val};
    use p3_field::{PackedValue, PrimeField64};
    use p3_symmetric::CryptographicHasher;

    #[test]
    fn interleaved_sponge_matches_upstream_with_partial_blocks_and_tails() {
        let hash = MyHash::new(p3_goldilocks::default_goldilocks_poseidon2_8());
        for columns in [1, 3, 4, 5, 8, 51, 94, 98, 200, 204, 112] {
            for count in 1..=4 {
                let rows: Vec<_> = (0..count * columns)
                    .map(|i| {
                        Packed::from_fn(|lane| {
                            let n = match (i + lane) % 5 {
                                0 => 0,
                                1 => Val::ORDER_U64 - 1,
                                _ => (i as u64)
                                    .wrapping_mul(0x9e3779b97f4a7c15)
                                    .rotate_left(lane as u32),
                            };
                            Val::from_u64(n)
                        })
                    })
                    .collect();
                let four = super::hash::<4>(&rows, columns);
                for row in 0..count {
                    let expected: [Packed; 4] =
                        hash.hash_iter(rows[row * columns..(row + 1) * columns].iter().copied());
                    for col in 0..4 {
                        assert_eq!(four[row][col].as_slice(), expected[col].as_slice());
                    }
                }
                if count <= 2 {
                    let two = super::hash::<2>(&rows, columns);
                    for row in 0..count {
                        for col in 0..4 {
                            assert_eq!(two[row][col].as_slice(), four[row][col].as_slice());
                        }
                    }
                }
            }
        }
    }
}
