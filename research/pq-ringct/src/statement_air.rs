//! Canonical full public-statement range and commitment component.
//! Proves the exact byte-length/LE-u32 framing used by LeafStatement, the fixed
//! network setup seed, coefficient ranges, and distinct input serials. It does
//! not verify a spend: consumers must bind this digest to the same polynomial
//! values used by every other component of the complete verifier.

use crate::rust_verify::constraints_ntt::POLYNOMIAL_DOMAIN;
use crate::shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH};
use crate::{
    native_packet::STATEMENT_BYTES, recursive_aggregation::STATEMENT_DOMAIN, rust_verify::Q,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use std::borrow::Borrow;

const WORDS: usize = STATEMENT_BYTES / 4;
const FIELDS: usize = WORDS + 1;
const ACTIVE_ROWS: usize = FIELDS.div_ceil(4);
pub const HEIGHT: usize = ACTIVE_ROWS.next_power_of_two();
const VALUE: usize = 0;
const BITS: usize = VALUE + 4;
const PREFIX: usize = BITS + 128;
const ACC: usize = PREFIX + 32;
const PRIOR: usize = ACC + 4;
const OLDER: usize = PRIOR + 4;
const EQUAL: usize = OLDER + 4;
const INVERSE: usize = EQUAL + 4;
const DIFFERENCES: usize = INVERSE + 4;
const FINAL_INVERSE: usize = DIFFERENCES + 1;
const ROW_INDEX: usize = FINAL_INVERSE + 1;
const SELECTOR: usize = ROW_INDEX + 1;
const SELECTOR_INVERSE: usize = SELECTOR + 8;
const ACTIVE_FLAG: usize = SELECTOR_INVERSE + 8;
const COEFFICIENT_FLAG: usize = ACTIVE_FLAG + 1;
const SERIAL_FLAG: usize = COEFFICIENT_FLAG + 1;
const POLY_ACC: usize = SERIAL_FLAG + 1;
const BUNDLE_ACC: usize = POLY_ACC + 4;
const POSEIDON: usize = BUNDLE_ACC + 4;
const POLY_POSEIDON: usize = POSEIDON + POSEIDON_WIDTH;
const BUNDLE_POSEIDON: usize = POLY_POSEIDON + POSEIDON_WIDTH;
pub const WIDTH: usize = BUNDLE_POSEIDON + POSEIDON_WIDTH;
pub const POLYNOMIALS: usize = (STATEMENT_BYTES - 96) / 1024;
pub const PUBLIC_VALUES: usize = 8;
pub const BUNDLE_DOMAIN: u64 = 0x5354_4d54_504f_4c31;
const COEFFICIENT: usize = 0;
const FIXED: usize = 4;
const EXPECTED: usize = 8;
const SECOND_SERIAL: usize = 12;
const ACTIVE: usize = 16;
const PERIODIC: usize = 17;
// The counter is fixed to 0 on the first row and increments exactly once on
// every transition. These equality selectors replace long periodic columns;
// their witnesses are checked by zero tests, never trusted as schedule masks.
const SELECTED_ROWS: [usize; 8] = [
    0,
    1,
    2,
    (FIELDS - 17) / 4 - 1,
    (FIELDS - 17) / 4,
    (FIELDS - 8) / 4,
    (FIELDS - 8) / 4 + 1,
    ACTIVE_ROWS - 1,
];

#[derive(Clone, Debug)]
pub struct StatementAir {
    pub setup_seed: [u8; 32],
}
pub struct StatementWitness {
    pub trace: RowMajorMatrix<Val>,
    /// Exact LeafStatement digest followed by the ordered polynomial/serial bundle.
    pub public_values: [Val; PUBLIC_VALUES],
}

pub mod bundle;

fn nibble_eq<E: PrimeCharacteristicRing>(bits: &[E], digit: u8) -> E {
    bits.iter().enumerate().fold(E::ONE, |p, (i, bit)| {
        p * if digit & (1 << i) != 0 {
            bit.clone()
        } else {
            E::ONE - bit.clone()
        }
    })
}

impl StatementAir {
    fn schedule(&self) -> Vec<Vec<Val>> {
        let mut schedule = vec![Val::zero_vec(HEIGHT); PERIODIC];
        for row in 0..HEIGHT {
            schedule[ACTIVE][row] = Val::from_bool(row < ACTIVE_ROWS);
            for slot in 0..4 {
                let index = 4 * row + slot;
                let fixed = if index == 0 {
                    Some(STATEMENT_BYTES as u32)
                } else if index <= 8 {
                    Some(u32::from_le_bytes(
                        self.setup_seed[(index - 1) * 4..index * 4]
                            .try_into()
                            .unwrap(),
                    ))
                } else if index >= FIELDS {
                    Some(0)
                } else {
                    None
                };
                if let Some(value) = fixed {
                    schedule[FIXED + slot][row] = Val::ONE;
                    schedule[EXPECTED + slot][row] = Val::from_u32(value);
                }
                schedule[COEFFICIENT + slot][row] =
                    Val::from_bool((9..FIELDS - 16).contains(&index));
                schedule[SECOND_SERIAL + slot][row] =
                    Val::from_bool((FIELDS - 8..FIELDS).contains(&index));
            }
        }
        schedule
    }

    /// Generates hints even for malformed coefficient/serial contents so tests
    /// can exercise the actual AIR rejection. Only the packet length is checked.
    pub fn generate(&self, bytes: &[u8]) -> Result<StatementWitness, &'static str> {
        if bytes.len() != STATEMENT_BYTES {
            return Err("statement length");
        }
        let fields: Vec<_> = std::iter::once(STATEMENT_BYTES as u32)
            .chain(
                bytes
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap())),
            )
            .collect();
        let schedule = self.schedule();
        let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
        let mut values = Val::zero_vec(HEIGHT * WIDTH);
        let mut acc = [
            Val::from_u64(STATEMENT_DOMAIN),
            Val::from_usize(FIELDS),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut prior = [Val::ZERO; 4];
        let mut older = [Val::ZERO; 4];
        let mut differences = Val::ZERO;
        let mut poseidon_inputs = Vec::with_capacity(HEIGHT);
        let poly_initial = [
            Val::from_u64(POLYNOMIAL_DOMAIN),
            Val::from_u64(Q),
            Val::from_usize(256),
            Val::ZERO,
        ];
        let mut poly_acc = poly_initial;
        let mut bundle_acc = bundle::initial(&self.setup_seed);
        let mut poly_inputs = Vec::with_capacity(HEIGHT);
        let mut bundle_inputs = Vec::with_capacity(HEIGHT);
        for row in 0..HEIGHT {
            let data = &mut values[row * WIDTH..(row + 1) * WIDTH];
            let words: [u32; 4] =
                core::array::from_fn(|slot| fields.get(4 * row + slot).copied().unwrap_or(0));
            let words_val = words.map(Val::from_u32);
            data[VALUE..BITS].copy_from_slice(&words_val);
            data[ACC..PRIOR].copy_from_slice(&acc);
            data[PRIOR..OLDER].copy_from_slice(&prior);
            data[OLDER..EQUAL].copy_from_slice(&older);
            data[DIFFERENCES] = differences;
            data[ROW_INDEX] = Val::from_usize(row);
            for (i, expected) in SELECTED_ROWS.into_iter().enumerate() {
                let delta = Val::from_usize(row) - Val::from_usize(expected);
                data[SELECTOR + i] = Val::from_bool(row == expected);
                data[SELECTOR_INVERSE + i] = delta.try_inverse().unwrap_or(Val::ZERO);
            }
            data[ACTIVE_FLAG] = Val::from_bool(row < ACTIVE_ROWS);
            data[COEFFICIENT_FLAG] = Val::from_bool((3..=SELECTED_ROWS[3]).contains(&row));
            let polynomial_active = (3..=SELECTED_ROWS[4]).contains(&row);
            let serial_active = row > SELECTED_ROWS[4] && row < ACTIVE_ROWS;
            data[SERIAL_FLAG] = Val::from_bool(serial_active);
            data[POLY_ACC..BUNDLE_ACC].copy_from_slice(&poly_acc);
            data[BUNDLE_ACC..POSEIDON].copy_from_slice(&bundle_acc);
            let shifted = [prior[1], prior[2], prior[3], words_val[0]];
            let mut updated_poly = if polynomial_active && row % 64 == 3 {
                poly_initial
            } else {
                poly_acc
            };
            poly_inputs.push(bundle::absorb(&mut updated_poly, shifted));
            if polynomial_active {
                poly_acc = updated_poly;
            }
            let poly_end = polynomial_active && row % 64 == 2;
            let mut updated_bundle = bundle_acc;
            bundle_inputs.push(bundle::absorb(
                &mut updated_bundle,
                if poly_end {
                    updated_poly
                } else if serial_active {
                    shifted
                } else {
                    [Val::ZERO; 4]
                },
            ));
            if poly_end || serial_active {
                bundle_acc = updated_bundle;
            }
            for slot in 0..4 {
                for bit in 0..32 {
                    data[BITS + 32 * slot + bit] = Val::from_u32((words[slot] >> bit) & 1);
                }
                let mut prefix = true;
                for step in 0..8 {
                    let nibble = 7 - step;
                    prefix &= ((u64::from(words[slot]) >> (4 * nibble)) & 15)
                        == (((Q - 1) >> (4 * nibble)) & 15);
                    data[PREFIX + 8 * slot + step] = Val::from_bool(prefix);
                }
                let delta = words_val[slot] - older[slot];
                let equal = delta == Val::ZERO;
                data[EQUAL + slot] = Val::from_bool(equal);
                data[INVERSE + slot] = delta.try_inverse().unwrap_or(Val::ZERO);
                differences += schedule[SECOND_SERIAL + slot][row] * Val::from_bool(!equal);
            }
            data[FINAL_INVERSE] = differences.try_inverse().unwrap_or(Val::ZERO);
            let mut input = [Val::ZERO; 8];
            input[..4].copy_from_slice(&acc);
            input[4..].copy_from_slice(&words_val);
            poseidon_inputs.push(input);
            permutation.permute_mut(&mut input);
            if row < ACTIVE_ROWS {
                acc.copy_from_slice(&input[..4]);
            }
            older = prior;
            prior = words_val;
        }
        for (start, inputs) in [
            (POSEIDON, poseidon_inputs),
            (POLY_POSEIDON, poly_inputs),
            (BUNDLE_POSEIDON, bundle_inputs),
        ] {
            let trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
                inputs,
                &round_constants(),
                0,
            );
            for (index, row) in values.chunks_exact_mut(WIDTH).enumerate() {
                row[start..start + POSEIDON_WIDTH].copy_from_slice(
                    &trace.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
                );
            }
        }
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        public_values[..4].copy_from_slice(&acc);
        public_values[4..].copy_from_slice(&bundle_acc);
        Ok(StatementWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values,
        })
    }
}

impl BaseAir<Val> for StatementAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        2
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        [3, 2]
            .into_iter()
            .map(|phase| (0..64).map(|row| Val::from_bool(row == phase)).collect())
            .collect()
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for StatementAir {
    fn eval(&self, b: &mut AB) {
        for start in [POSEIDON, POLY_POSEIDON, BUNDLE_POSEIDON] {
            PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
                parent: b,
                start,
                width: POSEIDON_WIDTH,
            });
        }
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values().to_vec();
        b.when_first_row().assert_zero(row[ROW_INDEX]);
        b.when_transition()
            .assert_eq(next[ROW_INDEX], row[ROW_INDEX] + Val::ONE);
        for (i, expected) in SELECTED_ROWS.into_iter().enumerate() {
            let delta = row[ROW_INDEX] - Val::from_usize(expected);
            b.assert_bool(row[SELECTOR + i]);
            b.assert_zero(delta.clone() * row[SELECTOR + i]);
            b.assert_eq(
                delta * row[SELECTOR_INVERSE + i],
                AB::Expr::ONE - row[SELECTOR + i],
            );
        }
        b.assert_bool(row[ACTIVE_FLAG]);
        b.assert_bool(row[COEFFICIENT_FLAG]);
        b.assert_bool(row[SERIAL_FLAG]);
        b.when_first_row().assert_one(row[ACTIVE_FLAG]);
        b.when_first_row().assert_zero(row[COEFFICIENT_FLAG]);
        b.when_first_row().assert_zero(row[SERIAL_FLAG]);
        b.when_transition()
            .assert_eq(next[ACTIVE_FLAG], row[ACTIVE_FLAG] - row[SELECTOR + 7]);
        b.when_transition().assert_eq(
            next[COEFFICIENT_FLAG],
            row[COEFFICIENT_FLAG] + row[SELECTOR + 2] - row[SELECTOR + 3],
        );
        b.when_transition().assert_eq(
            next[SERIAL_FLAG],
            row[SERIAL_FLAG] + row[SELECTOR + 4] - row[SELECTOR + 7],
        );
        let eq = |i: usize| -> AB::Expr { row[SELECTOR + i].into() };
        let phase = |i: usize| -> AB::Expr {
            match i {
                COEFFICIENT..FIXED => {
                    row[COEFFICIENT_FLAG] + if i == COEFFICIENT { eq(4) } else { eq(2) }
                }
                FIXED..EXPECTED => {
                    eq(0) + eq(1) + if i == FIXED { eq(2) } else { eq(7) } + AB::Expr::ONE
                        - row[ACTIVE_FLAG]
                }
                EXPECTED..SECOND_SERIAL => {
                    let slot = i - EXPECTED;
                    let seed = |word: usize| {
                        Val::from_u32(u32::from_le_bytes(
                            self.setup_seed[4 * word..4 * word + 4].try_into().unwrap(),
                        ))
                    };
                    if slot == 0 {
                        eq(0) * Val::from_usize(STATEMENT_BYTES) + eq(1) * seed(3) + eq(2) * seed(7)
                    } else {
                        eq(0) * seed(slot - 1) + eq(1) * seed(slot + 3)
                    }
                }
                SECOND_SERIAL..ACTIVE => eq(6) + if i == SECOND_SERIAL { eq(7) } else { eq(5) },
                ACTIVE => row[ACTIVE_FLAG].into(),
                _ => unreachable!(),
            }
        };
        let p: &PoseidonCols<AB::Var> = row[POSEIDON..POSEIDON + POSEIDON_WIDTH].borrow();
        let poly: &PoseidonCols<AB::Var> =
            row[POLY_POSEIDON..POLY_POSEIDON + POSEIDON_WIDTH].borrow();
        let bundle: &PoseidonCols<AB::Var> =
            row[BUNDLE_POSEIDON..BUNDLE_POSEIDON + POSEIDON_WIDTH].borrow();
        let periodic = b.periodic_values().to_vec();
        let polynomial_active: AB::Expr = row[COEFFICIENT_FLAG] + row[SELECTOR + 4];
        let start_phase: AB::Expr = periodic[0].into();
        let end_phase: AB::Expr = periodic[1].into();
        let polynomial_start = polynomial_active.clone() * start_phase;
        let polynomial_end = polynomial_active.clone() * end_phase;
        let bundle_active = polynomial_end.clone() + row[SERIAL_FLAG];
        let bundle_initial = bundle::initial(&self.setup_seed);
        for slot in 0..4 {
            let shifted = if slot < 3 {
                row[PRIOR + slot + 1]
            } else {
                row[VALUE]
            };
            let initial = match slot {
                0 => Val::from_u64(POLYNOMIAL_DOMAIN),
                1 => Val::from_u64(Q),
                2 => Val::from_usize(256),
                _ => Val::ZERO,
            };
            b.when_first_row().assert_eq(row[POLY_ACC + slot], initial);
            b.assert_eq(
                poly.inputs[slot],
                row[POLY_ACC + slot]
                    + polynomial_start.clone() * (AB::Expr::from(initial) - row[POLY_ACC + slot]),
            );
            b.assert_eq(poly.inputs[4 + slot], shifted);
            let updated_poly = row[POLY_ACC + slot]
                + polynomial_active.clone()
                    * (poly.ending_full_rounds[3].post[slot] - row[POLY_ACC + slot]);
            b.when_transition()
                .assert_eq(next[POLY_ACC + slot], updated_poly);
            b.when_first_row()
                .assert_eq(row[BUNDLE_ACC + slot], bundle_initial[slot]);
            b.assert_eq(bundle.inputs[slot], row[BUNDLE_ACC + slot]);
            b.assert_eq(
                bundle.inputs[4 + slot],
                polynomial_end.clone() * poly.ending_full_rounds[3].post[slot]
                    + row[SERIAL_FLAG] * shifted,
            );
            let updated_bundle = row[BUNDLE_ACC + slot]
                + bundle_active.clone()
                    * (bundle.ending_full_rounds[3].post[slot] - row[BUNDLE_ACC + slot]);
            b.when_transition()
                .assert_eq(next[BUNDLE_ACC + slot], updated_bundle.clone());
            b.when_last_row()
                .assert_eq(updated_bundle, public[4 + slot]);
        }
        let mut difference_increment = AB::Expr::ZERO;
        for slot in 0..4 {
            let bits: Vec<AB::Expr> = (0..32)
                .map(|bit| {
                    b.assert_bool(row[BITS + 32 * slot + bit]);
                    row[BITS + 32 * slot + bit].into()
                })
                .collect();
            let word = bits
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (bit, value)| {
                    sum + value.clone() * Val::from_u64(1 << bit)
                });
            b.assert_eq(row[VALUE + slot], word);
            let mut prefix = AB::Expr::ONE;
            for step in 0..8 {
                let nibble = 7 - step;
                let bound = (((Q - 1) >> (4 * nibble)) & 15) as u8;
                let part = &bits[4 * nibble..4 * nibble + 4];
                let greater =
                    ((bound + 1)..16).fold(AB::Expr::ZERO, |sum, n| sum + nibble_eq(part, n));
                b.assert_zero(phase(COEFFICIENT + slot) * prefix.clone() * greater);
                let current: AB::Expr = row[PREFIX + 8 * slot + step].into();
                b.assert_eq(current.clone(), prefix * nibble_eq(part, bound));
                prefix = current;
            }
            b.assert_zero(phase(FIXED + slot) * (row[VALUE + slot] - phase(EXPECTED + slot)));
            b.when_first_row().assert_zero(row[PRIOR + slot]);
            b.when_first_row().assert_zero(row[OLDER + slot]);
            b.when_transition()
                .assert_eq(next[PRIOR + slot], row[VALUE + slot]);
            b.when_transition()
                .assert_eq(next[OLDER + slot], row[PRIOR + slot]);
            let delta: AB::Expr = row[VALUE + slot] - row[OLDER + slot];
            b.assert_bool(row[EQUAL + slot]);
            b.assert_zero(delta.clone() * row[EQUAL + slot]);
            b.assert_eq(
                delta * row[INVERSE + slot],
                AB::Expr::ONE - row[EQUAL + slot],
            );
            difference_increment +=
                phase(SECOND_SERIAL + slot) * (AB::Expr::ONE - row[EQUAL + slot]);
            b.assert_eq(p.inputs[slot], row[ACC + slot]);
            b.assert_eq(p.inputs[4 + slot], row[VALUE + slot]);
            let updated = row[ACC + slot]
                + phase(ACTIVE) * (p.ending_full_rounds[3].post[slot] - row[ACC + slot]);
            b.when_transition()
                .assert_eq(next[ACC + slot], updated.clone());
            b.when_last_row().assert_eq(updated, public[slot]);
            let initial = match slot {
                0 => Val::from_u64(STATEMENT_DOMAIN),
                1 => Val::from_usize(FIELDS),
                _ => Val::ZERO,
            };
            b.when_first_row().assert_eq(row[ACC + slot], initial);
        }
        b.when_first_row().assert_zero(row[DIFFERENCES]);
        let differences = row[DIFFERENCES] + difference_increment;
        b.when_transition()
            .assert_eq(next[DIFFERENCES], differences.clone());
        // Exactly eight bounded Boolean comparisons contribute, so this count
        // cannot wrap. Its inverse enforces at least one differing serial word.
        b.when_last_row()
            .assert_eq(differences * row[FINAL_INVERSE], AB::Expr::ONE);
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "opencl")]
mod gpu;
