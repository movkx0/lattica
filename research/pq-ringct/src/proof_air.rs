//! Structured private-proof range, response-norm, and commitment component.
//!
//! The leaf statement does not commit the packed native proof bytes. This AIR
//! proves existence of the same canonically encodable structured witness,
//! preserving every coefficient bound and the six public-verifier norm checks.
//! It does not prove the MatRiCT relation, challenge sampling, or g_bound.

use crate::rust_verify::constraints_ntt::{POLYNOMIAL_DOMAIN, SIGNED_POLYNOMIAL_DOMAIN};
use crate::rust_verify::{Proof, D, Q, QHAT};
use crate::shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH};
use crate::statement_air::bundle::absorb;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

pub const POLYNOMIALS: usize = 91;
pub const HEIGHT: usize = 8192;
pub const BUNDLE_DOMAIN: u64 = 0x5052_4f4f_4650_5131;
const POLY_ROWS: usize = POLYNOMIALS * 64;
const WORD: usize = 0;
const BITS: usize = WORD + 4;
const PREFIX: usize = BITS + 128;
const POLY_ACC: usize = PREFIX + 32;
const BUNDLE_ACC: usize = POLY_ACC + 4;
const NORM_ACC: usize = BUNDLE_ACC + 4;
const NORM_BITS: usize = NORM_ACC + 1;
const NORM_PREFIX: usize = NORM_BITS + 60;
const POLY_POSEIDON: usize = NORM_PREFIX + 15;
const BUNDLE_POSEIDON: usize = POLY_POSEIDON + POSEIDON_WIDTH;
// Exact block index and authenticated boundary events replace full-height
// periodic columns. The anchored counter advances once per 64-row polynomial.
const POLYNOMIAL_COUNTER: usize = BUNDLE_POSEIDON + POSEIDON_WIDTH;
const EVENTS: [usize; 12] = [6, 11, 12, 21, 30, 39, 50, 61, 72, 82, 90, 91];
const EVENT_EQUAL: usize = POLYNOMIAL_COUNTER + 1;
const EVENT_INVERSE: usize = EVENT_EQUAL + EVENTS.len();
const CLASS: usize = EVENT_INVERSE + EVENTS.len();
const NORM_ACTIVE: usize = CLASS + 6;
const NORM_RESET: usize = NORM_ACTIVE + 1;
pub const WIDTH: usize = NORM_RESET + 1;
const PERIODIC_START: usize = 0;
const PERIODIC_END: usize = 1;
const PERIODIC_ALPHA: usize = 2;
const PERIODIC: usize = 3;
const SCHEDULE_PERIOD: usize = 64;
const MAXIMA: [u64; 8] = [
    Q - 1,
    QHAT - 1,
    2,
    76_692,
    1_130,
    12_425_172,
    u32::MAX as u64,
    0,
];
pub(crate) const OFFSETS: [u32; 8] = [0, 0, 1, 38_346, 565, 6_212_586, 0, 0];
pub(crate) const NORM_LIMITS: [u64; 3] = [135_519_727_172, 165_635_222_099, 3_161_803_581_581_766];
// Half-open polynomial intervals in the exact native proof field order.
pub(crate) const NORMS: [(usize, usize, usize); 6] = [
    (13, 22, 0),
    (22, 31, 0),
    (31, 40, 0),
    (40, 51, 1),
    (51, 62, 1),
    (83, 91, 2),
];
// These maximum integer sums follow from the constrained coefficient bounds.
// Consequently neither accumulation nor comparison can alias modulo Goldilocks.
const _: () = assert!(11u128 * 256 * 38_346 * 38_346 < 0xffff_ffff_0000_0001);
const _: () = assert!(8u128 * 256 * 6_212_586 * 6_212_586 < 0xffff_ffff_0000_0001);

pub mod join;

pub(crate) fn class(polynomial: usize) -> usize {
    match polynomial {
        0..=6 => 0,
        7..=11 => 1,
        12 => 2,
        13..=61 | 73..=82 => 3,
        62..=72 => 4,
        83..=90 => 5,
        _ => unreachable!(),
    }
}
fn polynomial_initial(kind: usize) -> [Val; 4] {
    [
        Val::from_u64(if kind < 2 {
            POLYNOMIAL_DOMAIN
        } else {
            SIGNED_POLYNOMIAL_DOMAIN
        }),
        Val::from_u64(match kind {
            0 => Q,
            1 => QHAT,
            _ => 0,
        }),
        Val::from_usize(D),
        Val::ZERO,
    ]
}
fn initial_bundle() -> [Val; 4] {
    [
        Val::from_u64(BUNDLE_DOMAIN),
        Val::from_usize(POLYNOMIALS),
        Val::from_u32(8),
        Val::ONE,
    ]
}

/// Hints only. All accepted bounds and norms are independently checked in AIR.
#[derive(Clone)]
pub struct ProofValues {
    pub polynomials: Vec<[i64; D]>,
    pub alpha: [u8; 32],
}
impl ProofValues {
    pub fn from_proof(p: &Proof) -> Result<Self, &'static str> {
        if p.v.len() != 4
            || p.b.len() != 5
            || p.z_out.len() != 2
            || p.z_out.iter().any(|v| v.len() != 9)
            || p.z0.len() != 9
            || p.z1.len() != 11
            || p.z2.len() != 11
            || p.f1.len() != 11
            || p.zb.len() != 10
            || p.z.len() != 8
        {
            return Err("private proof shape");
        }
        let mut polynomials = Vec::with_capacity(POLYNOMIALS);
        for poly in std::iter::once(&p.c)
            .chain(p.v.iter())
            .chain([&p.v1, &p.v2])
            .chain(p.b.iter())
        {
            let mut values = [0i64; D];
            for (dst, &value) in values.iter_mut().zip(poly) {
                *dst = i64::try_from(value).map_err(|_| "coefficient overflow")?;
            }
            polynomials.push(values);
        }
        polynomials.push(p.x);
        for polys in [
            &p.z_out[0],
            &p.z_out[1],
            &p.z0,
            &p.z1,
            &p.z2,
            &p.f1,
            &p.zb,
            &p.z,
        ] {
            polynomials.extend_from_slice(polys);
        }
        Ok(Self {
            polynomials,
            alpha: p.alpha,
        })
    }
    fn encoded(&self) -> Result<Vec<[u32; 4]>, &'static str> {
        if self.polynomials.len() != POLYNOMIALS {
            return Err("private polynomial count");
        }
        let mut rows = Vec::with_capacity(POLY_ROWS + 2);
        for (index, poly) in self.polynomials.iter().enumerate() {
            for values in poly.chunks_exact(4) {
                let mut encoded = [0; 4];
                for i in 0..4 {
                    encoded[i] = values[i]
                        .checked_add(i64::from(OFFSETS[class(index)]))
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or("coefficient encoding overflow")?;
                }
                rows.push(encoded);
            }
        }
        for bytes in self.alpha.chunks_exact(16) {
            rows.push(core::array::from_fn(|i| {
                u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap())
            }));
        }
        Ok(rows)
    }
    pub fn bundle(&self) -> Result<ProofBundle, &'static str> {
        let encoded = self.encoded()?;
        let mut roots = [[Val::ZERO; 4]; POLYNOMIALS];
        for (index, root) in roots.iter_mut().enumerate() {
            let kind = class(index);
            *root = polynomial_initial(kind);
            for chunk in &encoded[index * 64..(index + 1) * 64] {
                if chunk.iter().any(|&x| u64::from(x) > MAXIMA[kind]) {
                    return Err("noncanonical proof coefficient");
                }
                let _ = absorb(
                    root,
                    chunk.map(|x| Val::from_u32(x) - Val::from_u32(OFFSETS[kind])),
                );
            }
        }
        Ok(ProofBundle {
            roots,
            alpha: core::array::from_fn(|i| {
                u32::from_le_bytes(self.alpha[4 * i..4 * i + 4].try_into().unwrap())
            }),
        })
    }
}
#[derive(Clone)]
pub struct ProofBundle {
    pub roots: [[Val; 4]; POLYNOMIALS],
    pub alpha: [u32; 8],
}
impl ProofBundle {
    pub fn commitment(&self) -> [Val; 4] {
        let mut state = initial_bundle();
        for &root in &self.roots {
            let _ = absorb(&mut state, root);
        }
        for words in self.alpha.chunks_exact(4) {
            let _ = absorb(
                &mut state,
                core::array::from_fn(|i| Val::from_u32(words[i])),
            );
        }
        state
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProofAir;
pub struct ProofWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; 4],
}
impl ProofAir {
    fn schedule(&self) -> Vec<Vec<Val>> {
        let mut out = vec![Val::zero_vec(SCHEDULE_PERIOD); PERIODIC];
        out[PERIODIC_START][0] = Val::ONE;
        out[PERIODIC_END][SCHEDULE_PERIOD - 1] = Val::ONE;
        out[PERIODIC_ALPHA][0] = Val::ONE;
        out[PERIODIC_ALPHA][1] = Val::ONE;
        out
    }
    pub fn generate(&self, input: &ProofValues) -> Result<ProofWitness, &'static str> {
        let encoded = input.encoded()?;
        let mut trace = Val::zero_vec(HEIGHT * WIDTH);
        let mut poly_acc = polynomial_initial(0);
        let mut bundle_acc = initial_bundle();
        let mut norm_total = 0u64;
        let mut poly_inputs = Vec::with_capacity(HEIGHT);
        let mut bundle_inputs = Vec::with_capacity(HEIGHT);
        for row in 0..HEIGHT {
            let data = &mut trace[row * WIDTH..(row + 1) * WIDTH];
            let polynomial = row / SCHEDULE_PERIOD;
            let kind = if row < POLY_ROWS {
                class(polynomial)
            } else if row < POLY_ROWS + 2 {
                6
            } else {
                7
            };
            let norm = NORMS
                .iter()
                .find(|&&(first, end, _)| (first..end).contains(&polynomial));
            let norm_start = NORMS.iter().any(|&(first, _, _)| first == polynomial);
            let norm_limit = if row % SCHEDULE_PERIOD == SCHEDULE_PERIOD - 1 {
                NORMS
                    .iter()
                    .find(|&&(_, end, _)| polynomial + 1 == end)
                    .map(|&(_, _, limit)| limit)
            } else {
                None
            };
            data[POLYNOMIAL_COUNTER] = Val::from_usize(polynomial);
            for (i, &event) in EVENTS.iter().enumerate() {
                let difference = Val::from_usize(polynomial) - Val::from_usize(event);
                data[EVENT_EQUAL + i] = Val::from_bool(polynomial == event);
                data[EVENT_INVERSE + i] = difference.try_inverse().unwrap_or(Val::ZERO);
            }
            if kind < 6 {
                data[CLASS + kind] = Val::ONE;
            }
            data[NORM_ACTIVE] = Val::from_bool(norm.is_some());
            data[NORM_RESET] = Val::from_bool(norm_start);
            let words = encoded.get(row).copied().unwrap_or([0; 4]);
            data[WORD..BITS].copy_from_slice(&words.map(Val::from_u32));
            data[POLY_ACC..BUNDLE_ACC].copy_from_slice(&poly_acc);
            data[BUNDLE_ACC..NORM_ACC].copy_from_slice(&bundle_acc);
            data[NORM_ACC] = Val::from_u64(norm_total);
            let coefficients = words.map(|v| Val::from_u32(v) - Val::from_u32(OFFSETS[kind]));
            for slot in 0..4 {
                for bit in 0..32 {
                    data[BITS + 32 * slot + bit] = Val::from_u32((words[slot] >> bit) & 1);
                }
                let mut prefix = true;
                for step in 0..8 {
                    let shift = 4 * (7 - step);
                    prefix &=
                        ((u64::from(words[slot]) >> shift) & 15) == ((MAXIMA[kind] >> shift) & 15);
                    data[PREFIX + 8 * slot + step] = Val::from_bool(prefix);
                }
            }
            let mut updated_poly = if row < POLY_ROWS && row % SCHEDULE_PERIOD == 0 {
                polynomial_initial(kind)
            } else {
                poly_acc
            };
            poly_inputs.push(absorb(&mut updated_poly, coefficients));
            if row < POLY_ROWS {
                poly_acc = updated_poly;
            }
            let end = row < POLY_ROWS && row % SCHEDULE_PERIOD == SCHEDULE_PERIOD - 1;
            let mut updated_bundle = bundle_acc;
            bundle_inputs.push(absorb(
                &mut updated_bundle,
                if end {
                    updated_poly
                } else if kind == 6 {
                    coefficients
                } else {
                    [Val::ZERO; 4]
                },
            ));
            if end || kind == 6 {
                bundle_acc = updated_bundle;
            }
            if norm_start && row % SCHEDULE_PERIOD == 0 {
                norm_total = 0;
            }
            if norm.is_some() {
                for word in words {
                    let value = i64::from(word) - i64::from(OFFSETS[kind]);
                    norm_total = norm_total
                        .checked_add(
                            value
                                .unsigned_abs()
                                .checked_mul(value.unsigned_abs())
                                .ok_or("norm hint overflow")?,
                        )
                        .ok_or("norm hint overflow")?;
                }
            }
            let check = if norm_limit.is_some() { norm_total } else { 0 };
            for bit in 0..60 {
                data[NORM_BITS + bit] = Val::from_u64((check >> bit) & 1);
            }
            let mut prefix = true;
            for step in 0..15 {
                let equal = norm_limit
                    .map(|i| {
                        ((check >> (4 * (14 - step))) & 15)
                            == ((NORM_LIMITS[i] >> (4 * (14 - step))) & 15)
                    })
                    .unwrap_or(false);
                prefix &= equal;
                data[NORM_PREFIX + step] = Val::from_bool(prefix);
            }
        }
        for (start, inputs) in [
            (POLY_POSEIDON, poly_inputs),
            (BUNDLE_POSEIDON, bundle_inputs),
        ] {
            let p = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
                inputs,
                &round_constants(),
                0,
            );
            for (i, row) in trace.chunks_exact_mut(WIDTH).enumerate() {
                row[start..start + POSEIDON_WIDTH]
                    .copy_from_slice(&p.values[i * POSEIDON_WIDTH..(i + 1) * POSEIDON_WIDTH]);
            }
        }
        Ok(ProofWitness {
            trace: RowMajorMatrix::new(trace, WIDTH),
            public_values: bundle_acc,
        })
    }
}
impl BaseAir<Val> for ProofAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        4
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.schedule()
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ProofAir {
    fn eval(&self, b: &mut AB) {
        for start in [POLY_POSEIDON, BUNDLE_POSEIDON] {
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
        let periodic = b.periodic_values().to_vec();
        let first: AB::Expr = periodic[PERIODIC_START].into();
        let last: AB::Expr = periodic[PERIODIC_END].into();
        let alpha_rows: AB::Expr = periodic[PERIODIC_ALPHA].into();
        let counter: AB::Expr = row[POLYNOMIAL_COUNTER].into();
        b.when_first_row().assert_zero(counter.clone());
        b.when_last_row().assert_eq(
            counter.clone(),
            Val::from_usize(HEIGHT / SCHEDULE_PERIOD - 1),
        );
        b.when_transition()
            .assert_eq(next[POLYNOMIAL_COUNTER], counter.clone() + last.clone());
        // These zero tests pin each event in both directions. Inverses at zero
        // are also fixed, so there is no unused event-witness degree of freedom.
        for (i, &event) in EVENTS.iter().enumerate() {
            let equal: AB::Expr = row[EVENT_EQUAL + i].into();
            let inverse: AB::Expr = row[EVENT_INVERSE + i].into();
            let difference = counter.clone() - Val::from_usize(event);
            b.assert_zero(difference.clone() * equal.clone());
            b.assert_eq(difference * inverse.clone(), AB::Expr::ONE - equal.clone());
            b.assert_zero(equal * inverse);
        }
        let event = |index: usize| -> AB::Expr { row[EVENT_EQUAL + index].into() };
        let class_changes = [
            -event(0),
            event(0) - event(1),
            event(1) - event(2),
            event(2) - event(7) + event(8) - event(9),
            event(7) - event(8),
            event(9) - event(10),
        ];
        for (kind, change) in class_changes.into_iter().enumerate() {
            b.assert_bool(row[CLASS + kind]);
            b.when_first_row()
                .assert_eq(row[CLASS + kind], Val::from_bool(kind == 0));
            b.when_transition().assert_eq(
                next[CLASS + kind],
                row[CLASS + kind] + last.clone() * change,
            );
        }
        b.assert_bool(row[NORM_ACTIVE]);
        b.assert_bool(row[NORM_RESET]);
        b.when_first_row().assert_zero(row[NORM_ACTIVE]);
        b.when_first_row().assert_zero(row[NORM_RESET]);
        b.when_transition().assert_eq(
            next[NORM_ACTIVE],
            row[NORM_ACTIVE] + last.clone() * (event(2) - event(7) + event(9) - event(10)),
        );
        let reset = event(2) + event(3) + event(4) + event(5) + event(6) + event(9);
        b.when_transition().assert_eq(
            next[NORM_RESET],
            row[NORM_RESET] + last.clone() * (reset - row[NORM_RESET]),
        );
        let active = (0..6).fold(AB::Expr::ZERO, |sum, kind| sum + row[CLASS + kind]);
        let alpha = alpha_rows * event(11);
        let phases: Vec<AB::Expr> = (0..8)
            .map(|kind| match kind {
                0..=5 => row[CLASS + kind].into(),
                6 => alpha.clone(),
                _ => AB::Expr::ONE - active.clone() - alpha.clone(),
            })
            .collect();
        let phase = |kind: usize| phases[kind].clone();
        let poly_start = first.clone() * active.clone();
        let poly_end = last.clone() * active.clone();
        let norm_start = first * row[NORM_RESET];
        let norm_ends = [
            last.clone() * (event(3) + event(4) + event(5)),
            last.clone() * (event(6) + event(7)),
            last * event(10),
        ];
        let offset = (0..6).fold(AB::Expr::ZERO, |sum, kind| {
            sum + phase(kind) * Val::from_u32(OFFSETS[kind])
        });
        let poly: &PoseidonCols<AB::Var> =
            row[POLY_POSEIDON..POLY_POSEIDON + POSEIDON_WIDTH].borrow();
        let bundle: &PoseidonCols<AB::Var> =
            row[BUNDLE_POSEIDON..BUNDLE_POSEIDON + POSEIDON_WIDTH].borrow();
        let mut squares = AB::Expr::ZERO;
        for slot in 0..4 {
            let bits: Vec<AB::Expr> = (0..32)
                .map(|i| {
                    b.assert_bool(row[BITS + 32 * slot + i]);
                    row[BITS + 32 * slot + i].into()
                })
                .collect();
            let word = bits
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (i, bit)| {
                    sum + bit.clone() * Val::from_u64(1 << i)
                });
            b.assert_eq(row[WORD + slot], word);
            let coefficient = row[WORD + slot] - offset.clone();
            squares += coefficient.square();
            let mut prefix = AB::Expr::ONE;
            for step in 0..8 {
                let shift = 4 * (7 - step);
                let part = &bits[shift..shift + 4];
                let mut equal = AB::Expr::ZERO;
                let mut greater = AB::Expr::ZERO;
                for kind in 0..8 {
                    let digit = ((MAXIMA[kind] >> shift) & 15) as u8;
                    equal += phase(kind) * crate::ntt_air::nibble_eq(part, digit);
                    greater += phase(kind)
                        * ((digit + 1)..16).fold(AB::Expr::ZERO, |sum, d| {
                            sum + crate::ntt_air::nibble_eq(part, d)
                        });
                }
                b.assert_zero(prefix.clone() * greater);
                let current: AB::Expr = row[PREFIX + 8 * slot + step].into();
                b.assert_eq(current.clone(), prefix * equal);
                prefix = current;
            }
            let initial = (0..6).fold(AB::Expr::ZERO, |sum, kind| {
                sum + phase(kind) * polynomial_initial(kind)[slot]
            });
            b.when_first_row()
                .assert_eq(row[POLY_ACC + slot], polynomial_initial(0)[slot]);
            b.assert_eq(
                poly.inputs[slot],
                row[POLY_ACC + slot] + poly_start.clone() * (initial - row[POLY_ACC + slot]),
            );
            b.assert_eq(poly.inputs[4 + slot], coefficient.clone());
            let updated = row[POLY_ACC + slot]
                + active.clone() * (poly.ending_full_rounds[3].post[slot] - row[POLY_ACC + slot]);
            b.when_transition()
                .assert_eq(next[POLY_ACC + slot], updated);
            b.when_first_row()
                .assert_eq(row[BUNDLE_ACC + slot], initial_bundle()[slot]);
            b.assert_eq(bundle.inputs[slot], row[BUNDLE_ACC + slot]);
            b.assert_eq(
                bundle.inputs[4 + slot],
                poly_end.clone() * poly.ending_full_rounds[3].post[slot]
                    + alpha.clone() * coefficient,
            );
            let updated = row[BUNDLE_ACC + slot]
                + (poly_end.clone() + alpha.clone())
                    * (bundle.ending_full_rounds[3].post[slot] - row[BUNDLE_ACC + slot]);
            b.when_transition()
                .assert_eq(next[BUNDLE_ACC + slot], updated.clone());
            b.when_last_row().assert_eq(updated, public[slot]);
        }
        b.when_first_row().assert_zero(row[NORM_ACC]);
        let total = (AB::Expr::ONE - norm_start) * row[NORM_ACC] + row[NORM_ACTIVE] * squares;
        b.when_transition().assert_eq(next[NORM_ACC], total.clone());
        let norm_bits: Vec<AB::Expr> = (0..60)
            .map(|i| {
                b.assert_bool(row[NORM_BITS + i]);
                row[NORM_BITS + i].into()
            })
            .collect();
        let encoded = norm_bits
            .iter()
            .enumerate()
            .fold(AB::Expr::ZERO, |sum, (i, bit)| {
                sum + bit.clone() * Val::from_u64(1 << i)
            });
        let end = norm_ends
            .iter()
            .cloned()
            .fold(AB::Expr::ZERO, |sum, value| sum + value);
        b.assert_zero(end * (total - encoded));
        let mut prefix = AB::Expr::ONE;
        for step in 0..15 {
            let shift = 4 * (14 - step);
            let part = &norm_bits[shift..shift + 4];
            let mut equal = AB::Expr::ZERO;
            let mut greater = AB::Expr::ZERO;
            for kind in 0..3 {
                let digit = ((NORM_LIMITS[kind] >> shift) & 15) as u8;
                equal += norm_ends[kind].clone() * crate::ntt_air::nibble_eq(part, digit);
                greater += norm_ends[kind].clone()
                    * ((digit + 1)..16).fold(AB::Expr::ZERO, |sum, d| {
                        sum + crate::ntt_air::nibble_eq(part, d)
                    });
            }
            b.assert_zero(prefix.clone() * greater);
            let current: AB::Expr = row[NORM_PREFIX + step].into();
            b.assert_eq(current.clone(), prefix * equal);
            prefix = current;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "opencl")]
mod gpu;
