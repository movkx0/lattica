//! Exact bounded Q rejection sampling for sample_g and expand_alpha.
//! This proves stream parsing, canonical reduction, order, exhaustion checks,
//! and the ordered polynomial roots. AES generation is a separate obligation.
use crate::{
    rust_verify::{constraints_ntt::POLYNOMIAL_DOMAIN, D, Q},
    shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;
pub mod join;
#[cfg(test)]
mod tests;

pub const BUNDLE_DOMAIN: u64 = 0x554e_4946_5150_3031;
const ACCEPT_LIMIT: u64 = 4_194_256_025;
const RAW: usize = 0;
const RAW_BITS: usize = RAW + 1;
const ACCEPT: usize = RAW_BITS + 32;
const COMPARE_BITS: usize = ACCEPT + 1;
const REMAINDER: usize = COMPARE_BITS + 32;
const REMAINDER_BITS: usize = REMAINDER + 1;
const SLACK_BITS: usize = REMAINDER_BITS + 28;
const QUOTIENT_BITS: usize = SLACK_BITS + 28;
const COUNT: usize = QUOTIENT_BITS + 5;
const COUNT_BITS: usize = COUNT + 1;
const TAKE: usize = COUNT_BITS + 11;
const END_FOUR: usize = TAKE + 1;
const LOW_FULL: usize = END_FOUR + 1;
const HIGH_FULL: usize = LOW_FULL + 1;
const END_POLY: usize = HIGH_FULL + 1;
const PREVIOUS: usize = END_POLY + 1;
const BUFFER: usize = PREVIOUS + 2;
const BYTE_ACC: usize = BUFFER + 4;
const POLY_ACC: usize = BYTE_ACC + 4;
const BUNDLE_ACC: usize = POLY_ACC + 4;
const BYTE_POSEIDON: usize = BUNDLE_ACC + 4;
const POLY_POSEIDON: usize = BYTE_POSEIDON + POSEIDON_WIDTH;
const BUNDLE_POSEIDON: usize = POLY_POSEIDON + POSEIDON_WIDTH;
pub const WIDTH: usize = BUNDLE_POSEIDON + POSEIDON_WIDTH;
const P_DRAW: usize = 0;
const P_BYTE_HASH: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SampleG4,
    ExpandAlpha2,
}
impl Kind {
    pub fn draws(self) -> usize {
        match self {
            Self::SampleG4 => 1197,
            Self::ExpandAlpha2 => 643,
        }
    }
    pub fn polynomials(self) -> usize {
        match self {
            Self::SampleG4 => 4,
            Self::ExpandAlpha2 => 2,
        }
    }
    fn stop_bit(self) -> usize {
        match self {
            Self::SampleG4 => 10,
            Self::ExpandAlpha2 => 9,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct UniformAir {
    kind: Kind,
}
pub struct UniformWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; 8],
    pub polynomials: Vec<[u64; D]>,
}
fn absorb(acc: &mut [Val; 4], words: [Val; 4]) -> [Val; 8] {
    crate::statement_air::bundle::absorb(acc, words)
}
fn poly_initial() -> [Val; 4] {
    [
        Val::from_u64(POLYNOMIAL_DOMAIN),
        Val::from_u64(Q),
        Val::from_usize(D),
        Val::ZERO,
    ]
}
impl UniformAir {
    pub fn new(kind: Kind) -> Self {
        Self { kind }
    }
    pub fn kind(self) -> Kind {
        self.kind
    }
    pub fn height(self) -> usize {
        self.kind.draws().next_power_of_two()
    }
    pub fn bundle_initial(self) -> [Val; 4] {
        [
            Val::from_u64(BUNDLE_DOMAIN),
            Val::from_u64(Q),
            Val::from_usize(self.kind.draws()),
            Val::from_usize(self.kind.polynomials()),
        ]
    }
    fn byte_initial(self) -> [Val; 4] {
        [
            Val::from_u64(crate::rust_verify::constraints_crypto::AES_OUTPUT_DOMAIN),
            Val::from_usize(4 * self.kind.draws()),
            Val::ZERO,
            Val::ZERO,
        ]
    }
    pub fn bundle(self, roots: &[[Val; 4]]) -> Result<[Val; 4], &'static str> {
        if roots.len() != self.kind.polynomials() {
            return Err("uniform root count");
        }
        let mut state = self.bundle_initial();
        for root in roots {
            let _ = absorb(&mut state, *root);
        }
        Ok(state)
    }
    /// Rejection decisions are witness hints constrained independently by AIR.
    /// Exhausted streams produce invalid traces, never a verified result.
    pub fn generate(self, bytes: &[u8]) -> Result<UniformWitness, &'static str> {
        if bytes.len() != 4 * self.kind.draws() {
            return Err("uniform stream length");
        }
        let mut values = Val::zero_vec(self.height() * WIDTH);
        let mut count = 0usize;
        let mut previous = [0u16; 2];
        let mut buffer = [0u64; 4];
        let mut byte_acc = self.byte_initial();
        let mut poly_acc = poly_initial();
        let mut bundle_acc = self.bundle_initial();
        let mut streams = [Vec::new(), Vec::new(), Vec::new()];
        let mut coefficients = Vec::new();
        for (r, row) in values.chunks_exact_mut(WIDTH).enumerate() {
            let raw = if r < self.kind.draws() {
                u64::from(u32::from_le_bytes(
                    bytes[4 * r..4 * r + 4].try_into().unwrap(),
                ))
            } else {
                0
            };
            let accept = raw < ACCEPT_LIMIT;
            let compare = ACCEPT_LIMIT - 1 + (u64::from(!accept) << 32) - raw;
            let remainder = raw % Q;
            let quotient = raw / Q;
            row[RAW] = Val::from_u64(raw);
            row[ACCEPT] = Val::from_bool(accept);
            row[REMAINDER] = Val::from_u64(remainder);
            for (offset, width, value) in [
                (RAW_BITS, 32, raw),
                (COMPARE_BITS, 32, compare),
                (REMAINDER_BITS, 28, remainder),
                (SLACK_BITS, 28, Q - 1 - remainder),
                (QUOTIENT_BITS, 5, quotient),
                (COUNT_BITS, 11, count as u64),
            ] {
                for i in 0..width {
                    row[offset + i] = Val::from_u64((value >> i) & 1);
                }
            }
            let take = r < self.kind.draws() && accept && count < self.kind.polynomials() * D;
            let end_four = take && count % 4 == 3;
            let end_poly = take && count % D == D - 1;
            row[COUNT] = Val::from_usize(count);
            row[TAKE] = Val::from_bool(take);
            row[END_FOUR] = Val::from_bool(end_four);
            row[END_POLY] = Val::from_bool(end_poly);
            row[LOW_FULL] = Val::from_bool(count & 15 == 15);
            row[HIGH_FULL] = Val::from_bool((count >> 4) & 15 == 15);
            for i in 0..2 {
                row[PREVIOUS + i] = Val::from_u16(previous[i]);
            }
            for i in 0..4 {
                row[BUFFER + i] = Val::from_u64(buffer[i]);
            }
            row[BYTE_ACC..BYTE_ACC + 4].copy_from_slice(&byte_acc);
            row[POLY_ACC..POLY_ACC + 4].copy_from_slice(&poly_acc);
            row[BUNDLE_ACC..BUNDLE_ACC + 4].copy_from_slice(&bundle_acc);
            let current = [raw as u16, (raw >> 16) as u16];
            let mut next_byte = byte_acc;
            streams[0].push(absorb(
                &mut next_byte,
                [
                    Val::from_u16(previous[0]),
                    Val::from_u16(previous[1]),
                    Val::from_u16(current[0]),
                    Val::from_u16(current[1]),
                ],
            ));
            if r % 2 == 1 && r < self.kind.draws().div_ceil(2) * 2 {
                byte_acc = next_byte;
            }
            previous = current;
            if take {
                buffer[count % 4] = remainder;
                coefficients.push(remainder);
            }
            let mut next_poly = poly_acc;
            streams[1].push(absorb(&mut next_poly, buffer.map(Val::from_u64)));
            let mut next_bundle = bundle_acc;
            streams[2].push(absorb(&mut next_bundle, next_poly));
            if end_four {
                poly_acc = next_poly;
                buffer.fill(0);
            }
            if end_poly {
                bundle_acc = next_bundle;
                poly_acc = poly_initial();
            }
            if take {
                count += 1;
            }
        }
        for (offset, stream) in [BYTE_POSEIDON, POLY_POSEIDON, BUNDLE_POSEIDON]
            .into_iter()
            .zip(streams)
        {
            let p = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
                stream,
                &round_constants(),
                0,
            );
            for (r, row) in values.chunks_exact_mut(WIDTH).enumerate() {
                row[offset..offset + POSEIDON_WIDTH]
                    .copy_from_slice(&p.values[r * POSEIDON_WIDTH..(r + 1) * POSEIDON_WIDTH]);
            }
        }
        let mut public_values = [Val::ZERO; 8];
        public_values[..4].copy_from_slice(&byte_acc);
        public_values[4..].copy_from_slice(&bundle_acc);
        Ok(UniformWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values,
            polynomials: coefficients
                .chunks_exact(D)
                .map(|c| c.try_into().unwrap())
                .collect(),
        })
    }
}
impl BaseAir<Val> for UniformAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        8
    }
    fn num_periodic_columns(&self) -> usize {
        2
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        vec![
            (0..self.height())
                .map(|r| Val::from_bool(r < self.kind.draws()))
                .collect(),
            (0..self.height())
                .map(|r| Val::from_bool(r % 2 == 1 && r < self.kind.draws().div_ceil(2) * 2))
                .collect(),
        ]
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for UniformAir {
    fn eval(&self, b: &mut AB) {
        for start in [BYTE_POSEIDON, POLY_POSEIDON, BUNDLE_POSEIDON] {
            PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
                parent: b,
                start,
                width: POSEIDON_WIDTH,
            });
        }
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let p: Vec<AB::Expr> = b
            .periodic_values()
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        let public = b.public_values().to_vec();
        for (start, width) in [
            (RAW_BITS, 32),
            (COMPARE_BITS, 32),
            (REMAINDER_BITS, 28),
            (SLACK_BITS, 28),
            (QUOTIENT_BITS, 5),
            (COUNT_BITS, 11),
        ] {
            for i in 0..width {
                b.assert_bool(row[start + i]);
            }
        }
        let packed = |start: usize, width: usize| -> AB::Expr {
            (0..width).fold(AB::Expr::ZERO, |a, i| {
                a + row[start + i] * Val::from_u64(1 << i)
            })
        };
        b.assert_eq(row[RAW], packed(RAW_BITS, 32));
        b.assert_zero((AB::Expr::ONE - p[P_DRAW].clone()) * row[RAW]);
        b.assert_bool(row[ACCEPT]);
        b.assert_eq(
            row[RAW] + packed(COMPARE_BITS, 32),
            (AB::Expr::ONE - row[ACCEPT]) * Val::from_u64(1 << 32)
                + Val::from_u64(ACCEPT_LIMIT - 1),
        );
        b.assert_eq(row[REMAINDER], packed(REMAINDER_BITS, 28));
        b.assert_eq(
            row[REMAINDER] + packed(SLACK_BITS, 28),
            Val::from_u64(Q - 1),
        );
        b.assert_eq(
            row[RAW],
            packed(QUOTIENT_BITS, 5) * Val::from_u64(Q) + row[REMAINDER],
        );
        b.assert_eq(row[COUNT], packed(COUNT_BITS, 11));
        for i in self.kind.stop_bit() + 1..11 {
            b.assert_zero(row[COUNT_BITS + i]);
        }
        b.assert_eq(
            row[TAKE],
            p[P_DRAW].clone()
                * row[ACCEPT]
                * (AB::Expr::ONE - row[COUNT_BITS + self.kind.stop_bit()]),
        );
        b.assert_bool(row[TAKE]);
        b.assert_eq(
            row[END_FOUR],
            row[TAKE] * row[COUNT_BITS] * row[COUNT_BITS + 1],
        );
        b.assert_eq(
            row[LOW_FULL],
            (0..4).fold(AB::Expr::ONE, |a, i| a * row[COUNT_BITS + i]),
        );
        b.assert_eq(
            row[HIGH_FULL],
            (4..8).fold(AB::Expr::ONE, |a, i| a * row[COUNT_BITS + i]),
        );
        b.assert_eq(row[END_POLY], row[TAKE] * row[LOW_FULL] * row[HIGH_FULL]);
        b.when_first_row().assert_zero(row[COUNT]);
        b.when_transition()
            .assert_eq(next[COUNT], row[COUNT] + row[TAKE]);
        b.when_last_row()
            .assert_eq(row[COUNT], Val::from_usize(self.kind.polynomials() * D));
        let select = |i: usize| -> AB::Expr {
            (if i & 1 != 0 {
                row[COUNT_BITS].into()
            } else {
                AB::Expr::ONE - row[COUNT_BITS]
            }) * (if i & 2 != 0 {
                row[COUNT_BITS + 1].into()
            } else {
                AB::Expr::ONE - row[COUNT_BITS + 1]
            })
        };
        let byte: &PoseidonCols<AB::Var> =
            row[BYTE_POSEIDON..BYTE_POSEIDON + POSEIDON_WIDTH].borrow();
        let poly: &PoseidonCols<AB::Var> =
            row[POLY_POSEIDON..POLY_POSEIDON + POSEIDON_WIDTH].borrow();
        let bundle: &PoseidonCols<AB::Var> = row[BUNDLE_POSEIDON..].borrow();
        for i in 0..2 {
            b.when_first_row().assert_zero(row[PREVIOUS + i]);
            b.when_transition()
                .assert_eq(next[PREVIOUS + i], packed(RAW_BITS + 16 * i, 16));
            b.assert_eq(byte.inputs[4 + i], row[PREVIOUS + i]);
            b.assert_eq(byte.inputs[6 + i], packed(RAW_BITS + 16 * i, 16));
        }
        for i in 0..4 {
            let updated =
                row[BUFFER + i] + row[TAKE] * select(i) * (row[REMAINDER] - row[BUFFER + i]);
            b.when_first_row().assert_zero(row[BUFFER + i]);
            b.when_transition().assert_eq(
                next[BUFFER + i],
                (AB::Expr::ONE - row[END_FOUR]) * updated.clone(),
            );
            b.assert_eq(byte.inputs[i], row[BYTE_ACC + i]);
            b.assert_eq(poly.inputs[i], row[POLY_ACC + i]);
            b.assert_eq(poly.inputs[4 + i], updated);
            let poly_out = poly.ending_full_rounds[3].post[i];
            b.assert_eq(bundle.inputs[i], row[BUNDLE_ACC + i]);
            b.assert_eq(bundle.inputs[4 + i], poly_out);
            let byte_out = byte.ending_full_rounds[3].post[i];
            let bundle_out = bundle.ending_full_rounds[3].post[i];
            b.when_first_row()
                .assert_eq(row[BYTE_ACC + i], self.byte_initial()[i]);
            b.when_first_row()
                .assert_eq(row[POLY_ACC + i], poly_initial()[i]);
            b.when_first_row()
                .assert_eq(row[BUNDLE_ACC + i], self.bundle_initial()[i]);
            b.when_transition().assert_eq(
                next[BYTE_ACC + i],
                row[BYTE_ACC + i] + p[P_BYTE_HASH].clone() * (byte_out - row[BYTE_ACC + i]),
            );
            b.when_transition().assert_eq(
                next[POLY_ACC + i],
                row[POLY_ACC + i]
                    + row[END_FOUR] * (poly_out - row[POLY_ACC + i])
                    + row[END_POLY] * (AB::Expr::from(poly_initial()[i]) - poly_out),
            );
            b.when_transition().assert_eq(
                next[BUNDLE_ACC + i],
                row[BUNDLE_ACC + i] + row[END_POLY] * (bundle_out - row[BUNDLE_ACC + i]),
            );
            b.when_last_row().assert_eq(row[BYTE_ACC + i], public[i]);
            b.when_last_row()
                .assert_eq(row[BUNDLE_ACC + i], public[4 + i]);
        }
    }
}

#[cfg(feature="opencl")]
mod gpu;
