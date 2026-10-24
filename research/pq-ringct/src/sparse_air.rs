//! Exact bounded sparse samplers used by MatRiCT+.
//!
//! The two predicates are deliberately distinct: alpha-prime consumes 39 signs
//! and draws distinct indices in 256 positions; x consumes 44 signs, first one
//! in each residue class, then ten more per class. Rejected duplicates consume
//! input bytes. Every byte, including unused tail bytes, is committed. The input
//! root must still be joined to a verified AES or SHAKE request.
use crate::{
    rust_verify::constraints_ntt::SIGNED_POLYNOMIAL_DOMAIN,
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

pub const HEIGHT: usize = 256;
pub const PUBLIC_VALUES: usize = 8;
const OUTPUT: usize = 0;
const SIGNS: usize = OUTPUT + 256;
const BYTE: usize = SIGNS + 64;
const BYTE_BITS: usize = BYTE + 1;
const LOW: usize = BYTE_BITS + 8;
const HIGH: usize = LOW + 16;
const COUNT: usize = HIGH + 16;
const COUNT_BITS: usize = COUNT + 1;
const COUNT_LOW: usize = COUNT_BITS + 6;
const COUNT_HIGH: usize = COUNT_LOW + 16;
const GROUP: usize = COUNT_HIGH + 4;
const REMAINING: usize = GROUP + 4;
const READ: usize = REMAINING + 1;
const SIGN: usize = READ + 1;
const TAKE: usize = SIGN + 1;
const BUFFER: usize = TAKE + 1;
const BYTE_ACC: usize = BUFFER + 8;
const POLY_ACC: usize = BYTE_ACC + 4;
const POSEIDON: usize = POLY_ACC + 4;
pub const WIDTH: usize = POSEIDON + POSEIDON_WIDTH;

const P_RAW: usize = 0;
const P_DRAW: usize = 1;
const P_BYTE_HASH: usize = 2;
const P_POLY_HASH: usize = 3;
const P_SIGN: usize = 4;
const P_BUFFER: usize = P_SIGN + 6;
const P_POLY: usize = P_BUFFER + 8;
const PERIODIC: usize = P_POLY + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    AlphaPrime39,
    ChallengeX44,
}
impl Kind {
    pub fn input_len(self) -> usize {
        match self {
            Self::AlphaPrime39 => 127,
            Self::ChallengeX44 => 137,
        }
    }
    fn sign_bytes(self) -> usize {
        match self {
            Self::AlphaPrime39 => 5,
            Self::ChallengeX44 => 6,
        }
    }
    pub fn weight(self) -> usize {
        match self {
            Self::AlphaPrime39 => 39,
            Self::ChallengeX44 => 44,
        }
    }
    pub fn input_domain(self) -> u64 {
        match self {
            Self::AlphaPrime39 => crate::rust_verify::constraints_crypto::AES_OUTPUT_DOMAIN,
            Self::ChallengeX44 => {
                lattica_prover_p3::block_v2::machine::pq_bytes::SHAKE_OUTPUT_DOMAIN
            }
        }
    }
    fn group(self, count: usize) -> Option<usize> {
        if self == Self::AlphaPrime39 || count >= 44 {
            None
        } else if count < 4 {
            Some(count)
        } else {
            Some((count - 4) / 10)
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct SparseAir {
    kind: Kind,
}
pub struct SparseWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub polynomial: [i64; 256],
}

fn eq_bits<E: PrimeCharacteristicRing>(bits: &[E], value: usize) -> E {
    bits.iter().enumerate().fold(E::ONE, |x, (i, bit)| {
        x * if value & (1 << i) != 0 {
            bit.clone()
        } else {
            E::ONE - bit.clone()
        }
    })
}
fn absorb(acc: &mut [Val; 4], words: [Val; 4]) -> [Val; 8] {
    crate::statement_air::bundle::absorb(acc, words)
}
impl SparseAir {
    pub fn new(kind: Kind) -> Self {
        Self { kind }
    }
    pub fn kind(self) -> Kind {
        self.kind
    }
    fn byte_initial(self) -> [Val; 4] {
        [
            Val::from_u64(self.kind.input_domain()),
            Val::from_usize(self.kind.input_len()),
            Val::ZERO,
            Val::ZERO,
        ]
    }
    fn poly_initial() -> [Val; 4] {
        [
            Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
            Val::ZERO,
            Val::from_usize(256),
            Val::ZERO,
        ]
    }
    fn schedule(self) -> Vec<Vec<Val>> {
        let mut p = vec![Val::zero_vec(HEIGHT); P_BUFFER];
        for r in 0..HEIGHT {
            p[P_RAW][r] = Val::from_bool(r < self.kind.input_len());
            p[P_DRAW][r] =
                Val::from_bool((self.kind.sign_bytes()..self.kind.input_len()).contains(&r));
            p[P_BYTE_HASH][r] =
                Val::from_bool(r < self.kind.input_len().div_ceil(8) * 8 && r % 8 == 7);
            p[P_POLY_HASH][r] = Val::from_bool(r >= 192);
            for s in 0..self.kind.sign_bytes() {
                p[P_SIGN + s][r] = Val::from_bool(r == s);
            }
        }
        for s in 0..8 {
            p.push((0..8).map(|r| Val::from_bool(r == s)).collect());
        }
        for s in 0..64 {
            p.push((0..64).map(|r| Val::from_bool(r == s)).collect());
        }
        p
    }
    /// Witness construction, including for exhausted streams. Exhaustion is
    /// rejected by the constrained final count, never accepted by a host hint.
    pub fn generate(self, bytes: &[u8]) -> Result<SparseWitness, &'static str> {
        if bytes.len() != self.kind.input_len() {
            return Err("sparse input length");
        }
        let mut trace = Val::zero_vec(HEIGHT * WIDTH);
        let mut output = [0i64; 256];
        let mut signs = [false; 64];
        let mut count = 0;
        let mut buffer = [0u8; 8];
        let mut byte_acc = self.byte_initial();
        let mut poly_acc = Self::poly_initial();
        let mut poseidon_inputs = Vec::with_capacity(HEIGHT);
        for (r, row) in trace.chunks_exact_mut(WIDTH).enumerate() {
            let raw = bytes.get(r).copied().unwrap_or(0);
            for i in 0..256 {
                row[OUTPUT + i] = Val::from_i64(output[i]);
            }
            for i in 0..64 {
                row[SIGNS + i] = Val::from_bool(signs[i]);
            }
            row[BYTE] = Val::from_u8(raw);
            for i in 0..8 {
                row[BYTE_BITS + i] = Val::from_u8((raw >> i) & 1);
            }
            row[LOW + usize::from(raw & 15)] = Val::ONE;
            row[HIGH + usize::from(raw >> 4)] = Val::ONE;
            row[COUNT] = Val::from_usize(count);
            for i in 0..6 {
                row[COUNT_BITS + i] = Val::from_usize((count >> i) & 1);
            }
            row[COUNT_LOW + (count & 15)] = Val::ONE;
            row[COUNT_HIGH + (count >> 4)] = Val::ONE;
            let group = self.kind.group(count);
            if let Some(g) = group {
                row[GROUP + g] = Val::ONE;
            }
            let remaining = count < self.kind.weight();
            row[REMAINING] = Val::from_bool(remaining);
            let index = if self.kind == Kind::AlphaPrime39 {
                usize::from(raw)
            } else {
                4 * usize::from(raw & 63) + group.unwrap_or(0)
            };
            let read = if self.kind == Kind::ChallengeX44 && group.is_none() {
                0
            } else {
                output[index]
            };
            row[READ] = Val::from_i64(read);
            row[SIGN] = Val::from_bool(signs[count]);
            let take = r >= self.kind.sign_bytes() && r < bytes.len() && remaining && read == 0;
            row[TAKE] = Val::from_bool(take);
            for i in 0..8 {
                row[BUFFER + i] = Val::from_u8(buffer[i]);
            }
            row[BYTE_ACC..BYTE_ACC + 4].copy_from_slice(&byte_acc);
            row[POLY_ACC..POLY_ACC + 4].copy_from_slice(&poly_acc);
            buffer[r % 8] = raw;
            let input = if r < bytes.len().div_ceil(8) * 8 && r % 8 == 7 {
                let input = absorb(
                    &mut byte_acc,
                    core::array::from_fn(|i| {
                        Val::from_u16(u16::from_le_bytes([buffer[2 * i], buffer[2 * i + 1]]))
                    }),
                );
                buffer.fill(0);
                input
            } else if r >= 192 {
                absorb(
                    &mut poly_acc,
                    core::array::from_fn(|i| Val::from_i64(output[4 * (r - 192) + i])),
                )
            } else {
                [Val::ZERO; 8]
            };
            poseidon_inputs.push(input);
            if r < self.kind.sign_bytes() {
                for i in 0..8 {
                    signs[8 * r + i] = raw & (1 << i) != 0;
                }
            }
            if take {
                output[index] = 1 - 2 * i64::from(signs[count]);
                count += 1;
            }
        }
        let p = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            poseidon_inputs,
            &round_constants(),
            0,
        );
        for (r, row) in trace.chunks_exact_mut(WIDTH).enumerate() {
            row[POSEIDON..]
                .copy_from_slice(&p.values[r * POSEIDON_WIDTH..(r + 1) * POSEIDON_WIDTH]);
        }
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        public_values[..4].copy_from_slice(&byte_acc);
        public_values[4..].copy_from_slice(&poly_acc);
        Ok(SparseWitness {
            trace: RowMajorMatrix::new(trace, WIDTH),
            public_values,
            polynomial: output,
        })
    }
}
impl BaseAir<Val> for SparseAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.schedule()
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for SparseAir {
    fn eval(&self, b: &mut AB) {
        PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
            parent: b,
            start: POSEIDON,
            width: POSEIDON_WIDTH,
        });
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
        let raw: Vec<AB::Expr> = (0..8)
            .map(|i| {
                b.assert_bool(row[BYTE_BITS + i]);
                row[BYTE_BITS + i].into()
            })
            .collect();
        let count: Vec<AB::Expr> = (0..6)
            .map(|i| {
                b.assert_bool(row[COUNT_BITS + i]);
                row[COUNT_BITS + i].into()
            })
            .collect();
        b.assert_eq(
            row[BYTE],
            raw.iter().enumerate().fold(AB::Expr::ZERO, |a, (i, v)| {
                a + v.clone() * Val::from_u64(1 << i)
            }),
        );
        b.assert_zero((AB::Expr::ONE - p[P_RAW].clone()) * row[BYTE]);
        b.assert_eq(
            row[COUNT],
            count.iter().enumerate().fold(AB::Expr::ZERO, |a, (i, v)| {
                a + v.clone() * Val::from_u64(1 << i)
            }),
        );
        for i in 0..16 {
            b.assert_eq(row[LOW + i], eq_bits(&raw[..4], i));
            b.assert_eq(row[HIGH + i], eq_bits(&raw[4..], i));
            b.assert_eq(row[COUNT_LOW + i], eq_bits(&count[..4], i));
        }
        for i in 0..4 {
            b.assert_eq(row[COUNT_HIGH + i], eq_bits(&count[4..], i));
        }
        let at_count =
            |i: usize| -> AB::Expr { row[COUNT_LOW + (i & 15)] * row[COUNT_HIGH + (i >> 4)] };
        b.assert_eq(
            row[REMAINING],
            (0..self.kind.weight()).fold(AB::Expr::ZERO, |a, i| a + at_count(i)),
        );
        for g in 0..4 {
            b.assert_eq(
                row[GROUP + g],
                (0..64)
                    .filter(|&i| self.kind.group(i) == Some(g))
                    .fold(AB::Expr::ZERO, |a, i| a + at_count(i)),
            );
        }
        let choose = |i: usize| -> AB::Expr {
            if self.kind == Kind::AlphaPrime39 {
                row[LOW + (i & 15)] * row[HIGH + (i >> 4)]
            } else {
                let index = i / 4;
                let high = (0..4).fold(AB::Expr::ZERO, |a, j| a + row[HIGH + (index >> 4) + 4 * j]);
                row[LOW + (index & 15)] * high * row[GROUP + i % 4]
            }
        };
        b.assert_eq(
            row[READ],
            (0..256).fold(AB::Expr::ZERO, |a, i| a + choose(i) * row[OUTPUT + i]),
        );
        b.assert_eq(
            row[SIGN],
            (0..64).fold(AB::Expr::ZERO, |a, i| a + at_count(i) * row[SIGNS + i]),
        );
        b.assert_bool(row[TAKE]);
        b.assert_eq(
            row[TAKE],
            p[P_DRAW].clone() * row[REMAINING] * (AB::Expr::ONE - row[READ] * row[READ]),
        );
        b.when_first_row().assert_zero(row[COUNT]);
        b.when_transition()
            .assert_eq(next[COUNT], row[COUNT] + row[TAKE]);
        b.when_last_row()
            .assert_eq(row[COUNT], Val::from_usize(self.kind.weight()));
        for i in 0..256 {
            b.when_first_row().assert_zero(row[OUTPUT + i]);
            b.when_transition().assert_eq(
                next[OUTPUT + i],
                row[OUTPUT + i] + choose(i) * row[TAKE] * (AB::Expr::ONE - row[SIGN] * Val::TWO),
            );
        }
        for i in 0..64 {
            b.assert_bool(row[SIGNS + i]);
            b.when_first_row().assert_zero(row[SIGNS + i]);
            let load = if i / 8 < 6 {
                p[P_SIGN + i / 8].clone()
            } else {
                AB::Expr::ZERO
            };
            b.when_transition().assert_eq(
                next[SIGNS + i],
                row[SIGNS + i] + load * (raw[i % 8].clone() - row[SIGNS + i]),
            );
        }
        let byte_hash = p[P_BYTE_HASH].clone();
        let poly_hash = p[P_POLY_HASH].clone();
        let updated: Vec<AB::Expr> = (0..8)
            .map(|i| row[BUFFER + i] + p[P_BUFFER + i].clone() * (row[BYTE] - row[BUFFER + i]))
            .collect();
        for i in 0..8 {
            b.when_first_row().assert_zero(row[BUFFER + i]);
            b.when_transition().assert_eq(
                next[BUFFER + i],
                (AB::Expr::ONE - byte_hash.clone()) * updated[i].clone(),
            );
        }
        let poseidon: &PoseidonCols<AB::Var> = row[POSEIDON..].borrow();
        for i in 0..4 {
            let coeff = (0..64).fold(AB::Expr::ZERO, |a, j| {
                a + p[P_POLY + j].clone() * row[OUTPUT + 4 * j + i]
            });
            b.assert_eq(
                poseidon.inputs[i],
                byte_hash.clone() * row[BYTE_ACC + i] + poly_hash.clone() * row[POLY_ACC + i],
            );
            b.assert_eq(
                poseidon.inputs[4 + i],
                byte_hash.clone()
                    * (updated[2 * i].clone() + updated[2 * i + 1].clone() * Val::from_u16(256))
                    + poly_hash.clone() * coeff,
            );
            let out = poseidon.ending_full_rounds[3].post[i];
            b.when_first_row()
                .assert_eq(row[BYTE_ACC + i], self.byte_initial()[i]);
            b.when_first_row()
                .assert_eq(row[POLY_ACC + i], Self::poly_initial()[i]);
            b.when_transition().assert_eq(
                next[BYTE_ACC + i],
                row[BYTE_ACC + i] + byte_hash.clone() * (out - row[BYTE_ACC + i]),
            );
            b.when_transition().assert_eq(
                next[POLY_ACC + i],
                row[POLY_ACC + i] + poly_hash.clone() * (out - row[POLY_ACC + i]),
            );
            b.when_last_row().assert_eq(row[BYTE_ACC + i], public[i]);
            b.when_last_row().assert_eq(out, public[4 + i]);
        }
    }
}

#[cfg(feature="opencl")]
mod gpu;
