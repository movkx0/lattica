use super::*;

fn selector<AB: AirBuilder<F = Val>>(row: &[AB::Var], which: usize, index: usize) -> AB::Expr {
    row[ADDRESS_PREFIX + 32 * which + index % 16]
        * row[ADDRESS_PREFIX + 32 * which + 16 + index / 16]
}
impl<AB: AirBuilder<F = Val>> Air<AB> for GBoundAir {
    fn eval(&self, b: &mut AB) {
        PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
            parent: b,
            start: POSEIDON,
            width: POSEIDON_WIDTH,
        });
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values().to_vec();
        let periodic = b.periodic_values().to_vec();
        let meta = |index: usize| -> AB::Expr { periodic[index].into() };
        let phase = |index: usize| -> AB::Expr { row[PHASE + index].into() };
        let last = meta(BLOCK_END);
        for i in 0..PHASES {
            b.assert_bool(row[PHASE + i]);
            b.when_first_row()
                .assert_eq(row[PHASE + i], Val::from_bool(i == 0));
            let previous = if i == 0 { AB::Expr::ZERO } else { phase(i - 1) };
            b.when_transition().assert_eq(
                next[PHASE + i],
                phase(i) + last.clone() * (previous - phase(i)),
            );
        }
        b.when_last_row().assert_one(row[PHASE + PHASES - 1]);
        let hash_f = phase(0) * meta(FIRST_HALF);
        let hash_x = phase(0) * (AB::Expr::ONE - meta(FIRST_HALF));
        let check_g = phase(23) * meta(FIRST_HALF);
        let hash_or_check = phase(0) + check_g.clone();
        let twist = phase(1) + phase(2);
        let multiply = phase(11) + phase(12);
        let untwist = phase(21) + phase(22);
        let forward = (3..11).fold(AB::Expr::ZERO, |sum, i| sum + phase(i));
        let inverse = (13..21).fold(AB::Expr::ZERO, |sum, i| sum + phase(i));
        let mut address_a = hash_or_check.clone() * meta(HASH_INDEX)
            + (twist.clone() + multiply.clone() + untwist.clone()) * meta(ROW_INDEX)
            + (phase(2) + phase(12) + phase(22)) * Val::from_u32(128);
        let mut address_b = AB::Expr::ZERO;
        let mut factor_forward = AB::Expr::ZERO;
        let mut factor_inverse = AB::Expr::ZERO;
        for stage in 0..8 {
            address_a += (phase(3 + stage) + phase(20 - stage)) * meta(ADDRESS_A + stage);
            address_b += (phase(3 + stage) + phase(20 - stage)) * meta(ADDRESS_B + stage);
            factor_forward += phase(3 + stage) * meta(FORWARD_FACTOR + stage);
            factor_inverse += phase(20 - stage) * meta(INVERSE_FACTOR + stage);
        }
        let psi = Val::two_adic_generator(9);
        let factor_twist = meta(TWIST_FACTOR) * (phase(1) + phase(2) * psi.exp_u64(128));
        let factor_untwist =
            meta(UNTWIST_FACTOR) * (phase(21) + phase(22) * psi.inverse().exp_u64(128));
        for (which, expected) in [address_a, address_b].into_iter().enumerate() {
            let bits: Vec<AB::Expr> = (0..8)
                .map(|i| {
                    b.assert_bool(row[ADDRESS_BITS + 8 * which + i]);
                    row[ADDRESS_BITS + 8 * which + i].into()
                })
                .collect();
            let address = bits
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (i, bit)| {
                    sum + bit.clone() * Val::from_u64(1 << i)
                });
            b.assert_eq(address, expected);
            for nibble in 0..2 {
                for candidate in 0..16 {
                    b.assert_eq(
                        row[ADDRESS_PREFIX + which * 32 + nibble * 16 + candidate],
                        crate::ntt_air::nibble_eq(
                            &bits[4 * nibble..4 * nibble + 4],
                            candidate as u8,
                        ),
                    );
                }
            }
        }
        let mut reads: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
        let mut chunks_left: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
        let mut chunks_right: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
        let a: AB::Expr = row[READS].into();
        let c: AB::Expr = row[READS + 1].into();
        let x: AB::Expr = row[READS + 2].into();
        let y: AB::Expr = row[READS + 3].into();
        let left_a = twist.clone() * (factor_twist.clone() * a.clone() - a.clone())
            + multiply.clone() * (a.clone() * x.clone() - a.clone())
            + untwist.clone() * (factor_untwist.clone() * a.clone() - a.clone())
            + forward.clone() * c.clone()
            + inverse.clone() * factor_inverse.clone() * c.clone();
        let left_b = forward.clone()
            * ((a.clone() - c.clone()) * factor_forward.clone() - c.clone())
            + inverse.clone() * (a.clone() - factor_inverse.clone() * c.clone() - c.clone());
        let right_a = twist.clone() * ((x.clone() - a) * factor_twist.clone() - x.clone())
            + forward.clone() * y.clone();
        let right_b = forward.clone() * ((x - y.clone()) * factor_forward.clone() - y);
        for i in 0..D {
            let select_a = selector::<AB>(row, 0, i);
            let select_b = selector::<AB>(row, 1, i);
            reads[0] += select_a.clone() * row[LEFT + i];
            reads[1] += select_b.clone() * row[LEFT + i];
            reads[2] += select_a.clone() * row[RIGHT + i];
            reads[3] += select_b.clone() * row[RIGHT + i];
            b.when_transition().assert_eq(
                next[LEFT + i],
                row[LEFT + i]
                    + select_a.clone() * left_a.clone()
                    + select_b.clone() * left_b.clone(),
            );
            b.when_transition().assert_eq(
                next[RIGHT + i],
                row[RIGHT + i] + select_a * right_a.clone() + select_b * right_b.clone(),
            );
        }
        for i in 0..4 {
            b.assert_eq(row[READS + i], reads[i].clone());
        }
        for block in 0..64 {
            let select = selector::<AB>(row, 0, 4 * block);
            for i in 0..4 {
                chunks_left[i] += select.clone() * row[LEFT + 4 * block + i];
                chunks_right[i] += select.clone() * row[RIGHT + 4 * block + i];
            }
        }
        let kinds = [
            hash_f.clone(),
            hash_x.clone(),
            check_g.clone(),
            AB::Expr::ONE - hash_or_check,
        ];
        let bounds = [self.f_bound, 1, self.g_bound, 0];
        let offset = hash_f.clone() * Val::from_u32(self.f_bound)
            + hash_x.clone()
            + check_g.clone() * Val::from_u32(self.g_bound);
        let poseidon: &PoseidonCols<AB::Var> = row[POSEIDON..].borrow();
        for slot in 0..4 {
            let range = RANGES + slot * RANGE_WIDTH;
            let bits: Vec<AB::Expr> = (0..RANGE_BITS)
                .map(|i| {
                    b.assert_bool(row[range + 1 + i]);
                    row[range + 1 + i].into()
                })
                .collect();
            let encoded = bits
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (i, bit)| {
                    sum + bit.clone() * Val::from_u64(1 << i)
                });
            b.assert_eq(row[range], encoded);
            let value = (hash_f.clone() + check_g.clone()) * chunks_left[slot].clone()
                + hash_x.clone() * chunks_right[slot].clone();
            b.assert_eq(row[range], value + offset.clone());
            let mut prefix = AB::Expr::ONE;
            for step in 0..6 {
                let shift = 4 * (5 - step);
                let part = &bits[shift..shift + 4];
                let mut equal = AB::Expr::ZERO;
                let mut greater = AB::Expr::ZERO;
                for kind in 0..4 {
                    let digit = (((2 * bounds[kind]) >> shift) & 15) as u8;
                    equal += kinds[kind].clone() * crate::ntt_air::nibble_eq(part, digit);
                    greater += kinds[kind].clone()
                        * ((digit + 1)..16).fold(AB::Expr::ZERO, |sum, d| {
                            sum + crate::ntt_air::nibble_eq(part, d)
                        });
                }
                b.assert_zero(prefix.clone() * greater);
                let current: AB::Expr = row[range + 1 + RANGE_BITS + step].into();
                b.assert_eq(current.clone(), prefix * equal);
                prefix = current;
            }
            b.when_first_row()
                .assert_eq(row[ACC + slot], initial()[slot]);
            b.assert_eq(poseidon.inputs[slot], row[ACC + slot]);
            b.assert_eq(
                poseidon.inputs[4 + slot],
                hash_f.clone() * chunks_left[slot].clone()
                    + hash_x.clone() * chunks_right[slot].clone(),
            );
            let out = poseidon.ending_full_rounds[3].post[slot];
            let f_end = phase(0) * meta(HASH_END);
            let x_end = phase(0) * last.clone();
            b.when(f_end.clone()).assert_eq(out, public[slot]);
            b.when(x_end).assert_eq(out, public[4 + slot]);
            let updated = row[ACC + slot]
                + phase(0) * (out - row[ACC + slot])
                + f_end * (AB::Expr::from(initial()[slot]) - out);
            b.when_transition().assert_eq(next[ACC + slot], updated);
        }
    }
}
