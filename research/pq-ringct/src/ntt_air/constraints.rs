use super::*;

fn packed<AB: AirBuilder>(row: &[AB::Var], start: usize, count: usize) -> AB::Expr {
    (0..count).fold(AB::Expr::ZERO, |sum, bit| {
        sum + row[start + bit] * AB::F::from_u64(1 << bit)
    })
}
fn selector<AB: AirBuilder>(row: &[AB::Var], which: usize, index: usize) -> AB::Expr {
    row[PREFIX + which * 32 + index % 16] * row[PREFIX + which * 32 + 16 + index / 16]
}

/// Constrain a canonical residue using Boolean bits and high-nibble equality prefixes.
/// Layout: value, `bits` Boolean digits, then `bits / 4` prefix columns.
pub(crate) fn canonical_range<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    start: usize,
    bits: usize,
    modulus: u64,
) {
    assert!(bits > 0 && bits <= 32 && bits % 4 == 0);
    assert!(modulus > 0 && modulus <= (1_u64 << bits));
    let digits: Vec<AB::Expr> = (0..bits)
        .map(|bit| {
            b.assert_bool(row[start + 1 + bit]);
            row[start + 1 + bit].into()
        })
        .collect();
    b.assert_eq(row[start], packed::<AB>(row, start + 1, bits));
    let nibbles = bits / 4;
    let mut prefix = AB::Expr::ONE;
    for step in 0..nibbles {
        let nibble = nibbles - 1 - step;
        let bound = (((modulus - 1) >> (nibble * 4)) & 15) as u8;
        let part = &digits[nibble * 4..nibble * 4 + 4];
        let equal = nibble_eq(part, bound);
        let greater =
            ((bound + 1)..16).fold(AB::Expr::ZERO, |sum, value| sum + nibble_eq(part, value));
        b.assert_zero(prefix.clone() * greater);
        let current: AB::Expr = row[start + 1 + bits + step].into();
        b.assert_eq(current.clone(), prefix * equal);
        prefix = current;
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for NttAir {
    fn eval(&self, b: &mut AB) {
        PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
            parent: b,
            start: self.poseidon(),
            width: POSEIDON_WIDTH,
        });
        let window = b.main();
        let row = window.current_slice();
        let next = window.next_slice();
        let periodic = b.periodic_values().to_vec();
        let meta = |index: usize| -> AB::Expr { periodic[index].into() };
        let public = b.public_values().to_vec();
        for bit in 0..16 {
            b.assert_bool(row[INDEX_BITS + bit]);
        }
        for (which, column) in [(0, ADDRESS_A), (1, ADDRESS_B)] {
            b.assert_eq(packed::<AB>(row, INDEX_BITS + 8 * which, 8), meta(column));
        }
        for nibble in 0..4 {
            let bits: Vec<AB::Expr> = (0..4)
                .map(|bit| row[INDEX_BITS + nibble * 4 + bit].into())
                .collect();
            for candidate in 0..16 {
                b.assert_eq(
                    row[PREFIX + nibble * 16 + candidate],
                    nibble_eq(&bits, candidate as u8),
                );
            }
        }
        for slot in 0..6 {
            canonical_range(b, row, self.range(slot), self.bits(), self.modulus);
        }
        let mut a = AB::Expr::ZERO;
        let mut c = AB::Expr::ZERO;
        let mut hash_reads: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
        for i in 0..D {
            let select_a = selector::<AB>(row, 0, i);
            let select_b = selector::<AB>(row, 1, i);
            a += select_a.clone() * row[STATE + i];
            c += select_b.clone() * row[STATE + i];
            let updated: AB::Expr = row[STATE + i]
                + meta(IS_NTT)
                    * (select_a * (row[self.range(4)] - row[STATE + i])
                        + select_b * (row[self.range(5)] - row[STATE + i]));
            b.when_transition()
                .when(meta(LINK_STATE))
                .assert_eq(next[STATE + i], updated);
        }
        for block in 0..64 {
            let select = selector::<AB>(row, 0, block * 4);
            for i in 0..4 {
                hash_reads[i] += select.clone() * row[STATE + block * 4 + i];
            }
        }
        for i in 0..4 {
            let ntt = match i {
                0 => a.clone(),
                1 => c.clone(),
                _ => AB::Expr::ZERO,
            };
            b.assert_eq(
                row[READS + i],
                meta(IS_NTT) * ntt + meta(IS_HASH) * hash_reads[i].clone(),
            );
            b.when(meta(IS_HASH))
                .assert_eq(row[self.range(i)], row[READS + i]);
        }
        for slot in 4..6 {
            b.when(meta(IS_HASH)).assert_zero(row[self.range(slot)]);
        }
        let modulus = Val::from_u64(self.modulus);
        b.when(meta(IS_NTT)).assert_eq(
            row[READS] * meta(FACTOR_U),
            row[self.range(2)] * modulus + row[self.range(0)],
        );
        b.when(meta(IS_NTT)).assert_eq(
            row[READS + 1] * meta(FACTOR_V),
            row[self.range(3)] * modulus + row[self.range(1)],
        );
        b.assert_bool(row[self.carries()]);
        b.assert_bool(row[self.carries() + 1]);
        b.when(meta(IS_NTT)).assert_eq(
            row[self.range(0)] + row[self.range(1)],
            row[self.carries()] * modulus + row[self.range(4)],
        );
        b.when(meta(IS_NTT)).assert_eq(
            row[self.range(0)] + modulus - row[self.range(1)],
            row[self.carries() + 1] * modulus + row[self.range(5)],
        );
        let poseidon: &PoseidonCols<AB::Var> = row[self.poseidon()..].borrow();
        for lane in 0..4 {
            b.assert_eq(poseidon.inputs[lane], row[self.acc() + lane]);
            b.assert_eq(poseidon.inputs[4 + lane], meta(IS_HASH) * row[READS + lane]);
            let initial = match lane {
                0 => Val::from_u64(INPUT_DOMAIN),
                1 => modulus,
                2 => Val::from_usize(D),
                _ => Val::ZERO,
            };
            let output_initial = if lane == 0 {
                Val::from_u64(OUTPUT_DOMAIN)
            } else {
                initial
            };
            let updated = poseidon.ending_full_rounds[3].post[lane];
            let next_acc = row[self.acc() + lane]
                + meta(IS_HASH) * (updated - row[self.acc() + lane])
                + meta(RESET_OUTPUT) * (AB::Expr::from(output_initial) - updated)
                + meta(RESET_INPUT) * (AB::Expr::from(initial) - updated);
            b.when_transition()
                .assert_eq(next[self.acc() + lane], next_acc);
            b.when_first_row()
                .assert_eq(row[self.acc() + lane], initial);
            for polynomial in 0..self.count {
                b.when(meta(ENDS + polynomial))
                    .assert_eq(updated, public[8 * polynomial + lane]);
                b.when(meta(ENDS + self.count + polynomial))
                    .assert_eq(updated, public[8 * polynomial + 4 + lane]);
            }
        }
    }
}
