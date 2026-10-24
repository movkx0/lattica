use super::*;
impl<AB: AirBuilder<F = Val>> Air<AB> for PermutationAir {
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
        let active = meta(HASH_INPUT) + meta(HASH_OUTPUT);
        for index in 0..D {
            b.when_transition()
                .assert_eq(next[BANK + index], row[BANK + index]);
        }
        let poseidon: &PoseidonCols<AB::Var> = row[self.poseidon()..].borrow();
        for lane in 0..4 {
            let read = (0..64).fold(AB::Expr::ZERO, |sum, block| {
                sum + meta(SELECT_INPUT + block) * row[BANK + 4 * block + lane]
                    + meta(SELECT_OUTPUT + block) * row[BANK + self.source_index(4 * block + lane)]
            });
            b.assert_eq(row[READ + lane], read);
            canonical_range(b, row, self.range(lane), self.bits(), self.modulus());
            b.assert_bool(row[SIGN + lane]);
            let value = if self.kind == PermutationKind::AutomorphismQ {
                b.assert_zero(row[SIGN + lane]);
                canonical_range(b, row, self.quotient(lane), self.bits(), Q);
                b.when(meta(HASH_INPUT))
                    .assert_eq(row[self.range(lane)], row[READ + lane]);
                b.when(meta(HASH_OUTPUT)).assert_eq(
                    row[READ + lane] * meta(FACTOR + lane),
                    row[self.quotient(lane)] * Val::from_u64(Q) + row[self.range(lane)],
                );
                b.when(AB::Expr::ONE - meta(HASH_OUTPUT))
                    .assert_zero(row[self.quotient(lane)]);
                row[self.range(lane)].into()
            } else {
                let signed = (AB::Expr::ONE - row[SIGN + lane] * Val::TWO) * row[self.range(lane)];
                b.when(meta(HASH_INPUT))
                    .assert_eq(signed.clone(), row[READ + lane]);
                b.when(meta(HASH_OUTPUT))
                    .assert_eq(signed.clone(), row[READ + lane] * meta(FACTOR + lane));
                signed
            };
            b.when(AB::Expr::ONE - active.clone())
                .assert_zero(row[self.range(lane)]);
            b.assert_eq(
                poseidon.inputs[lane],
                meta(HASH_INPUT) * row[ACC + lane] + meta(HASH_OUTPUT) * row[ACC + 4 + lane],
            );
            b.assert_eq(poseidon.inputs[4 + lane], value);
            let hashed = poseidon.ending_full_rounds[3].post[lane];
            for which in 0..2 {
                let current = row[ACC + 4 * which + lane];
                let updated = current + meta(HASH_INPUT + which) * (hashed - current);
                b.when_first_row().assert_eq(current, self.initial()[lane]);
                b.when_transition()
                    .assert_eq(next[ACC + 4 * which + lane], updated.clone());
                b.when_last_row()
                    .assert_eq(updated, public[4 * which + lane]);
            }
        }
    }
}
