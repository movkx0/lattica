use super::*;
impl<AB: AirBuilder<F = Val>> Air<AB> for MulAir {
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
        let hash = meta(IS_A) + meta(IS_B) + meta(IS_O);
        for slot in 0..5 {
            canonical_range(b, row, self.range(slot), self.bits(), self.modulus);
        }
        let mut read_a = AB::Expr::ZERO;
        let mut read_b = AB::Expr::ZERO;
        let mut read_out = AB::Expr::ZERO;
        for lane in 0..4 {
            b.when_transition()
                .when(meta(LINK_INPUT))
                .assert_eq(next[LEFT + lane], row[LEFT + lane]);
            b.when_transition()
                .when(meta(LINK_INPUT))
                .assert_eq(next[RIGHT + lane], row[RIGHT + lane]);
            b.when_first_row().assert_zero(row[STATE + lane]);
            let updated = row[STATE + lane]
                + meta(SELECT_O + lane) * (row[self.range(4)] - row[STATE + lane]);
            b.when_transition().assert_eq(
                next[STATE + lane],
                (AB::Expr::ONE - meta(RESET_STATE)) * updated,
            );
            read_a += meta(SELECT_A + lane) * row[LEFT + lane];
            read_b += meta(SELECT_B + lane) * row[RIGHT + lane];
            read_out += meta(SELECT_O + lane) * row[STATE + lane];
            b.when(hash.clone()).assert_eq(
                row[self.range(lane)],
                meta(IS_A) * row[LEFT + lane]
                    + meta(IS_B) * row[RIGHT + lane]
                    + meta(IS_O) * row[STATE + lane],
            );
        }
        b.assert_eq(row[READS], read_a);
        b.assert_eq(row[READS + 1], read_b);
        b.assert_eq(row[READS + 2], read_out);
        b.when(hash.clone()).assert_zero(row[self.range(4)]);
        let q = Val::from_u64(self.modulus);
        b.when(meta(IS_MUL)).assert_eq(
            row[READS] * row[READS + 1],
            row[self.range(1)] * q + row[self.range(0)],
        );
        b.when(meta(IS_MUL)).assert_eq(
            row[self.range(0)] * meta(FACTOR),
            row[self.range(3)] * q + row[self.range(2)],
        );
        b.assert_bool(row[self.carry()]);
        b.when(meta(IS_MUL)).assert_eq(
            row[READS + 2]
                + row[self.range(2)]
                + meta(NEGATIVE) * (AB::Expr::from(q) - row[self.range(2)] * Val::TWO),
            row[self.carry()] * q + row[self.range(4)],
        );
        let poseidon: &PoseidonCols<AB::Var> = row[self.poseidon()..].borrow();
        let initial = self.initial();
        for lane in 0..4 {
            let selected = (0..3).fold(AB::Expr::ZERO, |sum, which| {
                sum + meta(which) * row[self.acc() + 4 * which + lane]
            });
            b.assert_eq(poseidon.inputs[lane], selected);
            b.assert_eq(
                poseidon.inputs[4 + lane],
                hash.clone() * row[self.range(lane)],
            );
            let output = poseidon.ending_full_rounds[3].post[lane];
            for which in 0..3 {
                let current = row[self.acc() + 4 * which + lane];
                let updated = current + meta(which) * (output - current);
                let next_acc = updated.clone()
                    + meta(RESET_ACC) * (AB::Expr::from(initial[lane]) - updated.clone());
                b.when_transition()
                    .assert_eq(next[self.acc() + 4 * which + lane], next_acc);
                b.when_first_row().assert_eq(current, initial[lane]);
                for polynomial in 0..self.count {
                    b.when(meta(ENDS + polynomial))
                        .assert_eq(updated.clone(), public[12 * polynomial + 4 * which + lane]);
                }
            }
        }
    }
}
