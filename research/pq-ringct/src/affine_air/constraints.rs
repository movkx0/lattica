use super::*;

impl<AB: AirBuilder<F = Val>> Air<AB> for AffineAir {
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
        let q = Val::from_u64(self.modulus);
        let poly_hash = meta(HASH_A) + meta(HASH_B) + meta(HASH_O);
        let bundle_hash = meta(BUNDLE_A) + meta(BUNDLE_B) + meta(BUNDLE_O);
        for lane in 0..4 {
            canonical_range(b, row, self.range(lane), self.bits(), self.modulus);
            b.assert_bool(row[SIGN + lane]);
            b.assert_bool(row[CARRY + lane]);
            for start in [LEFT, RIGHT, SIGN] {
                b.when_transition()
                    .when(meta(LINK))
                    .assert_eq(next[start + lane], row[start + lane]);
                b.when(meta(IDLE)).assert_zero(row[start + lane]);
            }
            let value = row[self.range(lane)];
            match self.kind {
                AffineKind::Add | AffineKind::Sub => {
                    b.assert_zero(row[SIGN + lane]);
                    b.when(meta(HASH_A)).assert_eq(value, row[LEFT + lane]);
                    b.when(meta(HASH_B)).assert_eq(value, row[RIGHT + lane]);
                    b.when(AB::Expr::ONE - poly_hash.clone()).assert_zero(value);
                    let left: AB::Expr = row[LEFT + lane].into();
                    let right: AB::Expr = row[RIGHT + lane].into();
                    if self.kind == AffineKind::Add {
                        b.when(meta(HASH_O))
                            .assert_eq(left + right, value + row[CARRY + lane] * q);
                    } else {
                        b.when(meta(HASH_O))
                            .assert_eq(left + row[CARRY + lane] * q, right + value);
                    }
                }
                AffineKind::SignedToCanonical { bound } => {
                    canonical_range(
                        b,
                        row,
                        self.magnitude(lane),
                        self.magnitude_bits(),
                        u64::from(bound) + 1,
                    );
                    b.assert_zero(row[RIGHT + lane]);
                    b.assert_zero(row[CARRY + lane]);
                    b.when(meta(HASH_A)).assert_eq(
                        row[LEFT + lane],
                        (AB::Expr::ONE - row[SIGN + lane] * Val::TWO) * row[self.magnitude(lane)],
                    );
                    b.when(meta(HASH_O))
                        .assert_eq(value, row[LEFT + lane] + row[SIGN + lane] * q);
                    b.when(AB::Expr::ONE - meta(HASH_O)).assert_zero(value);
                    b.when(AB::Expr::ONE - meta(HASH_A))
                        .assert_zero(row[self.magnitude(lane)]);
                }
            }
        }
        let poseidon: &PoseidonCols<AB::Var> = row[self.poseidon()..].borrow();
        let initial_bundle = self.bundle_initial();
        for lane in 0..4 {
            let state = (0..3).fold(AB::Expr::ZERO, |sum, which| {
                sum + meta(HASH_A + which) * row[ACC + 4 * which + lane]
            }) + bundle_hash.clone() * row[BUNDLE + lane];
            let values = meta(HASH_A) * row[LEFT + lane]
                + meta(HASH_B) * row[RIGHT + lane]
                + meta(HASH_O) * row[self.range(lane)]
                + (0..3).fold(AB::Expr::ZERO, |sum, which| {
                    sum + meta(BUNDLE_A + which) * row[ACC + 4 * which + lane]
                });
            b.assert_eq(poseidon.inputs[lane], state);
            b.assert_eq(poseidon.inputs[4 + lane], values);
            let hashed = poseidon.ending_full_rounds[3].post[lane];
            for which in 0..3 {
                let current = row[ACC + 4 * which + lane];
                let initial = self.initial(which)[lane];
                let updated = current + meta(HASH_A + which) * (hashed - current);
                b.when_first_row().assert_eq(current, initial);
                b.when_transition().assert_eq(
                    next[ACC + 4 * which + lane],
                    updated.clone() + meta(RESET) * (AB::Expr::from(initial) - updated),
                );
            }
            let updated = row[BUNDLE + lane] + bundle_hash.clone() * (hashed - row[BUNDLE + lane]);
            b.when_first_row()
                .assert_eq(row[BUNDLE + lane], initial_bundle[lane]);
            b.when_transition()
                .assert_eq(next[BUNDLE + lane], updated.clone());
            b.when_last_row().assert_eq(updated, public[lane]);
        }
    }
}
