use super::*;
impl<AB: AirBuilder<F = Val>> Air<AB> for TranscriptAir {
    fn eval(&self, b: &mut AB) {
        for start in [
            self.source_poseidon(),
            self.byte_poseidon(),
            self.bundle_poseidon(),
        ] {
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
        let p = |i: usize| -> AB::Expr { periodic[i].into() };
        let class = |i: usize| -> AB::Expr { row[self.class() + i].into() };
        b.when_first_row().assert_zero(row[COUNTER]);
        b.when_last_row().assert_eq(
            row[COUNTER],
            Val::from_usize(self.height / ROWS_PER_PART - 1),
        );
        b.when_transition()
            .assert_eq(next[COUNTER], row[COUNTER] + p(P_END));
        for (i, event) in self.events.iter().enumerate() {
            let difference = row[COUNTER] - Val::from_usize(event.at);
            b.assert_zero(difference.clone() * row[EVENTS + i]);
            b.assert_eq(
                difference * row[self.inverse() + i],
                AB::Expr::ONE - row[EVENTS + i],
            );
            b.assert_zero(row[EVENTS + i] * row[self.inverse() + i]);
        }
        for kind in 0..4 {
            b.assert_bool(row[self.class() + kind]);
            b.when_first_row().assert_eq(
                row[self.class() + kind],
                Val::from_bool(kind == self.parts[0].index()),
            );
            let change = self
                .events
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (i, event)| {
                    sum + row[EVENTS + i]
                        * (Val::from_bool(event.to == kind) - Val::from_bool(event.from == kind))
                });
            b.when_transition()
                .assert_eq(next[self.class() + kind], class(kind) + p(P_END) * change);
        }
        let raw_bytes = class(0) * p(P_BYTES);
        let polynomial = class(1) + class(2);
        let active = raw_bytes.clone() + polynomial.clone();
        let source_hash = raw_bytes.clone() + polynomial.clone() * (AB::Expr::ONE - p(P_EVEN));
        let kinds = [
            raw_bytes.clone(),
            class(1),
            class(2),
            AB::Expr::ONE - active.clone(),
        ];
        let maxima = [u32::MAX as u64, Q - 1, QHAT - 1, 0];
        let mut limbs: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
        for slot in 0..2 {
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
            for half in 0..2 {
                limbs[2 * slot + half] = (0..16).fold(AB::Expr::ZERO, |sum, i| {
                    sum + bits[16 * half + i].clone() * Val::from_u64(1 << i)
                });
            }
            let mut prefix = AB::Expr::ONE;
            for step in 0..8 {
                let shift = 4 * (7 - step);
                let part = &bits[shift..shift + 4];
                let mut equal = AB::Expr::ZERO;
                let mut greater = AB::Expr::ZERO;
                for kind in 0..4 {
                    let digit = ((maxima[kind] >> shift) & 15) as u8;
                    equal += kinds[kind].clone() * crate::ntt_air::nibble_eq(part, digit);
                    greater += kinds[kind].clone()
                        * ((digit + 1)..16).fold(AB::Expr::ZERO, |sum, d| {
                            sum + crate::ntt_air::nibble_eq(part, d)
                        });
                }
                b.assert_zero(prefix.clone() * greater);
                let current: AB::Expr = row[PREFIX + 8 * slot + step].into();
                b.assert_eq(current.clone(), prefix * equal);
                prefix = current;
            }
            b.when_first_row().assert_zero(row[BUFFER + slot]);
            b.when_transition()
                .assert_eq(next[BUFFER + slot], p(P_EVEN) * row[WORD + slot]);
        }
        let source: &PoseidonCols<AB::Var> =
            row[self.source_poseidon()..self.source_poseidon() + POSEIDON_WIDTH].borrow();
        let bytes: &PoseidonCols<AB::Var> =
            row[self.byte_poseidon()..self.byte_poseidon() + POSEIDON_WIDTH].borrow();
        let bundle: &PoseidonCols<AB::Var> = row[self.bundle_poseidon()..].borrow();
        let descriptor = [
            class(0) + class(1) * Val::TWO + class(2) * Val::from_u32(3),
            class(0) * Val::from_u32(32) + polynomial.clone() * Val::from_u32(1024),
            row[COUNTER].into(),
            AB::Expr::ZERO,
        ];
        let part_active = class(0) + polynomial.clone();
        let begin = p(P_START) * part_active.clone();
        let end = p(P_END) * part_active;
        for i in 0..4 {
            let initial = class(0) * PartKind::Bytes32.initial()[i]
                + class(1) * PartKind::PolynomialQ.initial()[i]
                + class(2) * PartKind::PolynomialQhat.initial()[i];
            b.when_first_row()
                .assert_eq(row[self.source_acc() + i], self.parts[0].initial()[i]);
            let base =
                row[self.source_acc() + i] + p(P_START) * (initial - row[self.source_acc() + i]);
            b.assert_eq(source.inputs[i], base.clone());
            let coefficient: AB::Expr = if i < 2 {
                row[BUFFER + i].into()
            } else {
                row[WORD + i - 2].into()
            };
            b.assert_eq(
                source.inputs[4 + i],
                raw_bytes.clone() * limbs[i].clone()
                    + polynomial.clone() * (AB::Expr::ONE - p(P_EVEN)) * coefficient,
            );
            let completed =
                base.clone() + source_hash.clone() * (source.ending_full_rounds[3].post[i] - base);
            b.when_transition()
                .assert_eq(next[self.source_acc() + i], completed.clone());
            b.when_first_row()
                .assert_eq(row[self.byte_acc() + i], self.byte_initial()[i]);
            b.assert_eq(bytes.inputs[i], row[self.byte_acc() + i]);
            b.assert_eq(bytes.inputs[4 + i], active.clone() * limbs[i].clone());
            let updated_bytes = row[self.byte_acc() + i]
                + active.clone() * (bytes.ending_full_rounds[3].post[i] - row[self.byte_acc() + i]);
            b.when_transition()
                .assert_eq(next[self.byte_acc() + i], updated_bytes.clone());
            b.when_last_row().assert_eq(updated_bytes, public[4 + i]);
            b.when_first_row()
                .assert_eq(row[self.bundle_acc() + i], self.bundle_initial()[i]);
            b.assert_eq(bundle.inputs[i], row[self.bundle_acc() + i]);
            b.assert_eq(
                bundle.inputs[4 + i],
                begin.clone() * descriptor[i].clone() + end.clone() * completed,
            );
            let updated_bundle = row[self.bundle_acc() + i]
                + (begin.clone() + end.clone())
                    * (bundle.ending_full_rounds[3].post[i] - row[self.bundle_acc() + i]);
            b.when_transition()
                .assert_eq(next[self.bundle_acc() + i], updated_bundle.clone());
            b.when_last_row().assert_eq(updated_bundle, public[i]);
        }
    }
}
