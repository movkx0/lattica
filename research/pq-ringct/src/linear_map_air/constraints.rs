use super::*;
impl<AB: AirBuilder<F = Val>> Air<AB> for LinearMapAir {
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
        let output_phase = meta(self.inputs());
        let active = (0..=self.inputs()).fold(AB::Expr::ZERO, |sum, i| sum + meta(i));
        let offset = self
            .descriptor
            .bounds
            .iter()
            .enumerate()
            .fold(AB::Expr::ZERO, |sum, (i, bound)| {
                sum + meta(self.bound_selector(i)) * Val::from_u32(*bound)
            });
        for index in 0..4 * self.inputs() {
            b.when_transition()
                .when(meta(self.link()))
                .assert_eq(next[index], row[index]);
        }
        let poseidon: &PoseidonCols<AB::Var> = row[self.poseidon()..].borrow();
        for lane in 0..4 {
            let range = self.range(lane);
            match self.descriptor.output {
                PolynomialKind::Canonical { modulus } => {
                    canonical_range(b, row, range, self.bits(), modulus);
                    canonical_range(
                        b,
                        row,
                        self.quotient(lane),
                        self.quotient_bits(),
                        2 * self.descriptor.quotient_bound + 1,
                    );
                    b.when(AB::Expr::ONE - output_phase.clone())
                        .assert_zero(row[self.quotient(lane)]);
                }
                PolynomialKind::Signed { .. } => {
                    let bits: Vec<AB::Expr> = (0..self.bits())
                        .map(|bit| {
                            b.assert_bool(row[range + 1 + bit]);
                            row[range + 1 + bit].into()
                        })
                        .collect();
                    let packed = bits
                        .iter()
                        .enumerate()
                        .fold(AB::Expr::ZERO, |sum, (bit, value)| {
                            sum + value.clone() * Val::from_u64(1 << bit)
                        });
                    b.assert_eq(row[range], packed);
                    let mut prefix = AB::Expr::ONE;
                    for step in 0..self.bits() / 4 {
                        let shift = 4 * (self.bits() / 4 - 1 - step);
                        let part = &bits[shift..shift + 4];
                        let mut equal = AB::Expr::ZERO;
                        let mut greater = AB::Expr::ZERO;
                        for (position, bound) in self.descriptor.bounds.iter().enumerate() {
                            let digit = (((u64::from(*bound) * 2) >> shift) & 15) as u8;
                            equal += meta(self.bound_selector(position))
                                * crate::ntt_air::nibble_eq(part, digit);
                            greater += meta(self.bound_selector(position))
                                * ((digit + 1)..16).fold(AB::Expr::ZERO, |sum, candidate| {
                                    sum + crate::ntt_air::nibble_eq(part, candidate)
                                });
                        }
                        b.assert_zero(prefix.clone() * greater);
                        let current: AB::Expr = row[range + 1 + self.bits() + step].into();
                        b.assert_eq(current.clone(), prefix * equal);
                        prefix = current;
                    }
                }
            }
            let input =
                (0..self.inputs()).fold(AB::Expr::ZERO, |sum, i| sum + meta(i) * row[4 * i + lane]);
            let output_value = row[range] - offset.clone();
            b.when(AB::Expr::ONE - output_phase.clone())
                .assert_eq(row[range], input.clone() + offset.clone());
            let sum = (0..self.inputs()).fold(meta(self.constant(lane)), |sum, i| {
                sum + meta(self.coefficient(i, lane)) * row[4 * i + lane]
            });
            match self.descriptor.output {
                PolynomialKind::Canonical { modulus } => {
                    b.when(output_phase.clone()).assert_eq(
                        sum + Val::from_u64(modulus * self.descriptor.quotient_bound),
                        output_value.clone() + row[self.quotient(lane)] * Val::from_u64(modulus),
                    );
                }
                PolynomialKind::Signed { .. } => b
                    .when(output_phase.clone())
                    .assert_eq(sum, output_value.clone()),
            }
            let state = (0..=self.inputs()).fold(AB::Expr::ZERO, |sum, i| {
                sum + meta(i) * row[self.acc() + 4 * i + lane]
            });
            b.assert_eq(poseidon.inputs[lane], state);
            b.assert_eq(
                poseidon.inputs[4 + lane],
                input + output_phase.clone() * output_value,
            );
            b.when(AB::Expr::ONE - active.clone())
                .assert_zero(row[range]);
            let hashed = poseidon.ending_full_rounds[3].post[lane];
            for which in 0..=self.inputs() {
                let current = row[self.acc() + 4 * which + lane];
                let updated = current + meta(which) * (hashed - current);
                b.when_first_row()
                    .assert_eq(current, self.initial(which)[lane]);
                b.when_transition()
                    .assert_eq(next[self.acc() + 4 * which + lane], updated.clone());
                b.when_last_row()
                    .assert_eq(updated, public[4 * which + lane]);
            }
        }
    }
}
