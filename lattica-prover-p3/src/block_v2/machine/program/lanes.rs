//! Reuse compiler-proven operand facts within one emission. No witness values
//! or wire facts cross builders, and ordinary folding, CSE and admission apply.
use super::*;

impl ScopedProgramBuilder<'_> {
    pub(crate) fn scale_lanes<const N: usize>(&mut self, a: [Wire; N], b: Wire) -> [Wire; N] {
        let bv = self.known.get(&b);
        a.map(|a| self.mul_known(a, b, self.known.get(&a), bv))
    }

    pub(crate) fn select_lanes<const N: usize>(
        &mut self,
        bit: Wire,
        a: [Wire; N],
        b: [Wire; N],
    ) -> [Wire; N] {
        let known = self.known.get(&bit);
        core::array::from_fn(|i| self.select_known(bit, a[i], b[i], known))
    }

    pub(crate) fn add_constant(&mut self, a: Wire, value: Val) -> Wire {
        let b = self.constant(value);
        self.add_known(a, b, self.known.get(&a), Some(value))
    }

    pub(crate) fn sub_lanes<const N: usize>(&mut self, a: [Wire; N], b: [Wire; N]) -> [Wire; N] {
        let minus_one = self.constant(Val::NEG_ONE);
        core::array::from_fn(|i| {
            let negative =
                self.mul_known(b[i], minus_one, self.known.get(&b[i]), Some(Val::NEG_ONE));
            self.add(a[i], negative)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_operand_facts_preserve_programs_and_boolean_checks() {
        for constant in [
            None,
            Some(Val::ZERO),
            Some(Val::ONE),
            Some(Val::from_u64(7)),
        ] {
            let build = |optimized| {
                let mut b = ProgramBuilder::new(0).unwrap();
                let a = core::array::from_fn::<_, 6, _>(|_| b.input());
                let shared = match constant {
                    Some(v) => b.constant(v),
                    None => b.input(),
                };
                let scaled = if optimized {
                    b.scale_lanes(a, shared)
                } else {
                    a.map(|v| b.mul(v, shared))
                };
                let selected = if optimized {
                    b.select_lanes(shared, a, scaled)
                } else {
                    core::array::from_fn(|i| b.select(shared, a[i], scaled[i]))
                };
                for w in selected {
                    if optimized {
                        b.add_constant(w, Val::from_u64(19));
                    } else {
                        let c = b.constant(Val::from_u64(19));
                        b.add(w, c);
                    }
                }
                if optimized {
                    b.sub_lanes(a, scaled);
                } else {
                    for i in 0..6 {
                        b.sub(a[i], scaled[i]);
                    }
                }
                b.finish(None).unwrap()
            };
            let reference = build(false);
            let actual = build(true);
            assert_eq!(actual, reference);
            assert_eq!(actual.manifest_fields(), reference.manifest_fields());
            for bit in [0, 1, 2] {
                let mut witness: Vec<_> = (2..8).map(Val::from_u64).collect();
                if constant.is_none() {
                    witness.push(Val::from_u64(bit));
                }
                assert_eq!(
                    actual.evaluate(&[], &witness),
                    reference.evaluate(&[], &witness)
                );
                if constant.is_none() {
                    assert_eq!(actual.evaluate(&[], &witness).is_ok(), bit < 2);
                }
            }
        }
    }

    #[test]
    fn base_coefficient_horner_preserves_exact_program_and_evaluation() {
        let build = |optimized| {
            let mut b = ProgramBuilder::new(0).unwrap();
            let point = core::array::from_fn(|_| b.input());
            let mut value = b.ext_constant([Val::ZERO; 3]);
            for coefficient in [7, 0, 1, 0, 19, 3].map(Val::from_u64) {
                value = b.ext_mul(value, point);
                if optimized {
                    value[0] = b.add_constant(value[0], coefficient);
                } else {
                    let term = b.ext_constant([coefficient, Val::ZERO, Val::ZERO]);
                    value = b.ext_add(value, term);
                }
            }
            b.finish(None).unwrap()
        };
        let reference = build(false);
        let actual = build(true);
        assert_eq!(actual, reference);
        assert_eq!(actual.manifest_fields(), reference.manifest_fields());
        for values in [[0, 0, 0], [1, 0, 0], [7, 11, 13]] {
            let witness = values.map(Val::from_u64);
            assert_eq!(
                actual.evaluate(&[], &witness).unwrap(),
                reference.evaluate(&[], &witness).unwrap()
            );
        }
    }
}

#[cfg(test)]
impl ScopedProgramBuilder<'_> {
    fn reference_cubic_mul(&mut self, a: [Wire; 3], b: [Wire; 3]) -> [Wire; 3] {
        if self.memory.failed {
            return [Wire(0); 3];
        }
        // Preserve cheaper scalar multiplication when either operand is in the base field.
        if self.known.get(&a[1]) == Some(Val::ZERO) && self.known.get(&a[2]) == Some(Val::ZERO) {
            return b.map(|w| self.mul(a[0], w));
        }
        if self.known.get(&b[1]) == Some(Val::ZERO) && self.known.get(&b[2]) == Some(Val::ZERO) {
            return a.map(|w| self.mul(b[0], w));
        }
        if let (Some(av), Some(bv)) = (self.known_cubic(a), self.known_cubic(b)) {
            return self
                .folding
                .fold(FoldOperation::CubicMul, av, bv)
                .unwrap()
                .map(|v| self.constant(v));
        }
        let key = (0, a.min(b), a.max(b));
        let vacant = match self.cubic_expressions.probe(key) {
            Ok(value) => return value,
            Err(vacant) => vacant,
        };
        let out = core::array::from_fn(|_| self.allocate());
        self.push_operation(Op::CubicMul { a, b, out });
        self.cubic_expressions
            .insert_vacant(vacant, out, &mut self.memory);
        out
    }
}

#[cfg(test)]
#[test]
fn cubic_facts_preserve_folding_scalar_fallback_and_interning() {
    for mask in 0u32..64 {
        let build = |fast| {
            let mut b = ProgramBuilder::new(0).unwrap();
            let wires: [Wire; 6] = core::array::from_fn(|i| {
                if mask & (1 << i) == 0 {
                    b.input()
                } else {
                    b.constant([Val::ONE, Val::ZERO, Val::ZERO][i % 3])
                }
            });
            let a = wires[..3].try_into().unwrap();
            let c = wires[3..].try_into().unwrap();
            for (a, c) in [(a, c), (c, a), (a, a), (a, c)] {
                if fast {
                    b.cubic_mul(a, c);
                } else {
                    b.reference_cubic_mul(a, c);
                }
            }
            b.finish(None).unwrap()
        };
        let reference = build(false);
        let actual = build(true);
        assert_eq!(actual, reference);
        assert_eq!(actual.manifest_fields(), reference.manifest_fields());
        let witness = vec![Val::from_u64(7); (6 - mask.count_ones()) as usize];
        assert_eq!(
            actual.evaluate(&[], &witness),
            reference.evaluate(&[], &witness)
        );
    }
}
