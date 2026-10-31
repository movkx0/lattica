// Derived from the retained single-permutation lane AIR. The deliberate
// differences are the exact permutation counter and inter-permutation RC reset.
use super::*;

fn xor<E: PrimeCharacteristicRing>(a: E, b: E) -> E {
    a.clone() + b.clone() - a * b * E::TWO
}

impl<AB: AirBuilder<F = Val>> Air<AB> for BatchShakeAir {
    fn eval(&self, b: &mut AB) {
        PoseidonAir::new(round_constants()).eval(&mut SubBuilder {
            parent: b,
            start: POSEIDON,
            width: POSEIDON_WIDTH,
        });
        let window = b.main();
        let row = window.current_slice();
        let next = window.next_slice();
        let public = b.public_values().to_vec();
        let p: Vec<AB::Expr> = b.periodic_values().iter().map(|v| (*v).into()).collect();
        let v = |i: usize| -> AB::Expr { row[i].into() };
        let bit = |slot: usize, z: usize| v(BITS + slot * 64 + z);
        let pack = |slot: usize, limb: usize| -> AB::Expr {
            (0..16)
                .map(|z| bit(slot, limb * 16 + z) * Val::from_u64(1 << z))
                .sum()
        };
        let select = |bank: usize, limb: usize| -> AB::Expr {
            (0..25)
                .map(|i| p[SX + i % 5].clone() * p[SY + i / 5].clone() * v(bank + i * 4 + limb))
                .sum()
        };
        let select_c = |limb: usize, dx: usize| -> AB::Expr {
            (0..5)
                .map(|x| p[SX + x].clone() * v(SCRATCH + ((x + dx) % 5) * 4 + limb))
                .sum()
        };
        let select_neighbor = |limb: usize, dx: usize| -> AB::Expr {
            (0..25)
                .map(|i| {
                    p[SX + i % 5].clone()
                        * p[SY + i / 5].clone()
                        * v(SCRATCH + (i / 5 * 5 + (i % 5 + dx) % 5) * 4 + limb)
                })
                .sum()
        };
        let pre = v(PRELUDE);
        let rounds = v(ROUNDS);
        let final_round = v(FINAL_ROUND);
        let absorb = pre.clone() * p[BYTES].clone() * Val::from_bool(self.absorbs());
        let squeeze = final_round.clone() * p[BYTES].clone();
        let c_op = p[C_RESET].clone() + p[C_UPDATE].clone();
        let round_main_read =
            rounds.clone() * (c_op.clone() + p[THETA].clone() + p[RHO].clone() + p[IOTA].clone());
        let chi = rounds.clone() * p[CHI].clone();
        let theta = rounds.clone() * p[THETA].clone();
        let c = rounds.clone() * c_op;
        let iota = rounds.clone() * p[IOTA].clone();

        for value in &row[BITS..BITS + 192] {
            b.assert_bool(*value);
        }
        for value in &row[COUNTER..POSEIDON] {
            b.assert_bool(*value);
        }
        let counter: Vec<_> = (0..5).map(|i| v(COUNTER + i)).collect();
        let is_zero: AB::Expr = counter.iter().map(|x| AB::Expr::ONE - x.clone()).product();
        let high = counter[4].clone()
            * counter[3].clone()
            * (AB::Expr::ONE
                - (AB::Expr::ONE - counter[0].clone())
                    * (AB::Expr::ONE - counter[1].clone())
                    * (AB::Expr::ONE - counter[2].clone()));
        let is_24 = counter[4].clone()
            * counter[3].clone()
            * (AB::Expr::ONE - counter[0].clone())
            * (AB::Expr::ONE - counter[1].clone())
            * (AB::Expr::ONE - counter[2].clone());
        b.assert_eq(pre.clone(), is_zero.clone());
        b.assert_eq(rounds.clone(), AB::Expr::ONE - is_zero - high);
        b.assert_eq(final_round.clone(), is_24);
        for i in 0..5 {
            b.when_first_row().assert_zero(row[COUNTER + i]);
            let carry: AB::Expr = counter[..i].iter().cloned().product();
            let incremented = xor(counter[i].clone(), carry);
            b.when_transition().assert_eq(
                next[COUNTER + i],
                counter[i].clone() + p[BLOCK_END].clone() * (incremented - counter[i].clone()),
            );
        }

        let boundary: AB::Expr =
            p[BLOCK_END].clone() * counter.iter().cloned().product::<AB::Expr>();
        b.when_first_row()
            .assert_eq(row[PERMUTATION], Val::from_usize(self.first_permutation));
        b.when_last_row().assert_eq(
            row[PERMUTATION],
            Val::from_usize(self.first_permutation + self.permutations - 1),
        );
        for i in 0..5 {
            b.when_last_row().assert_one(row[COUNTER + i]);
        }
        b.when_transition()
            .assert_eq(next[PERMUTATION], v(PERMUTATION) + boundary.clone());

        // rc(t+8)=rc(t+6) xor rc(t+5) xor rc(t+4) xor rc(t).
        // Advancing the sequence by seven positions generates the next round's
        // seven iota bits. This pins all 24 constants without long periodic data.
        for i in 0..7 {
            let expected = xor(
                xor(v(RC + i + 6), v(RC + i + 5)),
                xor(v(RC + i + 4), v(RC + i)),
            );
            b.assert_eq(row[RC + i + 8], expected);
        }
        for i in 0..8 {
            b.when_first_row()
                .assert_eq(row[RC + i], Val::from_bool(i == 0));
            b.when_transition().assert_eq(
                next[RC + i],
                v(RC + i)
                    + iota.clone() * (v(RC + i + 7) - v(RC + i))
                    + boundary.clone() * (AB::Expr::from(Val::from_bool(i == 0)) - v(RC + i)),
            );
        }

        for limb in 0..4 {
            b.when(round_main_read.clone() + absorb.clone() + squeeze.clone())
                .assert_eq(pack(0, limb), select(STATE, limb));
            b.when(chi.clone())
                .assert_eq(pack(0, limb), select(SCRATCH, limb));
            b.when(c.clone())
                .assert_eq(pack(1, limb), select_c(limb, 0));
            b.when(theta.clone())
                .assert_eq(pack(1, limb), select_c(limb, 4));
            b.when(theta.clone())
                .assert_eq(pack(2, limb), select_c(limb, 1));
            b.when(chi.clone())
                .assert_eq(pack(1, limb), select_neighbor(limb, 1));
            b.when(chi.clone())
                .assert_eq(pack(2, limb), select_neighbor(limb, 2));
        }
        for byte in 0..8 {
            for z in 0..8 {
                let suffix = p[SUFFIX + byte].clone() * Val::from_bool(z < 5);
                let final_bit = p[SX + 1].clone()
                    * p[SY + 3].clone()
                    * Val::from_bool(self.last_absorption() && byte == 7 && z == 7);
                b.when(absorb.clone() * (AB::Expr::ONE - p[INPUT_RAW + byte].clone()))
                    .assert_eq(bit(1, byte * 8 + z), suffix + final_bit);
            }
        }

        // Reuse expression nodes: the recursive compiler memoizes this DAG.
        let updates: Vec<_> = (0..4)
            .map(|limb| {
                let theta_value: AB::Expr = (0..16)
                    .map(|z| {
                        let j = limb * 16 + z;
                        xor(xor(bit(0, j), bit(1, j)), bit(2, (j + 63) % 64))
                            * Val::from_u64(1 << z)
                    })
                    .sum();
                let chi_value: AB::Expr = (0..16)
                    .map(|z| {
                        let j = limb * 16 + z;
                        xor(bit(0, j), (AB::Expr::ONE - bit(1, j)) * bit(2, j))
                            * Val::from_u64(1 << z)
                    })
                    .sum();
                let iota_value: AB::Expr = (0..16)
                    .map(|z| {
                        let j = limb * 16 + z;
                        let rc = (0..7)
                            .find(|k| (1usize << k) - 1 == j)
                            .map(|k| v(RC + k))
                            .unwrap_or(AB::Expr::ZERO);
                        xor(bit(0, j), rc) * Val::from_u64(1 << z)
                    })
                    .sum();
                let absorb_value: AB::Expr = (0..16)
                    .map(|z| {
                        xor(bit(0, limb * 16 + z), bit(1, limb * 16 + z)) * Val::from_u64(1 << z)
                    })
                    .sum();
                (theta_value, chi_value, iota_value, absorb_value)
            })
            .collect();
        for lane in 0..25 {
            let x = lane % 5;
            let y = lane / 5;
            let selected = p[SX + x].clone() * p[SY + y].clone();
            for limb in 0..4 {
                let old = v(STATE + lane * 4 + limb);
                let (theta_value, chi_value, iota_value, absorb_value) = &updates[limb];
                let delta = selected.clone()
                    * (theta.clone() * (theta_value.clone() - old.clone())
                        + chi.clone() * (chi_value.clone() - old.clone())
                        + iota.clone() * (iota_value.clone() - old.clone())
                        + absorb.clone() * (absorb_value.clone() - old.clone()));
                b.when_transition()
                    .assert_eq(next[STATE + lane * 4 + limb], old + delta);

                let scratch_old = v(SCRATCH + lane * 4 + limb);
                let mut scratch_delta = AB::Expr::ZERO;
                if y == 0 {
                    let folded = updates[limb].3.clone();
                    scratch_delta += rounds.clone()
                        * p[SX + x].clone()
                        * (p[C_RESET].clone() * (pack(0, limb) - scratch_old.clone())
                            + p[C_UPDATE].clone() * (folded - scratch_old.clone()));
                }
                // Pi maps source(x,y) to target(y,2x+3y). Invert this fixed
                // permutation so each destination uses a constant rotation.
                let source_y = x;
                let source_x = (3 * (y + 5 - (3 * source_y) % 5)) % 5;
                let source = source_y * 5 + source_x;
                let rotated: AB::Expr = (0..16)
                    .map(|z| {
                        bit(0, (limb * 16 + z + 64 - ROT[source] as usize) % 64)
                            * Val::from_u64(1 << z)
                    })
                    .sum();
                scratch_delta += rounds.clone()
                    * p[RHO].clone()
                    * p[SX + source_x].clone()
                    * p[SY + source_y].clone()
                    * (rotated - scratch_old.clone());
                b.when_transition()
                    .assert_eq(next[SCRATCH + lane * 4 + limb], scratch_old + scratch_delta);
            }
        }

        let poseidon: &PoseidonCols<AB::Var> = row[POSEIDON..POSEIDON + POSEIDON_WIDTH].borrow();
        let hash_input = pre * p[INPUT_RAW].clone();
        let hash_output = final_round * p[OUTPUT_RAW].clone();
        for limb in 0..4 {
            b.assert_eq(
                poseidon.inputs[limb],
                hash_input.clone() * v(INPUT_ACC + limb)
                    + hash_output.clone() * v(OUTPUT_ACC + limb),
            );
            let bytes = |slot: usize, mask: usize| -> AB::Expr {
                (0..16)
                    .map(|z| {
                        bit(slot, limb * 16 + z)
                            * p[mask + limb * 2 + z / 8].clone()
                            * Val::from_u64(1 << z)
                    })
                    .sum()
            };
            b.assert_eq(
                poseidon.inputs[4 + limb],
                hash_input.clone() * bytes(1, INPUT_RAW)
                    + hash_output.clone() * bytes(0, OUTPUT_RAW),
            );
            let digest: AB::Expr = poseidon.ending_full_rounds[3].post[limb].into();
            b.when_transition().assert_eq(
                next[INPUT_ACC + limb],
                v(INPUT_ACC + limb) + hash_input.clone() * (digest.clone() - v(INPUT_ACC + limb)),
            );
            b.when_transition().assert_eq(
                next[OUTPUT_ACC + limb],
                v(OUTPUT_ACC + limb) + hash_output.clone() * (digest - v(OUTPUT_ACC + limb)),
            );
            for (column, start, end) in [
                (INPUT_ACC, INPUT_START, INPUT_END),
                (OUTPUT_ACC, OUTPUT_START, OUTPUT_END),
            ] {
                b.when_first_row()
                    .assert_eq(row[column + limb], public[start + limb]);
                b.when_last_row()
                    .assert_eq(row[column + limb], public[end + limb]);
            }
        }
        for i in 0..100 {
            b.when_first_row()
                .assert_eq(row[STATE + i], public[START_STATE + i]);
            b.when_last_row()
                .assert_eq(row[STATE + i], public[END_STATE + i]);
            b.when_first_row().assert_zero(row[SCRATCH + i]);
        }
    }
}
