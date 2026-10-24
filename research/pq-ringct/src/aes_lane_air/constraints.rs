use super::*;

impl<AB: AirBuilder<F = Val>> Air<AB> for AesLaneAir {
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
        let p: Vec<AB::Expr> = b.periodic_values().iter().map(|v| (*v).into()).collect();
        let v = |i: usize| -> AB::Expr { row[i].into() };
        let read_bit = |byte: usize, bit: usize| v(READ + byte * 8 + bit);
        let read = |byte: usize| -> AB::Expr {
            (0..8)
                .map(|bit| read_bit(byte, bit) * Val::from_u64(1 << bit))
                .sum()
        };
        let selected = |bank: usize, shift: usize| -> AB::Expr {
            (0..16)
                .map(|i| p[SLOT + i].clone() * v(bank + shift + i))
                .sum()
        };
        let active = v(ACTIVE);
        let reset = active.clone() * v(OUTPUT_PHASE) * p[PHASE_END].clone();
        let init = active.clone() * v(PRELUDE) * p[MIX].clone();
        let sub = active.clone() * v(ROUNDS) * p[SUB].clone();
        let mix = active.clone() * v(ROUNDS) * p[MIX].clone();
        let key_sub = active.clone() * v(ROUNDS) * p[KEY_SUB].clone();
        let key_xor = active.clone() * v(ROUNDS) * p[KEY_XOR].clone();
        let rotate = active.clone() * v(ROUNDS) * p[KEY_ROTATE].clone();
        for i in PHASE_BITS..POSEIDON {
            b.assert_bool(row[i]);
        }
        let phase: Vec<_> = (0..4).map(|i| v(PHASE_BITS + i)).collect();
        let is_prelude: AB::Expr = phase.iter().map(|x| AB::Expr::ONE - x.clone()).product();
        let is_output: AB::Expr = phase.iter().cloned().product();
        let is_final = (AB::Expr::ONE - phase[0].clone())
            * phase[1].clone()
            * phase[2].clone()
            * phase[3].clone();
        b.assert_eq(row[PRELUDE], is_prelude.clone());
        b.assert_eq(row[OUTPUT_PHASE], is_output.clone());
        b.assert_eq(row[FINAL_ROUND], is_final);
        b.assert_eq(row[ROUNDS], AB::Expr::ONE - is_prelude - is_output);
        let xor = |a: AB::Expr, c: AB::Expr| a.clone() + c.clone() - a * c * Val::TWO;
        for i in 0..4 {
            b.when_first_row().assert_zero(row[PHASE_BITS + i]);
            let carry: AB::Expr = phase[..i].iter().cloned().product();
            let incremented = xor(phase[i].clone(), carry);
            b.when_transition().assert_eq(
                next[PHASE_BITS + i],
                phase[i].clone() + p[PHASE_END].clone() * (incremented - phase[i].clone()),
            );
        }
        let advance = p[PHASE_END].clone() * v(ROUNDS) * (AB::Expr::ONE - phase[0].clone());
        let reset_rcon = p[PHASE_END].clone() * v(OUTPUT_PHASE);
        for bit in 0..8 {
            let old = v(RCON_BITS + bit);
            let shifted = if bit == 0 {
                v(RCON_BITS + 7)
            } else if [1, 3, 4].contains(&bit) {
                xor(v(RCON_BITS + bit - 1), v(RCON_BITS + 7))
            } else {
                v(RCON_BITS + bit - 1)
            };
            let initial = AB::Expr::from(Val::from_bool(bit == 0));
            b.when_first_row()
                .assert_eq(row[RCON_BITS + bit], initial.clone());
            b.when_transition().assert_eq(
                next[RCON_BITS + bit],
                old.clone()
                    + advance.clone() * (shifted - old.clone())
                    + reset_rcon.clone() * (initial - old),
            );
        }
        for i in READ..SBOX {
            b.assert_bool(row[i]);
        }
        for i in RESULT..BLOCK_INDEX {
            b.assert_bool(row[i]);
        }
        for i in [ACTIVE, FIRST, LAST] {
            b.assert_bool(row[i]);
        }
        for (value, flag, inverse) in [
            (v(REMAINING), ACTIVE, ACTIVE_INV),
            (
                v(BLOCK_INDEX) - Val::from_usize(self.first_block),
                FIRST,
                FIRST_INV,
            ),
            (
                v(BLOCK_INDEX) - Val::from_usize(self.descriptor.blocks() - 1),
                LAST,
                LAST_INV,
            ),
        ] {
            let nonzero = if flag == ACTIVE {
                v(flag)
            } else {
                AB::Expr::ONE - v(flag)
            };
            b.assert_zero(value.clone() * (AB::Expr::ONE - nonzero.clone()));
            b.assert_eq(value * row[inverse], nonzero);
        }
        b.when_first_row()
            .assert_eq(row[BLOCK_INDEX], Val::from_usize(self.first_block));
        b.when_first_row()
            .assert_eq(row[REMAINING], Val::from_usize(self.blocks));
        b.when_transition()
            .assert_eq(next[BLOCK_INDEX], v(BLOCK_INDEX) + reset.clone());
        b.when_transition()
            .assert_eq(next[REMAINING], v(REMAINING) - reset.clone());
        let counter: AB::Expr = (0..32)
            .map(|i| v(COUNTER_BITS + i) * Val::from_u64(1 << i))
            .sum();
        let next_counter: AB::Expr = (0..32)
            .map(|i| next[COUNTER_BITS + i] * Val::from_u64(1 << i))
            .sum();
        b.when_first_row().assert_eq(
            counter.clone(),
            Val::from_u32(
                self.descriptor
                    .start_counter
                    .wrapping_add(self.first_block as u32),
            ),
        );
        b.when(AB::Expr::ONE - reset.clone())
            .assert_zero(row[COUNTER_CARRY]);
        b.when_transition().assert_eq(
            next_counter,
            counter + reset.clone() - v(COUNTER_CARRY) * Val::from_u64(1 << 32),
        );
        b.when_last_row().assert_eq(
            row[REMAINING],
            Val::from_bool(self.blocks * ROWS_PER_BLOCK == self.height),
        );

        let plain: AB::Expr = (0..16)
            .map(|i| {
                let byte: AB::Expr = if i < 4 {
                    (0..8)
                        .map(|bit| v(COUNTER_BITS + i * 8 + bit) * Val::from_u64(1 << bit))
                        .sum()
                } else if i < 8 {
                    AB::Expr::ZERO
                } else {
                    Val::from_u8(self.descriptor.domain.to_le_bytes()[i - 8]).into()
                };
                p[SLOT + i].clone() * byte
            })
            .sum();
        b.when(init.clone()).assert_eq(read(0), plain);
        b.when(init.clone())
            .assert_eq(read(1), selected(ROOT_KEY, 0));
        b.when(sub.clone()).assert_eq(read(0), selected(STATE, 0));
        for source in 0..4 {
            let value: AB::Expr = (0..16)
                .map(|i| p[SLOT + i].clone() * v(SCRATCH + shifted_byte(4 * (i / 4) + source)))
                .sum();
            b.when(mix.clone()).assert_eq(read(source), value);
        }
        b.when(mix.clone()).assert_eq(read(4), selected(KEY, 16));
        let key_read: AB::Expr = (0..4)
            .map(|i| {
                p[SLOT + i].clone()
                    * (v(KEY + 28 + i)
                        + v(PHASE_BITS) * (v(KEY + 28 + (i + 1) % 4) - v(KEY + 28 + i)))
            })
            .sum();
        b.when(key_sub.clone()).assert_eq(read(0), key_read);
        b.when(key_sub.clone()).assert_eq(read(1), selected(KEY, 0));
        b.when(key_xor.clone()).assert_eq(read(0), selected(KEY, 0));
        let previous_key: AB::Expr = (4..16)
            .map(|i| p[SLOT + i].clone() * v(SCRATCH + i - 4))
            .sum();
        b.when(key_xor.clone()).assert_eq(read(1), previous_key);

        crate::aes_air::constraints::sbox(
            b,
            row,
            SBOX,
            core::array::from_fn(|bit| read_bit(0, bit)),
            sub.clone() + key_sub.clone(),
        );
        for bit in 0..8 {
            let carry: AB::Expr = (0..3)
                .map(|j| v(CARRY + 3 * bit + j) * Val::from_u64(1 << j))
                .sum();
            let parity = v(RESULT + bit) + carry * Val::TWO;
            b.when(sub.clone())
                .assert_eq(row[RESULT + bit], row[SBOX + 42 + bit]);
            b.when(init.clone() + key_xor.clone())
                .assert_eq(parity.clone(), read_bit(0, bit) + read_bit(1, bit));
            b.when(key_sub.clone()).assert_eq(
                parity.clone(),
                v(SBOX + 42 + bit)
                    + read_bit(1, bit)
                    + v(RCON_BITS + bit) * v(PHASE_BITS) * p[SLOT].clone(),
            );
            let mut mixed = AB::Expr::ZERO;
            for outrow in 0..4 {
                let selected_row: AB::Expr = (0..4)
                    .map(|column| p[SLOT + 4 * column + outrow].clone())
                    .sum();
                let mut transformed = AB::Expr::ZERO;
                for source in 0..4 {
                    for source_bit in 0..8 {
                        let coefficient = [2, 3, 1, 1][(source + 4 - outrow) % 4];
                        if gf_mul(coefficient, 1 << source_bit) & (1 << bit) != 0 {
                            transformed += read_bit(source, source_bit);
                        }
                    }
                }
                mixed += selected_row
                    * ((AB::Expr::ONE - v(FINAL_ROUND)) * transformed
                        + v(FINAL_ROUND) * read_bit(outrow, bit));
            }
            b.when(mix.clone())
                .assert_eq(parity, mixed + read_bit(4, bit));
        }
        let result: AB::Expr = (0..8)
            .map(|bit| v(RESULT + bit) * Val::from_u64(1 << bit))
            .sum();
        for i in 0..32 {
            b.when_transition()
                .assert_eq(next[ROOT_KEY + i], row[ROOT_KEY + i]);
            b.when_first_row()
                .assert_eq(row[KEY + i], row[ROOT_KEY + i]);
            let rotated = if i < 16 {
                v(KEY + 16 + i)
            } else if i == 31 {
                result.clone()
            } else {
                v(SCRATCH + i - 16)
            };
            b.when_transition().assert_eq(
                next[KEY + i],
                v(KEY + i)
                    + rotate.clone() * (rotated - v(KEY + i))
                    + reset.clone() * (v(ROOT_KEY + i) - v(KEY + i)),
            );
        }
        for i in 0..16 {
            b.when_first_row().assert_zero(row[STATE + i]);
            b.when_first_row().assert_zero(row[SCRATCH + i]);
            let state_write = p[SLOT + i].clone() * (init.clone() + mix.clone());
            let scratch_write =
                p[SLOT + i].clone() * (sub.clone() + key_sub.clone() + key_xor.clone());
            b.when_transition().assert_eq(
                next[STATE + i],
                v(STATE + i) + state_write * (result.clone() - v(STATE + i))
                    - reset.clone() * v(STATE + i),
            );
            b.when_transition().assert_eq(
                next[SCRATCH + i],
                v(SCRATCH + i) + scratch_write * (result.clone() - v(SCRATCH + i))
                    - reset.clone() * v(SCRATCH + i),
            );
        }

        let header_gate: AB::Expr = (0..7).map(|i| p[HEADER + i].clone()).sum();
        let input_hash = active.clone() * v(FIRST) * v(PRELUDE) * header_gate.clone();
        let tail = self.descriptor.output_len - (self.descriptor.blocks() - 1) * 16;
        let second = AB::Expr::ONE - v(LAST) * Val::from_bool(tail <= 8);
        let output_hash = active.clone()
            * v(OUTPUT_PHASE)
            * (p[OUTPUT_CHUNK].clone() + p[OUTPUT_CHUNK + 1].clone() * second.clone());
        let metadata = self.descriptor.input_bytes(&[0; 32]);
        for byte in 0..8 {
            let expected: AB::Expr = (0..7)
                .map(|chunk| {
                    let i = 8 * chunk + byte;
                    let value = if i < 32 {
                        v(ROOT_KEY + i)
                    } else if i < 52 {
                        AB::Expr::from(Val::from_u8(metadata[i]))
                    } else {
                        AB::Expr::ZERO
                    };
                    p[HEADER + chunk].clone() * value
                })
                .sum();
            b.when(input_hash.clone()).assert_eq(read(byte), expected);
            let expected_output: AB::Expr = (0..2)
                .map(|chunk| {
                    let i = 8 * chunk + byte;
                    let enabled = AB::Expr::ONE - v(LAST) * Val::from_bool(i >= tail);
                    p[OUTPUT_CHUNK + chunk].clone() * enabled * v(STATE + i)
                })
                .sum();
            b.when(output_hash.clone())
                .assert_eq(read(byte), expected_output);
        }
        let poseidon: &PoseidonCols<AB::Var> = row[POSEIDON..].borrow();
        for limb in 0..4 {
            b.assert_eq(
                poseidon.inputs[limb],
                input_hash.clone() * v(INPUT_ACC + limb)
                    + output_hash.clone() * v(OUTPUT_ACC + limb),
            );
            b.assert_eq(
                poseidon.inputs[4 + limb],
                (input_hash.clone() + output_hash.clone())
                    * (read(2 * limb) + read(2 * limb + 1) * Val::from_u64(256)),
            );
            let digest: AB::Expr = poseidon.ending_full_rounds[3].post[limb].into();
            b.when_transition().assert_eq(
                next[INPUT_ACC + limb],
                v(INPUT_ACC + limb) + input_hash.clone() * (digest.clone() - v(INPUT_ACC + limb)),
            );
            b.when_transition().assert_eq(
                next[OUTPUT_ACC + limb],
                v(OUTPUT_ACC + limb) + output_hash.clone() * (digest - v(OUTPUT_ACC + limb)),
            );
            let input_initial = [
                Val::from_u64(AES_INPUT_DOMAIN),
                Val::from_u64(52),
                Val::ZERO,
                Val::ZERO,
            ];
            b.when_first_row()
                .assert_eq(row[INPUT_ACC + limb], input_initial[limb]);
            b.when_first_row()
                .assert_eq(row[OUTPUT_ACC + limb], public[OUTPUT_START + limb]);
            if self.first_block == 0 {
                let output_initial = [
                    Val::from_u64(AES_OUTPUT_DOMAIN),
                    Val::from_usize(self.descriptor.output_len),
                    Val::ZERO,
                    Val::ZERO,
                ];
                b.when_first_row()
                    .assert_eq(row[OUTPUT_ACC + limb], output_initial[limb]);
            }
            b.when_last_row()
                .assert_eq(row[INPUT_ACC + limb], public[INPUT_COMMITMENT + limb]);
            b.when_last_row()
                .assert_eq(row[OUTPUT_ACC + limb], public[OUTPUT_END + limb]);
        }
    }
}
