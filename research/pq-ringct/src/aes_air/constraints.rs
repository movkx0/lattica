use super::*;

fn packed<AB: AirBuilder>(row: &[AB::Var], start: usize, bits: usize) -> AB::Expr {
    (0..bits).fold(AB::Expr::ZERO, |sum, i| {
        sum + row[start + i] * AB::F::from_u64(1 << i)
    })
}
pub(crate) fn sbox<AB: AirBuilder<F = Val>>(
    b: &mut AB,
    row: &[AB::Var],
    start: usize,
    input: [AB::Expr; 8],
    active: AB::Expr,
) {
    for i in 0..SBOX_WIDTH {
        if i != FIELD_INV {
            b.assert_bool(row[start + i]);
        }
    }
    let input_byte = input
        .iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |sum, (i, v)| {
            sum + v.clone() * Val::from_u64(1 << i)
        });
    let zero: AB::Expr = row[start + ZERO].into();
    b.when(active.clone())
        .assert_zero(input_byte.clone() * zero.clone());
    b.when(active.clone()).assert_eq(
        input_byte * row[start + FIELD_INV],
        AB::Expr::ONE - zero.clone(),
    );
    for bit in 0..8 {
        b.when(active.clone())
            .assert_zero(zero.clone() * row[start + INV + bit]);
        let mut sum = AB::Expr::ZERO;
        for i in 0..8 {
            for j in 0..8 {
                if reduction(i + j) & (1 << bit) != 0 {
                    sum += input[i].clone() * row[start + INV + j];
                }
            }
        }
        let expected = if bit == 0 {
            AB::Expr::ONE - zero.clone()
        } else {
            AB::Expr::ZERO
        };
        let carry = packed::<AB>(row, start + GF_CARRY + 4 * bit, 4);
        b.when(active.clone())
            .assert_eq(sum, expected + carry * Val::TWO);
        let mut affine = AB::Expr::from(Val::from_u8((0x63 >> bit) & 1));
        for offset in [0, 4, 5, 6, 7] {
            affine += row[start + INV + (bit + offset) % 8].into();
        }
        let carry = packed::<AB>(row, start + AFFINE_CARRY + 2 * bit, 2);
        b.when(active.clone())
            .assert_eq(affine, row[start + SBOX_OUT + bit] + carry * Val::TWO);
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for AesAir {
    fn eval(&self, b: &mut AB) {
        let poseidon = PoseidonAir::new(round_constants());
        for start in [INPUT_POSEIDON, OUTPUT_POSEIDON] {
            poseidon.eval(&mut SubBuilder {
                parent: b,
                start,
                width: POSEIDON_WIDTH,
            });
        }
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let metadata = b.periodic_values().to_vec();
        let meta = |index: usize| -> AB::Expr { metadata[index].into() };
        let public = b.public_values().to_vec();
        let active: AB::Expr = meta(ACTIVE);
        for i in ROOT_KEY..STATE_SBOX {
            b.assert_bool(row[i]);
        }
        for i in NEXT_KEY..INPUT_ACC {
            b.assert_bool(row[i]);
        }
        for i in 0..256 {
            b.when_transition()
                .when(meta(GLOBAL_LINK))
                .assert_eq(row[ROOT_KEY + i], next[ROOT_KEY + i]);
            b.when(meta(FIRST))
                .assert_eq(row[KEY + i], row[ROOT_KEY + i]);
        }
        b.when(active.clone())
            .assert_eq(packed::<AB>(row, COUNTER_BITS, 32), meta(COUNTER));
        for i in 0..128 {
            let plain: AB::Expr = if i < 32 {
                row[COUNTER_BITS + i].into()
            } else if i < 64 {
                AB::Expr::ZERO
            } else {
                AB::Expr::from(Val::from_u64((self.descriptor.domain >> (i - 64)) & 1))
            };
            let key: AB::Expr = row[ROOT_KEY + i].into();
            b.when(meta(FIRST)).assert_eq(
                row[STATE + i],
                plain.clone() + key.clone() - plain * key * Val::TWO,
            );
            b.when_transition()
                .when(meta(MIDDLE))
                .assert_eq(next[STATE + i], row[STATE_OUT + i]);
            b.when_transition()
                .when(meta(MIDDLE))
                .assert_eq(next[CIPHER + i], row[CIPHER + i]);
            b.when(meta(LAST))
                .assert_eq(row[CIPHER + i], row[STATE_OUT + i]);
            b.when_transition()
                .when(meta(MIDDLE))
                .assert_eq(next[KEY + i], row[KEY + 128 + i]);
            b.when_transition()
                .when(meta(MIDDLE))
                .assert_eq(next[KEY + 128 + i], row[NEXT_KEY + i]);
        }
        for byte in 0..16 {
            sbox::<AB>(
                b,
                row,
                STATE_SBOX + byte * SBOX_WIDTH,
                core::array::from_fn(|bit| row[STATE + byte * 8 + bit].into()),
                active.clone(),
            );
        }
        for byte in 0..4 {
            let input = core::array::from_fn(|bit| {
                let rotated: AB::Expr = row[KEY + (28 + (byte + 1) % 4) * 8 + bit].into();
                let straight: AB::Expr = row[KEY + (28 + byte) * 8 + bit].into();
                straight.clone() + meta(ROTATE) * (rotated - straight)
            });
            sbox::<AB>(b, row, KEY_SBOX + byte * SBOX_WIDTH, input, active.clone());
        }
        for byte in 0..16 {
            for bit in 0..8 {
                let mut sum: AB::Expr = row[KEY + byte * 8 + bit].into();
                sum += if byte < 4 {
                    row[KEY_SBOX + byte * SBOX_WIDTH + SBOX_OUT + bit].into()
                } else {
                    row[NEXT_KEY + (byte - 4) * 8 + bit].into()
                };
                if byte == 0 {
                    sum += meta(RCON + bit);
                }
                b.when(active.clone()).assert_eq(
                    sum,
                    row[NEXT_KEY + byte * 8 + bit] + row[KEY_CARRY + byte * 8 + bit] * Val::TWO,
                );
            }
        }
        for byte in 0..16 {
            for bit in 0..8 {
                let mut mix = AB::Expr::ZERO;
                let out_row = byte % 4;
                let column = byte / 4;
                for in_row in 0..4 {
                    let coefficient = [2_u8, 3, 1, 1][(in_row + 4 - out_row) % 4];
                    let source = shifted_byte(column * 4 + in_row);
                    for source_bit in 0..8 {
                        if gf_mul(coefficient, 1 << source_bit) & (1 << bit) != 0 {
                            mix += row[STATE_SBOX + source * SBOX_WIDTH + SBOX_OUT + source_bit]
                                .into();
                        }
                    }
                }
                let final_bit: AB::Expr =
                    row[STATE_SBOX + shifted_byte(byte) * SBOX_WIDTH + SBOX_OUT + bit].into();
                let sum = (AB::Expr::ONE - meta(LAST)) * mix
                    + meta(LAST) * final_bit
                    + row[KEY + 128 + byte * 8 + bit];
                let carry = packed::<AB>(row, STATE_CARRY + (byte * 8 + bit) * 3, 3);
                b.when(active.clone())
                    .assert_eq(sum, row[STATE_OUT + byte * 8 + bit] + carry * Val::TWO);
            }
        }
        let input_poseidon: &PoseidonCols<AB::Var> = row[INPUT_POSEIDON..OUTPUT_POSEIDON].borrow();
        let output_poseidon: &PoseidonCols<AB::Var> = row[OUTPUT_POSEIDON..].borrow();
        let header = self.descriptor.input_bytes(&[0; 32]);
        let input_active = (0..7).fold(AB::Expr::ZERO, |sum, i| sum + meta(INPUT_CHUNK + i));
        let output_active: AB::Expr = meta(OUTPUT_CHUNK) + meta(OUTPUT_CHUNK + 1);
        for lane in 0..4 {
            let mut input_word = AB::Expr::ZERO;
            for chunk in 0..7 {
                for half in 0..2 {
                    let index = chunk * 8 + lane * 2 + half;
                    let byte = if index < 32 {
                        packed::<AB>(row, ROOT_KEY + index * 8, 8)
                    } else {
                        AB::Expr::from(Val::from_u8(*header.get(index).unwrap_or(&0)))
                    };
                    input_word += meta(INPUT_CHUNK + chunk) * byte * Val::from_u64(1 << (8 * half));
                }
            }
            let mut output_word = AB::Expr::ZERO;
            for chunk in 0..2 {
                for half in 0..2 {
                    let index = chunk * 8 + lane * 2 + half;
                    output_word += meta(OUTPUT_CHUNK + chunk)
                        * if index < (self.descriptor.output_len - 1) % 16 + 1 {
                            meta(ACTIVE)
                        } else {
                            meta(FULL_BLOCK)
                        }
                        * packed::<AB>(row, CIPHER + index * 8, 8)
                        * Val::from_u64(1 << (8 * half));
                }
            }
            b.assert_eq(input_poseidon.inputs[4 + lane], input_word);
            b.assert_eq(output_poseidon.inputs[4 + lane], output_word);
            for (p, acc, selector, domain, len, public_offset) in [
                (
                    input_poseidon,
                    INPUT_ACC,
                    input_active.clone(),
                    AES_INPUT_DOMAIN,
                    52,
                    0,
                ),
                (
                    output_poseidon,
                    OUTPUT_ACC,
                    output_active.clone(),
                    AES_OUTPUT_DOMAIN,
                    self.descriptor.output_len,
                    4,
                ),
            ] {
                b.assert_eq(p.inputs[lane], row[acc + lane]);
                let updated = p.ending_full_rounds[3].post[lane];
                b.when_transition().assert_eq(
                    next[acc + lane],
                    row[acc + lane] + selector * (updated - row[acc + lane]),
                );
                let initial = match lane {
                    0 => Val::from_u64(domain),
                    1 => Val::from_usize(len),
                    _ => Val::ZERO,
                };
                b.when_first_row().assert_eq(row[acc + lane], initial);
                b.when(meta(END))
                    .assert_eq(row[acc + lane], public[public_offset + lane]);
            }
        }
    }
}
