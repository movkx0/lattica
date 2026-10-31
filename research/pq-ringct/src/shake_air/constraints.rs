use super::*;

fn input_bit<AB: AirBuilder>(k: &KeccakCols<AB::Var>, bit: usize) -> AB::Expr {
    let lane = bit / 64;
    let x = lane % 5;
    let y = lane / 5;
    let z = bit % 64;
    let a: AB::Expr = k.a_prime[y][x][z].into();
    a.xor3(&k.c[x][z].into(), &k.c_prime[x][z].into())
}

fn prior_limb<AB: AirBuilder>(row: &[AB::Var], k: &KeccakCols<AB::Var>, limb: usize) -> AB::Expr {
    let mut result = AB::Expr::ZERO;
    for j in 0..16 {
        let bit = limb * 16 + j;
        let input = input_bit::<AB>(k, bit);
        let prior = if bit < 1088 {
            let message: AB::Expr = row[MESSAGE + bit].into();
            input.clone() + message.clone() - input * message * AB::F::TWO
        } else {
            input
        };
        result += prior * AB::F::from_u64(1 << j);
    }
    result
}

fn message_byte<AB: AirBuilder>(row: &[AB::Var], byte: usize) -> AB::Expr {
    (0..8).fold(AB::Expr::ZERO, |sum, bit| {
        sum + row[MESSAGE + byte * 8 + bit] * AB::F::from_u64(1 << bit)
    })
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ShakeAir {
    fn eval(&self, b: &mut AB) {
        KeccakAir {}.eval(&mut SubBuilder {
            parent: b,
            start: 0,
            width: NUM_KECCAK_COLS,
        });
        let poseidon = PoseidonAir::new(round_constants());
        for start in [INPUT_POSEIDON, OUTPUT_POSEIDON] {
            poseidon.eval(&mut SubBuilder {
                parent: b,
                start,
                width: POSEIDON_WIDTH,
            });
        }
        let window = b.main();
        let local = window.current_slice();
        let next = window.next_slice();
        let phase: Vec<AB::Expr> = b.periodic_values().iter().map(|v| (*v).into()).collect();
        let input_rem = self.descriptor.input_len % RATE;
        let output_rem = self.descriptor.output_len % RATE;
        let raw_mask = |byte: usize| {
            phase[FULL_INPUT].clone() + phase[LAST_INPUT].clone() * Val::from_bool(byte < input_rem)
        };
        let output_full = |limb: usize| {
            phase[FULL_OUTPUT].clone()
                + phase[LAST_OUTPUT].clone() * Val::from_bool(limb < output_rem / 2)
        };
        let output_low = |limb: usize| {
            phase[LAST_OUTPUT].clone()
                * Val::from_bool(output_rem % 2 != 0 && limb == output_rem / 2)
        };
        let k: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let next_k: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let pin: &PoseidonCols<AB::Var> = local[INPUT_POSEIDON..OUTPUT_POSEIDON].borrow();
        let pout: &PoseidonCols<AB::Var> = local[OUTPUT_POSEIDON..].borrow();
        let public = b.public_values().to_vec();
        let nonfinal = AB::Expr::ONE - k.step_flags[23];

        // Message bytes are the actual padded absorption block. Raw bytes are
        // unconstrained values; every suffix, final pad bit and squeeze-only
        // byte is fixed by the authenticated periodic schedule.
        for bit in 0..1088 {
            b.assert_bool(local[MESSAGE + bit]);
            b.when_transition()
                .when(nonfinal.clone())
                .assert_eq(local[MESSAGE + bit], next[MESSAGE + bit]);
        }
        for byte in 0..RATE {
            let value = message_byte::<AB>(local, byte);
            let padding = u16::from(byte == input_rem) * 0x1f + u16::from(byte == RATE - 1) * 0x80;
            b.assert_zero(
                (AB::Expr::ONE - raw_mask(byte)) * value
                    - phase[LAST_INPUT].clone() * Val::from_u16(padding),
            );
        }

        // Store the final permutation state throughout its 24 rows so output
        // commitment rounds can run alongside Keccak. Bind it to the real
        // final state, including iota, at round 23.
        for limb in 0..100 {
            let lane = limb / 4;
            let expected = k.a_prime_prime_prime(lane / 5, lane % 5, limb % 4);
            b.when(k.step_flags[23])
                .assert_eq(local[OUTPUT + limb], expected);
            b.when_transition()
                .when(nonfinal.clone())
                .assert_eq(local[OUTPUT + limb], next[OUTPUT + limb]);
            b.when_first_row()
                .assert_eq(prior_limb::<AB>(local, k, limb), public[START_STATE + limb]);
            b.when(phase[LINK].clone())
                .assert_eq(prior_limb::<AB>(next, next_k, limb), local[OUTPUT + limb]);
            b.when(phase[END].clone())
                .assert_eq(local[OUTPUT + limb], public[END_STATE + limb]);
            if self.first_permutation == 0 {
                b.when_first_row().assert_zero(public[START_STATE + limb]);
            }
        }

        // An odd final output length commits its last low byte without the
        // following unused squeeze byte. Boolean decomposition is unique.
        let mut odd_limb = AB::Expr::ZERO;
        let mut odd_low = AB::Expr::ZERO;
        for bit in 0..16 {
            b.assert_bool(local[ODD_BITS + bit]);
            let term = local[ODD_BITS + bit] * Val::from_u64(1 << bit);
            odd_limb += term.clone();
            if bit < 8 {
                odd_low += term;
            }
        }
        b.assert_eq(odd_limb, local[OUTPUT + self.odd_output_limb()]);

        let rounds = |count: usize| (0..count).fold(AB::Expr::ZERO, |sum, i| sum + k.step_flags[i]);
        let input_active = phase[FULL_INPUT].clone() * rounds(17)
            + phase[LAST_INPUT].clone() * rounds(input_rem.div_ceil(8));
        let output_active = phase[FULL_OUTPUT].clone() * rounds(17)
            + phase[LAST_OUTPUT].clone() * rounds(output_rem.div_ceil(8));
        for lane in 0..4 {
            let mut input_limb = AB::Expr::ZERO;
            let mut output_limb = AB::Expr::ZERO;
            for round in 0..17 {
                let limb = round * 4 + lane;
                let low = message_byte::<AB>(local, limb * 2) * raw_mask(limb * 2);
                let high = message_byte::<AB>(local, limb * 2 + 1) * raw_mask(limb * 2 + 1);
                input_limb += (low + high * Val::from_u64(256)) * k.step_flags[round];
                let output =
                    local[OUTPUT + limb] * output_full(limb) + odd_low.clone() * output_low(limb);
                output_limb += output * k.step_flags[round];
            }
            b.assert_eq(pin.inputs[4 + lane], input_limb);
            b.assert_eq(pout.inputs[4 + lane], output_limb);
            for (p, acc, active, start, end, domain, length) in [
                (
                    pin,
                    INPUT_ACC,
                    input_active.clone(),
                    INPUT_START,
                    INPUT_END,
                    SHAKE_INPUT_DOMAIN,
                    self.descriptor.input_len,
                ),
                (
                    pout,
                    OUTPUT_ACC,
                    output_active.clone(),
                    OUTPUT_START,
                    OUTPUT_END,
                    SHAKE_OUTPUT_DOMAIN,
                    self.descriptor.output_len,
                ),
            ] {
                b.assert_eq(p.inputs[lane], local[acc + lane]);
                let updated = p.ending_full_rounds[3].post[lane];
                b.when_transition().assert_eq(
                    next[acc + lane],
                    local[acc + lane] + active * (updated - local[acc + lane]),
                );
                b.when_first_row()
                    .assert_eq(local[acc + lane], public[start + lane]);
                // Last active row is round23; both hash-absorb selectors are
                // zero there, so this is the completed accumulator.
                b.when(phase[END].clone())
                    .assert_eq(local[acc + lane], public[end + lane]);
                if self.first_permutation == 0 {
                    let expected = match lane {
                        0 => Val::from_u64(domain),
                        1 => Val::from_usize(length),
                        _ => Val::ZERO,
                    };
                    b.when_first_row().assert_eq(public[start + lane], expected);
                }
            }
        }
    }
}
