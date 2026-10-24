use super::*;

fn limbs(state: &[u64; 25]) -> [Val; 100] {
    core::array::from_fn(|i| Val::from_u16((state[i / 4] >> (16 * (i % 4))) as u16))
}

impl LaneShakeAir {
    pub fn generate(&self, input: &[u8]) -> Result<SegmentWitness, Error> {
        // The independent wide implementation supplies boundary witnesses. All
        // lane operations and boundary equality are checked by this AIR.
        let reference = ShakeAir::new(self.descriptor, self.permutation, 1)?.generate(input)?;
        let public = reference.public_values;
        drop(reference);
        let mut state: [u64; 25] = core::array::from_fn(|i| {
            (0..4)
                .map(|j| public[START_STATE + i * 4 + j].as_canonical_u64() << (16 * j))
                .sum()
        });
        let mut scratch = [0u64; 25];
        let mut input_acc: [Val; 4] = public[INPUT_START..INPUT_END].try_into().unwrap();
        let mut output_acc: [Val; 4] = public[OUTPUT_START..OUTPUT_END].try_into().unwrap();
        let raw = self.descriptor.input_bytes(self.permutation);
        let take = self.descriptor.output_bytes(self.permutation);
        let mut message = [0u8; RATE];
        if raw != 0 {
            let offset = self.permutation * RATE;
            message[..raw].copy_from_slice(&input[offset..offset + raw]);
        }
        if self.last_absorption() {
            message[raw] ^= 0x1f;
            message[RATE - 1] ^= 0x80;
        }
        let mut rc = [0u8; 15];
        rc[0] = 1;
        let mut values = Val::zero_vec(HEIGHT * WIDTH);
        let mut hashes = Vec::with_capacity(HEIGHT);
        for (row_index, fields) in values.chunks_exact_mut(WIDTH).enumerate() {
            let block = row_index / SCHEDULE_PERIOD;
            let step = row_index % SCHEDULE_PERIOD;
            let prelude = block == 0;
            let rounds = (1..=24).contains(&block);
            let final_round = block == 24;
            for i in 0..7 {
                rc[i + 8] = rc[i + 6] ^ rc[i + 5] ^ rc[i + 4] ^ rc[i];
            }
            fields[STATE..SCRATCH].copy_from_slice(&limbs(&state));
            fields[SCRATCH..BITS].copy_from_slice(&limbs(&scratch));
            fields[INPUT_ACC..OUTPUT_ACC].copy_from_slice(&input_acc);
            fields[OUTPUT_ACC..COUNTER].copy_from_slice(&output_acc);
            for i in 0..5 {
                fields[COUNTER + i] = Val::from_usize((block >> i) & 1);
            }
            fields[PRELUDE] = Val::from_bool(prelude);
            fields[ROUNDS] = Val::from_bool(rounds);
            fields[FINAL_ROUND] = Val::from_bool(final_round);
            for i in 0..15 {
                fields[RC + i] = Val::from_u8(rc[i]);
            }
            let mut slots = [0u64; 3];
            if rounds {
                match step {
                    0..=24 => {
                        let x = step / 5;
                        let y = step % 5;
                        slots = [state[y * 5 + x], scratch[x], 0];
                        scratch[x] = if y == 0 {
                            slots[0]
                        } else {
                            slots[0] ^ slots[1]
                        };
                    }
                    25..=49 => {
                        let lane = step - 25;
                        let x = lane % 5;
                        slots = [state[lane], scratch[(x + 4) % 5], scratch[(x + 1) % 5]];
                        state[lane] = slots[0] ^ slots[1] ^ slots[2].rotate_left(1);
                    }
                    50..=74 => {
                        let lane = step - 50;
                        let x = lane % 5;
                        let y = lane / 5;
                        slots[0] = state[lane];
                        scratch[((2 * x + 3 * y) % 5) * 5 + y] = state[lane].rotate_left(ROT[lane]);
                    }
                    75..=99 => {
                        let lane = step - 75;
                        let x = lane % 5;
                        let y = lane / 5;
                        slots = [
                            scratch[lane],
                            scratch[y * 5 + (x + 1) % 5],
                            scratch[y * 5 + (x + 2) % 5],
                        ];
                        state[lane] = slots[0] ^ ((!slots[1]) & slots[2]);
                    }
                    100 => {
                        slots[0] = state[0];
                        let constant: u64 =
                            (0..7).map(|i| u64::from(rc[i]) << ((1 << i) - 1)).sum();
                        state[0] ^= constant;
                        rc.copy_within(7..15, 0);
                    }
                    _ => {}
                }
            }
            let mut hash = [Val::ZERO; 8];
            if (101..=117).contains(&step) {
                let lane = step - 101;
                if prelude && self.absorbs() {
                    slots[0] = state[lane];
                    slots[1] =
                        u64::from_le_bytes(message[lane * 8..lane * 8 + 8].try_into().unwrap());
                    state[lane] ^= slots[1];
                    let end = raw.min(lane * 8 + 8);
                    if lane * 8 < end {
                        hash = absorb_commitment(&mut input_acc, &message[lane * 8..end]);
                    }
                }
                if final_round {
                    slots[0] = state[lane];
                    let end = take.min(lane * 8 + 8);
                    if lane * 8 < end {
                        hash = absorb_commitment(
                            &mut output_acc,
                            &state[lane].to_le_bytes()[..end - lane * 8],
                        );
                    }
                }
            }
            for (slot, value) in slots.into_iter().enumerate() {
                for z in 0..64 {
                    fields[BITS + slot * 64 + z] = Val::from_u64((value >> z) & 1);
                }
            }
            hashes.push(hash);
        }
        let hash_trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            hashes,
            &round_constants(),
            0,
        );
        for (index, fields) in values.chunks_exact_mut(WIDTH).enumerate() {
            fields[POSEIDON..].copy_from_slice(
                &hash_trace.values[index * POSEIDON_WIDTH..(index + 1) * POSEIDON_WIDTH],
            );
        }
        assert_eq!(&limbs(&state), &public[END_STATE..INPUT_START]);
        assert_eq!(&input_acc, &public[INPUT_END..OUTPUT_START]);
        assert_eq!(&output_acc, &public[OUTPUT_END..]);
        Ok(SegmentWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values: public,
        })
    }
}
