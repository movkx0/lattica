use super::*;
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};

pub struct SegmentWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    /// Ciphertext bytes produced by this segment only.
    pub output: Vec<u8>,
}
fn bits(row: &mut [Val], start: usize, value: u64, count: usize) {
    for bit in 0..count {
        row[start + bit] = Val::from_u8(((value >> bit) & 1) as u8);
    }
}
fn scalar_bytes(row: &mut [Val], start: usize, bytes: &[u8]) {
    for (i, &byte) in bytes.iter().enumerate() {
        row[start + i] = Val::from_u8(byte);
    }
}
impl AesLaneAir {
    pub fn generate(&self, key: [u8; 32]) -> Result<SegmentWitness, Error> {
        let cipher = Aes256::new((&key).into());
        let header = self.descriptor.input_bytes(&key);
        let mut complete_output = Vec::with_capacity(self.descriptor.output_len);
        for block in 0..self.descriptor.blocks() {
            let mut plaintext = [0_u8; 16];
            plaintext[..4].copy_from_slice(
                &self
                    .descriptor
                    .start_counter
                    .wrapping_add(block as u32)
                    .to_le_bytes(),
            );
            plaintext[8..].copy_from_slice(&self.descriptor.domain.to_le_bytes());
            let mut encrypted = plaintext.into();
            cipher.encrypt_block(&mut encrypted);
            let take = (self.descriptor.output_len - block * 16).min(16);
            complete_output.extend_from_slice(&encrypted[..take]);
        }
        let output = complete_output[self.first_block * 16
            ..((self.first_block + self.blocks) * 16).min(self.descriptor.output_len)]
            .to_vec();
        let mut input_acc = [
            Val::from_u64(AES_INPUT_DOMAIN),
            Val::from_u64(52),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut output_acc = [
            Val::from_u64(AES_OUTPUT_DOMAIN),
            Val::from_usize(self.descriptor.output_len),
            Val::ZERO,
            Val::ZERO,
        ];
        for chunk in complete_output[..self.first_block * 16].chunks(8) {
            let _ = absorb_commitment(&mut output_acc, chunk);
        }
        let output_start = output_acc;
        let mut values = Val::zero_vec(self.height * WIDTH);
        let mut permutations = Vec::with_capacity(self.height);
        let mut rolling = key;
        let mut state = [0_u8; 16];
        let mut scratch = [0_u8; 16];
        let mut counter = self
            .descriptor
            .start_counter
            .wrapping_add(self.first_block as u32);
        let mut block = self.first_block;
        let mut remaining = self.blocks;
        for index in 0..self.height {
            let local = index % ROWS_PER_BLOCK;
            let phase = local / SCHEDULE_PERIOD;
            let active = remaining != 0;
            let row = &mut values[index * WIDTH..(index + 1) * WIDTH];
            scalar_bytes(row, ROOT_KEY, &key);
            scalar_bytes(row, KEY, &rolling);
            scalar_bytes(row, STATE, &state);
            scalar_bytes(row, SCRATCH, &scratch);
            bits(row, COUNTER_BITS, u64::from(counter), 32);
            row[BLOCK_INDEX] = Val::from_usize(block);
            row[REMAINING] = Val::from_usize(remaining);
            row[ACTIVE] = Val::from_bool(active);
            row[ACTIVE_INV] = if active {
                Val::from_usize(remaining).inverse()
            } else {
                Val::ZERO
            };
            for (flag, inverse, root) in [
                (FIRST, FIRST_INV, self.first_block),
                (LAST, LAST_INV, self.descriptor.blocks() - 1),
            ] {
                let difference = Val::from_usize(block) - Val::from_usize(root);
                row[flag] = Val::from_bool(block == root);
                row[inverse] = if block == root {
                    Val::ZERO
                } else {
                    difference.inverse()
                };
            }
            row[INPUT_ACC..INPUT_ACC + 4].copy_from_slice(&input_acc);
            row[OUTPUT_ACC..OUTPUT_ACC + 4].copy_from_slice(&output_acc);
            bits(row, PHASE_BITS, phase as u64, 4);
            row[PRELUDE] = Val::from_bool(phase == 0);
            row[ROUNDS] = Val::from_bool((1..15).contains(&phase));
            row[FINAL_ROUND] = Val::from_bool(phase == 14);
            row[OUTPUT_PHASE] = Val::from_bool(phase == 15);
            let rcon = gf_pow(2, (phase.saturating_sub(1) / 2) as u16);
            bits(row, RCON_BITS, u64::from(rcon), 8);
            let mut read = [0_u8; 8];
            let mut result = 0_u8;
            let mut parity = [0_u64; 8];
            let mut permutation = [Val::ZERO; 8];
            if active {
                if local < 7 && block == self.first_block {
                    let start = local * 8;
                    let end = (start + 8).min(52);
                    read[..end - start].copy_from_slice(&header[start..end]);
                    permutation = absorb_commitment(&mut input_acc, &header[start..end]);
                } else if (16..32).contains(&local) {
                    let i = local - 16;
                    read[0] = if i < 4 {
                        counter.to_le_bytes()[i]
                    } else if i < 8 {
                        0
                    } else {
                        self.descriptor.domain.to_le_bytes()[i - 8]
                    };
                    read[1] = key[i];
                    for bit in 0..8 {
                        parity[bit] =
                            u64::from((read[0] >> bit) & 1) + u64::from((read[1] >> bit) & 1);
                    }
                    result = read[0] ^ read[1];
                    state[i] = result;
                } else if (64..64 + 14 * 64).contains(&local) {
                    let round = (local - 64) / 64;
                    let phase = (local - 64) % 64;
                    let i = phase % 16;
                    if phase < 16 {
                        read[0] = state[i];
                        result = crate::aes_air::witness::sbox_witness(row, SBOX, read[0]);
                        scratch[i] = result;
                    } else if phase < 32 {
                        for source in 0..4 {
                            read[source] = scratch[shifted_byte(4 * (i / 4) + source)];
                        }
                        read[4] = rolling[16 + i];
                        for bit in 0..8 {
                            let mut sum = u64::from((read[4] >> bit) & 1);
                            if round == 13 {
                                sum += u64::from((read[i % 4] >> bit) & 1);
                            } else {
                                for source in 0..4 {
                                    for source_bit in 0..8 {
                                        let coefficient = [2, 3, 1, 1][(source + 4 - i % 4) % 4];
                                        if gf_mul(coefficient, 1 << source_bit) & (1 << bit) != 0 {
                                            sum += u64::from((read[source] >> source_bit) & 1);
                                        }
                                    }
                                }
                            }
                            parity[bit] = sum;
                            result |= ((sum & 1) as u8) << bit;
                        }
                        state[i] = result;
                    } else if phase < 48 {
                        let transformed;
                        let rc = if round % 2 == 0 && i == 0 {
                            gf_pow(2, (round / 2) as u16)
                        } else {
                            0
                        };
                        if i < 4 {
                            read[0] = rolling[28 + if round % 2 == 0 { (i + 1) % 4 } else { i }];
                            read[1] = rolling[i];
                            transformed = crate::aes_air::witness::sbox_witness(row, SBOX, read[0]);
                        } else {
                            read[0] = rolling[i];
                            read[1] = scratch[i - 4];
                            transformed = read[0];
                        }
                        for bit in 0..8 {
                            parity[bit] = u64::from((transformed >> bit) & 1)
                                + u64::from((read[1] >> bit) & 1)
                                + u64::from((rc >> bit) & 1);
                        }
                        result = transformed ^ read[1] ^ rc;
                        scratch[i] = result;
                        if phase == 47 {
                            rolling.copy_within(16..32, 0);
                            rolling[16..].copy_from_slice(&scratch);
                        }
                    }
                } else if local == 960 || local == 961 {
                    if local == 960 {
                        let take = (self.descriptor.output_len - block * 16).min(16);
                        assert_eq!(
                            &state[..take],
                            &complete_output[block * 16..block * 16 + take],
                            "serial constrained AES must match RustCrypto"
                        );
                    }
                    let start = block * 16 + (local - 960) * 8;
                    if start < self.descriptor.output_len {
                        let end = (start + 8).min(self.descriptor.output_len);
                        read[..end - start].copy_from_slice(&complete_output[start..end]);
                        permutation =
                            absorb_commitment(&mut output_acc, &complete_output[start..end]);
                    }
                } else if local == ROWS_PER_BLOCK - 1 {
                    row[COUNTER_CARRY] = Val::from_bool(counter == u32::MAX);
                    counter = counter.wrapping_add(1);
                    block += 1;
                    remaining -= 1;
                    rolling = key;
                    state = [0; 16];
                    scratch = [0; 16];
                }
            }
            for byte in 0..8 {
                bits(row, READ + 8 * byte, u64::from(read[byte]), 8);
            }
            bits(row, RESULT, u64::from(result), 8);
            for bit in 0..8 {
                bits(row, CARRY + 3 * bit, parity[bit] / 2, 3);
            }
            permutations.push(permutation);
        }
        let poseidon = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
            permutations,
            &round_constants(),
            0,
        );
        for (i, row) in values.chunks_exact_mut(WIDTH).enumerate() {
            row[POSEIDON..]
                .copy_from_slice(&poseidon.values[i * POSEIDON_WIDTH..(i + 1) * POSEIDON_WIDTH]);
        }
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        public_values[INPUT_COMMITMENT..INPUT_COMMITMENT + 4].copy_from_slice(&input_acc);
        public_values[OUTPUT_START..OUTPUT_START + 4].copy_from_slice(&output_start);
        public_values[OUTPUT_END..OUTPUT_END + 4].copy_from_slice(&output_acc);
        Ok(SegmentWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values,
            output,
        })
    }
}
