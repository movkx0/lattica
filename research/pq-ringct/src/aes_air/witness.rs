use super::*;
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};

pub struct AesWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub output: Vec<u8>,
}

fn bits(row: &mut [Val], start: usize, value: u64, count: usize) {
    for bit in 0..count {
        row[start + bit] = Val::from_u8(((value >> bit) & 1) as u8);
    }
}
fn bytes(row: &mut [Val], start: usize, value: &[u8]) {
    for (i, &byte) in value.iter().enumerate() {
        bits(row, start + i * 8, u64::from(byte), 8);
    }
}
pub(crate) fn sbox_witness(row: &mut [Val], start: usize, input: u8) -> u8 {
    let inverse = gf_pow(input, 254);
    bits(row, start + INV, u64::from(inverse), 8);
    row[start + ZERO] = Val::from_bool(input == 0);
    row[start + FIELD_INV] = if input == 0 {
        Val::ZERO
    } else {
        Val::from_u8(input).inverse()
    };
    let mut output = 0;
    for bit in 0..8 {
        let mut sum = 0_u64;
        for i in 0..8 {
            for j in 0..8 {
                if reduction(i + j) & (1 << bit) != 0 {
                    sum += u64::from((input >> i) & 1) * u64::from((inverse >> j) & 1);
                }
            }
        }
        let expected = u64::from(input != 0 && bit == 0);
        assert!(sum >= expected && (sum - expected) % 2 == 0);
        bits(row, start + GF_CARRY + 4 * bit, (sum - expected) / 2, 4);
        let affine = u64::from((0x63_u8 >> bit) & 1)
            + [0, 4, 5, 6, 7]
                .into_iter()
                .map(|offset| u64::from((inverse >> ((bit + offset) % 8)) & 1))
                .sum::<u64>();
        output |= ((affine & 1) as u8) << bit;
        bits(row, start + AFFINE_CARRY + 2 * bit, affine / 2, 2);
    }
    bits(row, start + SBOX_OUT, u64::from(output), 8);
    output
}

impl AesAir {
    pub fn generate(&self, key: [u8; 32]) -> Result<AesWitness, Error> {
        let cipher = Aes256::new((&key).into());
        let header = self.descriptor.input_bytes(&key);
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
        let mut input_poseidon = Vec::with_capacity(self.height);
        let mut output_poseidon = Vec::with_capacity(self.height);
        let mut values = Val::zero_vec(self.height * WIDTH);
        let mut output = Vec::with_capacity(self.descriptor.output_len);
        for block in 0..self.descriptor.blocks() {
            let plaintext = self.descriptor.counter(block);
            let mut native = plaintext.into();
            cipher.encrypt_block(&mut native);
            let ciphertext: [u8; 16] = native.into();
            let take = self
                .descriptor
                .output_len
                .saturating_sub(block * 16)
                .min(16);
            output.extend_from_slice(&ciphertext[..take]);
            let mut rolling = key;
            let mut state: [u8; 16] = core::array::from_fn(|i| plaintext[i] ^ key[i]);
            for round in 0..14 {
                let index = block * 14 + round;
                let row = &mut values[index * WIDTH..(index + 1) * WIDTH];
                bits(
                    row,
                    COUNTER_BITS,
                    u64::from(self.descriptor.start_counter.wrapping_add(block as u32)),
                    32,
                );
                bytes(row, ROOT_KEY, &key);
                bytes(row, KEY, &rolling);
                bytes(row, STATE, &state);
                bytes(row, CIPHER, &ciphertext);
                let substituted: [u8; 16] = core::array::from_fn(|i| {
                    sbox_witness(row, STATE_SBOX + i * SBOX_WIDTH, state[i])
                });
                let key_sub: [u8; 4] = core::array::from_fn(|i| {
                    sbox_witness(
                        row,
                        KEY_SBOX + i * SBOX_WIDTH,
                        rolling[28 + if round % 2 == 0 { (i + 1) % 4 } else { i }],
                    )
                });
                let rcon = if round % 2 == 0 {
                    gf_pow(2, (round / 2) as u16)
                } else {
                    0
                };
                let mut next_key = [0_u8; 16];
                for i in 0..16 {
                    let temp = if i < 4 { key_sub[i] } else { next_key[i - 4] };
                    let rc = if i == 0 { rcon } else { 0 };
                    next_key[i] = rolling[i] ^ temp ^ rc;
                    for bit in 0..8 {
                        let sum = u64::from((rolling[i] >> bit) & 1)
                            + u64::from((temp >> bit) & 1)
                            + u64::from((rc >> bit) & 1);
                        bits(row, KEY_CARRY + i * 8 + bit, sum / 2, 1);
                    }
                }
                bytes(row, NEXT_KEY, &next_key);
                let shifted: [u8; 16] = core::array::from_fn(|i| substituted[shifted_byte(i)]);
                let mut next_state = [0_u8; 16];
                for byte in 0..16 {
                    for bit in 0..8 {
                        let mut sum = u64::from((rolling[16 + byte] >> bit) & 1);
                        if round == 13 {
                            sum += u64::from((shifted[byte] >> bit) & 1);
                        } else {
                            for source in 0..4 {
                                let coefficient = [2_u8, 3, 1, 1][(source + 4 - byte % 4) % 4];
                                for source_bit in 0..8 {
                                    if gf_mul(coefficient, 1 << source_bit) & (1 << bit) != 0 {
                                        sum += u64::from(
                                            (shifted[byte / 4 * 4 + source] >> source_bit) & 1,
                                        );
                                    }
                                }
                            }
                        }
                        next_state[byte] |= ((sum & 1) as u8) << bit;
                        bits(row, STATE_CARRY + (byte * 8 + bit) * 3, sum / 2, 3);
                    }
                }
                bytes(row, STATE_OUT, &next_state);
                state = next_state;
                rolling.copy_within(16..32, 0);
                rolling[16..].copy_from_slice(&next_key);
                row[INPUT_ACC..OUTPUT_ACC].copy_from_slice(&input_acc);
                row[OUTPUT_ACC..INPUT_POSEIDON].copy_from_slice(&output_acc);
                let input_chunk = if block == 0 && round < 7 {
                    &header[round * 8..((round + 1) * 8).min(header.len())]
                } else {
                    &[]
                };
                let output_chunk = if round < 2 && round * 8 < take {
                    &ciphertext[round * 8..((round + 1) * 8).min(take)]
                } else {
                    &[]
                };
                for (acc, chunk, permutations) in [
                    (&mut input_acc, input_chunk, &mut input_poseidon),
                    (&mut output_acc, output_chunk, &mut output_poseidon),
                ] {
                    let mut updated = *acc;
                    permutations.push(absorb_commitment(&mut updated, chunk));
                    if !chunk.is_empty() {
                        *acc = updated;
                    }
                }
            }
            assert_eq!(
                state, ciphertext,
                "independent AES round witness must match RustCrypto"
            );
        }
        for index in self.descriptor.blocks() * 14..self.height {
            let row = &mut values[index * WIDTH..(index + 1) * WIDTH];
            row[INPUT_ACC..OUTPUT_ACC].copy_from_slice(&input_acc);
            row[OUTPUT_ACC..INPUT_POSEIDON].copy_from_slice(&output_acc);
            for (acc, permutations) in [
                (&mut input_acc, &mut input_poseidon),
                (&mut output_acc, &mut output_poseidon),
            ] {
                let mut unchanged = *acc;
                permutations.push(absorb_commitment(&mut unchanged, &[]));
            }
        }
        for (start, inputs) in [
            (INPUT_POSEIDON, input_poseidon),
            (OUTPUT_POSEIDON, output_poseidon),
        ] {
            let trace = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
                inputs,
                &round_constants(),
                0,
            );
            for (row, fields) in values.chunks_exact_mut(WIDTH).enumerate() {
                fields[start..start + POSEIDON_WIDTH].copy_from_slice(
                    &trace.values[row * POSEIDON_WIDTH..(row + 1) * POSEIDON_WIDTH],
                );
            }
        }
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        public_values[..4].copy_from_slice(&input_acc);
        public_values[4..].copy_from_slice(&output_acc);
        Ok(AesWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values,
            output,
        })
    }
}
