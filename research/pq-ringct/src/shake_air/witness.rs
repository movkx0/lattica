use super::*;

pub struct SegmentWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
}

struct PermutationData {
    message: [u8; RATE],
    input: [u64; 25],
    output: [u64; 25],
    raw: usize,
    take: usize,
}

fn limbs(state: &[u64; 25]) -> [Val; 100] {
    core::array::from_fn(|i| Val::from_u16((state[i / 4] >> (16 * (i % 4))) as u16))
}

fn state_bytes(state: &[u64; 25]) -> [u8; 200] {
    core::array::from_fn(|i| (state[i / 8] >> (8 * (i % 8))) as u8)
}

impl ShakeAir {
    /// Independent verifier endpoint calculation with constant working storage.
    /// This does not build a private trace and is never used to prove on GPU.
    pub fn expected_public_values(&self, input: &[u8]) -> Result<[Val; PUBLIC_VALUES], Error> {
        if input.len() != self.descriptor.input_len {
            return Err(Error::Length);
        }
        let mut state = [0u64; 25];
        let mut input_acc = [
            Val::from_u64(SHAKE_INPUT_DOMAIN),
            Val::from_usize(input.len()),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut output_acc = [
            Val::from_u64(SHAKE_OUTPUT_DOMAIN),
            Val::from_usize(self.descriptor.output_len),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut public = [Val::ZERO; PUBLIC_VALUES];
        for permutation in 0..self.first_permutation + self.permutations {
            if permutation == self.first_permutation {
                public[START_STATE..END_STATE].copy_from_slice(&limbs(&state));
                public[INPUT_START..INPUT_END].copy_from_slice(&input_acc);
                public[OUTPUT_START..OUTPUT_END].copy_from_slice(&output_acc);
            }
            let raw = self.descriptor.input_bytes(permutation);
            let take = self.descriptor.output_bytes(permutation);
            let mut message = [0u8; RATE];
            if raw != 0 {
                let offset = permutation * RATE;
                message[..raw].copy_from_slice(&input[offset..offset + raw]);
            }
            if permutation == self.descriptor.absorb_permutations() - 1 {
                message[raw] ^= 0x1f;
                message[RATE - 1] ^= 0x80;
            }
            for (i, &byte) in message.iter().enumerate() {
                state[i / 8] ^= u64::from(byte) << (8 * (i % 8));
            }
            keccak(&mut state);
            for chunk in message[..raw].chunks(8) {
                absorb_commitment(&mut input_acc, chunk);
            }
            let output = state_bytes(&state);
            for chunk in output[..take].chunks(8) {
                absorb_commitment(&mut output_acc, chunk);
            }
        }
        public[END_STATE..INPUT_START].copy_from_slice(&limbs(&state));
        public[INPUT_END..OUTPUT_START].copy_from_slice(&input_acc);
        public[OUTPUT_END..].copy_from_slice(&output_acc);
        Ok(public)
    }
    pub fn generate(&self, input: &[u8]) -> Result<SegmentWitness, Error> {
        if input.len() != self.descriptor.input_len {
            return Err(Error::Length);
        }
        let mut state = [0u64; 25];
        let mut input_acc = [
            Val::from_u64(SHAKE_INPUT_DOMAIN),
            Val::from_usize(input.len()),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut output_acc = [
            Val::from_u64(SHAKE_OUTPUT_DOMAIN),
            Val::from_usize(self.descriptor.output_len),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut public = [Val::ZERO; PUBLIC_VALUES];
        let mut permutations = Vec::with_capacity(self.permutations);
        let end = self.first_permutation + self.permutations;
        for permutation in 0..end {
            if permutation == self.first_permutation {
                public[START_STATE..END_STATE].copy_from_slice(&limbs(&state));
                public[INPUT_START..INPUT_END].copy_from_slice(&input_acc);
                public[OUTPUT_START..OUTPUT_END].copy_from_slice(&output_acc);
            }
            let raw = self.descriptor.input_bytes(permutation);
            let take = self.descriptor.output_bytes(permutation);
            let mut message = [0u8; RATE];
            if raw != 0 {
                let offset = permutation * RATE;
                message[..raw].copy_from_slice(&input[offset..offset + raw]);
            }
            if permutation == self.descriptor.absorb_permutations() - 1 {
                message[raw] ^= 0x1f;
                message[RATE - 1] ^= 0x80;
            }
            for (i, byte) in message.iter().enumerate() {
                state[i / 8] ^= u64::from(*byte) << (8 * (i % 8));
            }
            let before = state;
            keccak(&mut state);
            for chunk in message[..raw].chunks(8) {
                let _ = absorb_commitment(&mut input_acc, chunk);
            }
            let output = state_bytes(&state);
            for chunk in output[..take].chunks(8) {
                let _ = absorb_commitment(&mut output_acc, chunk);
            }
            if permutation >= self.first_permutation {
                permutations.push(PermutationData {
                    message,
                    input: before,
                    output: state,
                    raw,
                    take,
                });
            }
        }
        public[END_STATE..INPUT_START].copy_from_slice(&limbs(&state));
        public[INPUT_END..OUTPUT_START].copy_from_slice(&input_acc);
        public[OUTPUT_END..].copy_from_slice(&output_acc);

        let keccak_inputs = permutations.iter().map(|p| p.input).collect();
        let keccak_trace = p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs, 0);
        assert_eq!(keccak_trace.values.len(), self.height * NUM_KECCAK_COLS);
        let mut values = Val::zero_vec(self.height * WIDTH);
        let mut input_poseidon = Vec::with_capacity(self.height);
        let mut output_poseidon = Vec::with_capacity(self.height);
        input_acc.copy_from_slice(&public[INPUT_START..INPUT_END]);
        output_acc.copy_from_slice(&public[OUTPUT_START..OUTPUT_END]);
        let mut empty_output = [0u64; 25];
        keccak(&mut empty_output);
        let padding = PermutationData {
            message: [0; RATE],
            input: [0; 25],
            output: empty_output,
            raw: 0,
            take: 0,
        };

        for (row, fields) in values.chunks_exact_mut(WIDTH).enumerate() {
            fields[..NUM_KECCAK_COLS].copy_from_slice(
                &keccak_trace.values[row * NUM_KECCAK_COLS..(row + 1) * NUM_KECCAK_COLS],
            );
            let data = permutations.get(row / 24).unwrap_or(&padding);
            let round = row % 24;
            for i in 0..1088 {
                fields[MESSAGE + i] = Val::from_u8((data.message[i / 8] >> (i % 8)) & 1);
            }
            let output_limbs = limbs(&data.output);
            fields[OUTPUT..ODD_BITS].copy_from_slice(&output_limbs);
            let partial = output_limbs[self.odd_output_limb()].as_canonical_u64();
            for i in 0..16 {
                fields[ODD_BITS + i] = Val::from_u64((partial >> i) & 1);
            }
            fields[INPUT_ACC..OUTPUT_ACC].copy_from_slice(&input_acc);
            fields[OUTPUT_ACC..INPUT_POSEIDON].copy_from_slice(&output_acc);
            let output_bytes = state_bytes(&data.output);
            for (acc, count, bytes, inputs) in [
                (
                    &mut input_acc,
                    data.raw,
                    data.message.as_slice(),
                    &mut input_poseidon,
                ),
                (
                    &mut output_acc,
                    data.take,
                    output_bytes.as_slice(),
                    &mut output_poseidon,
                ),
            ] {
                let start = (round * 8).min(count);
                let end = (start + 8).min(count);
                let mut updated = *acc;
                inputs.push(absorb_commitment(&mut updated, &bytes[start..end]));
                if round * 8 < count {
                    *acc = updated;
                }
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
        Ok(SegmentWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values: public,
        })
    }
}

// Independent integer implementation used solely to populate trace witnesses.
// Every round is checked by p3-keccak-air and differential tests use RustCrypto
// SHAKE256, including rate boundaries and multi-block squeeze output.
fn keccak(a: &mut [u64; 25]) {
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    for rc in RC {
        let c: [u64; 5] =
            core::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut rotated = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = rotated[x + 5 * y]
                    ^ ((!rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}
