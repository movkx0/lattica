use super::*;

impl BatchShakeAir {
    pub fn generate(&self, input: &[u8]) -> Result<SegmentWitness, Error> {
        let mut values = Val::zero_vec(self.height * WIDTH);
        let mut public = [Val::ZERO; PUBLIC_VALUES];
        let mut scratch = [0u64; 25];
        for local in 0..self.permutations {
            let permutation = self.first_permutation + local;
            let component = LaneShakeAir::new(self.descriptor, permutation)?.generate(input)?;
            if local == 0 {
                public[START_STATE..END_STATE]
                    .copy_from_slice(&component.public_values[START_STATE..END_STATE]);
                public[INPUT_START..INPUT_END]
                    .copy_from_slice(&component.public_values[INPUT_START..INPUT_END]);
                public[OUTPUT_START..OUTPUT_END]
                    .copy_from_slice(&component.public_values[OUTPUT_START..OUTPUT_END]);
            } else {
                assert_eq!(
                    &public[END_STATE..INPUT_START],
                    &component.public_values[START_STATE..END_STATE]
                );
                assert_eq!(
                    &public[INPUT_END..OUTPUT_START],
                    &component.public_values[INPUT_START..INPUT_END]
                );
                assert_eq!(
                    &public[OUTPUT_END..],
                    &component.public_values[OUTPUT_START..OUTPUT_END]
                );
            }
            public[END_STATE..INPUT_START]
                .copy_from_slice(&component.public_values[END_STATE..INPUT_START]);
            public[INPUT_END..OUTPUT_START]
                .copy_from_slice(&component.public_values[INPUT_END..OUTPUT_START]);
            public[OUTPUT_END..].copy_from_slice(&component.public_values[OUTPUT_END..]);
            for row in 0..HEIGHT {
                let start = (local * HEIGHT + row) * WIDTH;
                let fields = &mut values[start..start + WIDTH];
                fields[..super::super::WIDTH].copy_from_slice(
                    &component.trace.values
                        [row * super::super::WIDTH..(row + 1) * super::super::WIDTH],
                );
                fields[PERMUTATION] = Val::from_usize(permutation);
                // A single component starts scratch at zero. A batch carries
                // all scratch words instead; theta overwrites C before use.
                for i in 0..100 {
                    fields[SCRATCH + i] = Val::from_u16((scratch[i / 4] >> (16 * (i % 4))) as u16);
                }
                let state = |lane: usize| -> u64 {
                    (0..4)
                        .map(|i| fields[STATE + lane * 4 + i].as_canonical_u64() << (16 * i))
                        .sum()
                };
                let block = row / SCHEDULE_PERIOD;
                let step = row % SCHEDULE_PERIOD;
                if (1..=24).contains(&block) {
                    if step < 25 {
                        let x = step / 5;
                        let y = step % 5;
                        let word = state(y * 5 + x);
                        for z in 0..64 {
                            fields[BITS + 64 + z] = Val::from_u64((scratch[x] >> z) & 1);
                        }
                        scratch[x] = if y == 0 { word } else { scratch[x] ^ word };
                    } else if (50..75).contains(&step) {
                        let lane = step - 50;
                        let x = lane % 5;
                        let y = lane / 5;
                        scratch[((2 * x + 3 * y) % 5) * 5 + y] = state(lane).rotate_left(ROT[lane]);
                    }
                }
            }
        }
        Ok(SegmentWitness {
            trace: RowMajorMatrix::new(values, WIDTH),
            public_values: public,
        })
    }
}
