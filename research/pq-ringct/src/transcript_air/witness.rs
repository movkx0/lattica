use super::*;
pub struct TranscriptWitness {
    pub trace: RowMajorMatrix<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
}
impl TranscriptAir {
    pub fn generate(&self, values: &[PartValues]) -> Result<TranscriptWitness, &'static str> {
        if values.len() != self.parts.len() {
            return Err("transcript source count");
        }
        let words = self
            .parts
            .iter()
            .zip(values)
            .map(|(&kind, value)| value.words(kind))
            .collect::<Result<Vec<_>, _>>()?;
        let mut trace = Val::zero_vec(self.height * self.width());
        let mut source_acc = self.parts[0].initial();
        let mut byte_acc = self.byte_initial();
        let mut bundle_acc = self.bundle_initial();
        let mut buffer = [Val::ZERO; 2];
        let mut source_inputs = Vec::with_capacity(self.height);
        let mut byte_inputs = Vec::with_capacity(self.height);
        let mut bundle_inputs = Vec::with_capacity(self.height);
        for index in 0..self.height {
            let part = index / ROWS_PER_PART;
            let row = index % ROWS_PER_PART;
            let kind = self.parts.get(part).copied();
            let class = kind.map(|k| k.index()).unwrap_or(3);
            let active = kind.is_some_and(|k| k != PartKind::Bytes32 || row < 4);
            let data = &mut trace[index * self.width()..(index + 1) * self.width()];
            data[COUNTER] = Val::from_usize(part);
            data[self.class() + class] = Val::ONE;
            for (i, event) in self.events.iter().enumerate() {
                let difference = Val::from_usize(part) - Val::from_usize(event.at);
                data[EVENTS + i] = Val::from_bool(part == event.at);
                data[self.inverse() + i] = difference.try_inverse().unwrap_or(Val::ZERO);
            }
            data[BUFFER..COUNTER].copy_from_slice(&buffer);
            data[self.source_acc()..self.byte_acc()].copy_from_slice(&source_acc);
            data[self.byte_acc()..self.bundle_acc()].copy_from_slice(&byte_acc);
            data[self.bundle_acc()..self.source_poseidon()].copy_from_slice(&bundle_acc);
            let pair: [u32; 2] = core::array::from_fn(|slot| {
                words
                    .get(part)
                    .and_then(|v| v.get(2 * row + slot))
                    .copied()
                    .unwrap_or(0)
            });
            let maximum = if active {
                kind.unwrap().modulus() - 1
            } else {
                0
            };
            for slot in 0..2 {
                data[WORD + slot] = Val::from_u32(pair[slot]);
                for bit in 0..32 {
                    data[BITS + 32 * slot + bit] = Val::from_u32((pair[slot] >> bit) & 1);
                }
                let mut prefix = true;
                for step in 0..8 {
                    let shift = 4 * (7 - step);
                    prefix &= ((u64::from(pair[slot]) >> shift) & 15) == ((maximum >> shift) & 15);
                    data[PREFIX + 8 * slot + step] = Val::from_bool(prefix);
                }
            }
            let limbs = [
                Val::from_u16(pair[0] as u16),
                Val::from_u16((pair[0] >> 16) as u16),
                Val::from_u16(pair[1] as u16),
                Val::from_u16((pair[1] >> 16) as u16),
            ];
            if row == 0 {
                source_acc = kind.map(|k| k.initial()).unwrap_or([Val::ZERO; 4]);
            }
            let source_hash = kind.is_some_and(|k| {
                if k == PartKind::Bytes32 {
                    row < 4
                } else {
                    row % 2 == 1
                }
            });
            let source_chunk = if kind == Some(PartKind::Bytes32) && row < 4 {
                limbs
            } else if source_hash {
                [
                    buffer[0],
                    buffer[1],
                    Val::from_u32(pair[0]),
                    Val::from_u32(pair[1]),
                ]
            } else {
                [Val::ZERO; 4]
            };
            let mut updated = source_acc;
            source_inputs.push(absorb(&mut updated, source_chunk));
            if source_hash {
                source_acc = updated;
            }
            let mut updated = byte_acc;
            byte_inputs.push(absorb(
                &mut updated,
                if active { limbs } else { [Val::ZERO; 4] },
            ));
            if active {
                byte_acc = updated;
            }
            let bundle_chunk = if row == 0 {
                kind.map(|k| Self::metadata(k, part))
                    .unwrap_or([Val::ZERO; 4])
            } else if row == 127 && kind.is_some() {
                source_acc
            } else {
                [Val::ZERO; 4]
            };
            let mut updated = bundle_acc;
            bundle_inputs.push(absorb(&mut updated, bundle_chunk));
            if kind.is_some() && (row == 0 || row == 127) {
                bundle_acc = updated;
            }
            buffer = if row % 2 == 0 {
                pair.map(Val::from_u32)
            } else {
                [Val::ZERO; 2]
            };
        }
        for (start, inputs) in [
            (self.source_poseidon(), source_inputs),
            (self.byte_poseidon(), byte_inputs),
            (self.bundle_poseidon(), bundle_inputs),
        ] {
            let p = p3_poseidon2_air::generate_trace_rows::<Val, Linear, 8, 7, 0, 4, 22>(
                inputs,
                &round_constants(),
                0,
            );
            for (i, row) in trace.chunks_exact_mut(self.width()).enumerate() {
                row[start..start + POSEIDON_WIDTH]
                    .copy_from_slice(&p.values[i * POSEIDON_WIDTH..(i + 1) * POSEIDON_WIDTH]);
            }
        }
        let mut public_values = [Val::ZERO; PUBLIC_VALUES];
        public_values[..4].copy_from_slice(&bundle_acc);
        public_values[4..].copy_from_slice(&byte_acc);
        Ok(TranscriptWitness {
            trace: RowMajorMatrix::new(trace, self.width()),
            public_values,
        })
    }
}
