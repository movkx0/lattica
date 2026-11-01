//! Streaming local-control hashing with the exact `hash_fields` framing.
//! Working storage does not grow with payload length. The slice implementation
//! remains unchanged as an independent protocol reference.
use super::*;

/// Single-use streaming sponge. A prefix retains its partial rate block and
/// is framed with the length of the *complete* message, including its suffix.
pub(crate) struct State {
    permutation: p3_goldilocks::Poseidon2Goldilocks<8>,
    capacity: [Goldilocks; 4],
    rate: [Goldilocks; 4],
    used: usize,
    remaining: usize,
}
impl State {
    pub(crate) fn new(domain: u64, count: usize) -> Result<Self, String> {
        if domain >= MODULUS {
            return Err(CommitmentError::NonCanonicalField.to_string());
        }
        let len = u64::try_from(count).map_err(|_| CommitmentError::InvalidLength.to_string())?;
        if len >= MODULUS {
            return Err(CommitmentError::InvalidLength.to_string());
        }
        // Construct the public round tables once, not once per rate block.
        // The Linux CPU worker path admits these bounded allocations and
        // propagates allocation failure through the scoped worker join.
        #[cfg(not(target_arch = "aarch64"))]
        let permutation = {
            use p3_goldilocks::{
                GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
                GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
                GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
            };
            fn table<T: Copy>(values: &[T]) -> Result<Vec<T>, String> {
                let mut table = Vec::new();
                table
                    .try_reserve_exact(values.len())
                    .map_err(|_| "CPU identity round-table allocation")?;
                table.extend_from_slice(values);
                Ok(table)
            }
            p3_goldilocks::Poseidon2Goldilocks::<8>::new(
                p3_poseidon2::ExternalLayerConstants::new(table(&INITIAL)?, table(&FINAL)?),
                table(&INTERNAL)?,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let permutation = default_goldilocks_poseidon2_8();
        Ok(Self {
            permutation,
            capacity: [domain, len, 0, 0].map(Goldilocks::from_u64),
            rate: [Goldilocks::ZERO; 4],
            used: 0,
            remaining: count,
        })
    }
    pub(crate) fn retained_heap_bytes(&self) -> usize {
        use p3_goldilocks::{
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
            GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
        };
        core::mem::size_of_val(&INITIAL)
            + core::mem::size_of_val(&FINAL)
            + core::mem::size_of_val(&INTERNAL)
    }
    pub(crate) fn push(&mut self, field: u64) -> Result<(), CommitmentError> {
        if self.remaining == 0 {
            return Err(CommitmentError::InvalidLength);
        }
        if field >= MODULUS {
            return Err(CommitmentError::NonCanonicalField);
        }
        self.rate[self.used] = Goldilocks::from_u64(field);
        self.used += 1;
        self.remaining -= 1;
        if self.used == 4 {
            self.permute();
        }
        Ok(())
    }
    fn permute(&mut self) {
        let mut input = [Goldilocks::ZERO; 8];
        input[..4].copy_from_slice(&self.capacity);
        input[4..].copy_from_slice(&self.rate);
        self.permutation.permute_mut(&mut input);
        self.capacity.copy_from_slice(&input[..4]);
        self.rate = [Goldilocks::ZERO; 4];
        self.used = 0;
    }
    pub(crate) fn finish(mut self) -> Result<Digest, CommitmentError> {
        if self.remaining != 0 {
            return Err(CommitmentError::InvalidLength);
        }
        if self.used != 0 {
            self.permute();
        }
        Ok(self.capacity.map(|v| v.as_canonical_u64()))
    }
}

pub(crate) fn words(bytes: &[u8]) -> impl Iterator<Item = u64> + '_ {
    bytes.chunks(4).map(|part| {
        let mut word = [0; 4];
        word[..part.len()].copy_from_slice(part);
        u64::from(u32::from_le_bytes(word))
    })
}

pub(crate) fn hash_fields(
    domain: u64,
    count: usize,
    fields: impl IntoIterator<Item = u64>,
) -> Result<Digest, CommitmentError> {
    if domain >= MODULUS {
        return Err(CommitmentError::NonCanonicalField);
    }
    let len = u64::try_from(count).map_err(|_| CommitmentError::InvalidLength)?;
    if len >= MODULUS {
        return Err(CommitmentError::InvalidLength);
    }
    let mut fields = fields.into_iter();
    let mut state = [domain, len, 0, 0].map(Goldilocks::from_u64);
    let permutation = default_goldilocks_poseidon2_8();
    let mut left = count;
    while left != 0 {
        let n = left.min(4);
        let mut input = [Goldilocks::ZERO; 8];
        input[..4].copy_from_slice(&state);
        for slot in &mut input[4..4 + n] {
            let value = fields.next().ok_or(CommitmentError::InvalidLength)?;
            if value >= MODULUS {
                return Err(CommitmentError::NonCanonicalField);
            }
            *slot = Goldilocks::from_u64(value);
        }
        permutation.permute_mut(&mut input);
        state.copy_from_slice(&input[..4]);
        left -= n;
    }
    if fields.next().is_some() {
        return Err(CommitmentError::InvalidLength);
    }
    Ok(state.map(|value| value.as_canonical_u64()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_matches_slice_reference_across_chunk_boundaries() {
        for count in (0..65).chain([257, 4096]) {
            let fields: Vec<_> = (0..count)
                .map(|i| (i as u64 * 123_456_789) % MODULUS)
                .collect();
            for domain in [0, 0x4c42563276, MODULUS - 1] {
                assert_eq!(
                    hash_fields(domain, count, fields.iter().copied()),
                    super::super::hash_fields(domain, &fields)
                );
            }
        }
        for bytes in (0..=33).map(|n| (0..n).map(|i| (i * 31) as u8).collect::<Vec<_>>()) {
            let actual: Vec<_> = words(&bytes).collect();
            assert_eq!(actual.len(), bytes.len().div_ceil(4));
            for (i, value) in actual.iter().enumerate() {
                let mut word = [0; 4];
                let chunk = &bytes[i * 4..bytes.len().min(i * 4 + 4)];
                word[..chunk.len()].copy_from_slice(chunk);
                assert_eq!(*value, u32::from_le_bytes(word) as u64);
            }
        }
    }

    #[test]
    fn invalid_lengths_and_noncanonical_fields_never_return_a_digest() {
        assert_eq!(hash_fields(1, 2, [1]), Err(CommitmentError::InvalidLength));
        assert_eq!(
            hash_fields(1, 1, [1, 2]),
            Err(CommitmentError::InvalidLength)
        );
        assert_eq!(hash_fields(1, 0, [0]), Err(CommitmentError::InvalidLength));
        assert_eq!(
            hash_fields(1, 7, [0, 0, 0, 0, 0, 0, MODULUS]),
            Err(CommitmentError::NonCanonicalField)
        );
        let never =
            std::iter::from_fn(|| -> Option<u64> { panic!("invalid domain consumed fields") });
        assert_eq!(
            hash_fields(MODULUS, 1, never),
            Err(CommitmentError::NonCanonicalField)
        );
        if let Ok(count) = usize::try_from(MODULUS) {
            let never =
                std::iter::from_fn(|| -> Option<u64> { panic!("invalid length consumed fields") });
            assert_eq!(
                hash_fields(1, count, never),
                Err(CommitmentError::InvalidLength)
            );
        }
    }
}
