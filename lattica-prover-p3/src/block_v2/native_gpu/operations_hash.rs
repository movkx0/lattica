//! Bounded sequential Poseidon compression for graph endpoint commitments.
use super::OperationContext;

pub(crate) const MAX_FIELD_CHUNK_WORDS: usize = 1 << 20;

pub(crate) fn field_chunk_staging_bytes(words: usize) -> Result<usize, String> {
    if words > MAX_FIELD_CHUNK_WORDS {
        return Err("raw field commitment exceeds bounded input length".into());
    }
    words
        .max(1)
        .checked_add(9)
        .and_then(|n| n.checked_mul(8))
        .ok_or_else(|| "raw field commitment staging overflow".into())
}

impl OperationContext<'_> {
    /// Admit a raw field stream before allocating serialized host input.
    pub fn admit_field_chunks(&self, words: usize) -> Result<(), String> {
        self.execute(|| self.admit_host_bytes(field_chunk_staging_bytes(words)?))
    }

    /// Compress each successive four-word chunk as Poseidon2([state, chunk]),
    /// retaining the first four outputs. The final chunk is zero-padded; an
    /// empty stream returns the initial state after device validation. Callers
    /// supply the existing domain/length framing in `initial` or `words`.
    /// Every field word must be canonical. Validation and hashing run on GPU.
    pub fn commit_field_chunks(
        &self,
        initial: [u64; 4],
        words: &[u64],
    ) -> Result<[u64; 4], String> {
        self.execute(|| {
            self.admit_host_bytes(field_chunk_staging_bytes(words.len())?)?;
            #[cfg(feature = "gpu")]
            {
                self.session.pq_operation_commit_fields(
                    initial,
                    words,
                    self.host_allowance,
                    self.run,
                )
            }
            #[cfg(not(feature = "gpu"))]
            {
                let _ = initial;
                Err("raw field commitments require OpenCL".into())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_stream_staging_is_bounded_before_serialization() {
        assert_eq!(field_chunk_staging_bytes(0).unwrap(), 80);
        assert_eq!(field_chunk_staging_bytes(4).unwrap(), 104);
        assert!(field_chunk_staging_bytes(MAX_FIELD_CHUNK_WORDS).is_ok());
        assert!(field_chunk_staging_bytes(MAX_FIELD_CHUNK_WORDS + 1).is_err());
        assert!(field_chunk_staging_bytes(usize::MAX).is_err());
    }
}
