//! Borrowed streams are marshalled a tile at a time. No full packed copy is
//! retained, and stream state never returns to the host between tiles.
use super::*;

#[derive(Clone, Copy)]
pub enum FieldStreamInput<'a> { Fields(&'a [u64]), Bytes(&'a [u8]) }
#[derive(Clone, Copy)]
pub struct FieldStream<'a> { pub initial: [u64; 4], pub input: FieldStreamInput<'a> }
impl FieldStream<'_> {
    pub(crate) fn words(self) -> usize {
        match self.input { FieldStreamInput::Fields(values) => values.len(), FieldStreamInput::Bytes(bytes) => bytes.len().div_ceil(2) }
    }
    pub(crate) fn word(self, index: usize) -> u64 {
        match self.input {
            FieldStreamInput::Fields(values) => values[index],
            FieldStreamInput::Bytes(bytes) => u64::from(bytes[2 * index]) | (u64::from(*bytes.get(2 * index + 1).unwrap_or(&0)) << 8),
        }
    }
}
impl OperationContext<'_> {
    /// Admission is for the fixed tile and descriptors. Callers retain and fund
    /// every borrowed source until this operation returns, including failures.
    pub fn commit_field_streams(&self, streams: &[FieldStream<'_>]) -> Result<Vec<[u64; 4]>, String> {
        self.execute(|| {
            self.admit_commitment_batch()?;
            if streams.len() > COMMITMENT_BATCH_SIZE { return Err("field stream count exceeds admission".into()); }
            for stream in streams { self.admit_field_chunks(stream.words())?; }
            if streams.is_empty() { return Ok(Vec::new()); }
            #[cfg(feature = "gpu")]
            { self.session.prepared_field_streams(&self.workspace, streams, self.run)
                .ok_or_else(|| "field streams require the admitted reusable workspace".to_owned())? }
            #[cfg(not(feature = "gpu"))]
            { Err("field streams require OpenCL".into()) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_byte_stream_preserves_little_endian_framing() {
        let bytes = [1, 2, 255, 128, 37];
        let stream = FieldStream { initial: [9, 5, 0, 0], input: FieldStreamInput::Bytes(&bytes) };
        assert_eq!(stream.words(), 3);
        assert_eq!((0..stream.words()).map(|i| stream.word(i)).collect::<Vec<_>>(), [513, 33023, 37]);
        assert_eq!(FieldStream { initial: [0; 4], input: FieldStreamInput::Bytes(&[]) }.words(), 0);
    }
}
