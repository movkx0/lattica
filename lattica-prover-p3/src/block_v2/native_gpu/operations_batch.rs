//! Bounded batches of independent commitments. Framing and all field arithmetic
//! remain on the device; these requests carry no proving or acceptance authority.
use super::OperationContext;

pub const COMMITMENT_BATCH_SIZE: usize = 64;
pub const COMMITMENT_BATCH_WORDS: usize = 1 << 17;

#[derive(Clone, Copy)]
pub enum NodeCommitment<'a> {
    Canonical { values: &'a [u64; 256], modulus: u64 },
    Signed(&'a [i64; 256]),
    Bytes(&'a [u8; 32]),
}
impl NodeCommitment<'_> {
    fn shape(self) -> (u32, u64, usize) {
        match self {
            Self::Canonical { modulus, .. } => (0, modulus, 256),
            Self::Signed(_) => (1, 0, 256), Self::Bytes(_) => (2, 0, 32),
        }
    }
    fn word(self, index: usize) -> u64 {
        match self {
            Self::Canonical { values, .. } => values[index],
            Self::Signed(values) => values[index] as u64,
            Self::Bytes(values) => u64::from(values[index]),
        }
    }
}
#[derive(Clone, Copy)]
pub struct FieldCommitment<'a> { pub initial: [u64; 4], pub words: &'a [u64] }

/// Internal packing plus all batch/result forwarding frames. Caller-owned
/// source streams and the separately funded reusable workspace are additional.
pub struct RawCommitmentBatchStorage;
impl RawCommitmentBatchStorage {
    pub const HOST_BYTES: usize = 2 * COMMITMENT_BATCH_WORDS * 8 + 8 * (
        COMMITMENT_BATCH_SIZE * (core::mem::size_of::<NodeCommitment<'static>>()
            + core::mem::size_of::<FieldCommitment<'static>>() + 16 * 8)
        + 4096);
}
pub(super) struct PackedWords(pub Vec<u64>);
impl Drop for PackedWords {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: exclusive live backing, scrubbed on every exit.
            unsafe { core::ptr::write_volatile(word, 0); }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
impl OperationContext<'_> {
    /// The workspace must already be enabled. Call before allocating batch
    /// framing; all subsequent operations repeat this admission and scope check.
    pub fn admit_commitment_batch(&self) -> Result<(), String> {
        self.execute(|| self.admit_host_bytes(RawCommitmentBatchStorage::HOST_BYTES))
    }
    pub fn commit_node_batch(&self, nodes: &[NodeCommitment<'_>]) -> Result<Vec<[u64; 4]>, String> {
        self.execute(|| {
            self.admit_commitment_batch()?;
            if nodes.len() > COMMITMENT_BATCH_SIZE { return Err("node batch exceeds 64 nodes".into()); }
            let Some(first) = nodes.first() else { return Ok(Vec::new()); };
            let (kind, modulus, width) = first.shape();
            if (kind == 0 && !matches!(modulus, 167_770_241 | 3_489_661_057))
                || nodes.iter().any(|node| node.shape() != (kind, modulus, width)) {
                return Err("heterogeneous or unsupported node batch".into());
            }
            let mut packed = PackedWords(vec![0; width * nodes.len()]);
            for coefficient in 0..width {
                for (index, node) in nodes.iter().enumerate() {
                    packed.0[coefficient * nodes.len() + index] = node.word(coefficient);
                }
            }
            #[cfg(feature = "gpu")]
            { self.session.prepared_node_batch(&self.workspace, kind, modulus, nodes.len(), &packed.0, self.run)
                .ok_or_else(|| "node batches require the admitted reusable workspace".to_owned())? }
            #[cfg(not(feature = "gpu"))]
            { Err("node batches require OpenCL".into()) }
        })
    }
    pub fn commit_field_batch(&self, streams: &[FieldCommitment<'_>]) -> Result<Vec<[u64; 4]>, String> {
        self.execute(|| {
            self.admit_commitment_batch()?;
            if streams.len() > COMMITMENT_BATCH_SIZE { return Err("field batch exceeds 64 streams".into()); }
            let words = streams.iter().try_fold(0usize, |n, s| n.checked_add(s.words.len()))
                .filter(|n| *n <= COMMITMENT_BATCH_WORDS).ok_or("field batch exceeds bounded input")?;
            if streams.is_empty() { return Ok(Vec::new()); }
            let mut packed = PackedWords(Vec::with_capacity(words));
            let mut descriptors = PackedWords(Vec::with_capacity(6 * streams.len()));
            for stream in streams {
                descriptors.0.extend([packed.0.len() as u64, stream.words.len() as u64]);
                descriptors.0.extend(stream.initial);
                packed.0.extend_from_slice(stream.words);
            }
            let maximum = streams.iter().map(|s| s.words.len()).max().unwrap();
            #[cfg(feature = "gpu")]
            { self.session.prepared_field_batch(&self.workspace, streams.len(), maximum, &packed.0, &descriptors.0, self.run)
                .ok_or_else(|| "field batches require the admitted reusable workspace".to_owned())? }
            #[cfg(not(feature = "gpu"))]
            { let _ = maximum; Err("field batches require OpenCL".into()) }
        })
    }
}
