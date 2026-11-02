//! Bounded packing for independent field commitments. Pending roots stay private
//! until the batch completes; long streams use the original tiled GPU API.
use lattica_prover_p3::block_v2::{machine::program::Val, native_gpu::{OperationContext,
    FieldCommitment, operations_batch::{COMMITMENT_BATCH_SIZE, COMMITMENT_BATCH_WORDS}}};
use p3_field::PrimeCharacteristicRing;

struct Queued { initial: [u64; 4], words: Vec<u64>, result: usize }
pub(crate) const MAX_RESULTS: usize = 512;
pub(crate) const HOST_BYTES: usize = COMMITMENT_BATCH_WORDS * 8 + 8 * (
    COMMITMENT_BATCH_SIZE * (core::mem::size_of::<Queued>() + core::mem::size_of::<FieldCommitment<'static>>())
    + MAX_RESULTS * (core::mem::size_of::<[Val; 4]>() + 2 * core::mem::size_of::<[usize; 2]>()) + 4096);
pub(crate) struct FieldBatch<'a, 'run> {
    operations: &'a OperationContext<'run>, queued: Vec<Queued>, words: usize,
    results: Vec<[Val; 4]>, limit: usize, batched: bool,
}
impl<'a, 'run> FieldBatch<'a, 'run> {
    pub(crate) fn new(operations: &'a OperationContext<'run>, maximum: usize, batched: bool) -> Result<Self, String> {
        if maximum > MAX_RESULTS { return Err("field result catalog exceeds bound".into()); }
        if batched { operations.admit_commitment_batch()?; } else { operations.admit_field_chunks(0)?; }
        Ok(Self { operations, queued: Vec::with_capacity(if batched { COMMITMENT_BATCH_SIZE } else { 0 }),
            words: 0, results: Vec::with_capacity(maximum), limit: maximum, batched })
    }
    pub(crate) fn push(&mut self, initial: [u64; 4], words: Vec<u64>) -> Result<usize, String> {
        self.operations.admit_field_chunks(words.len())?;
        if self.results.len() == self.limit { return Err("field result count exceeds admission".into()); }
        if self.queued.len() == COMMITMENT_BATCH_SIZE
            || self.words.checked_add(words.len()).is_none_or(|n| n > COMMITMENT_BATCH_WORDS) { self.flush()?; }
        let result = self.results.len();
        if !self.batched || words.len() > COMMITMENT_BATCH_WORDS {
            self.results.push(self.operations.commit_field_chunks(initial, &words)?.map(Val::from_u64));
        } else {
            self.words += words.len();
            self.results.push([Val::ZERO; 4]);
            self.queued.push(Queued { initial, words, result });
        }
        Ok(result)
    }
    fn flush(&mut self) -> Result<(), String> {
        if self.queued.is_empty() { return Ok(()); }
        let mut inputs = [FieldCommitment { initial: [0; 4], words: &[] }; COMMITMENT_BATCH_SIZE];
        for (input, job) in inputs.iter_mut().zip(&self.queued) {
            *input = FieldCommitment { initial: job.initial, words: &job.words };
        }
        let roots = self.operations.commit_field_batch(&inputs[..self.queued.len()])?;
        if roots.len() != self.queued.len() { return Err("field result count mismatch".into()); }
        for (job, root) in self.queued.iter().zip(roots) { self.results[job.result] = root.map(Val::from_u64); }
        self.queued.clear(); self.words = 0;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<Vec<[Val; 4]>, String> {
        self.flush()?; Ok(self.results)
    }
}
