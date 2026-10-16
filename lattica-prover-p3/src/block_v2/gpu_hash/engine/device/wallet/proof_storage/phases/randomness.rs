//! Runtime sampling storage checks against conservative wallet phase lifetimes.
use super::super::super::super::random::FieldStoragePlan;
use super::*;

#[derive(Debug)]
pub(super) struct RandomnessPlan {
    name: &'static str,
    chunks: usize,
    retain_outputs: bool,
    storage: FieldStoragePlan,
}
impl RandomnessPlan {
    pub(super) fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name, "quotient_chunks": self.chunks,
            "requests": self.storage.requests, "retain_outputs": self.retain_outputs,
            "largest_request_words": self.storage.largest_request_words,
            "retained_output_bytes": self.storage.retained_output_bytes,
            "managed_bytes_at_bound": self.storage.peak_bytes,
            "max_allocation_bytes": self.storage.max_allocation_bytes,
            "minimum_stream_words_from_fresh": self.storage.minimum_end_position,
        })
    }
}
impl Plan {
    pub(super) fn admit_randomness(
        &mut self,
        name: &'static str,
        chunks: usize,
        requests: impl ExactSizeIterator<Item = usize>,
        retain_outputs: bool,
        live: usize,
    ) -> Result<(), String> {
        let storage = FieldStoragePlan::new(
            requests,
            &[],
            retain_outputs,
            0,
            live,
            self.ceiling,
            self.max_allocation,
        )?;
        self.randomness.push(RandomnessPlan {
            name,
            chunks,
            retain_outputs,
            storage,
        });
        Ok(())
    }
}
