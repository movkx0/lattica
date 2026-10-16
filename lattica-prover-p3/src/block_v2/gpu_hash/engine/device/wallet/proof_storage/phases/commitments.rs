use super::super::super::super::{CommitInputStorage, SampleLocation};
use super::*;

#[derive(Debug)]
pub(super) struct CommitmentPlan {
    pub name: &'static str,
    pub chunks: usize,
    pub storage: CommitInputStorage,
}

impl CommitmentPlan {
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name, "quotient_chunks": self.chunks,
            "managed_bytes_at_bound": self.storage.peak_bytes,
            "allocation_bytes": self.storage.allocation_bytes,
            "sample_bytes": self.storage.sample_bytes,
            "pending_bytes": self.storage.pending_bytes,
            "samples_already_resident": self.storage.location == SampleLocation::Resident,
        })
    }
}
