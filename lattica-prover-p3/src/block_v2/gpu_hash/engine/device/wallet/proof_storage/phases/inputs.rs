#[derive(Debug)]
pub(super) struct InputPlan {
    pub name: &'static str,
    pub chunks: usize,
    pub peak: usize,
    pub largest: usize,
    pub coset_rows: usize,
    pub cosets: usize,
}

impl InputPlan {
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name, "quotient_chunks": self.chunks,
            "managed_bytes_at_bound": self.peak,
            "max_allocation_bytes": self.largest,
            "coset_rows": self.coset_rows, "cosets": self.cosets,
        })
    }
}
