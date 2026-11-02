use std::time::Instant;
pub(super) struct Timeline { previous: Option<Instant>, wall_ns: [u128; 5], completed: usize }
impl Timeline {
    pub(super) fn new() -> Self {
        Self { previous: (std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1")).then(Instant::now),
            wall_ns: [0; 5], completed: 0 }
    }
    pub(super) fn mark(&mut self, index: usize) {
        if let Some(before) = self.previous {
            assert_eq!(index, self.completed);
            let now = Instant::now(); self.wall_ns[index] = now.duration_since(before).as_nanos();
            self.previous = Some(now); self.completed += 1;
        }
    }
}
impl Drop for Timeline {
    fn drop(&mut self) {
        if self.previous.is_none() { return; }
        #[derive(serde::Serialize)]
        struct Record<'a> { steps: [&'static str; 5], wall_ns: &'a [u128; 5], completed: usize }
        let record = Record { steps: ["input_validation", "scope_startup", "imports", "relation", "finalize"],
            wall_ns: &self.wall_ns, completed: self.completed };
        use std::io::Write;
        let mut out = std::io::stderr().lock();
        let _ = out.write_all(b"RINGCT_GRAPH_PREPARATION_PROFILE ")
            .and_then(|_| serde_json::to_writer(&mut out, &record).map_err(std::io::Error::other))
            .and_then(|_| out.write_all(b"\n"));
    }
}
pub(in crate::rust_verify::committed_backend) const FRAME_BYTES: usize = 8 * (core::mem::size_of::<Timeline>() + 512);
