//! Fixed-size, test-only wall timings. These include host work and GPU waits;
//! only the operation reports independently measure device execution.
use std::time::Instant;
pub(super) struct Timeline {
    previous: Option<Instant>,
    ns: [u128; 9],
    completed: usize,
}
impl Timeline {
    pub(super) fn new() -> Self {
        Self {
            previous: (std::env::var("LATTICA_RINGCT_METADATA_STAGE_PROFILE").as_deref()
                == Ok("n3-paired-v1"))
            .then(Instant::now),
            ns: [0; 9],
            completed: 0,
        }
    }
    pub(super) fn mark(&mut self, index: usize) {
        if let Some(previous) = self.previous {
            assert_eq!(index, self.completed);
            let now = Instant::now();
            self.ns[index] = now.duration_since(previous).as_nanos();
            self.previous = Some(now);
            self.completed += 1;
        }
    }
}
impl Drop for Timeline {
    fn drop(&mut self) {
        if self.previous.is_none() {
            return;
        }
        #[derive(serde::Serialize)]
        struct Report<'a> {
            steps: [&'static str; 9],
            wall_ns: &'a [u128; 9],
            completed: usize,
        }
        let report = Report {
            steps: [
                "registration",
                "algebra",
                "tree",
                "statement",
                "manifest",
                "native",
                "crypto",
                "auxiliary",
                "producer",
            ],
            wall_ns: &self.ns,
            completed: self.completed,
        };
        use std::io::Write;
        let mut out = std::io::stderr().lock();
        out.write_all(b"RINGCT_SOURCE_PREPARATION_PROFILE ")
            .unwrap();
        serde_json::to_writer(&mut out, &report).unwrap();
        out.write_all(b"\n").unwrap();
    }
}
pub(super) const FRAME_BYTES: usize = 8 * (core::mem::size_of::<Timeline>() + 512);
