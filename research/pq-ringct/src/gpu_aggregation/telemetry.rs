//! Bounded, monotonic intervals; overlapping worker durations are not wall time.
use std::{
    cell::Cell,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Instant,
};
static ORIGIN: OnceLock<Instant> = OnceLock::new();
static TREES: AtomicU64 = AtomicU64::new(0);
thread_local! { static JOB: Cell<Option<(u64, usize)>> = const { Cell::new(None) }; }
pub(crate) fn now() -> u128 {
    ORIGIN.get_or_init(Instant::now).elapsed().as_nanos()
}
pub(crate) fn tree() -> u64 {
    TREES.fetch_add(1, Ordering::Relaxed)
}
pub(crate) struct Job(Option<(u64, usize)>);
impl Job {
    pub fn enter(tree: u64, job: usize) -> Self {
        Self(JOB.replace(Some((tree, job))))
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        JOB.set(self.0);
    }
}
pub(crate) fn interval(tree: u64, job: usize, phase: &str, start: u128, end: u128) {
    eprintln!(
        "GPU_AGGREGATION_INTERVAL {}",
        serde_json::json!({"tree":tree,"job":job,
        "phase":phase,"start_ns":start,"end_ns":end,"duration_ns":end.saturating_sub(start)})
    );
}
pub(crate) struct Span {
    phase: &'static str,
    start: u128,
    job: Option<(u64, usize)>,
}
impl Span {
    pub fn start(phase: &'static str) -> Self {
        Self {
            phase,
            start: now(),
            job: JOB.get(),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some((tree, job)) = self.job {
            interval(tree, job, self.phase, self.start, now());
        }
    }
}
