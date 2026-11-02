//! Optional fixed-size attribution for a serial raw preparation scope.
//! Wall, device and nested metric times are separate, not additive phases.
use std::{cell::RefCell, time::Instant};
use serde::Serialize;

pub(crate) const NODE: usize = 0;
pub(crate) const FIELDS: usize = 1;
pub(crate) const ARITHMETIC: usize = 2;
const OTHER: usize = 3;
pub(crate) const ALLOCATE: usize = 0;
pub(crate) const KERNEL: usize = 1;
pub(crate) const UPLOAD: usize = 2;
pub(crate) const READBACK: usize = 3;
pub(crate) const CLEANUP: usize = 4;
pub(crate) const DEVICE_WAIT: usize = 5;
#[derive(Clone, Copy, Default, Serialize)]
struct Counters {
    calls: u64,
    logical_hashes: u64,
    wall_ns: u128,
    device_calls: u64,
    device_ns: u128,
    allocations: u64,
    allocated_words: u64,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    metric_ns: [u128; 6],
}
#[derive(Clone, Copy, Default, Serialize)]
struct ArithmeticCounts { opcode: u64, output_words: usize, calls: u64 }
#[derive(Clone, Copy, Serialize)]
struct Statistics {
    schema: &'static str,
    families: [&'static str; 4],
    metrics: [&'static str; 6],
    counters: [Counters; 4],
    complete: bool,
    arithmetic_shapes: [ArithmeticCounts; 32],
    arithmetic_overflow: u64,
    #[serde(skip)]
    current: usize,
}
thread_local! { static CURRENT: RefCell<Option<Statistics>> = const { RefCell::new(None) }; }
// Fixed records, scope/metric forwarding and streaming JSON frames. No per-call
// log/vector/string is retained. Charged by RawPreparationReportStorage.
pub(crate) const HOST_BYTES: usize = 8 * (3 * core::mem::size_of::<Statistics>()
    + 4 * core::mem::size_of::<Span>() + 4096);
pub(crate) struct Scope { enabled: bool }
impl Scope {
    pub(crate) fn begin() -> Self {
        let enabled = std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1");
        if enabled { CURRENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "nested preparation profile");
            *slot = Some(Statistics { schema: "ringct-preparation-operations-v2",
                families: ["node_commitment", "field_commitment", "arithmetic", "other"],
                metrics: ["allocation", "kernel_setup", "upload_enqueue", "readback_wait", "cleanup", "device_wait"],
                counters: [Counters::default(); 4], complete: false, current: OTHER,
                arithmetic_shapes: [ArithmeticCounts::default(); 32], arithmetic_overflow: 0 });
        }); }
        Self { enabled }
    }
    pub(crate) fn complete(&self) {
        if self.enabled { CURRENT.with(|slot| slot.borrow_mut().as_mut().unwrap().complete = true); }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.enabled { return; }
        let statistics = CURRENT.with(|slot| slot.borrow_mut().take().unwrap());
        use std::io::Write;
        let mut out = std::io::stderr().lock();
        let _ = out.write_all(b"RINGCT_PREPARATION_OPERATIONS ")
            .and_then(|_| serde_json::to_writer(&mut out, &statistics).map_err(std::io::Error::other))
            .and_then(|_| out.write_all(b"\n"));
    }
}
pub(crate) struct Span { started: Option<Instant>, family: usize, metric: Option<usize>, previous: usize }
pub(crate) fn operation(family: usize) -> Span {
    let previous = CURRENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.as_mut().map(|s| {
            let previous = s.current; s.current = family; s.counters[family].calls += 1;
            if family == NODE || family == FIELDS { s.counters[family].logical_hashes += 1; }
            previous
        })
    });
    Span { started: previous.map(|_| Instant::now()), family, metric: None, previous: previous.unwrap_or(OTHER) }
}
pub(crate) fn batch_hashes(count: usize) {
    CURRENT.with(|slot| { if let Some(s) = slot.borrow_mut().as_mut() {
        s.counters[s.current].logical_hashes += count.saturating_sub(1) as u64;
    } });
}
pub(crate) fn metric(metric: usize) -> Span {
    let family = CURRENT.with(|slot| slot.borrow().as_ref().map(|s| s.current));
    Span { started: family.map(|_| Instant::now()), family: family.unwrap_or(OTHER), metric: Some(metric), previous: OTHER }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(started) = self.started else { return; };
        let ns = started.elapsed().as_nanos();
        CURRENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(s) = slot.as_mut() {
                if let Some(metric) = self.metric { s.counters[self.family].metric_ns[metric] += ns; }
                else { s.counters[self.family].wall_ns += ns; s.current = self.previous; }
            }
        });
    }
}
pub(crate) fn allocation(words: usize) {
    CURRENT.with(|slot| { if let Some(s) = slot.borrow_mut().as_mut() {
        s.counters[s.current].allocations += 1;
        s.counters[s.current].allocated_words += words as u64;
    } });
}
pub(crate) fn device(calls: u64, ns: u128) {
    CURRENT.with(|slot| { if let Some(s) = slot.borrow_mut().as_mut() {
        s.counters[s.current].device_calls += calls;
        s.counters[s.current].device_ns += ns;
    } });
}
pub(crate) fn transfer(upload: u64, download: u64) {
    CURRENT.with(|slot| { if let Some(s) = slot.borrow_mut().as_mut() {
        s.counters[s.current].uploaded_bytes += upload;
        s.counters[s.current].downloaded_bytes += download;
    } });
}

pub(crate) fn arithmetic_shape(opcode: u64, output_words: usize) {
    CURRENT.with(|slot| { if let Some(s) = slot.borrow_mut().as_mut() {
        if let Some(row) = s.arithmetic_shapes.iter_mut().find(|row| row.calls == 0 || (row.opcode == opcode && row.output_words == output_words)) {
            row.opcode = opcode; row.output_words = output_words; row.calls += 1;
        } else { s.arithmetic_overflow += 1; }
    } });
}
