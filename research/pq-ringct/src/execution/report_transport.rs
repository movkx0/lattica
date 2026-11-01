//! Fixed report transport with no I/O error allocation. This is Linux x86_64
//! full-workflow infrastructure, not a general-purpose serializer adapter.
use core::ffi::c_void;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::execution) enum Error { Write }

/// Implement only for source-audited derive-Serialize report/epoch records.
/// Allowed fields are supported primitive scalars, strings, ordinary enums,
/// fixed structs, Options and bounded slices/Vecs thereof. No custom serializer
/// or non-string map keys may enter. Payloads and their recursive/caller frames
/// stay charged by the original report/source owner throughout this call.
pub(in crate::execution) trait FixedPayload: serde::Serialize {}

// proving::Report, Capabilities, Observation and their enums are derives over
// &'static str, integers, booleans and Vecs of those fixed records. Callers first
// apply their exact scope/stage validator; native/outer components are empty.
impl FixedPayload for lattica_prover_p3::proving::Report {}

// Bounded to sixteen workers, with two fixed-scope reports and primitive
// worker records. Prefix admission includes report and serialization frames.
#[cfg(feature = "full-workflow-experiment")]
impl FixedPayload for lattica_prover_p3::block_v2::machine::backend::identity_cpu::IdentityBatchReport {}

trait Sink { fn write(&mut self, bytes: &[u8]) -> isize; }

struct StderrSink;
unsafe extern "C" {
    #[link_name = "write"]
    fn system_write(fd: i32, data: *const c_void, count: usize) -> isize;
}
impl Sink for StderrSink {
    fn write(&mut self, bytes: &[u8]) -> isize {
        // SAFETY: the immutable input slice remains live for this synchronous
        // POSIX call. FD2 is the sole production destination; the stderr lock
        // is held by emit. An errno value never becomes an allocated io::Error.
        unsafe { system_write(2, bytes.as_ptr().cast(), bytes.len()) }
    }
}

struct RecordWriter<'sink, S> { sink: &'sink mut S, failed: bool }
impl<S: Sink> Write for RecordWriter<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut remaining = bytes;
        while !self.failed && !remaining.is_empty() {
            let written = self.sink.write(remaining);
            if written <= 0 || written as usize > remaining.len() {
                self.failed = true;
            } else {
                remaining = &remaining[written as usize..];
            }
        }
        // serde_json never receives an I/O Err and therefore never allocates
        // ErrorImpl/Message boxes for an OS write refusal. Latching failure is
        // separate from the serializer's successful traversal of fixed fields.
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn record<S: Sink, T: FixedPayload + ?Sized>(sink: &mut S, prefix: &[u8], value: &T)
    -> Result<(), Error>
{
    let mut writer = RecordWriter { sink, failed: false };
    // RecordWriter implements infallible Write. These result branches contain
    // no allocated diagnostics; no ordinary I/O failure reaches serde_json.
    let _ = writer.write_all(prefix);
    if serde_json::to_writer(&mut writer, value).is_err() {
        // Source-audited derives cannot return a serialization error for these
        // supported field types. A changed/custom Serialize implementation is
        // outside this contract; do not format, retry, or continue that worker.
        std::process::abort();
    }
    let _ = writer.write_all(b"\n");
    if writer.failed { Err(Error::Write) } else { Ok(()) }
}

/// Serialize exactly one record under the standard stderr lock. Failure is a
/// fixed terminal status; no partial record is retried or treated as a receipt.
pub(in crate::execution) fn emit<T: FixedPayload + ?Sized>(prefix: &'static [u8], value: &T)
    -> Result<(), Error>
{
    let stderr = std::io::stderr();
    let _locked = stderr.lock();
    record(&mut StderrSink, prefix, value)
}

/// Only transport forwarding frames. The fixed payload's Report storage and
/// concrete serialization traversal/caller frames remain separately precharged.
pub(in crate::execution) fn required_host_bytes() -> usize {
    use core::mem::size_of;
    8 * (size_of::<StderrSink>() + size_of::<RecordWriter<'static, StderrSink>>()
        + size_of::<std::io::Stderr>() + size_of::<std::io::StderrLock<'static>>()
        + size_of::<serde_json::Serializer<&'static mut RecordWriter<'static, StderrSink>>>()
        + size_of::<Result<(), Error>>() + size_of::<Result<(), serde_json::Error>>()
        + size_of::<std::io::Result<usize>>() + size_of::<&'static [u8]>()
        + 4 * size_of::<usize>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Entry { value: u64 }
    impl FixedPayload for Entry {}

    struct FaultSink {
        bytes: [u8; 128], used: usize, calls: usize,
        script: [isize; 4], scripted: usize,
    }
    impl FaultSink {
        fn new(script: &[isize]) -> Self {
            let mut result = Self { bytes: [0; 128], used: 0, calls: 0,
                script: [0; 4], scripted: script.len() };
            result.script[..script.len()].copy_from_slice(script);
            result
        }
        fn output(&self) -> &[u8] { &self.bytes[..self.used] }
    }
    impl Sink for FaultSink {
        fn write(&mut self, bytes: &[u8]) -> isize {
            let result = if self.calls < self.scripted { self.script[self.calls] }
                else { bytes.len() as isize };
            self.calls += 1;
            if result > 0 && result as usize <= bytes.len() {
                let count = result as usize;
                self.bytes[self.used..self.used + count].copy_from_slice(&bytes[..count]);
                self.used += count;
            }
            result
        }
    }

    #[test]
    fn exact_record_and_newline_survive_partial_writes() {
        let mut sink = FaultSink::new(&[2, 1]);
        assert_eq!(record(&mut sink, b"test ", &Entry { value: 7 }), Ok(()));
        assert_eq!(sink.output(), b"test {\"value\":7}\n");
    }

    #[test]
    fn zero_negative_and_overreported_writes_latch_without_retry() {
        for failure in [0, -1, isize::MAX] {
            let mut sink = FaultSink::new(&[2, failure]);
            assert_eq!(record(&mut sink, b"test ", &Entry { value: 7 }), Err(Error::Write));
            assert_eq!(sink.calls, 2);
            assert_eq!(sink.output(), b"te");
        }
    }

    #[test]
    fn os_refusal_never_becomes_a_serde_json_io_error() {
        let mut sink = FaultSink::new(&[-1]);
        let mut writer = RecordWriter { sink: &mut sink, failed: false };
        assert!(serde_json::to_writer(&mut writer, &Entry { value: 7 }).is_ok());
        assert!(writer.failed);
        writer.write_all(b"not retried").unwrap();
        writer.flush().unwrap();
        assert_eq!(sink.calls, 1);
        assert!(sink.output().is_empty());
    }
}
