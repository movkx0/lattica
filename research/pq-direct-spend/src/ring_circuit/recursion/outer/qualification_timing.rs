//! Test-driver orchestration only. No library report, proof owner or allowance
//! changes layout. The source-bound coordinator owns interpretation of the
//! success marker; it is neither a receipt nor an acceptance input.
use super::{CompilerCapacityProfile, CompilerRepresentation, Context, Error};
use crate::ring_circuit::verification::CALLER_ORCHESTRATION_BYTES;
use std::{
    io::{self, Stderr, StderrLock, Write},
    mem::size_of,
    time::{Duration, Instant},
};

const PREFIX: &[u8] = b"direct_ring_recursive_outer_component_timing elapsed_ns=";
const DECIMAL_DIGITS: usize = 39; // u128::MAX has exactly 39 decimal digits.

type JsonStream = serde_json::Serializer<StderrLock<'static>>;
type JsonCompound =
    serde_json::ser::Compound<'static, StderrLock<'static>, serde_json::ser::CompactFormatter>;

// The genuine driver survives library calls with fixed selectors and borrows.
// Report/proof/program/source/statement owners and their forwarding Results
// remain in the original independent caller/phase censuses, unchanged. Their
// allowances cannot be spent again here. There is no argv, path or Vec owner
// in this driver. Environment Strings are destroyed before this admission.
//
// Existing streamed reports contain only fixed structs/enums, scalar/string
// leaves and one-dimensional lists, with fewer than 16 simultaneous compound
// levels. Reserve four copies of every serializer-level reference/result and
// cursor frame at each of 16 levels; list length does not add nesting. The
// pinned serde_json integer formatter uses a 40-byte itoa buffer and a six-byte
// escaping buffer; 64 bytes per copy covers those sequential scratch arrays.
// None of these reports has floating-point fields or custom collect_str output.
// Both existing eprint/eprintln formatting and serializer/writer owners are
// counted additively, even though the output calls are sequential.
const EXISTING_ORCHESTRATION_BYTES: usize = 8
    * (size_of::<Context>()
        + size_of::<CompilerCapacityProfile>()
        + size_of::<CompilerRepresentation>())
    + 8 * (size_of::<Stderr>() + size_of::<StderrLock<'static>>() + size_of::<JsonStream>())
    + 64 * (size_of::<JsonCompound>()
        + size_of::<&mut JsonStream>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Option<usize>>()
        + 2 * size_of::<usize>()
        + 2 * size_of::<&str>()
        + size_of::<bool>())
    + 8 * size_of::<[u8; 64]>()
    + 8 * (size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Formatter<'static>>()
        + size_of::<std::fmt::Result>())
    + 32 * (size_of::<u128>()
        + size_of::<u64>()
        + size_of::<usize>()
        + size_of::<bool>()
        + size_of::<&str>()
        + size_of::<&usize>()
        + size_of::<&u128>())
    + 16 * (size_of::<&crate::ring::Statement>()
        + size_of::<&crate::ring_circuit::proving::ProofReport>()
        + size_of::<&super::Report>()
        + size_of::<&super::Failure>());

// Explicit additive timer, decimal encoder, output and admission frames. Eight
// Instant/Duration/array copies and sixteen scalar/reference/result copies
// count transfers/temporaries conservatively, without relying on move elision.
// No dynamic formatting, heap buffer, report clone or extra retained owner is
// introduced. The static prefix bytes are charged too, rather than credited as
// free process-image storage. The same reserved slice applies in proving and
// verification; this is not an additional 32 KiB phase allowance.
pub(in crate::ring_circuit) const TIMING_ADDITIONAL_BYTES: usize = PREFIX.len()
    + 8 * (size_of::<Instant>() + size_of::<Duration>() + size_of::<[u8; DECIMAL_DIGITS]>())
    + 8 * (size_of::<Stderr>() + size_of::<StderrLock<'static>>())
    + 16 * (size_of::<u128>()
        + size_of::<usize>()
        + size_of::<u8>()
        + size_of::<&Instant>()
        + size_of::<&Duration>()
        + size_of::<&[u8]>()
        + size_of::<&mut StderrLock<'static>>()
        + size_of::<io::ErrorKind>()
        + size_of::<io::Result<()>>()
        + size_of::<io::Result<usize>>()
        + size_of::<Result<usize, Error>>()
        + size_of::<Option<usize>>());

pub(in crate::ring_circuit) fn caller_bytes() -> Result<usize, Error> {
    let bytes = EXISTING_ORCHESTRATION_BYTES
        .checked_add(TIMING_ADDITIONAL_BYTES)
        .ok_or(Error::ResourceLimit)?;
    if bytes > CALLER_ORCHESTRATION_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

fn write_marker(writer: &mut impl Write, mut elapsed_ns: u128) -> io::Result<()> {
    if elapsed_ns == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut digits = [0u8; DECIMAL_DIGITS];
    let mut first = DECIMAL_DIGITS;
    while elapsed_ns != 0 {
        first -= 1;
        digits[first] = b'0' + (elapsed_ns % 10) as u8;
        elapsed_ns /= 10;
    }
    writer.write_all(PREFIX)?;
    writer.write_all(&digits[first..])?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub(super) fn emit(elapsed_ns: u128) {
    let stderr = io::stderr();
    let mut writer = stderr.lock();
    // An output failure panics and withholds the exact successful test footer.
    // The coordinator must require both the complete marker and that footer.
    write_marker(&mut writer, elapsed_ns).unwrap();
}

#[test]
fn fixed_marker_encodes_positive_u128_without_allocation_or_leading_zeroes() {
    for (value, expected) in [
        (1, b"direct_ring_recursive_outer_component_timing elapsed_ns=1\n".as_slice()),
        (10, b"direct_ring_recursive_outer_component_timing elapsed_ns=10\n".as_slice()),
        (u128::MAX, b"direct_ring_recursive_outer_component_timing elapsed_ns=340282366920938463463374607431768211455\n".as_slice()),
    ] {
        let mut bytes = [0u8; 128];
        let mut output = io::Cursor::new(bytes.as_mut_slice());
        write_marker(&mut output, value).unwrap();
        let len = output.position() as usize;
        drop(output);
        assert_eq!(&bytes[..len], expected);
    }
}

#[test]
fn zero_elapsed_refuses_before_writing_a_marker() {
    let mut bytes = [0u8; 128];
    let mut output = io::Cursor::new(bytes.as_mut_slice());
    assert_eq!(
        write_marker(&mut output, 0).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(output.position(), 0);
}

#[test]
fn marker_output_errors_remain_terminal() {
    struct RefusedOutput {
        refuse_write: bool,
    }
    impl Write for RefusedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.refuse_write {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    for refuse_write in [true, false] {
        assert_eq!(
            write_marker(&mut RefusedOutput { refuse_write }, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
