//! Fixed syntax/equality observations only; no decoder, proof or verifier.
use super::*;

pub(in crate::component_tree::owned_shake) struct HeaderProbeReport {
    pub(in crate::component_tree::owned_shake) positive_checks: usize,
    pub(in crate::component_tree::owned_shake) syntax_rejections: usize,
    pub(in crate::component_tree::owned_shake) public_rejections: usize,
    pub(in crate::component_tree::owned_shake) cap_rejections: usize,
    pub(in crate::component_tree::owned_shake) height_rejections: usize,
    pub(in crate::component_tree::owned_shake) canonical_rejections: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum HeaderProbeError {
    Header(HeaderRefusal),
    UnexpectedAcceptance,
    UnexpectedRefusal { expected: HeaderRefusal, actual: HeaderRefusal },
    ScratchTooSmall,
    NoTrailingRoom,
    Overflow,
}

fn advance(counter: &mut usize) -> Result<(), HeaderProbeError> {
    *counter = counter.checked_add(1).ok_or(HeaderProbeError::Overflow)?;
    Ok(())
}

fn rejects(
    packet: &[u8],
    values: RootHeaderValues<'_>,
    expected: HeaderRefusal,
) -> Result<(), HeaderProbeError> {
    match validate_packet(packet, values) {
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(HeaderProbeError::UnexpectedRefusal { expected, actual }),
        Ok(_) => Err(HeaderProbeError::UnexpectedAcceptance),
    }
}

fn reset_header(original: &[u8], scratch: &mut [u8]) {
    scratch[..HEADER_BYTES].copy_from_slice(&original[..HEADER_BYTES]);
}

fn next_canonical(word: u64) -> u64 {
    if word == MODULUS - 1 { 0 } else { word + 1 }
}

/// The caller admits both full packet capacities before dispatch. It must also
/// preflight one trailing byte inside the unchanged two-MiB packet allowance.
/// Only scratch (packet two) changes. The original packet is always immutable.
pub(in super::super) fn probe_packet(
    original: &[u8],
    scratch: &mut [u8],
    expected: RootHeaderValues<'_>,
) -> Result<HeaderProbeReport, HeaderProbeError> {
    validate_packet(original, expected).map_err(HeaderProbeError::Header)?;
    let length = original.len();
    let trailing = length.checked_add(TRAILING_PROBE_BYTES).ok_or(HeaderProbeError::Overflow)?;
    if trailing > PACKET_LIMIT {
        return Err(HeaderProbeError::NoTrailingRoom);
    }
    if scratch.len() < trailing || scratch.len() > PACKET_LIMIT {
        return Err(HeaderProbeError::ScratchTooSmall);
    }
    scratch[..length].copy_from_slice(original);
    let mut report = HeaderProbeReport {
        positive_checks: 1, syntax_rejections: 0, public_rejections: 0,
        cap_rejections: 0, height_rejections: 0, canonical_rejections: 0,
    };
    for (offset, error) in [(0, HeaderRefusal::Magic), (8, HeaderRefusal::Domain)] {
        reset_header(original, scratch);
        scratch[offset] ^= 1;
        rejects(&scratch[..length], expected, error)?;
        advance(&mut report.syntax_rejections)?;
    }
    for (offset, word, error) in [
        (VERSION, 2, HeaderRefusal::Version),
        (HEADER_LENGTH, HEADER_BYTES as u16 - 1, HeaderRefusal::HeaderLength),
        (PUBLIC_COUNT, PUBLICS as u16 - 1, HeaderRefusal::PublicCount),
        (CAP_COUNT, CAP_ROOTS as u16 - 1, HeaderRefusal::CapCount),
    ] {
        reset_header(original, scratch);
        write_u16(scratch, offset, word);
        rejects(&scratch[..length], expected, error)?;
        advance(&mut report.syntax_rejections)?;
    }
    for (offset, word, error) in [
        (CODEC_REVISION, 3, HeaderRefusal::CodecRevision),
        (SCOPE, SOURCE_ONLY_SCOPE + 1, HeaderRefusal::Scope),
        (INNER_LENGTH, 7, HeaderRefusal::InnerLength),
        (INNER_LENGTH, u64::MAX, HeaderRefusal::InnerLength),
        (INNER_LENGTH, (PACKET_LIMIT - HEADER_BYTES + 1) as u64, HeaderRefusal::InnerLength),
        (HEIGHT, 0, HeaderRefusal::Height),
        (HEIGHT, 1 << 21, HeaderRefusal::Height),
    ] {
        reset_header(original, scratch);
        write_u64(scratch, offset, word);
        rejects(&scratch[..length], expected, error)?;
        advance(&mut report.syntax_rejections)?;
    }
    reset_header(original, scratch);
    write_u64(scratch, HEIGHT, if expected.height == 8 { 16 } else { 8 });
    rejects(&scratch[..length], expected, HeaderRefusal::HeightMismatch)?;
    advance(&mut report.height_rejections)?;

    for index in 0..PUBLICS {
        reset_header(original, scratch);
        let offset = PUBLIC_OFFSET + index * 8;
        write_u64(scratch, offset, next_canonical(read_u64(original, offset)));
        rejects(&scratch[..length], expected, HeaderRefusal::PublicMismatch(index as u16))?;
        advance(&mut report.public_rejections)?;
        write_u64(scratch, offset, MODULUS);
        rejects(&scratch[..length], expected, HeaderRefusal::NoncanonicalPublic(index as u16))?;
        advance(&mut report.canonical_rejections)?;
    }
    for index in 0..CAP_ROOTS * 4 {
        reset_header(original, scratch);
        let offset = CAP_OFFSET + index * 8;
        write_u64(scratch, offset, next_canonical(read_u64(original, offset)));
        rejects(&scratch[..length], expected, HeaderRefusal::CapMismatch(index as u16))?;
        advance(&mut report.cap_rejections)?;
        write_u64(scratch, offset, MODULUS);
        rejects(&scratch[..length], expected, HeaderRefusal::NoncanonicalCap(index as u16))?;
        advance(&mut report.canonical_rejections)?;
    }
    reset_header(original, scratch);
    for cut in [0, 7, 23, 31, 63, HEADER_BYTES - 1, HEADER_BYTES, MIN_PACKET - 1] {
        rejects(&scratch[..cut], expected, HeaderRefusal::Truncated)?;
        advance(&mut report.syntax_rejections)?;
    }
    let missing = if length - 1 < MIN_PACKET { HeaderRefusal::Truncated } else { HeaderRefusal::PacketLength };
    rejects(&scratch[..length - 1], expected, missing)?;
    advance(&mut report.syntax_rejections)?;
    scratch[length] = 0;
    rejects(&scratch[..trailing], expected, HeaderRefusal::PacketLength)?;
    advance(&mut report.syntax_rejections)?;
    scratch[HEADER_BYTES] ^= 1;
    rejects(&scratch[..length], expected, HeaderRefusal::InnerMagic)?;
    advance(&mut report.syntax_rejections)?;

    // A returned error above leaves only disposable scratch changed. The
    // original, retained proof/key and all authority owners remain untouched.
    scratch[..length].copy_from_slice(original);
    validate_packet(&scratch[..length], expected).map_err(HeaderProbeError::Header)?;
    advance(&mut report.positive_checks)?;
    Ok(report)
}
