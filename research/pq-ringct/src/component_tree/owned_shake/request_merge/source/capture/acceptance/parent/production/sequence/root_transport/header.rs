//! Fixed local root-artifact framing, not a transaction acceptance format.
//! These borrowed values and parsed bytes confer no source/request authority.
use lattica_prover_p3::block_v2::{
    codec, commitment::MODULUS, machine::program::Val, profile,
};
use p3_field::PrimeField64;

mod probes;
pub(super) use probes::{probe_packet, HeaderProbeError};
pub(in crate::component_tree::owned_shake) use probes::HeaderProbeReport;

pub(super) const HEADER_BYTES: usize = 2_480;
pub(super) const PACKET_LIMIT: usize = 2 << 20;
pub(super) const PUBLICS: usize = 46;
pub(super) const CAP_ROOTS: usize = 64;
pub(super) const TRAILING_PROBE_BYTES: usize = 1;

const MAGIC: &[u8; 8] = b"LRCART01";
const DOMAIN: &[u8; 16] = b"RC_SHAKE_ROOT_V1";
const VERSION: usize = 24;
const HEADER_LENGTH: usize = 26;
const PUBLIC_COUNT: usize = 28;
const CAP_COUNT: usize = 30;
const CODEC_REVISION: usize = 32;
const INNER_LENGTH: usize = 40;
const HEIGHT: usize = 48;
const SCOPE: usize = 56;
const PUBLIC_OFFSET: usize = 64;
const CAP_OFFSET: usize = PUBLIC_OFFSET + PUBLICS * 8;
const MIN_INNER: usize = 8;
const MIN_PACKET: usize = HEADER_BYTES + MIN_INNER;
const SOURCE_ONLY_SCOPE: u64 = 1;

/// A value view only. The sealed action must independently authenticate the
/// actual root, source/request/ledger, spec and first 38 source public values.
#[derive(Clone, Copy)]
pub(super) struct RootHeaderValues<'a> {
    pub(super) height: usize,
    pub(super) public: &'a [Val; PUBLICS],
    pub(super) cap: &'a [[Val; 4]; CAP_ROOTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeaderRefusal {
    Profile,
    ExpectedHeight,
    HeaderBuffer,
    PacketLimit,
    Truncated,
    Magic,
    Domain,
    Version,
    HeaderLength,
    PublicCount,
    CapCount,
    CodecRevision,
    Scope,
    InnerLength,
    PacketLength,
    Height,
    HeightMismatch,
    NoncanonicalPublic(u16),
    NoncanonicalCap(u16),
    PublicMismatch(u16),
    CapMismatch(u16),
    InnerMagic,
    Overflow,
}

/// Only the inner borrowed bytes escape. This is a framing result, not an
/// authenticated key, decoded proof, original-ledger token or acceptance.
pub(super) struct HeaderCheckedPacket<'packet> {
    inner: &'packet [u8],
}

impl<'packet> HeaderCheckedPacket<'packet> {
    pub(super) fn inner(&self) -> &'packet [u8] {
        self.inner
    }
}

fn check_profile() -> Result<(), HeaderRefusal> {
    if profile::NODE_CODEC_REVISION != 2
        || codec::REGISTERED_PROOF_MAGIC != b"LBV2RP02"
        || profile::MAX_PROOF_BYTES != PACKET_LIMIT
        || MODULUS != 0xffff_ffff_0000_0001
        || core::mem::size_of::<Val>() != 8
        || CAP_OFFSET + CAP_ROOTS * 4 * 8 != HEADER_BYTES
    {
        return Err(HeaderRefusal::Profile);
    }
    Ok(())
}

fn valid_height(height: u64) -> bool {
    (8..=1 << 20).contains(&height) && height.is_power_of_two()
}

fn expected_height(values: RootHeaderValues<'_>) -> Result<u64, HeaderRefusal> {
    let height = u64::try_from(values.height).map_err(|_| HeaderRefusal::Overflow)?;
    if !valid_height(height) {
        return Err(HeaderRefusal::ExpectedHeight);
    }
    Ok(height)
}

fn packet_bytes(inner_bytes: usize) -> Result<usize, HeaderRefusal> {
    if !(MIN_INNER..=PACKET_LIMIT - HEADER_BYTES).contains(&inner_bytes) {
        return Err(HeaderRefusal::InnerLength);
    }
    HEADER_BYTES.checked_add(inner_bytes).ok_or(HeaderRefusal::Overflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(core::array::from_fn(|index| bytes[offset + index]))
}

fn write_u16(bytes: &mut [u8], offset: usize, word: u16) {
    bytes[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, word: u64) {
    bytes[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
}

/// Writes an exactly HEADER_BYTES-long prefix borrowed from an already admitted
/// caller-owned packet. The inner length includes its own eight-byte magic.
/// The caller owns the body; this helper never writes it or allocates storage.
pub(super) fn encode_header(
    values: RootHeaderValues<'_>,
    inner_bytes: usize,
    output: &mut [u8],
) -> Result<(), HeaderRefusal> {
    check_profile()?;
    let height = expected_height(values)?;
    packet_bytes(inner_bytes)?;
    if output.len() != HEADER_BYTES {
        return Err(HeaderRefusal::HeaderBuffer);
    }
    output[..8].copy_from_slice(MAGIC);
    output[8..24].copy_from_slice(DOMAIN);
    for (offset, word) in [
        (VERSION, 1),
        (HEADER_LENGTH, HEADER_BYTES as u16),
        (PUBLIC_COUNT, PUBLICS as u16),
        (CAP_COUNT, CAP_ROOTS as u16),
    ] {
        write_u16(output, offset, word);
    }
    for (offset, word) in [
        (CODEC_REVISION, 2),
        (INNER_LENGTH, u64::try_from(inner_bytes).map_err(|_| HeaderRefusal::Overflow)?),
        (HEIGHT, height),
        (SCOPE, SOURCE_ONLY_SCOPE),
    ] {
        write_u64(output, offset, word);
    }
    for (index, value) in values.public.iter().enumerate() {
        write_u64(output, PUBLIC_OFFSET + index * 8, value.as_canonical_u64());
    }
    for (root, values) in values.cap.iter().enumerate() {
        for (column, value) in values.iter().enumerate() {
            write_u64(output, CAP_OFFSET + (root * 4 + column) * 8, value.as_canonical_u64());
        }
    }
    Ok(())
}

/// Validates syntax and equality against local actual-root values. No key is
/// reconstructed from the packet; the caller keeps its original verifier.
pub(super) fn validate_packet<'packet>(
    packet: &'packet [u8],
    expected: RootHeaderValues<'_>,
) -> Result<HeaderCheckedPacket<'packet>, HeaderRefusal> {
    check_profile()?;
    let expected_height = expected_height(expected)?;
    if packet.len() > PACKET_LIMIT {
        return Err(HeaderRefusal::PacketLimit);
    }
    if packet.len() < MIN_PACKET {
        return Err(HeaderRefusal::Truncated);
    }
    if &packet[..8] != MAGIC {
        return Err(HeaderRefusal::Magic);
    }
    if &packet[8..24] != DOMAIN {
        return Err(HeaderRefusal::Domain);
    }
    for (offset, word, error) in [
        (VERSION, 1, HeaderRefusal::Version),
        (HEADER_LENGTH, HEADER_BYTES as u16, HeaderRefusal::HeaderLength),
        (PUBLIC_COUNT, PUBLICS as u16, HeaderRefusal::PublicCount),
        (CAP_COUNT, CAP_ROOTS as u16, HeaderRefusal::CapCount),
    ] {
        if read_u16(packet, offset) != word {
            return Err(error);
        }
    }
    if read_u64(packet, CODEC_REVISION) != 2 {
        return Err(HeaderRefusal::CodecRevision);
    }
    if read_u64(packet, SCOPE) != SOURCE_ONLY_SCOPE {
        return Err(HeaderRefusal::Scope);
    }
    let inner = usize::try_from(read_u64(packet, INNER_LENGTH))
        .map_err(|_| HeaderRefusal::InnerLength)?;
    if packet_bytes(inner)? != packet.len() {
        return Err(HeaderRefusal::PacketLength);
    }
    let height = read_u64(packet, HEIGHT);
    if !valid_height(height) {
        return Err(HeaderRefusal::Height);
    }
    if height != expected_height {
        return Err(HeaderRefusal::HeightMismatch);
    }
    for (index, expected) in expected.public.iter().enumerate() {
        let word = read_u64(packet, PUBLIC_OFFSET + index * 8);
        if word >= MODULUS {
            return Err(HeaderRefusal::NoncanonicalPublic(index as u16));
        }
        if word != expected.as_canonical_u64() {
            return Err(HeaderRefusal::PublicMismatch(index as u16));
        }
    }
    for (root, values) in expected.cap.iter().enumerate() {
        for (column, expected) in values.iter().enumerate() {
            let index = root * 4 + column;
            let word = read_u64(packet, CAP_OFFSET + index * 8);
            if word >= MODULUS {
                return Err(HeaderRefusal::NoncanonicalCap(index as u16));
            }
            if word != expected.as_canonical_u64() {
                return Err(HeaderRefusal::CapMismatch(index as u16));
            }
        }
    }
    if &packet[HEADER_BYTES..HEADER_BYTES + MIN_INNER] != codec::REGISTERED_PROOF_MAGIC {
        return Err(HeaderRefusal::InnerMagic);
    }
    Ok(HeaderCheckedPacket { inner: &packet[HEADER_BYTES..] })
}

#[cfg(test)]
mod tests;
