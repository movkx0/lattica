use super::super::{
    ledger::{LedgerCheckpoint, LedgerSource, ACCOUNT_BYTES, RING_ACCOUNTS},
    statement, Error,
};
use super::proof;
use crate::native_packet::{self, NativePacket};

const MAGIC: &[u8; 8] = b"LPQMCP02";
pub(super) const HEADER_BYTES: usize = 80;
const FULL: u32 = 1;
const REFERENCED: u32 = 2;
const PACKET_PREFIX: usize = HEADER_BYTES + statement::STATEMENT_BYTES;
const REFERENCED_PREFIX: usize =
    HEADER_BYTES + 64 + RING_ACCOUNTS * 8 + statement::COMPACT_SUFFIX_BYTES;
pub const MIN_PACKET_BYTES: usize = PACKET_PREFIX + proof::MIN_PROOF_BYTES;
pub const MAX_PACKET_BYTES: usize = PACKET_PREFIX + proof::MAX_PROOF_BYTES;
pub const MIN_REFERENCED_PACKET_BYTES: usize = REFERENCED_PREFIX + proof::MIN_PROOF_BYTES;
pub const MAX_REFERENCED_PACKET_BYTES: usize = REFERENCED_PREFIX + proof::MAX_PROOF_BYTES;

/// Standalone, lossless transport. Encoding does not verify the proof.
pub fn encode_packet(packet: &NativePacket) -> Result<Vec<u8>, Error> {
    check_legacy_lengths(packet)?;
    let mut out = header(packet, FULL, MAX_PACKET_BYTES);
    out.extend_from_slice(&statement::encode_statement(&packet.statement)?);
    out.extend_from_slice(&proof::encode_proof(&packet.proof)?);
    debug_assert!((MIN_PACKET_BYTES..=MAX_PACKET_BYTES).contains(&out.len()));
    Ok(out)
}

/// Reconstruct a native packet under an independently supplied expected context.
/// The caller must subsequently verify its native proof and ledger acceptance.
pub fn decode_packet(bytes: &[u8], expected_context: &[u8; 32]) -> Result<NativePacket, Error> {
    check_header(bytes, expected_context, FULL, PACKET_PREFIX)?;
    let end = HEADER_BYTES + statement::STATEMENT_BYTES;
    Ok(NativePacket {
        context: *expected_context,
        statement: statement::decode_statement(&bytes[HEADER_BYTES..end])?,
        proof: proof::decode_proof(&bytes[end..])?,
    })
}

/// Reference all 20 accounts in their original order (ten candidate pairs).
/// Source accounts must authenticate against the supplied checkpoint and match
/// the original statement exactly. No ring member or relation is removed.
pub fn encode_referenced_packet(
    packet: &NativePacket,
    checkpoint: &LedgerCheckpoint,
    indices: &[u64; RING_ACCOUNTS],
    source: &(impl LedgerSource + ?Sized),
) -> Result<Vec<u8>, Error> {
    check_legacy_lengths(packet)?;
    if packet.statement[..32] != checkpoint.setup_seed() {
        return Err(Error::LedgerCheckpoint);
    }
    let mut out = header(packet, REFERENCED, MAX_REFERENCED_PACKET_BYTES);
    out.extend_from_slice(&checkpoint.id());
    out.extend_from_slice(&packet.statement[..statement::RING_START]);
    for (i, &index) in indices.iter().enumerate() {
        if index >= checkpoint.account_count() {
            return Err(Error::Reference);
        }
        let witness = source.account(index).ok_or(Error::MissingAccount)?;
        let account = witness.verify(index, checkpoint)?;
        let start = statement::RING_START + i * ACCOUNT_BYTES;
        if account != &packet.statement[start..start + ACCOUNT_BYTES] {
            return Err(Error::Reference);
        }
        out.extend_from_slice(&index.to_le_bytes());
    }
    let suffix = &packet.statement[statement::RING_END..];
    debug_assert_eq!(suffix.len(), statement::SUFFIX_BYTES);
    let serial_start = statement::SUFFIX_POLYS * statement::POLY_BYTES;
    out.extend_from_slice(&statement::encode_polys(&suffix[..serial_start])?);
    out.extend_from_slice(&suffix[serial_start..]);
    out.extend_from_slice(&proof::encode_proof(&packet.proof)?);
    debug_assert!((MIN_REFERENCED_PACKET_BYTES..=MAX_REFERENCED_PACKET_BYTES).contains(&out.len()));
    Ok(out)
}

/// Resolve a compact packet against the receiver's trusted ledger state.
/// Account data and membership paths are out-of-band, normally already local.
/// Successful resolution authenticates membership, not the spend proof or serials.
pub fn decode_referenced_packet(
    bytes: &[u8],
    expected_context: &[u8; 32],
    checkpoint: &LedgerCheckpoint,
    source: &(impl LedgerSource + ?Sized),
) -> Result<NativePacket, Error> {
    check_header(bytes, expected_context, REFERENCED, REFERENCED_PREFIX)?;
    if bytes[HEADER_BYTES..HEADER_BYTES + 32] != checkpoint.id() {
        return Err(Error::LedgerCheckpoint);
    }
    let seed_start = HEADER_BYTES + 32;
    let indices_start = seed_start + 32;
    if bytes[seed_start..indices_start] != checkpoint.setup_seed() {
        return Err(Error::LedgerCheckpoint);
    }
    let suffix_start = indices_start + RING_ACCOUNTS * 8;
    let mut indices = [0u64; RING_ACCOUNTS];
    for (i, index) in indices.iter_mut().enumerate() {
        let start = indices_start + i * 8;
        *index = u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
        if *index >= checkpoint.account_count() {
            return Err(Error::Reference);
        }
    }
    // Framing, context, checkpoint and all index bounds precede allocations/lookups.
    let mut statement = Vec::with_capacity(native_packet::STATEMENT_BYTES);
    statement.extend_from_slice(&bytes[seed_start..indices_start]);
    for index in indices {
        let witness = source.account(index).ok_or(Error::MissingAccount)?;
        statement.extend_from_slice(witness.verify(index, checkpoint)?);
    }
    let serial_start = suffix_start + statement::SUFFIX_POLYS * statement::COMPACT_POLY_BYTES;
    let proof_start = serial_start + 64;
    statement.extend_from_slice(&statement::decode_polys(
        &bytes[suffix_start..serial_start],
    )?);
    statement.extend_from_slice(&bytes[serial_start..proof_start]);
    debug_assert_eq!(statement.len(), native_packet::STATEMENT_BYTES);
    Ok(NativePacket {
        context: *expected_context,
        statement,
        proof: proof::decode_proof(&bytes[proof_start..])?,
    })
}

fn check_legacy_lengths(packet: &NativePacket) -> Result<(), Error> {
    if packet.statement.len() != native_packet::STATEMENT_BYTES
        || packet.proof.len() != native_packet::PROOF_BYTES
    {
        return Err(Error::Length);
    }
    Ok(())
}

fn header(packet: &NativePacket, mode: u32, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&native_packet::PROFILE_SCHEME.to_le_bytes());
    out.extend_from_slice(&native_packet::PROFILE_VERSION.to_le_bytes());
    out.extend_from_slice(&native_packet::PROFILE_PARAMETERS);
    out.extend_from_slice(&packet.context);
    out.extend_from_slice(&mode.to_le_bytes());
    out
}

fn check_header(bytes: &[u8], context: &[u8; 32], mode: u32, prefix: usize) -> Result<(), Error> {
    if !(prefix + proof::MIN_PROOF_BYTES..=prefix + proof::MAX_PROOF_BYTES).contains(&bytes.len()) {
        return Err(Error::Length);
    }
    if &bytes[..8] != MAGIC || bytes[76..80] != mode.to_le_bytes() {
        return Err(Error::Format);
    }
    if bytes[8..10] != native_packet::PROFILE_SCHEME.to_le_bytes()
        || bytes[10..12] != native_packet::PROFILE_VERSION.to_le_bytes()
        || bytes[12..44] != native_packet::PROFILE_PARAMETERS
    {
        return Err(Error::Profile);
    }
    if &bytes[44..76] != context {
        return Err(Error::Context);
    }
    Ok(())
}
