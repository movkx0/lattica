//! Fixed final25 packet. Serialized key fields are compared to the local key;
//! they never construct or select a verifier. All fields have canonical bytes.
use super::*;

const MAGIC: &[u8; 8] = b"LQRFN001";
const VERSION: u64 = 1;
pub(super) const CAP_ROOTS: usize = 64;
pub(super) const HEADER_BYTES: usize = 8 + 8 + 4 * 32 + 8 * 8
    + PUBLIC_VALUES * 8 + CAP_ROOTS * 4 * 8;

#[derive(Clone, Copy)]
pub(super) struct Header<'a> {
    pub(super) compiled_source: [u8; 32],
    pub(super) source: [u8; 32],
    pub(super) batch_profile: [u8; 32],
    pub(super) context: [u8; 32],
    pub(super) merge: usize,
    pub(super) first: usize,
    pub(super) count: usize,
    pub(super) total: usize,
    pub(super) height: usize,
    pub(super) public: &'a [Val; PUBLIC_VALUES],
    pub(super) cap: &'a [[Val; 4]],
}

fn put(output: &mut [u8], cursor: &mut usize, value: &[u8]) -> OwnedResult<()> {
    let end = add(*cursor, value.len())?;
    output.get_mut(*cursor..end).ok_or(FinalFailure::Capacity)?.copy_from_slice(value);
    *cursor = end;
    Ok(())
}

pub(super) fn encode(header: Header<'_>, inner_bytes: usize, output: &mut [u8]) -> OwnedResult<()> {
    if PUBLIC_VALUES != 25 || HEADER_BYTES != 2456 || output.len() != HEADER_BYTES
        || header.cap.len() != CAP_ROOTS || header.first != 0
        || !matches!(header.total, 3 | 4) || header.count != header.total
        || header.merge.checked_add(2) != Some(header.total)
        || inner_bytes < codec::REGISTERED_PROOF_MAGIC.len()
        || inner_bytes > profile::MAX_PROOF_BYTES
        || !(8..=ROW_LIMIT).contains(&header.height) || !header.height.is_power_of_two()
    { return Err(FinalFailure::Source); }
    let mut cursor = 0;
    put(output, &mut cursor, MAGIC)?;
    put(output, &mut cursor, &VERSION.to_le_bytes())?;
    for field in [&header.compiled_source, &header.source, &header.batch_profile, &header.context] {
        put(output, &mut cursor, field)?;
    }
    for value in [header.merge, header.first, header.count, header.total, header.height,
        PUBLIC_VALUES, CAP_ROOTS, inner_bytes]
    {
        put(output, &mut cursor, &u64::try_from(value).map_err(|_| FinalFailure::Overflow)?.to_le_bytes())?;
    }
    for value in header.public.iter().chain(header.cap.iter().flatten()) {
        put(output, &mut cursor, &value.as_canonical_u64().to_le_bytes())?;
    }
    if cursor != HEADER_BYTES { return Err(FinalFailure::Source); }
    Ok(())
}

/// Comparing a freshly encoded fixed header also rejects noncanonical field
/// words, wrong source/profile/context, cap drift, trailing data and lengths.
/// Serialized public values are checked against the exact original values;
/// their authenticated owning reference remains outside the packet.
pub(super) fn validate<'a>(bytes: &'a [u8], expected: Header<'_>,
    inner_bytes: usize) -> OwnedResult<&'a [u8]>
{
    if bytes.len() != add(HEADER_BYTES, inner_bytes)? { return Err(FinalFailure::Source); }
    let mut canonical = [0u8; HEADER_BYTES];
    encode(expected, inner_bytes, &mut canonical)?;
    if bytes.get(..HEADER_BYTES) != Some(canonical.as_slice()) {
        return Err(FinalFailure::Source);
    }
    bytes.get(HEADER_BYTES..).ok_or(FinalFailure::Source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final25_header_binds_every_byte_and_exact_packet_length() {
        let public = [Val::NEG_ONE; PUBLIC_VALUES];
        let cap = [[Val::ONE; 4]; CAP_ROOTS];
        let header = Header { compiled_source: [1; 32], source: [2; 32],
            batch_profile: [3; 32], context: [4; 32], merge: 1, first: 0,
            count: 3, total: 3, height: 1 << 20, public: &public, cap: &cap };
        let mut packet = [0u8; HEADER_BYTES + 8];
        encode(header, 8, &mut packet[..HEADER_BYTES]).unwrap();
        assert_eq!(validate(&packet, header, 8).unwrap(), &[0; 8]);
        for byte in 0..HEADER_BYTES {
            packet[byte] ^= 1;
            assert!(validate(&packet, header, 8).is_err(), "header byte {byte}");
            packet[byte] ^= 1;
        }
        assert!(validate(&packet[..packet.len() - 1], header, 8).is_err());
        assert!(validate(&packet, header, 9).is_err());
        let mut wrong = header;
        wrong.context[0] ^= 1;
        assert!(validate(&packet, wrong, 8).is_err());
        wrong = header; wrong.batch_profile[0] ^= 1;
        assert!(validate(&packet, wrong, 8).is_err());
    }
}
