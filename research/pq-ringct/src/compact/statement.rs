use super::{radix, Error};
use crate::{native_packet, rust_verify::Q};

pub const STATEMENT_BYTES: usize = 173_346;
pub(super) const POLY_BYTES: usize = 1024;
pub(super) const COMPACT_POLY_BYTES: usize = 875;
pub const ACCOUNT_BYTES: usize = 9 * POLY_BYTES;
pub const RING_ACCOUNTS: usize = 20;
pub(super) const RING_START: usize = 32;
pub(super) const RING_END: usize = RING_START + RING_ACCOUNTS * ACCOUNT_BYTES;
pub(super) const SUFFIX_POLYS: usize = 18;
pub(super) const SUFFIX_BYTES: usize = SUFFIX_POLYS * POLY_BYTES + 64;
pub(super) const COMPACT_SUFFIX_BYTES: usize = SUFFIX_POLYS * COMPACT_POLY_BYTES + 64;

pub fn encode_statement(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() != native_packet::STATEMENT_BYTES {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(STATEMENT_BYTES);
    out.extend_from_slice(&input[..32]);
    out.extend_from_slice(&encode_polys(&input[32..input.len() - 64])?);
    out.extend_from_slice(&input[input.len() - 64..]);
    Ok(out)
}

pub fn decode_statement(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() != STATEMENT_BYTES {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(native_packet::STATEMENT_BYTES);
    out.extend_from_slice(&input[..32]);
    out.extend_from_slice(&decode_polys(&input[32..input.len() - 64])?);
    out.extend_from_slice(&input[input.len() - 64..]);
    Ok(out)
}

pub(super) fn encode_polys(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() % POLY_BYTES != 0 || input.len() > 198 * POLY_BYTES {
        return Err(Error::Length);
    }
    let mut out = vec![0; input.len() / POLY_BYTES * COMPACT_POLY_BYTES];
    for (poly, encoded) in input
        .chunks_exact(POLY_BYTES)
        .zip(out.chunks_exact_mut(COMPACT_POLY_BYTES))
    {
        let digits = radix::unpack_bits(poly, 32)?;
        radix::encode(&digits, Q as u32, encoded)?;
    }
    Ok(out)
}

pub(super) fn decode_polys(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() % COMPACT_POLY_BYTES != 0 || input.len() > 198 * COMPACT_POLY_BYTES {
        return Err(Error::Length);
    }
    let mut out = vec![0; input.len() / COMPACT_POLY_BYTES * POLY_BYTES];
    for (encoded, poly) in input
        .chunks_exact(COMPACT_POLY_BYTES)
        .zip(out.chunks_exact_mut(POLY_BYTES))
    {
        let digits = radix::decode(encoded, Q as u32)?;
        radix::pack_bits(&digits, 32, poly)?;
    }
    Ok(out)
}

pub(super) fn validate_account(account: &[u8]) -> Result<(), Error> {
    if account.len() != ACCOUNT_BYTES {
        return Err(Error::Length);
    }
    for coefficient in account.chunks_exact(4) {
        if u64::from(u32::from_le_bytes(coefficient.try_into().unwrap())) >= Q {
            return Err(Error::NonCanonical);
        }
    }
    Ok(())
}
