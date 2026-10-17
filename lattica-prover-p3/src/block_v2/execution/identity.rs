//! Portable domain-separated identities for worker and scheduler metadata.
use crate::block_v2::{commitment, recursive::Error};

pub(crate) fn digest(domain: u64, bytes: &[u8]) -> Result<[u8; 32], Error> {
    let fields = [1, bytes.len() as u64]
        .into_iter()
        .chain(commitment::stream::words(bytes));
    Ok(commitment::digest_bytes(commitment::stream::hash_fields(
        domain,
        2 + bytes.len().div_ceil(4),
        fields,
    )?)?)
}
