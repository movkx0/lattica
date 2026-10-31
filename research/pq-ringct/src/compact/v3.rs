//! Opt-in lossless transport with fixed probability tables and bounded rANS.
//!
//! All native bytes and acceptance rules are preserved. v1/v2 remain available.
//! Decoding is not proof verification; ledger checkpoint trust is external.

mod ans;
mod head;
mod models;
mod packet;
mod proof;
#[cfg(test)]
mod tests;

pub use packet::{
    decode_packet, decode_referenced_packet, encode_packet, encode_referenced_packet,
    MAX_PACKET_BYTES, MAX_REFERENCED_PACKET_BYTES, MIN_PACKET_BYTES, MIN_REFERENCED_PACKET_BYTES,
};
pub use proof::{decode_proof, encode_proof, MAX_PROOF_BYTES, MIN_PROOF_BYTES};
