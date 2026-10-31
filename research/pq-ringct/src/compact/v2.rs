//! Opt-in, lossless adaptive Rice transport for the unchanged native profile.
//!
//! Decoding is not proof verification. All v1 APIs and wire bytes remain intact.
//! Packet references have the same independently trusted checkpoint requirements
//! as v1. The native proof must still be verified after reconstruction.

mod bits;
mod packet;
mod proof;
#[cfg(test)]
mod tests;

pub use packet::{
    decode_packet, decode_referenced_packet, encode_packet, encode_referenced_packet,
    MAX_PACKET_BYTES, MAX_REFERENCED_PACKET_BYTES, MIN_PACKET_BYTES, MIN_REFERENCED_PACKET_BYTES,
};
pub use proof::{decode_proof, encode_proof, MAX_PROOF_BYTES, MIN_PROOF_BYTES};
