//! Lossless transport for the fixed native MatRiCT+ profile.
//!
//! These codecs reproduce the original statement and proof bytes exactly. They
//! do not change the transcript, security parameters, or proof relation. Decoding
//! is not proof verification or transaction acceptance. Use the existing native
//! or independent Rust verifier on the reconstructed packet.
//!
//! Referenced packets additionally require a caller-trusted ledger checkpoint
//! and locally available account membership witnesses. They do not authenticate
//! a checkpoint supplied by a sender, check spent serials, or implement consensus.

mod error;
pub mod ledger;
mod packet;
mod proof;
mod radix;
mod statement;
pub mod v2;
pub mod v3;

pub use error::Error;
pub use packet::{
    decode_packet, decode_referenced_packet, encode_packet, encode_referenced_packet, PACKET_BYTES,
    REFERENCED_PACKET_BYTES,
};
pub use proof::{decode_proof, encode_proof, PROOF_BYTES};
pub use statement::{decode_statement, encode_statement, STATEMENT_BYTES};

#[cfg(test)]
mod tests;
