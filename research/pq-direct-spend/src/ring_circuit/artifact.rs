//! Bounded transport for one full direct-ring proof, never an acceptance receipt.
//!
//! The envelope contains claims, not a program, preprocessing cap, verifier or
//! public AES matrices. Verification reconstructs all of those independently
//! from the expected statement. The concrete core codec checks every nested
//! allocation before reserving and rejects noncanonical encodings.

use super::{CompilerRepresentation, Val};
use crate::{ring::Statement, Context, Error};
use lattica_prover_p3::block_v2::{
    codec, machine::backend::retained_proof_capacity_bytes, profile,
};
use p3_batch_stark::BatchProof;
use serde::Serialize;
use std::mem::size_of;

mod header;
use header::Header;
#[cfg(feature = "ring-recursive-outer-experiment")]
pub(super) mod outer;
#[cfg(feature = "ring-direct-aggregate-experiment")]
pub mod aggregate;

pub(super) fn statement_binding(statement: &Statement) -> [Val; 4] {
    header::public_binding(statement)
}

pub(super) fn profile_digest(representation: CompilerRepresentation) -> [u8; 32] {
    header::profile_digest(representation)
}

pub const MAX_PADDED_ROWS: u64 = 1 << 20;
pub const HEADER_BYTES: usize = header::HEADER_BYTES;
pub const MAX_ENCODED_BYTES: usize = HEADER_BYTES + profile::MAX_PROOF_BYTES;
/// Cumulative decoder allocations, including canonical re-encoding scratch.
pub const DECODE_STORAGE_LIMIT_BYTES: usize = codec::REGISTERED_PROOF_STORAGE_LIMIT_BYTES;
pub const MAX_RETAINED_PROOF_BYTES: usize = DECODE_STORAGE_LIMIT_BYTES;
// Fixed headers, parser state and short-lived moves are charged inside the
// caller's remaining worker allowance. This is not an extra worker budget.
pub const FIXED_CODEC_BYTES: usize = 16 << 10;
const WORKER_HOST_BYTES: usize = 32 << 30;
const _: () = assert!(
    8 * size_of::<Header>()
        + 8 * size_of::<ProofDescriptor>()
        + 4 * size_of::<BatchProof<profile::Config>>()
        + 4 * size_of::<Result<(Header, BatchProof<profile::Config>), Error>>()
        + 4 * size_of::<Result<Vec<u8>, Error>>()
        + 8 * size_of::<Vec<u8>>()
        + 4 * HEADER_BYTES
        + (2 << 10)
        < FIXED_CODEC_BYTES
);

/// Public transport claims. Copying this value conveys no authority to prove
/// or verify, and no claimed dimension selects the reconstructed relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProofDescriptor {
    pub active_rows: u64,
    pub padded_rows: u64,
    pub wires: u64,
    pub witness_values: u64,
    pub canonical_manifest_digest: [u8; 32],
    pub registered_program_id: [u64; 4],
}

impl ProofDescriptor {
    fn admit(self) -> Result<(), Error> {
        use lattica_prover_p3::block_v2::machine::program::MAX_WIRES;
        if !(8..=MAX_PADDED_ROWS).contains(&self.padded_rows)
            || !self.padded_rows.is_power_of_two()
            || self.active_rows == 0
            || self.active_rows > self.padded_rows
            || !(4..=MAX_WIRES as u64).contains(&self.wires)
            || self.witness_values > self.wires - 4
        {
            return Err(Error::Geometry);
        }
        if self
            .registered_program_id
            .iter()
            .any(|&v| v >= crate::GOLDILOCKS_MODULUS)
        {
            return Err(Error::NonCanonical);
        }
        Ok(())
    }

    fn admit_proof(self, proof: &BatchProof<profile::Config>) -> Result<(), Error> {
        self.admit()?;
        let degree = self.padded_rows.ilog2() as usize + 1;
        if proof.degree_bits.as_slice() != [degree]
            || proof.opened_values.instances.len() != 1
            || proof.opening_proof.1.query_proofs.len() != profile::NUM_QUERIES
        {
            return Err(Error::Geometry);
        }
        Ok(())
    }
}

/// An owned, unverified proof. No raw program, verifier key or trusted cap can
/// enter this container. Its descriptor must match independently rebuilt state.
pub struct Artifact {
    header: Header,
    proof: BatchProof<profile::Config>,
}

fn checked_sum(parts: &[usize]) -> Result<usize, Error> {
    parts
        .iter()
        .try_fold(0usize, |sum, n| sum.checked_add(*n))
        .ok_or(Error::ResourceLimit)
}

fn admit_host(required: usize, allowance: usize) -> Result<(), Error> {
    if allowance > WORKER_HOST_BYTES || required > allowance {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

fn proof_bytes(proof: &BatchProof<profile::Config>) -> Result<usize, Error> {
    retained_proof_capacity_bytes(proof, MAX_RETAINED_PROOF_BYTES).map_err(|_| Error::ResourceLimit)
}

/// Source-derived reservation for an existing proof, the full encoded output
/// capacity and fixed codec state. Other live owners must be charged separately.
/// This allocation-free measurement does not attest to proof validity.
pub fn encoding_required_host_bytes(proof: &BatchProof<profile::Config>) -> Result<usize, Error> {
    checked_sum(&[proof_bytes(proof)?, MAX_ENCODED_BYTES, FIXED_CODEC_BYTES])
}

/// Source-derived decoder reservation from the complete input Vec owner,
/// including spare capacity, cumulative decoding/canonicalization and fixed
/// state. Other live owners are separate. No bytes are decoded by this query.
pub fn decoding_required_host_bytes(bytes: &Vec<u8>) -> Result<usize, Error> {
    checked_sum(&[
        bytes.capacity(),
        DECODE_STORAGE_LIMIT_BYTES,
        FIXED_CODEC_BYTES,
    ])
}

fn encode_header(
    header: Header,
    proof: &BatchProof<profile::Config>,
    host_allowance: usize,
) -> Result<Vec<u8>, Error> {
    encode_header_with(header, proof, host_allowance, Header::encode)
}

fn encode_header_with(
    header: Header,
    proof: &BatchProof<profile::Config>,
    host_allowance: usize,
    encode: fn(Header, usize) -> Result<[u8; HEADER_BYTES], Error>,
) -> Result<Vec<u8>, Error> {
    header.descriptor.admit_proof(proof)?;
    // Existing proof, full output capacity and all fixed codec state coexist.
    admit_host(encoding_required_host_bytes(proof)?, host_allowance)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(MAX_ENCODED_BYTES)
        .map_err(|_| Error::ResourceLimit)?;
    if output.capacity() != MAX_ENCODED_BYTES {
        return Err(Error::ResourceLimit);
    }
    output.resize(MAX_ENCODED_BYTES, 0);
    let payload_len = codec::encode_registered_proof_into(proof, &mut output[HEADER_BYTES..])
        .map_err(|_| Error::ProofRejected)?
        .len();
    let bytes = encode(header, payload_len)?;
    output[..HEADER_BYTES].copy_from_slice(&bytes);
    output.truncate(HEADER_BYTES + payload_len);
    Ok(output)
}

// Shared bounded decoder. The selected caller fixes the domain before any
// allocation; an encoded domain never chooses an expected relation or key.
fn decode_header_with(
    bytes: Vec<u8>,
    host_allowance: usize,
    decode: fn(&[u8]) -> Result<(Header, usize), Error>,
) -> Result<(Header, BatchProof<profile::Config>), Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::ResourceLimit);
    }
    let (header, payload_len) = decode(&bytes)?;
    if bytes.len() != checked_sum(&[HEADER_BYTES, payload_len])? {
        return Err(Error::Geometry);
    }
    admit_host(decoding_required_host_bytes(&bytes)?, host_allowance)?;
    let proof =
        codec::decode_registered_proof_bounded(&bytes[HEADER_BYTES..], DECODE_STORAGE_LIMIT_BYTES)
            .map_err(|_| Error::ProofRejected)?;
    header.descriptor.admit_proof(&proof)?;
    proof_bytes(&proof)?;
    drop(bytes);
    Ok((header, proof))
}

/// Encode one already-owned proof by borrow. This performs bounded transport
/// checks only. The caller must separately charge any other live owners.
pub fn encode(
    statement: &Statement,
    expected: Context,
    representation: CompilerRepresentation,
    descriptor: ProofDescriptor,
    proof: &BatchProof<profile::Config>,
    host_allowance: usize,
) -> Result<Vec<u8>, Error> {
    let header = Header::for_statement(statement, expected, representation, descriptor)?;
    encode_header(header, proof, host_allowance)
}

impl Artifact {
    /// Wrap an already-owned proof without cloning. This does not claim that
    /// the proof is valid; independent verification remains mandatory.
    pub fn from_proof(
        statement: &Statement,
        expected: Context,
        representation: CompilerRepresentation,
        descriptor: ProofDescriptor,
        proof: BatchProof<profile::Config>,
        host_allowance: usize,
    ) -> Result<Self, Error> {
        let header = Header::for_statement(statement, expected, representation, descriptor)?;
        descriptor.admit_proof(&proof)?;
        admit_host(
            checked_sum(&[proof_bytes(&proof)?, FIXED_CODEC_BYTES])?,
            host_allowance,
        )?;
        Ok(Self { header, proof })
    }

    /// Consume the complete packet owner so spare input capacity can be charged
    /// before any decoder allocation. The packet drops only after decoding and
    /// canonicality checks finish. The quota includes canonical re-encoding.
    pub fn decode(bytes: Vec<u8>, host_allowance: usize) -> Result<Self, Error> {
        let (header, proof) = decode_header_with(bytes, host_allowance, Header::decode)?;
        Ok(Self { header, proof })
    }

    pub fn encode(&self, host_allowance: usize) -> Result<Vec<u8>, Error> {
        encode_header(self.header, &self.proof, host_allowance)
    }

    pub fn encoding_required_host_bytes(&self) -> Result<usize, Error> {
        encoding_required_host_bytes(&self.proof)
    }

    pub fn descriptor(&self) -> ProofDescriptor {
        self.header.descriptor
    }

    pub fn representation(&self) -> CompilerRepresentation {
        self.header.representation
    }

    pub fn context(&self) -> Context {
        self.header.context
    }

    pub fn public(&self) -> [Val; 4] {
        self.header.public
    }

    pub fn proof(&self) -> &BatchProof<profile::Config> {
        &self.proof
    }

    // Only the sibling verifier's restored mutation probe may change an owned
    // proof. The public transport API never exposes mutable acceptance claims.
    pub(super) fn proof_mut(&mut self) -> &mut BatchProof<profile::Config> {
        &mut self.proof
    }

    #[cfg(all(test, feature = "gpu-proving"))]
    pub(super) fn forge_header_for_test(
        &mut self,
        statement: &Statement,
        representation: CompilerRepresentation,
        descriptor: ProofDescriptor,
    ) -> Result<(), Error> {
        self.header =
            Header::for_statement(statement, statement.context, representation, descriptor)?;
        Ok(())
    }

    /// Complete owned header plus proof backing, including all spare capacity.
    /// Packet buffers, other owners and verifier scratch are separate lifetimes.
    pub fn retained_host_bytes(&self) -> Result<usize, Error> {
        checked_sum(&[size_of::<Self>(), proof_bytes(&self.proof)?])
    }

    pub(super) fn check_expected(
        &self,
        statement: &Statement,
        expected: Context,
        representation: CompilerRepresentation,
    ) -> Result<(), Error> {
        statement.admit(expected)?;
        if self.header.representation != representation {
            return Err(Error::Profile);
        }
        if self.header.context != expected {
            return Err(Error::Context);
        }
        if self.header.public != header::public_binding(statement) {
            return Err(Error::ProofRejected);
        }
        self.header.descriptor.admit_proof(&self.proof)
    }
}

#[cfg(test)]
mod tests;
