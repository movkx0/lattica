//! Bounded transport of one outer proof. This helper has no acceptance API:
//! every returned proof still requires expected-source reconstruction and a
//! fresh independently registered verifier. No cap, program or key is encoded.
use super::*;
use std::time::Instant;

/// Transport observations only. Neither parsing nor these numbers attest to
/// proof validity; the enclosing independent-verification report does that.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Report {
    pub encoded_bytes: usize,
    pub decoded_proof_retained_bytes: usize,
    pub total_ns: u128,
}

// This additive, transport-only state is separate from the original fixed
// codec and caller allowances. Both are retained in required_host_bytes.
// Count helper/return/move frames explicitly, without assuming move elision.
const TRANSPORT_FIXED_BYTES: usize = 8 * size_of::<Header>()
    + 8 * size_of::<ProofDescriptor>()
    + 4 * size_of::<BatchProof<profile::Config>>()
    + 4 * size_of::<Result<BatchProof<profile::Config>, Error>>()
    + 4 * size_of::<Result<(BatchProof<profile::Config>, Report), Error>>()
    + 4 * size_of::<std::thread::Result<Result<(BatchProof<profile::Config>, Report), Error>>>()
    + 4 * size_of::<Result<(Header, BatchProof<profile::Config>), Error>>()
    + 8 * size_of::<Vec<u8>>()
    + 8 * size_of::<Report>()
    + 8 * size_of::<Context>()
    + 8 * size_of::<CompilerRepresentation>()
    + 8 * size_of::<[Val; 4]>()
    + 8 * size_of::<Instant>()
    + (2 << 10);

/// Before dispatch, admit the full possible original proof, full encoded
/// capacity, existing codec scratch and additive transport state. After encode
/// the original proof drops before decode, so the same slot covers the entire
/// cumulative decode/canonicalization bound. Other owners remain separate.
pub(in crate::ring_circuit) fn required_host_bytes() -> Result<usize, Error> {
    checked_sum(&[
        MAX_RETAINED_PROOF_BYTES.max(DECODE_STORAGE_LIMIT_BYTES),
        MAX_ENCODED_BYTES,
        FIXED_CODEC_BYTES,
        TRANSPORT_FIXED_BYTES,
    ])
}

fn codec_allowance(host_allowance: usize) -> Result<usize, Error> {
    admit_host(required_host_bytes()?, host_allowance)?;
    host_allowance
        .checked_sub(TRANSPORT_FIXED_BYTES)
        .ok_or(Error::ResourceLimit)
}

fn decode_expected(
    bytes: Vec<u8>,
    expected: Header,
    host_allowance: usize,
) -> Result<BatchProof<profile::Config>, Error> {
    // Full input capacity, not length, is admitted before decoding. Check the
    // immutable expected claims before allocating a single decoded proof.
    admit_host(decoding_required_host_bytes(&bytes)?, host_allowance)?;
    let (header, _) = Header::decode_outer(&bytes)?;
    if header.representation != expected.representation {
        return Err(Error::Profile);
    }
    if header.context != expected.context {
        return Err(Error::Context);
    }
    if header.public != expected.public || header.descriptor != expected.descriptor {
        return Err(Error::ProofRejected);
    }
    let (_, proof) = decode_header_with(bytes, host_allowance, Header::decode_outer)?;
    Ok(proof)
}

/// Consume the sole original proof. Expected fields come from the private
/// independently verified child source and the outer prover's actual descriptor;
/// the latter is checked against independent reconstruction after this returns.
pub(in crate::ring_circuit) fn roundtrip(
    proof: BatchProof<profile::Config>,
    context: Context,
    representation: CompilerRepresentation,
    public: [Val; 4],
    descriptor: ProofDescriptor,
    host_allowance: usize,
) -> Result<(BatchProof<profile::Config>, Report), Error> {
    let allowance = codec_allowance(host_allowance)?;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        roundtrip_inner(
            proof,
            context,
            representation,
            public,
            descriptor,
            allowance,
        )
    })) {
        Ok(result) => result,
        Err(payload) => {
            drop(payload);
            Err(Error::ProofRejected)
        }
    }
}

fn roundtrip_inner(
    proof: BatchProof<profile::Config>,
    context: Context,
    representation: CompilerRepresentation,
    public: [Val; 4],
    descriptor: ProofDescriptor,
    allowance: usize,
) -> Result<(BatchProof<profile::Config>, Report), Error> {
    let started = Instant::now();
    let expected = Header {
        representation,
        context,
        public,
        descriptor,
    };
    let bytes = encode_header_with(expected, &proof, allowance, Header::encode_outer)?;
    let encoded_bytes = bytes.len();
    // No clone or second retained proof may overlap decoder allocation.
    drop(proof);
    let proof = decode_expected(bytes, expected, allowance)?;
    let decoded_proof_retained_bytes = proof_bytes(&proof)?;
    Ok((
        proof,
        Report {
            encoded_bytes,
            decoded_proof_retained_bytes,
            total_ns: started.elapsed().as_nanos(),
        },
    ))
}

#[cfg(test)]
mod tests;
