//! Owned, bounded fixed N3/N4 aggregate transport. Parsing grants no acceptance.
use super::*;
use super::super::aggregation::{ExpectedBatch, Selection};
use std::{io::{Read, Seek, SeekFrom, Write}, path::Path, time::Instant};
use sha3::{Digest, Sha3_256};

pub struct AggregateArtifact {
    selection: Selection,
    header: Header,
    proof: BatchProof<profile::Config>,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RoundtripReport {
    pub encoded_bytes: usize,
    pub decoded_proof_retained_bytes: usize,
    pub artifact_sha3_256: [u8; 32],
    pub distinct_aggregate_domain: bool,
    pub exact_disk_roundtrip: bool,
    pub total_ns: u128,
}

const PATH_BYTES: usize = 512;
const TRANSPORT_FIXED_BYTES: usize = 8 * size_of::<AggregateArtifact>()
    + 8 * size_of::<Header>() + 8 * size_of::<ProofDescriptor>()
    + 8 * size_of::<Result<AggregateArtifact, Error>>()
    + 8 * size_of::<Result<(AggregateArtifact, RoundtripReport), Error>>()
    + 8 * size_of::<std::thread::Result<Result<(AggregateArtifact, RoundtripReport), Error>>>()
    + 8 * size_of::<Vec<u8>>() + 8 * size_of::<std::fs::File>()
    + 8 * size_of::<std::fs::Metadata>() + 8 * size_of::<RoundtripReport>()
    + 8 * size_of::<Instant>() + 8 * size_of::<Sha3_256>() + 8 * size_of::<[u8; 32]>()
    + 8 * PATH_BYTES + (8 << 10);

pub(in crate::ring_circuit) fn required_host_bytes() -> Result<usize, Error> {
    checked_sum(&[MAX_RETAINED_PROOF_BYTES.max(DECODE_STORAGE_LIMIT_BYTES),
        MAX_ENCODED_BYTES, FIXED_CODEC_BYTES, TRANSPORT_FIXED_BYTES])
}
type Encoder = fn(Header, usize) -> Result<[u8; HEADER_BYTES], Error>;
type Decoder = fn(&[u8]) -> Result<(Header, usize), Error>;
fn domain(selection: Selection) -> (Encoder, Decoder) {
    match selection { Selection::N3 => (Header::encode_n3, Header::decode_n3),
        Selection::N4 => (Header::encode_n4, Header::decode_n4) }
}
fn io_error(_: std::io::Error) -> Error { Error::ProofRejected }

/// A freshly created, bounded transport destination admitted before proving.
/// Keep the same file handle for writing and reading so a substituted path
/// cannot change the owner used by this round trip. Failed files are evidence.
pub(in crate::ring_circuit) struct Destination(std::fs::File);
pub(in crate::ring_circuit) fn prepare_destination(path: &Path, host_allowance: usize) -> Result<Destination, Error> {
    admit_host(required_host_bytes()?, host_allowance)?;
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > PATH_BYTES {
        return Err(Error::ResourceLimit);
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(path).map_err(io_error)?;
    Ok(Destination(file))
}

impl AggregateArtifact {
    pub(in crate::ring_circuit) fn from_proof(expected: &ExpectedBatch, descriptor: ProofDescriptor,
        proof: BatchProof<profile::Config>, host_allowance: usize) -> Result<Self, Error> {
        descriptor.admit_proof(&proof)?;
        admit_host(checked_sum(&[proof_bytes(&proof)?, FIXED_CODEC_BYTES, TRANSPORT_FIXED_BYTES])?, host_allowance)?;
        Ok(Self { selection: expected.selection(), header: Header {
            representation: CompilerRepresentation::FusedTernaryRangesV1,
            context: expected.context(), public: expected.public_binding(), descriptor }, proof })
    }
    pub fn decode(bytes: Vec<u8>, expected_selection: Selection, host_allowance: usize) -> Result<Self, Error> {
        admit_host(required_host_bytes()?, host_allowance)?;
        // The expected research representation is fixed before any proof
        // decoder allocation. An encoded profile never selects a circuit.
        let (claimed, _) = (domain(expected_selection).1)(&bytes)?;
        if claimed.representation != CompilerRepresentation::FusedTernaryRangesV1 { return Err(Error::Profile); }
        let allowance = host_allowance.checked_sub(TRANSPORT_FIXED_BYTES).ok_or(Error::ResourceLimit)?;
        let (header, proof) = decode_header_with(bytes, allowance, domain(expected_selection).1)?;
        Ok(Self { selection: expected_selection, header, proof })
    }
    pub fn encode(&self, host_allowance: usize) -> Result<Vec<u8>, Error> {
        admit_host(required_host_bytes()?, host_allowance)?;
        let allowance = host_allowance.checked_sub(TRANSPORT_FIXED_BYTES).ok_or(Error::ResourceLimit)?;
        encode_header_with(self.header, &self.proof, allowance, domain(self.selection).0)
    }
    pub fn selection(&self) -> Selection { self.selection }
    pub fn descriptor(&self) -> ProofDescriptor { self.header.descriptor }
    pub fn public_binding(&self) -> [Val; 4] { self.header.public }
    pub fn context(&self) -> Context { self.header.context }
    pub(in crate::ring_circuit) fn proof(&self) -> &BatchProof<profile::Config> { &self.proof }
    pub(in crate::ring_circuit) fn proof_mut(&mut self) -> &mut BatchProof<profile::Config> { &mut self.proof }
    pub(in crate::ring_circuit) fn check_expected(&self, expected: &ExpectedBatch) -> Result<(), Error> {
        if self.selection != expected.selection() || self.header.representation != CompilerRepresentation::FusedTernaryRangesV1 {
            return Err(Error::Profile);
        }
        if self.header.context != expected.context() { return Err(Error::Context); }
        if self.header.public != expected.public_binding() { return Err(Error::ProofRejected); }
        self.header.descriptor.admit_proof(&self.proof)
    }
    pub(in crate::ring_circuit) fn check_descriptor(&self, expected: ProofDescriptor) -> Result<(), Error> {
        if self.header.descriptor != expected { return Err(Error::ProofRejected); }
        Ok(())
    }
    /// Consume the original proof before allocating any replacement proof. The
    /// existing file is never overwritten, every read is length/capacity bounded,
    /// and canonical decoding includes its own cumulative scratch admission.
    pub(in crate::ring_circuit) fn disk_roundtrip(self, destination: Destination, host_allowance: usize)
        -> Result<(Self, RoundtripReport), Error> {
        admit_host(required_host_bytes()?, host_allowance)?;
        let started = Instant::now();
        let selection = self.selection;
        let expected = self.header;
        let bytes = self.encode(host_allowance)?;
        let encoded_bytes = bytes.len();
        let artifact_sha3_256: [u8; 32] = Sha3_256::digest(&bytes).into();
        let Destination(mut output) = destination;
        output.write_all(&bytes).map_err(io_error)?;
        output.sync_all().map_err(io_error)?;
        drop(self);
        drop(bytes);
        output.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut input = output;
        let length = usize::try_from(input.metadata().map_err(io_error)?.len()).map_err(|_| Error::ResourceLimit)?;
        if length != encoded_bytes || length > MAX_ENCODED_BYTES { return Err(Error::Geometry); }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(MAX_ENCODED_BYTES).map_err(|_| Error::ResourceLimit)?;
        if bytes.capacity() != MAX_ENCODED_BYTES { return Err(Error::ResourceLimit); }
        bytes.resize(length, 0);
        input.read_exact(&mut bytes).map_err(io_error)?;
        if input.read(&mut [0; 1]).map_err(io_error)? != 0 { return Err(Error::Geometry); }
        drop(input);
        let read_digest: [u8; 32] = Sha3_256::digest(&bytes).into();
        if read_digest != artifact_sha3_256 { return Err(Error::ProofRejected); }
        // Expected transport claims are checked before decoder allocation. They
        // remain untrusted until separately reconstructed numerical verification.
        let (header, _) = domain(selection).1(&bytes)?;
        if header.representation != expected.representation || header.context != expected.context
            || header.public != expected.public || header.descriptor != expected.descriptor { return Err(Error::ProofRejected); }
        let decoded = Self::decode(bytes, selection, host_allowance)?;
        let retained = proof_bytes(&decoded.proof)?;
        Ok((decoded, RoundtripReport { encoded_bytes, decoded_proof_retained_bytes: retained, artifact_sha3_256,
            distinct_aggregate_domain: true, exact_disk_roundtrip: true, total_ns: started.elapsed().as_nanos() }))
    }

    pub(in crate::ring_circuit) fn probe_envelopes(&mut self, expected: &ExpectedBatch, descriptor: ProofDescriptor) -> Result<usize, Error> {
        self.check_expected(expected)?;
        self.check_descriptor(descriptor)?;
        let saved = self.header;
        self.header.context.0[0] ^= 1;
        let wrong_context = self.check_expected(expected).is_err();
        self.header = saved;
        self.header.public[0] += <Val as p3_field::PrimeCharacteristicRing>::ONE;
        let wrong_public = self.check_expected(expected).is_err();
        self.header = saved;
        self.header.descriptor.canonical_manifest_digest[0] ^= 1;
        let wrong_manifest = self.check_descriptor(descriptor).is_err();
        self.header = saved;
        if !(wrong_context && wrong_public && wrong_manifest) { return Err(Error::ProofRejected); }
        Ok(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    fn header() -> Header {
        Header { representation: CompilerRepresentation::FusedTernaryRangesV1,
            context: Context([3; 32]), public: [Val::ZERO; 4],
            descriptor: ProofDescriptor { active_rows: 1, padded_rows: 8, wires: 4,
                witness_values: 0, canonical_manifest_digest: [9; 32], registered_program_id: [0; 4] } }
    }
    #[test]
    fn aggregate_domains_cannot_be_reinterpreted_as_another_count_or_old_artifact() {
        let n3 = Header::encode_n3(header(), 8).unwrap();
        let n4 = Header::encode_n4(header(), 8).unwrap();
        assert!(Header::decode_n3(&n3).is_ok());
        assert!(Header::decode_n4(&n4).is_ok());
        assert!(Header::decode_n4(&n3).is_err());
        assert!(Header::decode_n3(&n4).is_err());
        assert!(Header::decode(&n3).is_err());
        assert!(Header::decode_outer(&n3).is_err());
        let wrong_representation = Header { representation: CompilerRepresentation::InlinePublicMontgomeryConstantsV2, ..header() };
        let wrong_profile = Header::encode_n3(wrong_representation, 8).unwrap().to_vec();
        assert!(matches!(AggregateArtifact::decode(wrong_profile, Selection::N3, required_host_bytes().unwrap()), Err(Error::Profile)));
        let mut mutated = n3;
        mutated[8] ^= 1;
        assert!(Header::decode_n3(&mutated).is_err());
        let mut noncanonical = n3;
        noncanonical[8+32+4+32..8+32+4+32+8].copy_from_slice(&crate::GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(Header::decode_n3(&noncanonical), Err(Error::NonCanonical)));
    }
    #[test]
    fn codec_refuses_complete_storage_boundary_before_allocation_or_file_creation() {
        let needed = required_host_bytes().unwrap();
        assert!(needed <= WORKER_HOST_BYTES);
        assert!(AggregateArtifact::decode(Vec::new(), Selection::N3, needed - 1).is_err());
        assert!(AggregateArtifact::decode(Vec::new(), Selection::N4, WORKER_HOST_BYTES + 1).is_err());
        assert!(prepare_destination(Path::new("/tmp/direct-ring-aggregate-must-not-be-created"), needed - 1).is_err());
        assert!(prepare_destination(Path::new("relative"), needed).is_err());
    }
}
