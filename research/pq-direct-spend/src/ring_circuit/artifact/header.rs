use super::{CompilerRepresentation, Context, Error, ProofDescriptor, Statement, Val};
use lattica_prover_p3::block_v2::{machine, profile};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Digest, Sha3_256};

const MAGIC: [u8; 8] = *b"LDRING01";
#[cfg(feature = "ring-recursive-outer-experiment")]
const OUTER_MAGIC: [u8; 8] = *b"LDOUTR01";
// Magic, local-profile digest, representation tag, context, binding, geometry,
// manifest digest, registered program ID, encoded proof length. No padding.
pub(super) const HEADER_BYTES: usize = 8 + 32 + 4 + 32 + 32 + 32 + 32 + 32 + 8;

#[derive(Clone, Copy)]
pub(super) struct Header {
    pub(super) representation: CompilerRepresentation,
    pub(super) context: Context,
    pub(super) public: [Val; 4],
    pub(super) descriptor: ProofDescriptor,
}

/// The same two SHAKE invocations as Statement::binding, streamed through fixed
/// state so envelope checks do not allocate a temporary public-statement Vec.
pub(super) fn public_binding(statement: &Statement) -> [Val; 4] {
    let mut first = sha3::Shake256::default();
    let mut update = |bytes: &[u8]| sha3::digest::Update::update(&mut first, bytes);
    update(statement.profile.tag().as_bytes());
    update(&statement.context.0);
    update(&statement.setup_seed);
    for poly in statement
        .ring
        .iter()
        .flatten()
        .flat_map(|account| account.public_key.iter().chain(account.coin.iter()))
        .chain(statement.recipients.iter().flatten())
        .chain(statement.output_coins.iter().flatten())
    {
        for value in poly {
            update(&value.to_le_bytes());
        }
    }
    for serial in statement.serials {
        update(&serial);
    }
    let mut digest = [0; 32];
    first.finalize_xof().read(&mut digest);
    let mut second = sha3::Shake256::default();
    sha3::digest::Update::update(&mut second, crate::Profile::RingDirectV1.tag().as_bytes());
    sha3::digest::Update::update(&mut second, &digest);
    second.finalize_xof().read(&mut digest);
    std::array::from_fn(|i| {
        Val::from_u64(
            u64::from_le_bytes(
                digest[i * 8..i * 8 + 8]
                    .try_into()
                    .expect("fixed digest lane"),
            ) % crate::GOLDILOCKS_MODULUS,
        )
    })
}

fn representation_tag(value: CompilerRepresentation) -> u32 {
    match value {
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2 => 1,
        CompilerRepresentation::FusedPublicLinearV1 => 2,
        CompilerRepresentation::FusedPublicNttV1 => 3,
        CompilerRepresentation::FusedTernaryNttV1 => 4,
        CompilerRepresentation::FusedTernaryRangesV1 => 5,
    }
}

fn representation(value: u32) -> Result<CompilerRepresentation, Error> {
    Ok(match value {
        1 => CompilerRepresentation::InlinePublicMontgomeryConstantsV2,
        2 => CompilerRepresentation::FusedPublicLinearV1,
        3 => CompilerRepresentation::FusedPublicNttV1,
        4 => CompilerRepresentation::FusedTernaryNttV1,
        5 => CompilerRepresentation::FusedTernaryRangesV1,
        _ => return Err(Error::Profile),
    })
}

/// Descriptive local profile identity. The expected statement, complete
/// reconstructed program and fresh preprocessing cap remain authoritative.
pub(super) fn profile_digest(representation: CompilerRepresentation) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/research/direct-ring/full-proof/profile/v1");
    hash.update(crate::Profile::RingDirectV1.tag().as_bytes());
    hash.update(representation.name().as_bytes());
    hash.update(profile::CANDIDATE_PROFILE_ID);
    for word in [
        crate::GOLDILOCKS_MODULUS,
        crate::ring::Q,
        crate::ring::QHAT,
        crate::ring::D as u64,
        crate::ring::RING_PAIRS as u64,
        crate::INPUTS as u64,
        crate::OUTPUTS as u64,
        crate::VALUE_BITS as u64,
        machine::program::LANES as u64,
        machine::WIDTH as u64,
        machine::program::OPCODE_BITS as u64,
        machine::program::MAX_PUBLIC_VALUES as u64,
        profile::NODE_CODEC_REVISION,
        profile::NUM_QUERIES as u64,
        profile::LOG_BLOWUP as u64,
        profile::CAP_HEIGHT as u64,
        profile::NUM_RANDOM_CODEWORDS as u64,
        profile::QUERY_POW_BITS as u64,
        profile::CHALLENGE_FIELD_BITS as u64,
        profile::HASH_COLLISION_BITS as u64,
    ] {
        hash.update(word.to_le_bytes());
    }
    hash.finalize().into()
}

#[cfg(feature = "ring-recursive-outer-experiment")]
fn outer_profile_digest(representation: CompilerRepresentation) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/research/direct-ring/single-child-outer-artifact/v1");
    hash.update(profile_digest(representation));
    hash.update(1u64.to_le_bytes()); // Exactly one independently verified child.
    hash.update(4u64.to_le_bytes()); // Unchanged statement public binding.
    hash.finalize().into()
}

#[cfg(feature = "ring-direct-aggregate-experiment")]
fn aggregate_digest(representation: CompilerRepresentation, children: u64) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/research/direct-ring/fixed-flat-aggregate/artifact/v1");
    hash.update(profile_digest(representation));
    hash.update(children.to_le_bytes());
    hash.update(4u64.to_le_bytes());
    hash.finalize().into()
}
#[cfg(feature = "ring-direct-aggregate-experiment")]
fn n3_digest(representation: CompilerRepresentation) -> [u8; 32] { aggregate_digest(representation, 3) }
#[cfg(feature = "ring-direct-aggregate-experiment")]
fn n4_digest(representation: CompilerRepresentation) -> [u8; 32] { aggregate_digest(representation, 4) }

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::Geometry)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::Geometry)?
            .try_into()
            .map_err(|_| Error::Geometry)?;
        self.offset = end;
        Ok(value)
    }

    fn word(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
}

impl Header {
    pub(super) fn for_statement(
        statement: &Statement,
        expected: Context,
        representation: CompilerRepresentation,
        descriptor: ProofDescriptor,
    ) -> Result<Self, Error> {
        statement.admit(expected)?;
        descriptor.admit()?;
        Ok(Self {
            representation,
            context: expected,
            public: public_binding(statement),
            descriptor,
        })
    }

    pub(super) fn encode(self, payload_len: usize) -> Result<[u8; HEADER_BYTES], Error> {
        self.encode_domain(payload_len, &MAGIC, profile_digest(self.representation))
    }

    #[cfg(feature = "ring-recursive-outer-experiment")]
    pub(super) fn encode_outer(self, payload_len: usize) -> Result<[u8; HEADER_BYTES], Error> {
        self.encode_domain(
            payload_len,
            &OUTER_MAGIC,
            outer_profile_digest(self.representation),
        )
    }

    #[cfg(feature = "ring-direct-aggregate-experiment")]
    pub(super) fn encode_n3(self, payload_len: usize) -> Result<[u8; HEADER_BYTES], Error> {
        self.encode_domain(payload_len, b"LDAGG301", n3_digest(self.representation))
    }
    #[cfg(feature = "ring-direct-aggregate-experiment")]
    pub(super) fn encode_n4(self, payload_len: usize) -> Result<[u8; HEADER_BYTES], Error> {
        self.encode_domain(payload_len, b"LDAGG401", n4_digest(self.representation))
    }

    fn encode_domain(
        self,
        payload_len: usize,
        magic: &[u8; 8],
        digest: [u8; 32],
    ) -> Result<[u8; HEADER_BYTES], Error> {
        self.descriptor.admit()?;
        if !(8..=profile::MAX_PROOF_BYTES).contains(&payload_len) {
            return Err(Error::Geometry);
        }
        let mut bytes = [0; HEADER_BYTES];
        let mut offset = 0;
        let mut push = |value: &[u8]| {
            bytes[offset..offset + value.len()].copy_from_slice(value);
            offset += value.len();
        };
        push(magic);
        push(&digest);
        push(&representation_tag(self.representation).to_le_bytes());
        push(&self.context.0);
        for value in self.public {
            push(&value.as_canonical_u64().to_le_bytes());
        }
        for value in [
            self.descriptor.active_rows,
            self.descriptor.padded_rows,
            self.descriptor.wires,
            self.descriptor.witness_values,
        ] {
            push(&value.to_le_bytes());
        }
        push(&self.descriptor.canonical_manifest_digest);
        for value in self.descriptor.registered_program_id {
            push(&value.to_le_bytes());
        }
        push(&(payload_len as u64).to_le_bytes());
        debug_assert_eq!(offset, HEADER_BYTES);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        Self::decode_domain(bytes, &MAGIC, profile_digest)
    }

    #[cfg(feature = "ring-recursive-outer-experiment")]
    pub(super) fn decode_outer(bytes: &[u8]) -> Result<(Self, usize), Error> {
        Self::decode_domain(bytes, &OUTER_MAGIC, outer_profile_digest)
    }

    #[cfg(feature = "ring-direct-aggregate-experiment")]
    pub(super) fn decode_n3(bytes: &[u8]) -> Result<(Self, usize), Error> {
        Self::decode_domain(bytes, b"LDAGG301", n3_digest)
    }
    #[cfg(feature = "ring-direct-aggregate-experiment")]
    pub(super) fn decode_n4(bytes: &[u8]) -> Result<(Self, usize), Error> {
        Self::decode_domain(bytes, b"LDAGG401", n4_digest)
    }

    fn decode_domain(
        bytes: &[u8],
        magic: &[u8; 8],
        profile: fn(CompilerRepresentation) -> [u8; 32],
    ) -> Result<(Self, usize), Error> {
        let mut reader = Reader { bytes, offset: 0 };
        if &reader.bytes::<8>()? != magic {
            return Err(Error::Profile);
        }
        let digest = reader.bytes::<32>()?;
        let representation = representation(u32::from_le_bytes(reader.bytes()?))?;
        if digest != profile(representation) {
            return Err(Error::Profile);
        }
        let context = Context(reader.bytes()?);
        let mut public = [Val::ZERO; 4];
        for value in &mut public {
            let word = reader.word()?;
            if word >= crate::GOLDILOCKS_MODULUS {
                return Err(Error::NonCanonical);
            }
            *value = Val::from_u64(word);
        }
        let active_rows = reader.word()?;
        let padded_rows = reader.word()?;
        let wires = reader.word()?;
        let witness_values = reader.word()?;
        let canonical_manifest_digest = reader.bytes()?;
        let mut registered_program_id = [0; 4];
        for value in &mut registered_program_id {
            *value = reader.word()?;
        }
        let descriptor = ProofDescriptor {
            active_rows,
            padded_rows,
            wires,
            witness_values,
            canonical_manifest_digest,
            registered_program_id,
        };
        descriptor.admit()?;
        let payload_len = usize::try_from(reader.word()?).map_err(|_| Error::Geometry)?;
        if !(8..=profile::MAX_PROOF_BYTES).contains(&payload_len) || reader.offset != HEADER_BYTES {
            return Err(Error::Geometry);
        }
        Ok((
            Self {
                representation,
                context,
                public,
                descriptor,
            },
            payload_len,
        ))
    }
}
