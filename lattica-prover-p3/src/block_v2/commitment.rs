//! Candidate v2 ordered transaction commitment; NOT recursive proof verification.
//!
//! Matches `src/block_v2.zig`. This is a native hashing/codec foundation, not a
//! block wire format or a production-ready proof path. Statements must be
//! derived/verified by the caller. Summary helpers check structure, not proof
//! authority: a nonempty root does not authenticate its claimed count or context
//! without its leaves (or a future constrained proof).

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

pub type Digest = [u64; 4];
pub const CAPACITY: usize = 64;
pub const DEPTH: u8 = 6;
pub const LEAF: u64 = 0x4c42563201;
pub const EMPTY: u64 = 0x4c42563202;
pub const NODE: u64 = 0x4c42563203;
/// Per-kind statement domains are STATEMENT + kind (5, 6, 7 in this namespace).
pub const STATEMENT: u64 = 0x4c42563204;
pub const MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    InvalidLength,
    InvalidKind,
    NonCanonicalField,
    EmptyBlock,
    TooManyEntries,
    InvalidLevel,
    InvalidCount,
    ContextMismatch,
    LevelMismatch,
    NonDensePrefix,
    InvalidEmptyRoot,
}

impl core::fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidLength => "invalid commitment encoding or field length",
            Self::InvalidKind => "unknown transaction kind",
            Self::NonCanonicalField => "noncanonical Goldilocks field element",
            Self::EmptyBlock => "transaction block must contain at least one entry",
            Self::TooManyEntries => "transaction block exceeds capacity 64",
            Self::InvalidLevel => "subtree level exceeds depth 6",
            Self::InvalidCount => "subtree count exceeds its level capacity",
            Self::ContextMismatch => "child contexts differ",
            Self::LevelMismatch => "child levels differ",
            Self::NonDensePrefix => "nonempty right subtree requires a full left subtree",
            Self::InvalidEmptyRoot => "zero-count subtree must have its canonical empty root",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CommitmentError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    /// Caller-supplied profile bytes; this module does not register or approve
    /// a consensus profile identity (a candidate label is only a label).
    pub profile_id: [u8; 32],
    pub chain_id: [u8; 32],
}

impl Context {
    /// Injective encoding: profile's eight LE u32 limbs, then chain's eight.
    /// Arbitrary identifiers are NOT reduced modulo Goldilocks.
    pub fn to_fields(self) -> [u64; 16] {
        let mut fields = [0; 16];
        for i in 0..8 {
            fields[i] =
                u32::from_le_bytes(self.profile_id[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
            fields[8 + i] =
                u32::from_le_bytes(self.chain_id[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
        }
        fields
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    JoinSplit = 1,
    Htlc = 2,
    Coinbase = 3,
}

impl Kind {
    pub fn from_code(code: u8) -> Result<Self, CommitmentError> {
        match code {
            1 => Ok(Self::JoinSplit),
            2 => Ok(Self::Htlc),
            3 => Ok(Self::Coinbase),
            _ => Err(CommitmentError::InvalidKind),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub statement_digest: Digest,
}

impl Entry {
    pub fn new(kind: u8, statement_digest: Digest) -> Result<Self, CommitmentError> {
        let kind = Kind::from_code(kind)?;
        validate_fields(&statement_digest)?;
        Ok(Self {
            kind,
            statement_digest,
        })
    }

    /// Local fixed-width codec: one kind byte followed by four LE u64 limbs.
    /// Not a transaction/block encoding. Rejects short and trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CommitmentError> {
        if bytes.len() != 33 {
            return Err(CommitmentError::InvalidLength);
        }
        let kind = Kind::from_code(bytes[0])?;
        Ok(Self {
            kind,
            statement_digest: digest_from_bytes(&bytes[1..])?,
        })
    }

    pub fn to_bytes(self) -> Result<[u8; 33], CommitmentError> {
        let mut bytes = [0; 33];
        bytes[0] = self.kind as u8;
        bytes[1..].copy_from_slice(&digest_bytes(self.statement_digest)?);
        Ok(bytes)
    }
}

/// Reject, never reduce, noncanonical statement/root limbs.
pub fn digest_from_bytes(bytes: &[u8]) -> Result<Digest, CommitmentError> {
    if bytes.len() != 32 {
        return Err(CommitmentError::InvalidLength);
    }
    let digest =
        core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
    validate_fields(&digest)?;
    Ok(digest)
}

pub fn digest_bytes(digest: Digest) -> Result<[u8; 32], CommitmentError> {
    validate_fields(&digest)?;
    let mut bytes = [0; 32];
    for (i, value) in digest.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}

fn validate_fields(fields: &[u64]) -> Result<(), CommitmentError> {
    if fields.iter().any(|&x| x >= MODULUS) {
        return Err(CommitmentError::NonCanonicalField);
    }
    Ok(())
}

/// Initialize [domain, len, 0, 0], then compress each zero-padded four-field
/// chunk with native Poseidon2(state || chunk)[0..4]. An empty input performs
/// no permutations; the length lane distinguishes trailing zero fields.
pub fn hash_fields(domain: u64, fields: &[u64]) -> Result<Digest, CommitmentError> {
    if domain >= MODULUS {
        return Err(CommitmentError::NonCanonicalField);
    }
    let len = u64::try_from(fields.len()).map_err(|_| CommitmentError::InvalidLength)?;
    if len >= MODULUS {
        return Err(CommitmentError::InvalidLength);
    }
    validate_fields(fields)?;
    let mut state = [domain, len, 0, 0].map(Goldilocks::from_u64);
    // Same native permutation as crate::poseidon2_air::native_permute; using
    // p3 directly keeps this foundation independently testable without AIRs.
    let permutation = default_goldilocks_poseidon2_8();
    for chunk in fields.chunks(4) {
        let mut input = [Goldilocks::ZERO; 8];
        input[..4].copy_from_slice(&state);
        for (i, &value) in chunk.iter().enumerate() {
            input[4 + i] = Goldilocks::from_u64(value);
        }
        permutation.permute_mut(&mut input);
        state.copy_from_slice(&input[..4]);
    }
    Ok(state.map(|value| value.as_canonical_u64()))
}

/// Digest the complete canonical public statement, without accepting a caller's
/// claimed digest. This does not verify the statement's proof or its type schema.
pub fn statement_digest(kind: u8, public_fields: &[u64]) -> Result<Digest, CommitmentError> {
    let kind = Kind::from_code(kind)?;
    hash_fields(STATEMENT + kind as u64, public_fields)
}

#[test]
fn statement_digest_known_answer() {
    let fields = [0, 1, MODULUS - 1, 7, 99];
    let digest = statement_digest(1, &fields).unwrap();
    assert_eq!(
        digest,
        [
            12972822681639718207,
            2119591620538778127,
            17220032490829815117,
            9009558452664936917
        ]
    );
    assert_ne!(digest, statement_digest(2, &fields).unwrap());
    assert_ne!(digest, statement_digest(1, &fields[..4]).unwrap());
    assert!(statement_digest(0, &fields).is_err());
    assert!(statement_digest(1, &[MODULUS]).is_err());
}

/// Native summary only, NOT evidence of valid transactions or child proofs.
/// Merge checks all supplied metadata. In-range nonempty counts cannot be
/// authenticated from opaque roots: future AIR must constrain their derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeSummary {
    pub context: Context,
    pub level: u8, // leaf = 0, block root = 6
    pub count: u8,
    pub root: Digest,
}

pub fn leaf(context: Context, entry: Entry) -> Result<NodeSummary, CommitmentError> {
    validate_fields(&entry.statement_digest)?;
    let mut fields = [0; 21];
    fields[..16].copy_from_slice(&context.to_fields());
    fields[16] = entry.kind as u64;
    fields[17..].copy_from_slice(&entry.statement_digest);
    Ok(NodeSummary {
        context,
        level: 0,
        count: 1,
        root: hash_fields(LEAF, &fields)?,
    })
}

fn level_capacity(level: u8) -> Result<u8, CommitmentError> {
    if level > DEPTH {
        return Err(CommitmentError::InvalidLevel);
    }
    Ok(1 << level)
}

/// Only called for locally constructed or validated compatible children.
fn parent(left: NodeSummary, right: NodeSummary) -> Result<NodeSummary, CommitmentError> {
    let level = left.level + 1;
    let fields = [
        level as u64,
        left.count as u64,
        right.count as u64,
        left.root[0],
        left.root[1],
        left.root[2],
        left.root[3],
        right.root[0],
        right.root[1],
        right.root[2],
        right.root[3],
    ];
    Ok(NodeSummary {
        context: left.context,
        level,
        count: left.count + right.count,
        root: hash_fields(NODE, &fields)?,
    })
}

/// Canonical padding ONLY. Even level 6 is not an accepted transaction block.
pub fn empty_subtree(context: Context, level: u8) -> Result<NodeSummary, CommitmentError> {
    level_capacity(level)?;
    let mut node = NodeSummary {
        context,
        level: 0,
        count: 0,
        root: hash_fields(EMPTY, &context.to_fields())?,
    };
    for _ in 0..level {
        node = parent(node, node)?;
    }
    Ok(node)
}

/// Structural validation, not proof verification. Also authenticates the
/// canonical empty root when count == 0; no arbitrary padding is accepted.
pub fn validate_summary(node: NodeSummary) -> Result<(), CommitmentError> {
    let capacity = level_capacity(node.level)?;
    if node.count > capacity {
        return Err(CommitmentError::InvalidCount);
    }
    validate_fields(&node.root)?;
    if node.count == 0 && node.root != empty_subtree(node.context, node.level)?.root {
        return Err(CommitmentError::InvalidEmptyRoot);
    }
    Ok(())
}

/// Validates child metadata and derives the parent count; no caller-supplied
/// parent count. A nonempty right child requires a completely full left child.
/// This native helper MUST NOT be used as recursive proof authority.
pub fn merge_nodes(left: NodeSummary, right: NodeSummary) -> Result<NodeSummary, CommitmentError> {
    validate_summary(left)?;
    validate_summary(right)?;
    if left.context != right.context {
        return Err(CommitmentError::ContextMismatch);
    }
    if left.level != right.level {
        return Err(CommitmentError::LevelMismatch);
    }
    if left.level == DEPTH {
        return Err(CommitmentError::InvalidLevel);
    }
    if right.count > 0 && left.count != level_capacity(left.level)? {
        return Err(CommitmentError::NonDensePrefix);
    }
    parent(left, right)
}

/// Pure fixed-depth ordered root, derived solely from 1..64 actual entries.
/// Entries occupy a dense left prefix; all remaining leaves are canonical empty
/// padding. Does not validate the transactions represented by the statements.
pub fn root(context: Context, entries: &[Entry]) -> Result<Digest, CommitmentError> {
    if entries.is_empty() {
        return Err(CommitmentError::EmptyBlock);
    }
    if entries.len() > CAPACITY {
        return Err(CommitmentError::TooManyEntries);
    }
    let mut nodes = [empty_subtree(context, 0)?; CAPACITY];
    for (i, &entry) in entries.iter().enumerate() {
        nodes[i] = leaf(context, entry)?;
    }
    let mut width = CAPACITY;
    while width > 1 {
        for i in 0..width / 2 {
            nodes[i] = merge_nodes(nodes[2 * i], nodes[2 * i + 1])?;
        }
        width /= 2;
    }
    Ok(nodes[0].root)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared with Zig: profile bytes 0..31, chain bytes 32..63; entry i has
    // kind 1 + i % 3 and statement [4*i+1, 4*i+2, 4*i+3, 4*i+4].
    fn test_context() -> Context {
        Context {
            profile_id: core::array::from_fn(|i| i as u8),
            chain_id: core::array::from_fn(|i| (i + 32) as u8),
        }
    }

    fn test_entries() -> [Entry; CAPACITY] {
        core::array::from_fn(|i| Entry {
            kind: Kind::from_code((1 + i % 3) as u8).unwrap(),
            statement_digest: core::array::from_fn(|j| (4 * i + j + 1) as u64),
        })
    }

    #[test]
    fn injective_context_and_strict_statement_codecs() {
        for (i, x) in test_context().to_fields().into_iter().enumerate() {
            let b = (4 * i) as u64;
            assert_eq!(x, b | ((b + 1) << 8) | ((b + 2) << 16) | ((b + 3) << 24));
        }
        assert_eq!(
            Context {
                profile_id: [255; 32],
                chain_id: [255; 32]
            }
            .to_fields(),
            [0xffff_ffff; 16]
        );
        let digest = [0, 1, MODULUS - 1, 0x0102030405060708];
        let bytes = digest_bytes(digest).unwrap();
        assert_eq!(digest_from_bytes(&bytes).unwrap(), digest);
        assert_eq!(&bytes[24..], &[8, 7, 6, 5, 4, 3, 2, 1]);
        for kind in [1, 2, 3] {
            let entry = Entry::new(kind, digest).unwrap();
            let encoded = entry.to_bytes().unwrap();
            assert_eq!(encoded[0], kind);
            assert_eq!(Entry::from_bytes(&encoded).unwrap(), entry);
            root(test_context(), &[entry]).unwrap();
        }
        for kind in [0, 4, 255] {
            assert_eq!(Entry::new(kind, digest), Err(CommitmentError::InvalidKind));
            let mut encoded = [0; 33];
            encoded[0] = kind;
            assert_eq!(
                Entry::from_bytes(&encoded),
                Err(CommitmentError::InvalidKind)
            );
        }
        assert_eq!(
            digest_from_bytes(&bytes[..31]),
            Err(CommitmentError::InvalidLength)
        );
        assert_eq!(
            digest_from_bytes(&[0; 33]),
            Err(CommitmentError::InvalidLength)
        );
        assert_eq!(
            Entry::from_bytes(&bytes),
            Err(CommitmentError::InvalidLength)
        );
        assert_eq!(
            Entry::from_bytes(&[0; 34]),
            Err(CommitmentError::InvalidLength)
        );
        for lane in 0..4 {
            for invalid in [MODULUS, MODULUS + 1, u64::MAX] {
                let mut bad = digest;
                bad[lane] = invalid;
                let mut encoded = bytes;
                encoded[lane * 8..lane * 8 + 8].copy_from_slice(&invalid.to_le_bytes());
                let mut encoded_entry = [0; 33];
                encoded_entry[0] = 1;
                encoded_entry[1..].copy_from_slice(&encoded);
                assert_eq!(
                    Entry::from_bytes(&encoded_entry),
                    Err(CommitmentError::NonCanonicalField)
                );
                assert_eq!(
                    digest_from_bytes(&encoded),
                    Err(CommitmentError::NonCanonicalField)
                );
                assert_eq!(digest_bytes(bad), Err(CommitmentError::NonCanonicalField));
                assert_eq!(Entry::new(1, bad), Err(CommitmentError::NonCanonicalField));
                let entry = Entry {
                    kind: Kind::JoinSplit,
                    statement_digest: bad,
                };
                assert_eq!(entry.to_bytes(), Err(CommitmentError::NonCanonicalField));
                assert_eq!(
                    root(test_context(), &[entry]),
                    Err(CommitmentError::NonCanonicalField)
                );
            }
        }
    }

    #[test]
    fn hash_domain_length_and_canonicality() {
        assert_eq!(hash_fields(LEAF, &[]).unwrap(), [LEAF, 0, 0, 0]);
        let a = hash_fields(LEAF, &[1]).unwrap();
        assert_ne!(a, hash_fields(EMPTY, &[1]).unwrap());
        assert_ne!(a, hash_fields(LEAF, &[1, 0]).unwrap());
        assert_ne!(a, hash_fields(LEAF, &[1, 0, 0, 0]).unwrap());
        assert_ne!(a, hash_fields(LEAF, &[1, 0, 0, 0, 0]).unwrap());
        assert_eq!(
            hash_fields(MODULUS, &[]),
            Err(CommitmentError::NonCanonicalField)
        );
        assert_eq!(
            hash_fields(LEAF, &[0, 0, 0, 0, MODULUS]),
            Err(CommitmentError::NonCanonicalField)
        );
    }

    #[test]
    fn ordering_type_digest_and_both_context_identifiers_bind_root() {
        let context = test_context();
        let mut entries = test_entries();
        let base = root(context, &entries[..3]).unwrap();
        entries.swap(0, 1);
        assert_ne!(base, root(context, &entries[..3]).unwrap());
        entries = test_entries();
        entries[0].kind = Kind::Htlc;
        assert_ne!(base, root(context, &entries[..3]).unwrap());
        entries[0].kind = Kind::Coinbase;
        assert_ne!(base, root(context, &entries[..3]).unwrap());
        entries = test_entries();
        entries[0].statement_digest[3] += 1;
        assert_ne!(base, root(context, &entries[..3]).unwrap());
        entries = test_entries();
        for i in 0..32 {
            let mut changed = context;
            changed.profile_id[i] ^= 1;
            assert_ne!(base, root(changed, &entries[..3]).unwrap());
            changed = context;
            changed.chain_id[i] ^= 1;
            assert_ne!(base, root(changed, &entries[..3]).unwrap());
        }
        assert_ne!(base, root(context, &entries[..2]).unwrap());
    }

    #[test]
    fn padding_dense_prefix_and_validated_summary_metadata() {
        let context = test_context();
        let entries = test_entries();
        let a = leaf(context, entries[0]).unwrap();
        let b = leaf(context, entries[1]).unwrap();
        let empty = empty_subtree(context, 0).unwrap();
        assert_ne!(
            empty.root,
            leaf(context, Entry::new(1, [0; 4]).unwrap()).unwrap().root
        );
        let mut padding = empty;
        for level in 1..=DEPTH {
            padding = merge_nodes(padding, padding).unwrap();
            assert_eq!(padding, empty_subtree(context, level).unwrap());
        }
        assert_eq!(merge_nodes(empty, a), Err(CommitmentError::NonDensePrefix));
        let partial = merge_nodes(a, empty).unwrap();
        assert_eq!(
            merge_nodes(partial, partial),
            Err(CommitmentError::NonDensePrefix)
        );
        let full = merge_nodes(a, b).unwrap();
        let three = merge_nodes(full, partial).unwrap();
        assert_eq!((three.count, three.level), (3, 2));
        assert_eq!(merge_nodes(a, full), Err(CommitmentError::LevelMismatch));
        let mut changed = context;
        changed.chain_id[0] ^= 1;
        assert_eq!(
            merge_nodes(a, leaf(changed, entries[1]).unwrap()),
            Err(CommitmentError::ContextMismatch)
        );
        assert_eq!(
            merge_nodes(padding, padding),
            Err(CommitmentError::InvalidLevel)
        );
        assert_eq!(
            empty_subtree(context, 7),
            Err(CommitmentError::InvalidLevel)
        );
        assert_eq!(
            empty_subtree(context, 255),
            Err(CommitmentError::InvalidLevel)
        );
        let mut malformed = a;
        malformed.count = 2;
        assert_eq!(
            merge_nodes(malformed, b),
            Err(CommitmentError::InvalidCount)
        );
        malformed.count = 255;
        assert_eq!(
            validate_summary(malformed),
            Err(CommitmentError::InvalidCount)
        );
        malformed = padding;
        malformed.count = 65;
        assert_eq!(
            validate_summary(malformed),
            Err(CommitmentError::InvalidCount)
        );
        malformed = a;
        malformed.level = 255;
        assert_eq!(
            validate_summary(malformed),
            Err(CommitmentError::InvalidLevel)
        );
        malformed = a;
        malformed.root[2] = MODULUS;
        assert_eq!(
            merge_nodes(b, malformed),
            Err(CommitmentError::NonCanonicalField)
        );
        malformed = empty;
        malformed.root[0] ^= 1;
        assert_eq!(
            merge_nodes(a, malformed),
            Err(CommitmentError::InvalidEmptyRoot)
        );
        malformed = a;
        malformed.count = 0;
        assert_eq!(
            validate_summary(malformed),
            Err(CommitmentError::InvalidEmptyRoot)
        );
        malformed = padding;
        malformed.context = changed;
        assert_eq!(
            validate_summary(malformed),
            Err(CommitmentError::InvalidEmptyRoot)
        );
    }

    fn reference_tree(context: Context, entries: &[Entry], level: u8) -> NodeSummary {
        if entries.is_empty() {
            return empty_subtree(context, level).unwrap();
        }
        if level == 0 {
            return leaf(context, entries[0]).unwrap();
        }
        let split = entries
            .len()
            .min(level_capacity(level - 1).unwrap() as usize);
        merge_nodes(
            reference_tree(context, &entries[..split], level - 1),
            reference_tree(context, &entries[split..], level - 1),
        )
        .unwrap()
    }

    #[test]
    fn fixed_depth_all_supported_counts_and_block_bounds() {
        let context = test_context();
        let entries = test_entries();
        for count in 1..=CAPACITY {
            let reference = reference_tree(context, &entries[..count], DEPTH);
            assert_eq!((reference.count, reference.level), (count as u8, DEPTH));
            assert_eq!(reference.root, root(context, &entries[..count]).unwrap());
        }
        assert_eq!(root(context, &[]), Err(CommitmentError::EmptyBlock));
        assert_eq!(
            root(context, &[entries[0]; CAPACITY + 1]),
            Err(CommitmentError::TooManyEntries)
        );
        assert_ne!(
            leaf(context, entries[0]).unwrap().root,
            root(context, &entries[..1]).unwrap()
        );
    }

    #[test]
    fn cross_language_known_answers() {
        let context = test_context();
        let entries = test_entries();
        let cases = [
            (
                1,
                [
                    17302586004775321400,
                    14060252879667703226,
                    4653393007796374416,
                    4872023104817232206,
                ],
            ),
            (
                3,
                [
                    4814516697696595194,
                    16120349432758846240,
                    10073192216511493316,
                    3373496859766494287,
                ],
            ),
            (
                64,
                [
                    10210199181207880258,
                    12592273171222783804,
                    5412254068206525201,
                    9204339462543883831,
                ],
            ),
        ];
        for (count, expected) in cases {
            assert_eq!(root(context, &entries[..count]).unwrap(), expected);
        }
        assert_eq!(
            empty_subtree(context, 0).unwrap().root,
            [
                336848228289249662,
                7767320990335710777,
                1138699809743786389,
                7731264857985018234
            ]
        );
        assert_eq!(
            empty_subtree(context, 6).unwrap().root,
            [
                2271525178863671688,
                10306419023861907142,
                11839189680640350544,
                1606716923507119681
            ]
        );
        assert_eq!(
            leaf(context, entries[0]).unwrap().root,
            [
                2387791423884938754,
                18063362552844145910,
                7285074225670006941,
                10663012433430753868
            ]
        );
        assert_eq!(
            merge_nodes(
                leaf(context, entries[0]).unwrap(),
                leaf(context, entries[1]).unwrap()
            )
            .unwrap()
            .root,
            [
                4396680036629166094,
                15904754847456670127,
                9218176674975975282,
                16593340716784826968
            ]
        );
    }
}
