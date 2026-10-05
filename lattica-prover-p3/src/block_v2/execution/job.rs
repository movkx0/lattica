//! Bounded public-artifact and semantic-job contracts for the local proof DAG.
//!
//! Constructors derive statements rather than accepting worker-claimed roots.
//! Randomized artifact identities are deliberately separate from reusable job
//! identities. These are local records, not an allocated network wire format.

use p3_field::PrimeField64;

use crate::block_v2::{
    codec,
    commitment::{self, Context, Digest, NodeSummary, CAPACITY, DEPTH},
    machine::{program::Val, programs},
    profile,
    recursive::{self, Error, Registry, WalletProof, WrapperConstruction},
};

const SCHEMA: u64 = 1;
// Distinct from commitment, registry, AIR and statement hash domains.
const JOB_DOMAIN: u64 = 0x4c42563271;
const ARTIFACT_DOMAIN: u64 = 0x4c42563272;
// Existing local research wallet-artifact header used by the registered runners.
// This does not allocate or accept a new network format.
pub(super) const WALLET_MAGIC: &[u8; 8] = b"LBV2WL02";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(Digest);

impl JobId {
    /// Pure operational identity calculation, never a proof-validity ticket or
    /// a way to admit a worker-claimed Job into the scheduler.
    pub(super) fn for_summary(
        pin: RegistryPin,
        operation: Operation,
        start: u8,
        expected: NodeSummary,
        dependencies: &[JobId],
    ) -> Result<Self, Error> {
        commitment::validate_summary(expected)?;
        if expected.context.profile_id != pin.profile
            || expected.level > DEPTH
            || dependencies.len() > 2
        {
            return Err("execution identity profile/level/dependencies".into());
        }
        let width = 1usize << expected.level;
        if start as usize % width != 0 || start as usize + width > CAPACITY {
            return Err("execution identity range".into());
        }

        let mut fields = vec![SCHEMA, pin.code(), operation.code(), start as u64];
        fields.extend(
            programs::statement(expected, operation.proof_mode())
                .iter()
                .map(PrimeField64::as_canonical_u64),
        );
        fields.push(dependencies.len() as u64);
        for id in dependencies {
            fields.extend(id.0);
        }
        // Randomized wallet proof bytes are intentionally not hashed here.
        // Their verified statements are already bound in the expected root.
        let id = JobId(commitment::hash_fields(JOB_DOMAIN, &fields)?);
        Ok(id)
    }
    #[cfg(target_os = "linux")]
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Ok(Self(commitment::digest_from_bytes(&bytes)?))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        commitment::digest_bytes(self.0).expect("derived canonical job digest")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    Wallet,
    Node,
}

/// Exact bytes selected for one attempt. This is not proof-validity authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactRef {
    kind: ArtifactKind,
    digest: Digest,
    byte_len: u32,
}

impl ArtifactRef {
    /// Untrusted on-disk inventory metadata, never a proof-validity ticket.
    pub(super) fn from_descriptor(
        kind: ArtifactKind,
        byte_len: u32,
        digest: [u8; 32],
    ) -> Result<Self, Error> {
        if byte_len == 0 || byte_len as usize > profile::MAX_PROOF_BYTES {
            return Err("execution artifact descriptor length".into());
        }
        Ok(Self {
            kind,
            byte_len,
            digest: commitment::digest_from_bytes(&digest)?,
        })
    }

    /// Length is admitted before allocating the hash input. Encoding and proof
    /// verification are performed by the typed admission functions below.
    pub fn from_bytes(kind: ArtifactKind, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > profile::MAX_PROOF_BYTES {
            return Err("execution artifact length".into());
        }
        let mut fields = Vec::with_capacity(3 + bytes.len().div_ceil(4));
        fields.extend([SCHEMA, kind.code(), bytes.len() as u64]);
        for chunk in bytes.chunks(4) {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            fields.push(u32::from_le_bytes(word) as u64);
        }
        Ok(Self {
            kind,
            digest: commitment::hash_fields(ARTIFACT_DOMAIN, &fields)?,
            byte_len: bytes.len() as u32,
        })
    }

    pub fn check_bytes(self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != self.byte_len as usize || Self::from_bytes(self.kind, bytes)? != self {
            return Err("execution artifact identity".into());
        }
        Ok(())
    }

    pub fn kind(self) -> ArtifactKind {
        self.kind
    }

    pub fn byte_len(self) -> u32 {
        self.byte_len
    }

    pub fn digest_bytes(self) -> [u8; 32] {
        commitment::digest_bytes(self.digest).expect("derived canonical artifact digest")
    }
}

impl ArtifactKind {
    fn code(self) -> u64 {
        match self {
            Self::Wallet => 1,
            Self::Node => 2,
        }
    }
}

/// An externally expected registry identity and explicit program construction.
/// Matching this pin is not an audit or production activation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryPin {
    profile: [u8; 32],
    construction: WrapperConstruction,
}

impl RegistryPin {
    pub fn new(
        registry: &Registry,
        expected_profile: [u8; 32],
        construction: WrapperConstruction,
    ) -> Result<Self, Error> {
        Self::validate_shape(registry)?;
        if registry.id()? != expected_profile {
            return Err("execution registry pin".into());
        }
        Ok(Self {
            profile: expected_profile,
            construction,
        })
    }

    pub fn profile(self) -> [u8; 32] {
        self.profile
    }

    pub fn construction(self) -> WrapperConstruction {
        self.construction
    }

    fn check(self, registry: &Registry) -> Result<(), Error> {
        Self::validate_shape(registry)?;
        if registry.id()? != self.profile {
            return Err("execution registry substitution".into());
        }
        Ok(())
    }

    fn validate_shape(registry: &Registry) -> Result<(), Error> {
        if !registry.height.is_power_of_two()
            || !(8..=1 << 21).contains(&registry.height)
            || registry
                .caps
                .iter()
                .any(|cap| cap.len() != 1 << profile::CAP_HEIGHT)
        {
            return Err("execution registry shape".into());
        }
        Ok(())
    }

    fn code(self) -> u64 {
        match self.construction {
            WrapperConstruction::SingleWallet => 1,
            WrapperConstruction::GroupedPair => 2,
        }
    }
}

/// A cryptographically checked public wallet proof. No witness-bearing type is
/// accepted here. Host anchor/nullifier/height/issuance checks remain mandatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedWallet {
    pin: RegistryPin,
    summary: NodeSummary,
    artifact: ArtifactRef,
}

impl VerifiedWallet {
    pub fn verify(
        pin: RegistryPin,
        registry: &Registry,
        expected_chain: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, Error> {
        // Both codec and artifact hash independently enforce the byte ceiling.
        if bytes.len() <= WALLET_MAGIC.len()
            || bytes.len() > profile::MAX_PROOF_BYTES
            || !bytes.starts_with(WALLET_MAGIC)
        {
            return Err("execution wallet length".into());
        }
        pin.check(registry)?;
        let wallet: WalletProof = codec::decode(&bytes[WALLET_MAGIC.len()..])?;
        if wallet.chain != expected_chain {
            return Err("execution wallet chain".into());
        }
        recursive::verify_wallet(&wallet)?;
        Ok(Self {
            pin,
            summary: recursive::wallet_summary(registry, &wallet)?,
            artifact: ArtifactRef::from_bytes(ArtifactKind::Wallet, bytes)?,
        })
    }

    pub fn summary(self) -> NodeSummary {
        self.summary
    }

    pub fn artifact(self) -> ArtifactRef {
        self.artifact
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Wrap,
    WrapPair,
    Empty,
    Merge,
}

impl Operation {
    pub(super) fn code(self) -> u64 {
        match self {
            Self::Wrap => 1,
            Self::WrapPair => 2,
            Self::Empty => 3,
            Self::Merge => 4,
        }
    }

    pub(super) fn proof_mode(self) -> u64 {
        match self {
            Self::Wrap | Self::WrapPair => programs::WRAPPER,
            Self::Empty => programs::EMPTY,
            Self::Merge => programs::MERGE,
        }
    }
}

/// Immutable semantic work. Candidate epochs, worker choice, attempts and proof
/// randomness never enter this identity. Exact source artifacts are kept apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    id: JobId,
    pin: RegistryPin,
    operation: Operation,
    start: u8,
    expected: NodeSummary,
    dependencies: Vec<JobId>,
    wallet_inputs: Vec<ArtifactRef>,
}

impl Job {
    fn derive(
        pin: RegistryPin,
        operation: Operation,
        start: u8,
        expected: NodeSummary,
        dependencies: Vec<JobId>,
        wallet_inputs: Vec<ArtifactRef>,
    ) -> Result<Self, Error> {
        commitment::validate_summary(expected)?;
        if expected.context.profile_id != pin.profile || expected.level > DEPTH {
            return Err("execution job profile or level".into());
        }
        let width = 1usize << expected.level;
        if start as usize % width != 0 || start as usize + width > CAPACITY {
            return Err("execution ordered range".into());
        }
        if dependencies.len() > 2 || wallet_inputs.len() > 2 {
            return Err("execution input bound".into());
        }
        let id = JobId::for_summary(pin, operation, start, expected, &dependencies)?;
        Ok(Self {
            id,
            pin,
            operation,
            start,
            expected,
            dependencies,
            wallet_inputs,
        })
    }

    pub fn wrap(start: u8, wallet: VerifiedWallet) -> Result<Self, Error> {
        if wallet.pin.construction != WrapperConstruction::SingleWallet {
            return Err("single wrapper not registered for this construction".into());
        }
        Self::derive(
            wallet.pin,
            Operation::Wrap,
            start,
            wallet.summary,
            vec![],
            vec![wallet.artifact],
        )
    }

    pub fn wrap_pair(
        start: u8,
        left: VerifiedWallet,
        right: VerifiedWallet,
    ) -> Result<Self, Error> {
        if left.pin != right.pin || left.pin.construction != WrapperConstruction::GroupedPair {
            return Err("paired wrapper construction mismatch".into());
        }
        let expected = commitment::merge_nodes(left.summary, right.summary)?;
        Self::derive(
            left.pin,
            Operation::WrapPair,
            start,
            expected,
            vec![],
            vec![left.artifact, right.artifact],
        )
    }

    pub fn empty(pin: RegistryPin, chain: [u8; 32], start: u8, level: u8) -> Result<Self, Error> {
        let expected = commitment::empty_subtree(
            Context {
                profile_id: pin.profile,
                chain_id: chain,
            },
            level,
        )?;
        Self::derive(pin, Operation::Empty, start, expected, vec![], vec![])
    }

    pub fn merge(left: &Self, right: &Self) -> Result<Self, Error> {
        if left.pin != right.pin {
            return Err("execution merge registry/construction mismatch".into());
        }
        if left.start as usize + (1usize << left.expected.level) != right.start as usize {
            return Err("execution merge ranges are not ordered and contiguous".into());
        }
        let expected = commitment::merge_nodes(left.expected, right.expected)?;
        Self::derive(
            left.pin,
            Operation::Merge,
            left.start,
            expected,
            vec![left.id, right.id],
            vec![],
        )
    }

    pub fn id(&self) -> JobId {
        self.id
    }
    pub fn pin(&self) -> RegistryPin {
        self.pin
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn start(&self) -> u8 {
        self.start
    }
    pub fn expected(&self) -> NodeSummary {
        self.expected
    }
    pub fn dependencies(&self) -> &[JobId] {
        &self.dependencies
    }
    pub fn wallet_inputs(&self) -> &[ArtifactRef] {
        &self.wallet_inputs
    }
    pub fn expected_public(&self) -> [Val; programs::PUBLIC_VALUES] {
        programs::statement(self.expected, self.operation.proof_mode())
    }

    /// Semantic equality permits a second valid randomized wallet artifact.
    /// An in-flight attempt must continue to use its original frozen manifest.
    pub fn same_semantics(&self, other: &Self) -> bool {
        self.id == other.id
            && self.pin == other.pin
            && self.operation == other.operation
            && self.start == other.start
            && self.expected == other.expected
            && self.dependencies == other.dependencies
    }
}

/// CPU-verified result bound to a derived job statement. Attempt/candidate
/// fencing and durable publication are still required by the coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedNode {
    job: JobId,
    artifact: ArtifactRef,
}

impl VerifiedNode {
    pub fn verify(job: &Job, registry: &Registry, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > profile::MAX_PROOF_BYTES {
            return Err("execution node length".into());
        }
        job.pin.check(registry)?;
        let node = codec::decode_node(bytes)?;
        registry.verify(job.pin.profile, &node, &job.expected_public())?;
        Ok(Self {
            job: job.id,
            artifact: ArtifactRef::from_bytes(ArtifactKind::Node, bytes)?,
        })
    }

    pub fn job(self) -> JobId {
        self.job
    }
    pub fn artifact(self) -> ArtifactRef {
        self.artifact
    }
}

/// Structural state-machine fixtures only. These constructors never exist in a
/// non-test build and do not provide evidence of cryptographic acceptance.
#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub fn pin() -> RegistryPin {
        pin_for(WrapperConstruction::SingleWallet)
    }

    pub fn pin_for(construction: WrapperConstruction) -> RegistryPin {
        RegistryPin {
            profile: [7; 32],
            construction,
        }
    }

    pub fn wallet(value: u64, bytes: &[u8]) -> VerifiedWallet {
        wallet_for(WrapperConstruction::SingleWallet, value, bytes)
    }

    pub fn wallet_for(
        construction: WrapperConstruction,
        value: u64,
        bytes: &[u8],
    ) -> VerifiedWallet {
        let pin = pin_for(construction);
        VerifiedWallet {
            pin,
            summary: commitment::leaf(
                Context {
                    profile_id: pin.profile,
                    chain_id: [9; 32],
                },
                commitment::Entry {
                    kind: commitment::Kind::JoinSplit,
                    statement_digest: [value, 0, 0, 0],
                },
            )
            .unwrap(),
            artifact: ArtifactRef::from_bytes(ArtifactKind::Wallet, bytes).unwrap(),
        }
    }

    pub fn node(job: &Job, bytes: &[u8]) -> VerifiedNode {
        VerifiedNode {
            job: job.id(),
            artifact: ArtifactRef::from_bytes(ArtifactKind::Node, bytes).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commitment::{Entry, Kind};

    // Native structural fixtures only, not cryptographic proof tickets.
    fn wallet(construction: WrapperConstruction, value: u64, proof_bytes: &[u8]) -> VerifiedWallet {
        let pin = RegistryPin {
            profile: [7; 32],
            construction,
        };
        let context = Context {
            profile_id: pin.profile,
            chain_id: [9; 32],
        };
        VerifiedWallet {
            pin,
            summary: commitment::leaf(
                context,
                Entry {
                    kind: Kind::JoinSplit,
                    statement_digest: [value, 0, 0, 0],
                },
            )
            .unwrap(),
            artifact: ArtifactRef::from_bytes(ArtifactKind::Wallet, proof_bytes).unwrap(),
        }
    }

    #[test]
    fn artifact_identity_binds_kind_length_padding_and_bytes() {
        let a = ArtifactRef::from_bytes(ArtifactKind::Wallet, &[1]).unwrap();
        assert_ne!(
            a,
            ArtifactRef::from_bytes(ArtifactKind::Wallet, &[1, 0]).unwrap()
        );
        assert_ne!(
            a,
            ArtifactRef::from_bytes(ArtifactKind::Node, &[1]).unwrap()
        );
        assert!(a.check_bytes(&[2]).is_err());
        assert!(a.check_bytes(&[1, 0]).is_err());
        assert!(a.check_bytes(&[1]).is_ok());
        assert!(ArtifactRef::from_bytes(ArtifactKind::Wallet, &[]).is_err());
        assert!(ArtifactRef::from_bytes(
            ArtifactKind::Wallet,
            &vec![0; profile::MAX_PROOF_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn registry_geometry_is_rejected_before_identity_work() {
        for height in [0, 3, 1 << 22, usize::MAX] {
            let registry = Registry {
                height,
                caps: core::array::from_fn(|_| Vec::new()),
            };
            assert!(
                RegistryPin::new(&registry, [0; 32], WrapperConstruction::SingleWallet).is_err()
            );
        }
        let registry = Registry {
            height: 8,
            caps: core::array::from_fn(|_| Vec::new()),
        };
        assert!(RegistryPin::new(&registry, [0; 32], WrapperConstruction::GroupedPair).is_err());
    }

    #[test]
    fn semantic_identity_excludes_randomized_artifacts_but_binds_order_and_position() {
        let left = wallet(WrapperConstruction::GroupedPair, 1, &[1]);
        let mut alternate = left;
        alternate.artifact = ArtifactRef::from_bytes(ArtifactKind::Wallet, &[2, 3]).unwrap();
        let right = wallet(WrapperConstruction::GroupedPair, 2, &[4]);
        let a = Job::wrap_pair(0, left, right).unwrap();
        let b = Job::wrap_pair(0, alternate, right).unwrap();
        assert!(a.same_semantics(&b));
        assert_eq!(a.id(), b.id());
        assert_ne!(a.wallet_inputs(), b.wallet_inputs());
        assert_ne!(a.id(), Job::wrap_pair(0, right, left).unwrap().id());
        assert_ne!(a.id(), Job::wrap_pair(2, left, right).unwrap().id());
        assert!(Job::wrap_pair(1, left, right).is_err());
        assert!(Job::wrap_pair(64, left, right).is_err());
    }

    #[test]
    fn construction_context_and_dense_prefix_are_checked() {
        let single = wallet(WrapperConstruction::SingleWallet, 1, &[1]);
        let pair = wallet(WrapperConstruction::GroupedPair, 1, &[1]);
        assert!(Job::wrap(0, pair).is_err());
        assert!(Job::wrap_pair(0, single, single).is_err());
        assert!(Job::wrap_pair(0, single, pair).is_err());
        let left = Job::wrap(0, single).unwrap();
        let right = Job::wrap(1, single).unwrap();
        assert!(Job::merge(&right, &left).is_err());
        assert!(Job::merge(&left, &left).is_err());
        assert_eq!(Job::merge(&left, &right).unwrap().expected().count, 2);
        let empty_left = Job::empty(single.pin, single.summary.context.chain_id, 0, 0).unwrap();
        assert!(Job::merge(&empty_left, &right).is_err());
        let other_chain = Job::empty(single.pin, [8; 32], 1, 0).unwrap();
        assert!(Job::merge(&left, &other_chain).is_err());
        let wrong_level = Job::empty(single.pin, single.summary.context.chain_id, 2, 1).unwrap();
        assert!(Job::merge(&left, &wrong_level).is_err());
    }

    #[test]
    fn padded_six_level_statement_matches_independent_commitment() {
        let input = wallet(WrapperConstruction::SingleWallet, 3, &[1]);
        let mut current = Job::wrap(0, input).unwrap();
        for level in 0..DEPTH {
            let right =
                Job::empty(input.pin, input.summary.context.chain_id, 1 << level, level).unwrap();
            current = Job::merge(&current, &right).unwrap();
        }
        let entry = Entry {
            kind: Kind::JoinSplit,
            statement_digest: [3, 0, 0, 0],
        };
        assert_eq!(
            current.expected().root,
            commitment::root(input.summary.context, &[entry]).unwrap()
        );
        assert_eq!(current.expected().level, DEPTH);
        assert_eq!(current.expected().count, 1);
        assert!(Job::empty(input.pin, input.summary.context.chain_id, 0, DEPTH + 1).is_err());
        assert!(Job::merge(&current, &current).is_err());
    }

    /// Replay only: no proving, GPU initialization, witness access or writes.
    /// Explicitly supplied frozen private research directories are required.
    /// The fixed external profile/chain/root are independent of their contents.
    #[cfg(feature = "block-v2-wide-lanes")]
    #[test]
    #[ignore = "requires the independently pinned compact eight-wallet fixture and root-only bundle"]
    fn cpu_gate_accepts_pinned_public_root_and_rejects_wrong_job() -> Result<(), Error> {
        use p3_field::PrimeCharacteristicRing;
        use std::{fs, io::Read, path::Path};

        fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
            let before = fs::symlink_metadata(path)?;
            if !before.is_file() || before.len() > limit as u64 {
                return Err("fixture type/size".into());
            }
            let file = fs::File::open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > limit as u64 {
                return Err("fixture type/size".into());
            }
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > limit {
                return Err("fixture grew".into());
            }
            Ok(bytes)
        }
        fn hex(value: &str) -> [u8; 32] {
            assert_eq!(value.len(), 64);
            core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
        }
        let inputs = std::env::var("LATTICA_V2_EXECUTION_TEST_INPUTS")?;
        let bundle = std::env::var("LATTICA_V2_EXECUTION_TEST_ROOT")?;
        let inputs = Path::new(&inputs);
        let bundle = Path::new(&bundle);
        let expected_profile =
            hex("8ec1bbde8ade9c60a90398a6a30f3bb095d5adc1f1fed881e7b72ea051bab3cb");
        let expected_root = hex("23ccda6b5581d09e8d0107be85d09c2795f3f767bfc844a9b5168e7f4a9c20e8");
        let chain = [0x5a; 32];
        let height = read(&inputs.join("height"), 4)?;
        let height = u32::from_le_bytes(height.as_slice().try_into()?) as usize;
        if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
            return Err("fixture geometry".into());
        }
        let mut caps = core::array::from_fn(|_| Vec::new());
        let key_size = (1 << profile::CAP_HEIGHT) * 32;
        for (i, cap) in caps.iter_mut().enumerate() {
            let bytes = read(&inputs.join(format!("key.{}", i + 1)), key_size)?;
            if bytes.len() != key_size {
                return Err("fixture cap size".into());
            }
            for digest in bytes.chunks_exact(32) {
                let mut values = [Val::ZERO; 4];
                for (value, word) in values.iter_mut().zip(digest.chunks_exact(8)) {
                    let decoded = u64::from_le_bytes(word.try_into()?);
                    if decoded >= commitment::MODULUS {
                        return Err("fixture noncanonical cap".into());
                    }
                    *value = Val::from_u64(decoded);
                }
                cap.push(values);
            }
        }
        let registry = Registry { height, caps };
        let pin = RegistryPin::new(
            &registry,
            expected_profile,
            WrapperConstruction::GroupedPair,
        )?;
        let mut wrong_profile = expected_profile;
        wrong_profile[0] ^= 1;
        assert!(
            RegistryPin::new(&registry, wrong_profile, WrapperConstruction::GroupedPair).is_err()
        );
        let mut wallets = Vec::new();
        for i in 0..8 {
            let bytes = read(
                &inputs.join(format!("wallet.{i}")),
                profile::MAX_PROOF_BYTES,
            )?;
            let wallet = VerifiedWallet::verify(pin, &registry, chain, &bytes)?;
            wallet.artifact().check_bytes(&bytes)?;
            if i == 0 {
                assert!(VerifiedWallet::verify(
                    pin,
                    &registry,
                    chain,
                    &bytes[WALLET_MAGIC.len()..]
                )
                .is_err());
                let mut wrong_header = bytes.clone();
                wrong_header[0] ^= 1;
                assert!(VerifiedWallet::verify(pin, &registry, chain, &wrong_header).is_err());
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert!(VerifiedWallet::verify(pin, &registry, chain, &trailing).is_err());
                assert!(VerifiedWallet::verify(pin, &registry, [0x5b; 32], &bytes).is_err());
                let mut changed = bytes.clone();
                *changed.last_mut().unwrap() ^= 1;
                assert!(wallet.artifact().check_bytes(&changed).is_err());
                assert!(VerifiedWallet::verify(pin, &registry, chain, &changed).is_err());
            }
            wallets.push(wallet);
        }
        let pairs: Vec<_> = (0..4)
            .map(|i| Job::wrap_pair((i * 2) as u8, wallets[i * 2], wallets[i * 2 + 1]).unwrap())
            .collect();
        let left = Job::merge(&pairs[0], &pairs[1])?;
        let right = Job::merge(&pairs[2], &pairs[3])?;
        let root = Job::merge(&left, &right)?;
        assert_eq!(
            commitment::digest_bytes(root.expected().root)?,
            expected_root
        );
        assert_eq!(root.expected().level, 3);
        assert_eq!(root.expected().count, 8);
        let bytes = read(&bundle.join("node.3.0"), profile::MAX_PROOF_BYTES)?;
        let result = VerifiedNode::verify(&root, &registry, &bytes)?;
        assert_eq!(result.job(), root.id());
        result.artifact().check_bytes(&bytes)?;
        assert!(VerifiedNode::verify(&left, &registry, &bytes).is_err());
        let swapped_pair = Job::wrap_pair(0, wallets[1], wallets[0])?;
        let swapped_left = Job::merge(&swapped_pair, &pairs[1])?;
        let swapped_root = Job::merge(&swapped_left, &right)?;
        assert_ne!(root.id(), swapped_root.id());
        assert!(VerifiedNode::verify(&swapped_root, &registry, &bytes).is_err());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(VerifiedNode::verify(&root, &registry, &changed).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(VerifiedNode::verify(&root, &registry, &trailing).is_err());
        Ok(())
    }
}
