//! Opt-in single-wrapper/eight-wallet CPU comparison runner; not production.
//! No production activation, registry approval, host integration or GPU path.
//! Preparation generates unapproved fixture proofs/keys. Every aggregation,
//! resume, pruning and root-verification command requires external profile,
//! chain and expected-root inputs. Never reads profile.hex or a job's expected.
//! Heavy commands still require an external hard-bounded CPU/stream harness.

use lattica_prover_p3::{
    block_v2::{
        codec,
        commitment::{self, Context, NodeSummary},
        machine::programs,
        perf::Profiler,
        profile,
        recursive::{
            self, ConstructionSession, NodeProof, Registry, WalletProof, WrapperConstruction,
        },
    },
    joinsplit_air as js, spill_alloc,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

type Error = recursive::Error;
type Public = [Val; programs::PUBLIC_VALUES];
// Explicit comparison construction; no production approval is implied.
const CONSTRUCTION: WrapperConstruction = WrapperConstruction::SingleWallet;
const WALLETS: usize = 8;
const ROOT_LEVEL: usize = 3;
const ROOT_FILE: &str = "node.3.0";
const WALLET_MAGIC: &[u8; 8] = b"LBV2WL02";

const USAGE: &str = "\
Unapproved preparation only:
  prepare DIR
  common-height DIR
  register DIR MODE                         (MODE = 1, 2 or 3; CPU only)
  describe-registry DIR                     (candidate fingerprint, NOT approval)
Externally pinned research commands:
  check-registered DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX
  wrap-leaf DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX LEAF_INDEX
  wrap-all DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX
  merge DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX LEVEL INDEX
  merge-all DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX
  remove-inners DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX
  verify-root DIR PINNED_PROFILE CHAIN_ID_HEX EXPECTED_ROOT_HEX
All three hex values encode exactly 32 bytes. Root = four canonical u64 limbs,
each little-endian, in digest order. Leaf indices 0..8; merge levels 1..=3 with index < 8 >> level.
The root is an eight-entry level-three subtree, NOT a level-six block proof.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalExpected {
    profile: [u8; 32],
    chain: [u8; 32],
    root: commitment::Digest,
}

impl ExternalExpected {
    fn parse(profile: &str, chain: &str, root: &str) -> Result<Self, Error> {
        Ok(Self {
            profile: hex32(profile, "profile")?,
            chain: hex32(chain, "chain")?,
            root: root_hex(root)?,
        })
    }

    fn statement(self) -> Result<Public, Error> {
        let summary = NodeSummary {
            context: Context {
                profile_id: self.profile,
                chain_id: self.chain,
            },
            level: ROOT_LEVEL as u8,
            count: WALLETS as u8,
            root: self.root,
        };
        commitment::validate_summary(summary)?;
        Ok(programs::statement(summary, programs::MERGE))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preparation {
    Wallets,
    CommonHeight,
    Register(u64),
    DescribeRegistry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinnedAction {
    CheckRegistered,
    WrapLeaf(usize),
    WrapAll,
    Merge { level: usize, index: usize },
    MergeAll,
    RemoveInners,
    VerifyRoot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Preparation {
        action: Preparation,
        dir: PathBuf,
    },
    Pinned {
        action: PinnedAction,
        dir: PathBuf,
        expected: ExternalExpected,
    },
}

fn exact_args(args: &[String], count: usize) -> Result<(), Error> {
    if args.len() != count {
        return Err(format!("incorrect argument count\n{USAGE}").into());
    }
    Ok(())
}

fn parse_command(args: &[String]) -> Result<Command, Error> {
    let name = args.first().ok_or(USAGE)?.as_str();
    let preparation = match name {
        "prepare" => Some(Preparation::Wallets),
        "common-height" => Some(Preparation::CommonHeight),
        "describe-registry" => Some(Preparation::DescribeRegistry),
        "register" => {
            exact_args(args, 3)?;
            let mode: u64 = args[2].parse()?;
            if !(programs::WRAPPER..=programs::MERGE).contains(&mode) {
                return Err("registration mode must be 1, 2 or 3".into());
            }
            Some(Preparation::Register(mode))
        }
        _ => None,
    };
    if let Some(action) = preparation {
        exact_args(
            args,
            if matches!(action, Preparation::Register(_)) {
                3
            } else {
                2
            },
        )?;
        return Ok(Command::Preparation {
            action,
            dir: PathBuf::from(&args[1]),
        });
    }
    let action = match name {
        "check-registered" => {
            exact_args(args, 5)?;
            PinnedAction::CheckRegistered
        }
        "wrap-leaf" => {
            exact_args(args, 6)?;
            let index: usize = args[5].parse()?;
            if index >= WALLETS {
                return Err("leaf index must be 0..8".into());
            }
            PinnedAction::WrapLeaf(index)
        }
        "wrap-all" => {
            exact_args(args, 5)?;
            PinnedAction::WrapAll
        }
        "merge" => {
            exact_args(args, 7)?;
            let level: usize = args[5].parse()?;
            let index: usize = args[6].parse()?;
            if !(1..=ROOT_LEVEL).contains(&level) || index >= (WALLETS >> level) {
                return Err("merge coordinates require levels 1..=3 and index < 8 >> level".into());
            }
            PinnedAction::Merge { level, index }
        }
        "merge-all" => {
            exact_args(args, 5)?;
            PinnedAction::MergeAll
        }
        "remove-inners" => {
            exact_args(args, 5)?;
            PinnedAction::RemoveInners
        }
        "verify-root" => {
            exact_args(args, 5)?;
            PinnedAction::VerifyRoot
        }
        _ => return Err(USAGE.into()),
    };
    Ok(Command::Pinned {
        action,
        dir: PathBuf::from(&args[1]),
        expected: ExternalExpected::parse(&args[2], &args[3], &args[4])?,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex32(value: &str, label: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{label} must be exactly 64 ASCII hex characters").into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

fn root_hex(value: &str) -> Result<commitment::Digest, Error> {
    let bytes = hex32(value, "expected root")?;
    let mut root = [0; 4];
    for (limb, word) in root.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(word.try_into()?);
        if *limb >= commitment::MODULUS {
            return Err("noncanonical expected-root field limb".into());
        }
    }
    Ok(root)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    // Reject symlinks/nonregular files before opening; O_NONBLOCK also prevents
    // a substituted FIFO from blocking before the descriptor type check.
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("artifact must be a regular, nonsymlink file".into());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("artifact size/type".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("artifact grew beyond limit".into());
    }
    Ok(bytes)
}

fn ensure_absent(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(format!("refusing to replace artifact {}", path.display()).into()),
    }
}

fn write_new_bytes(path: &Path, bytes: &[u8], limit: usize) -> Result<(), Error> {
    if bytes.len() > limit {
        return Err("output artifact exceeds bound".into());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write<T: Serialize>(path: &Path, magic: &[u8; 8], value: &T) -> Result<(), Error> {
    let mut bytes = magic.to_vec();
    bytes.extend(postcard::to_allocvec(value)?);
    write_new_bytes(path, &bytes, profile::MAX_PROOF_BYTES)
}

fn read<T: DeserializeOwned + Serialize>(path: &Path, magic: &[u8; 8]) -> Result<T, Error> {
    let bytes = read_bounded(path, profile::MAX_PROOF_BYTES)?;
    if !bytes.starts_with(magic) {
        return Err("artifact envelope".into());
    }
    Ok(codec::decode(&bytes[8..])?)
}

fn write_node(path: &Path, node: &NodeProof) -> Result<(), Error> {
    let bytes = codec::encode_node(node)?;
    write_new_bytes(path, &bytes, profile::MAX_PROOF_BYTES)
}

fn read_node(path: &Path) -> Result<NodeProof, Error> {
    Ok(codec::decode_node(&read_bounded(
        path,
        profile::MAX_PROOF_BYTES,
    )?)?)
}

fn validate_height(height: usize) -> Result<(), Error> {
    if !height.is_power_of_two() || !((1usize << 18)..=(1usize << 21)).contains(&height) {
        return Err("single-eight candidate height outside search range".into());
    }
    Ok(())
}

fn read_height(dir: &Path) -> Result<usize, Error> {
    let bytes = read_bounded(&dir.join("height"), 4)?;
    let height = u32::from_le_bytes(bytes.as_slice().try_into()?) as usize;
    validate_height(height)?;
    Ok(height)
}

fn read_registry(dir: &Path) -> Result<Registry, Error> {
    let height = read_height(dir)?;
    let length = (1 << profile::CAP_HEIGHT) * 32;
    let mut caps = core::array::from_fn(|_| Vec::new());
    for (i, cap) in caps.iter_mut().enumerate() {
        let bytes = read_bounded(&dir.join(format!("key.{}", i + 1)), length)?;
        if bytes.len() != length {
            return Err("key size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut fields = [Val::ZERO; 4];
            for (out, word) in fields.iter_mut().zip(digest.chunks_exact(8)) {
                let value = u64::from_le_bytes(word.try_into()?);
                if value >= commitment::MODULUS {
                    return Err("noncanonical key".into());
                }
                *out = Val::from_u64(value);
            }
            cap.push(fields);
        }
    }
    Ok(Registry { height, caps })
}

fn pinned_registry(dir: &Path, expected: ExternalExpected) -> Result<Registry, Error> {
    let registry = read_registry(dir)?;
    if registry.id()? != expected.profile {
        return Err("registry differs from externally supplied profile pin".into());
    }
    Ok(registry)
}

/// Native public-only checks for this fixed fixture runner, NOT host consensus.
/// Does not load or reconstruct any private wallet witness.
fn load_verified_wallets(
    dir: &Path,
    expected_chain: Option<[u8; 32]>,
) -> Result<Vec<WalletProof>, Error> {
    let mut wallets: Vec<WalletProof> = Vec::with_capacity(WALLETS);
    let mut nullifiers = BTreeSet::new();
    for index in 0..WALLETS {
        let wallet: WalletProof = read(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
        if expected_chain.is_some_and(|chain| wallet.chain != chain) {
            return Err("wallet chain differs from externally supplied chain".into());
        }
        recursive::verify_wallet(&wallet)?;
        if wallet.public[js::PI_MINT] != Val::ZERO {
            return Err("eight-wallet fixture must not contain issuance".into());
        }
        if let Some(first) = wallets.first() {
            if wallet.chain != first.chain
                || wallet.public[js::PI_ANCHOR..js::PI_NF] != first.public[js::PI_ANCHOR..js::PI_NF]
            {
                return Err("mixed eight-wallet fixture chain/anchor".into());
            }
        }
        for nf in wallet.public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
            let fields: Vec<_> = nf.iter().map(|value| value.as_canonical_u64()).collect();
            if !nullifiers.insert(fields) {
                return Err("duplicate nullifier in eight-wallet fixture".into());
            }
        }
        wallets.push(wallet);
    }
    Ok(wallets)
}

#[derive(Clone)]
struct ExpectedNode {
    filename: String,
    public: Public,
}

/// Commitment arithmetic only. The caller separately authenticates the wallet
/// proofs and compares the resulting root/chain/profile with external inputs.
fn nodes_from_leaves(leaves: &[NodeSummary]) -> Result<Vec<ExpectedNode>, Error> {
    if leaves.len() != WALLETS {
        return Err("expected exactly eight ordered leaves".into());
    }
    for leaf in leaves {
        commitment::validate_summary(*leaf)?;
        if leaf.level != 0 || leaf.count != 1 || leaf.context != leaves[0].context {
            return Err("expected matching-context count-one level-zero wallet leaves".into());
        }
    }
    let mut summaries = leaves.to_vec();
    let mut nodes = Vec::with_capacity(15);
    for (index, &leaf) in leaves.iter().enumerate() {
        nodes.push(ExpectedNode {
            filename: format!("node.0.{index}"),
            public: programs::statement(leaf, programs::WRAPPER),
        });
    }
    for level in 1..=ROOT_LEVEL {
        let mut parents = Vec::with_capacity(summaries.len() / 2);
        for (index, pair) in summaries.chunks_exact(2).enumerate() {
            let parent = commitment::merge_nodes(pair[0], pair[1])?;
            nodes.push(ExpectedNode {
                filename: format!("node.{level}.{index}"),
                public: programs::statement(parent, programs::MERGE),
            });
            parents.push(parent);
        }
        summaries = parents;
    }
    Ok(nodes)
}

fn expected_node(
    nodes: &[ExpectedNode],
    level: usize,
    index: usize,
) -> Result<&ExpectedNode, Error> {
    let slot = match (level, index) {
        (0, 0..=7) => index,
        (1, 0..=3) => 8 + index,
        (2, 0..=1) => 12 + index,
        (3, 0) => 14,
        _ => return Err("single-eight node coordinates".into()),
    };
    nodes
        .get(slot)
        .ok_or_else(|| "incomplete expected-node plan".into())
}

fn compare_external_root(nodes: &[ExpectedNode], expected: ExternalExpected) -> Result<(), Error> {
    let root = expected_node(nodes, ROOT_LEVEL, 0)?;
    if root.filename != ROOT_FILE || root.public != expected.statement()? {
        return Err("ordered wallet statements differ from external root/chain/profile".into());
    }
    Ok(())
}

fn optional_node(path: &Path) -> Result<Option<NodeProof>, Error> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(Some(read_node(path)?)),
    }
}

struct CheckedJob {
    registry: Registry,
    wallets: Vec<WalletProof>,
    nodes: Vec<ExpectedNode>,
    existing_nodes: usize,
}

/// All aggregation/resume routes enter here BEFORE creating a proving session.
/// Keep the authenticated public wallet artifacts in memory for this command,
/// instead of rereading different files after checking the externally expected root.
fn checked_job(dir: &Path, external: ExternalExpected) -> Result<CheckedJob, Error> {
    let registry = pinned_registry(dir, external)?;
    let wallets = load_verified_wallets(dir, Some(external.chain))?;
    let leaves: Result<Vec<_>, Error> = wallets
        .iter()
        .map(|wallet| recursive::wallet_summary(&registry, wallet))
        .collect();
    let nodes = nodes_from_leaves(&leaves?)?;
    compare_external_root(&nodes, external)?;
    let mut existing_nodes = 0;
    for expected in &nodes {
        if let Some(node) = optional_node(&dir.join(&expected.filename))? {
            registry.verify(external.profile, &node, &expected.public)?;
            existing_nodes += 1;
        }
    }
    Ok(CheckedJob {
        registry,
        wallets,
        nodes,
        existing_nodes,
    })
}

fn read_expected_node(
    dir: &Path,
    job: &CheckedJob,
    external: ExternalExpected,
    level: usize,
    index: usize,
) -> Result<NodeProof, Error> {
    let expected = expected_node(&job.nodes, level, index)?;
    let node: NodeProof = read_node(&dir.join(&expected.filename))?;
    job.registry
        .verify(external.profile, &node, &expected.public)?;
    Ok(node)
}

fn report_node(
    filename: &str,
    started: Instant,
    resumed: bool,
    session: &ConstructionSession,
    profiler: Option<&Profiler>,
) {
    println!(
        "single_eight_node_complete artifact={filename} resumed={resumed} elapsed_ms={} setups={} cache_hits={} production_ready=false",
        started.elapsed().as_millis(), session.stats().setups, session.stats().hits
    );
    if let Some(profiler) = profiler {
        profiler.report(filename);
    }
}

fn wrap_leaf(
    dir: &Path,
    job: &CheckedJob,
    external: ExternalExpected,
    index: usize,
    session: &mut ConstructionSession,
    profiler: Option<&Profiler>,
) -> Result<(), Error> {
    let expected = expected_node(&job.nodes, 0, index)?;
    let path = dir.join(&expected.filename);
    let started = Instant::now();
    let resumed = if let Some(node) = optional_node(&path)? {
        job.registry
            .verify(external.profile, &node, &expected.public)?;
        true
    } else {
        let wallet = job.wallets.get(index).ok_or("single wrapper index")?;
        let node = session.wrap(wallet)?;
        job.registry
            .verify(external.profile, &node, &expected.public)?;
        write_node(&path, &node)?;
        false
    };
    report_node(&expected.filename, started, resumed, session, profiler);
    Ok(())
}

fn merge(
    dir: &Path,
    job: &CheckedJob,
    external: ExternalExpected,
    level: usize,
    index: usize,
    session: &mut ConstructionSession,
    profiler: Option<&Profiler>,
) -> Result<(), Error> {
    if !(1..=ROOT_LEVEL).contains(&level) || index >= (WALLETS >> level) {
        return Err("single-eight merge coordinates".into());
    }
    let expected = expected_node(&job.nodes, level, index)?;
    let started = Instant::now();
    // Both child statements are fixed by the external-root-checked public tree,
    // not taken as trusted merely because each proof verifies against itself.
    let left = read_expected_node(dir, job, external, level - 1, 2 * index)?;
    let right = read_expected_node(dir, job, external, level - 1, 2 * index + 1)?;
    let path = dir.join(&expected.filename);
    let resumed = if let Some(node) = optional_node(&path)? {
        job.registry
            .verify(external.profile, &node, &expected.public)?;
        true
    } else {
        let node = session.merge(&left, &right)?;
        job.registry
            .verify(external.profile, &node, &expected.public)?;
        write_node(&path, &node)?;
        false
    };
    report_node(&expected.filename, started, resumed, session, profiler);
    Ok(())
}

fn inner_names() -> Vec<String> {
    (0..WALLETS)
        .map(|index| format!("wallet.{index}"))
        .chain((0..8).map(|index| format!("node.0.{index}")))
        .chain((0..4).map(|index| format!("node.1.{index}")))
        .chain((0..2).map(|index| format!("node.2.{index}")))
        .collect()
}

fn is_inner_name(name: &str) -> bool {
    name.starts_with("wallet.") || (name.starts_with("node.") && name != ROOT_FILE)
}

fn require_no_inners(dir: &Path) -> Result<(), Error> {
    // Reject every wallet/node-prefixed inner, including unexpected coordinates.
    // This is NOT the separate auditor's exact-five-file directory policy.
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let filename = entry.file_name();
        let name = filename.to_str().ok_or("non-UTF8 artifact name")?;
        if is_inner_name(name) {
            return Err(format!("inner artifact still present: {name}").into());
        }
    }
    Ok(())
}

/// Reads exactly height, three caps, and the root proof. No wallet proof,
/// intermediate node, local expected statement, profile.hex or scratch data.
fn verify_root_proof(dir: &Path, external: ExternalExpected) -> Result<(), Error> {
    let registry = pinned_registry(dir, external)?;
    let node: NodeProof = read_node(&dir.join(ROOT_FILE))?;
    registry.verify(external.profile, &node, &external.statement()?)
}

fn verify_root_only(dir: &Path, external: ExternalExpected) -> Result<(), Error> {
    require_no_inners(dir)?;
    verify_root_proof(dir, external)?;
    println!(
        "single_eight_root_verification=PASS level=3 count=8 inner_proofs_loaded=0 full_tree_security=UNREVIEWED production_ready=false"
    );
    Ok(())
}

fn remove_inners(dir: &Path, external: ExternalExpected) -> Result<(), Error> {
    // Authenticate the final proof against the external statement before deleting
    // anything. This also makes interrupted pruning resumable without wallets.
    verify_root_proof(dir, external)?;
    let mut removed = 0;
    for name in inner_names() {
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err("refusing to prune a nonregular inner artifact".into());
                }
                fs::remove_file(path)?;
                removed += 1;
            }
        }
    }
    verify_root_only(dir, external)?;
    println!(
        "single_eight_inner_artifacts_removed={removed} pruning_does_not_approve_profile=true"
    );
    Ok(())
}

fn prepare(dir: &Path) -> Result<(), Error> {
    // Fresh directory only; no silent reuse of four-wallet or prior fixture files.
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join("scratch"))?;
    println!("single_eight_preparation=UNAPPROVED construction={CONSTRUCTION:?} wallets=8");
    for index in 0..WALLETS {
        let wallet = recursive::demo_wallet_eight(index)?;
        recursive::verify_wallet(&wallet)?;
        write(&dir.join(format!("wallet.{index}")), WALLET_MAGIC, &wallet)?;
        println!("single_eight_fixture_wallet_created index={index} approval=false");
    }
    // Validate shared public anchor/chain and distinct nullifiers as a fixture
    // consistency check, not a block-acceptance or registry-approval decision.
    load_verified_wallets(dir, Some(recursive::DEMO_CHAIN))?;
    Ok(())
}

fn prepare_common_height(dir: &Path) -> Result<(), Error> {
    let path = dir.join("height");
    ensure_absent(&path)?;
    let wallets = load_verified_wallets(dir, Some(recursive::DEMO_CHAIN))?;
    let height = CONSTRUCTION.common_height(&wallets[0])?;
    validate_height(height)?;
    write_new_bytes(&path, &u32::try_from(height)?.to_le_bytes(), 4)?;
    println!(
        "single_eight_candidate_height={height} measured_recursive_closure=false approval=false"
    );
    Ok(())
}

fn register(dir: &Path, mode: u64) -> Result<(), Error> {
    let path = dir.join(format!("key.{mode}"));
    ensure_absent(&path)?;
    let wallets = load_verified_wallets(dir, Some(recursive::DEMO_CHAIN))?;
    let cap = CONSTRUCTION.register(read_height(dir)?, mode, Some(&wallets[0]))?;
    if cap.len() != 1 << profile::CAP_HEIGHT {
        return Err("generated cap length".into());
    }
    let mut bytes = Vec::new();
    for digest in cap {
        for field in digest {
            bytes.extend(field.as_canonical_u64().to_le_bytes());
        }
    }
    write_new_bytes(&path, &bytes, (1 << profile::CAP_HEIGHT) * 32)?;
    println!("single_eight_key_generated mode={mode} cpu_only=true approval=false");
    Ok(())
}

fn run(command: Command, profiler: Option<&Profiler>) -> Result<(), Error> {
    let (action, dir, external) = match command {
        Command::Preparation { action, dir } => {
            return match action {
                Preparation::Wallets => prepare(&dir),
                Preparation::CommonHeight => prepare_common_height(&dir),
                Preparation::Register(mode) => register(&dir, mode),
                Preparation::DescribeRegistry => {
                    let registry = read_registry(&dir)?;
                    println!(
                        "single_eight_candidate_profile={} height={} approval=false proof_verified=false",
                        hex(&registry.id()?), registry.height
                    );
                    Ok(())
                }
            };
        }
        Command::Pinned {
            action,
            dir,
            expected,
        } => (action, dir, expected),
    };
    match action {
        PinnedAction::VerifyRoot => return verify_root_only(&dir, external),
        PinnedAction::RemoveInners => return remove_inners(&dir, external),
        _ => {}
    }
    let job = checked_job(&dir, external)?;
    if action == PinnedAction::CheckRegistered {
        println!(
            "single_eight_checkpoint=PASS wallets=8 existing_nodes_verified={} external_statement_checked=true production_ready=false",
            job.existing_nodes
        );
        return Ok(());
    }
    // A single immutable preprocessing workspace for the entire selected command.
    // No legacy one-shot helper, environment construction switch or self-derived pin.
    let mut session = CONSTRUCTION.session(job.registry.clone(), external.profile)?;
    match action {
        PinnedAction::WrapLeaf(index) => {
            wrap_leaf(&dir, &job, external, index, &mut session, profiler)?;
        }
        PinnedAction::WrapAll => {
            for index in 0..WALLETS {
                wrap_leaf(&dir, &job, external, index, &mut session, profiler)?;
            }
        }
        PinnedAction::Merge { level, index } => {
            merge(&dir, &job, external, level, index, &mut session, profiler)?;
        }
        PinnedAction::MergeAll => {
            for level in 1..=ROOT_LEVEL {
                for index in 0..(WALLETS >> level) {
                    merge(&dir, &job, external, level, index, &mut session, profiler)?;
                }
            }
        }
        _ => return Err("internal command dispatch".into()),
    }
    Ok(())
}

fn main() {
    match lattica_prover_p3::block_v2::quotient_pcs::initialize_research_from_env() {
        Ok(enabled) => {
            println!("quotient_fusion_research enabled={enabled} production_ready=false")
        }
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    }
    // This binary has no GPU initialization or shutdown calls. Reject GPU-enabled
    // builds before setup, proof verification or any stage work; do not silently
    // treat a GPU-feature build/environment as the CPU-only registration gate.
    if cfg!(feature = "gpu") {
        eprintln!(
            "FAILED: single-eight research requires a CPU-only build without the gpu feature"
        );
        std::process::exit(1);
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    };
    let started = Instant::now();
    let _spill = spill_alloc::SpillScope::arm();
    let profiler = match Profiler::from_env() {
        Ok(profiler) => profiler,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    };
    let result = run(command, profiler.as_ref());
    if let Some(profiler) = &profiler {
        profiler.report("single-eight process remainder");
    }
    println!(
        "single_eight_stage_elapsed_ms={} spill_peak_bytes={} cpu_only=true production_ready=false",
        started.elapsed().as_millis(),
        spill_alloc::spill_peak_bytes()
    );
    if let Err(error) = result {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}

// Cheap/native checks only. No wallet/recursive proving, key generation,
// interpreter, GPU, filesystem mutation or benchmark is used by these tests.
// Compilation and executed test results are recorded separately in docs/evidence.
#[cfg(all(test, not(feature = "gpu")))]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::commitment::{Entry, Kind};

    fn root_string(root: commitment::Digest) -> String {
        let mut bytes = Vec::new();
        for limb in root {
            bytes.extend(limb.to_le_bytes());
        }
        hex(&bytes)
    }

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn external_fixture() -> ExternalExpected {
        ExternalExpected {
            profile: [0x11; 32],
            chain: [0x22; 32],
            root: [1, 2, 3, 4],
        }
    }

    fn structural_leaves() -> Vec<NodeSummary> {
        let external = external_fixture();
        let context = Context {
            profile_id: external.profile,
            chain_id: external.chain,
        };
        (0..WALLETS)
            .map(|index| {
                // Synthetic PUBLIC statements only; these are not wallet proofs.
                let fields = vec![index as u64; js::N_PUBLIC];
                commitment::leaf(
                    context,
                    Entry {
                        kind: Kind::JoinSplit,
                        statement_digest: commitment::statement_digest(1, &fields).unwrap(),
                    },
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn hex_inputs_are_strict_and_root_limbs_are_canonical_little_endian() {
        assert_eq!(hex32(&"aB".repeat(32), "test").unwrap(), [0xab; 32]);
        for bad in [
            "é".repeat(32),
            "z0".repeat(32),
            "0".repeat(63),
            "0".repeat(65),
        ] {
            assert!(hex32(&bad, "test").is_err());
        }
        let root = [1, 256, commitment::MODULUS - 1, 0];
        assert_eq!(root_hex(&root_string(root)).unwrap(), root);
        assert!(root_string([1, 0, 0, 0]).starts_with("0100000000000000"));
        for slot in 0..4 {
            for value in [commitment::MODULUS, u64::MAX] {
                let mut root = [0; 4];
                root[slot] = value;
                assert!(root_hex(&root_string(root)).is_err());
            }
        }
    }

    #[test]
    fn every_pinned_command_requires_all_three_explicit_inputs_and_exact_arity() {
        let e = external_fixture();
        let pin = hex(&e.profile);
        let chain = hex(&e.chain);
        let root = root_string(e.root);
        for (name, extra) in [
            ("check-registered", vec![]),
            ("wrap-leaf", vec!["0"]),
            ("wrap-all", vec![]),
            ("merge", vec!["2", "0"]),
            ("merge-all", vec![]),
            ("remove-inners", vec![]),
            ("verify-root", vec![]),
        ] {
            let mut complete = args(&[name, "job", &pin, &chain, &root]);
            complete.extend(extra.iter().map(|s| (*s).to_owned()));
            match parse_command(&complete).unwrap() {
                Command::Pinned { expected, .. } => assert_eq!(expected, e),
                _ => panic!("pinned command became a preparation command"),
            }
            for missing in 2..=4 {
                let mut incomplete = complete.clone();
                incomplete.remove(missing);
                assert!(parse_command(&incomplete).is_err());
            }
            let mut extra = complete.clone();
            extra.push("unexpected".into());
            assert!(parse_command(&extra).is_err());
            assert!(parse_command(&args(&[name, "job"])).is_err());
        }
    }

    #[test]
    fn preparation_is_separate_and_single_leaf_coordinates_are_bounded() {
        assert!(matches!(
            parse_command(&args(&["prepare", "job"])).unwrap(),
            Command::Preparation {
                action: Preparation::Wallets,
                ..
            }
        ));
        for mode in ["1", "2", "3"] {
            assert!(parse_command(&args(&["register", "job", mode])).is_ok());
        }
        for mode in ["0", "4", "-1"] {
            assert!(parse_command(&args(&["register", "job", mode])).is_err());
        }
        let e = external_fixture();
        let pin = hex(&e.profile);
        let chain = hex(&e.chain);
        let root = root_string(e.root);
        assert_eq!(CONSTRUCTION, WrapperConstruction::SingleWallet);
        assert!(parse_command(&args(&["wrap-pair", "job", &pin, &chain, &root, "0"])).is_err());
        for index in ["0", "7"] {
            assert!(
                parse_command(&args(&["wrap-leaf", "job", &pin, &chain, &root, index])).is_ok()
            );
        }
        assert!(parse_command(&args(&["wrap-leaf", "job", &pin, &chain, &root, "8"])).is_err());
        for (level, index) in [("1", "0"), ("1", "3"), ("2", "0"), ("2", "1"), ("3", "0")] {
            assert!(
                parse_command(&args(&["merge", "job", &pin, &chain, &root, level, index])).is_ok()
            );
        }
        for (level, index) in [("0", "0"), ("1", "4"), ("2", "2"), ("3", "1"), ("4", "0")] {
            assert!(
                parse_command(&args(&["merge", "job", &pin, &chain, &root, level, index])).is_err()
            );
        }
        assert!(parse_command(&args(&["finish-registry", "job"])).is_err());
    }

    #[test]
    fn native_plan_has_exact_single_eight_artifact_names_modes_levels_and_counts() {
        let nodes = nodes_from_leaves(&structural_leaves()).unwrap();
        assert_eq!(nodes.len(), 15);
        for level in 0..=ROOT_LEVEL {
            for index in 0..(WALLETS >> level) {
                let node = expected_node(&nodes, level, index).unwrap();
                assert_eq!(node.filename, format!("node.{level}.{index}"));
                assert_eq!(node.public[programs::LEVEL], Val::from_usize(level));
                assert_eq!(node.public[programs::COUNT], Val::from_usize(1 << level));
                assert_eq!(
                    node.public[programs::MODE],
                    Val::from_u64(if level == 0 {
                        programs::WRAPPER
                    } else {
                        programs::MERGE
                    })
                );
            }
        }
        assert!(expected_node(&nodes, 0, 8).is_err());
        assert!(expected_node(&nodes, 1, 4).is_err());
        assert!(expected_node(&nodes, 2, 2).is_err());
        assert!(expected_node(&nodes, 3, 1).is_err());
    }

    #[test]
    fn native_expected_root_comparison_binds_order_profile_chain_and_fixed_metadata() {
        let leaves = structural_leaves();
        let nodes = nodes_from_leaves(&leaves).unwrap();
        let mut expected = external_fixture();
        expected.root = recursive::summary(&nodes[14].public).unwrap().root;
        compare_external_root(&nodes, expected).unwrap();
        let mut reordered = leaves.clone();
        reordered.swap(0, 1);
        assert!(compare_external_root(&nodes_from_leaves(&reordered).unwrap(), expected).is_err());
        let mut wrong = expected;
        wrong.chain[0] ^= 1;
        assert!(compare_external_root(&nodes, wrong).is_err());
        wrong = expected;
        wrong.profile[0] ^= 1;
        assert!(compare_external_root(&nodes, wrong).is_err());
        wrong = expected;
        wrong.root[0] = (wrong.root[0] + 1) % commitment::MODULUS;
        assert!(compare_external_root(&nodes, wrong).is_err());
        for field in [programs::MODE, programs::LEVEL, programs::COUNT] {
            let mut changed = nodes.clone();
            changed[14].public[field] += Val::ONE;
            assert!(compare_external_root(&changed, expected).is_err());
        }
    }

    #[test]
    fn native_plan_rejects_wrong_leaf_count_context_and_nonleaf_summaries() {
        let leaves = structural_leaves();
        assert!(nodes_from_leaves(&leaves[..7]).is_err());
        let mut too_many = leaves.clone();
        too_many.push(leaves[0]);
        assert!(nodes_from_leaves(&too_many).is_err());
        let mut changed = leaves.clone();
        let mut context = leaves[0].context;
        context.chain_id[0] ^= 1;
        changed[0] = commitment::leaf(
            context,
            Entry {
                kind: Kind::JoinSplit,
                statement_digest: commitment::statement_digest(1, &[42]).unwrap(),
            },
        )
        .unwrap();
        assert!(nodes_from_leaves(&changed).is_err());
        changed = leaves.clone();
        changed[0] = commitment::empty_subtree(leaves[0].context, 0).unwrap();
        assert!(nodes_from_leaves(&changed).is_err());
        changed[0] = commitment::merge_nodes(leaves[0], leaves[1]).unwrap();
        assert!(nodes_from_leaves(&changed).is_err());
    }

    #[test]
    fn height_bounds_and_inner_names_match_only_the_single_eight_layout() {
        for height in [1usize << 18, 1usize << 19, 1usize << 20, 1usize << 21] {
            validate_height(height).unwrap();
        }
        for height in [0, 8, (1usize << 18) + 1, 1usize << 22, usize::MAX] {
            assert!(validate_height(height).is_err());
        }
        let names = inner_names();
        assert_eq!(names.len(), 22);
        assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), 22);
        assert!(!names.iter().any(|name| name == ROOT_FILE));
        for name in names {
            assert!(is_inner_name(&name));
        }
        assert!(is_inner_name("node.0.0"));
        assert!(is_inner_name("wallet.999"));
        assert!(!is_inner_name(ROOT_FILE));
        assert!(!is_inner_name("height"));
    }
}
