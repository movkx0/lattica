//! Mixed depth-six research artifacts and bounded CPU/GPU qualification.
//! The typed registry needs its own admission and qualification evidence.
#[cfg(all(target_os = "linux", feature = "stream"))]
#[path = "execution.rs"]
mod execution;
#[cfg(feature = "gpu")]
#[path = "gpu.rs"]
mod typed_gpu;
use lattica_prover_p3::block_v2::{
    codec,
    commitment::{self, Context, Entry, Kind, NodeSummary},
    machine::{analysis, programs, typed_finalizer, typed_pairs},
    profile,
    recursive::{Error, NodeProof, WalletProof},
    typed_fixture,
    typed_recursive::{self, Policy},
};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks as Val;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Instant,
};

use super::{FINALIZER, PAIRED};
const KEY_COUNT: usize = if PAIRED {
    12
} else if FINALIZER {
    6
} else {
    5
};
const FINALIZE_MODE: u64 = if PAIRED {
    typed_pairs::FINALIZE
} else {
    typed_finalizer::FINALIZE
};
const CONSTRUCTION: &str = if PAIRED {
    "typed-paired-v1"
} else if FINALIZER {
    "typed-finalizer-v1"
} else {
    "typed-reference-v1"
};
type Registry = typed_recursive::Registry<KEY_COUNT>;
type Session = typed_recursive::Session<KEY_COUNT>;

const WALLET_MAGIC: &[u8; 8] = b"LBV2TW01";
const KEY_MAGIC: &[u8; 8] = if PAIRED {
    b"LBV2TP01"
} else if FINALIZER {
    b"LBV2TF01"
} else {
    b"LBV2TK01"
};
const JSON_LIMIT: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TransactionType {
    Joinsplit,
    HtlcRedeem,
    HtlcRefund,
    Issuance,
}

impl TransactionType {
    fn kind(self) -> Kind {
        match self {
            Self::Joinsplit => Kind::JoinSplit,
            Self::HtlcRedeem | Self::HtlcRefund => Kind::Htlc,
            Self::Issuance => Kind::Coinbase,
        }
    }

    fn mode(self) -> u64 {
        match self {
            Self::Joinsplit => 1,
            Self::HtlcRedeem | Self::HtlcRefund => 4,
            Self::Issuance => 5,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    kind: TransactionType,
    statement: Vec<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema_version: u32,
    chain: [u8; 32],
    transactions: Vec<Transaction>,
}

/// Independently supplied by the benchmark controller/host before proving.
/// Do not derive audit expectations from a worker's root or result file.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    schema_version: u32,
    profile: [u8; 32],
    chain: [u8; 32],
    root: [u64; 4],
    count: u8,
    block_height: u64,
    authorized_issuance: BTreeMap<usize, u64>,
}

impl Expected {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || !(1..=64).contains(&self.count)
            || self.block_height >= 1u64 << lattica_prover_p3::htlc_air::BITS
            || self.root.iter().any(|v| *v >= commitment::MODULUS)
            || self.authorized_issuance.iter().any(|(i, mint)| {
                *i >= self.count as usize
                    || *mint == 0
                    || *mint >= 1u64 << lattica_prover_p3::joinsplit_air::BITS
            })
        {
            return Err("invalid independent mixed-root expectation".into());
        }
        Ok(())
    }

    fn context(&self) -> Context {
        Context {
            profile_id: self.profile,
            chain_id: self.chain,
        }
    }

    fn public(&self) -> [Val; programs::PUBLIC_VALUES] {
        programs::statement(
            NodeSummary {
                context: self.context(),
                root: self.root,
                count: self.count,
                level: commitment::DEPTH,
            },
            if FINALIZER && self.count <= 32 {
                FINALIZE_MODE
            } else {
                programs::MERGE
            },
        )
    }
}

fn read_bytes(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("artifact must be a regular nonsymlink file".into());
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
        return Err("artifact grew beyond bound".into());
    }
    Ok(bytes)
}

fn write_bytes(path: &Path, bytes: &[u8], limit: usize) -> Result<(), Error> {
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
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_slice(&read_bytes(path, JSON_LIMIT)?)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    write_bytes(path, &serde_json::to_vec_pretty(value)?, JSON_LIMIT)
}

fn read_artifact<T: DeserializeOwned + Serialize>(
    path: &Path,
    magic: &[u8; 8],
) -> Result<T, Error> {
    let bytes = read_bytes(path, profile::MAX_PROOF_BYTES)?;
    if !bytes.starts_with(magic) {
        return Err("mixed artifact envelope".into());
    }
    Ok(codec::decode(&bytes[8..])?)
}

fn write_artifact<T: Serialize>(path: &Path, magic: &[u8; 8], value: &T) -> Result<(), Error> {
    let mut bytes = magic.to_vec();
    bytes.extend(postcard::to_allocvec(value)?);
    write_bytes(path, &bytes, profile::MAX_PROOF_BYTES)
}

fn body(dir: &Path) -> Result<Body, Error> {
    let body: Body = read_json(&dir.join("body.json"))?;
    validate_body(&body)?;
    Ok(body)
}

fn validate_body(body: &Body) -> Result<(), Error> {
    if body.schema_version != 1 || body.transactions.is_empty() || body.transactions.len() > 64 {
        return Err("invalid mixed body size/version".into());
    }
    for tx in &body.transactions {
        let width = if tx.kind.kind() == Kind::Htlc {
            lattica_prover_p3::htlc_air::N_PUBLIC
        } else {
            lattica_prover_p3::joinsplit_air::N_PUBLIC
        };
        if tx.statement.len() != width || tx.statement.iter().any(|v| *v >= commitment::MODULUS) {
            return Err("invalid mixed body statement".into());
        }
    }
    Ok(())
}

fn registry(dir: &Path) -> Result<Registry, Error> {
    let height: usize = read_json(&dir.join("height.json"))?;
    if !height.is_power_of_two() || !(1 << 18..=1 << 21).contains(&height) {
        return Err("unqualified typed height range".into());
    }
    let mut caps = core::array::from_fn(|_| Vec::new());
    for mode in 1..=KEY_COUNT {
        caps[mode - 1] = read_artifact(&dir.join(format!("key.{mode}")), KEY_MAGIC)?;
        if caps[mode - 1].len() != 1 << profile::CAP_HEIGHT {
            return Err("typed key shape".into());
        }
    }
    Ok(Registry { height, caps })
}

fn policy(tx: &Transaction, index: usize, expected: &Expected) -> Result<Policy, Error> {
    use lattica_prover_p3::{htlc_air as htlc, joinsplit_air as js};
    if tx.kind != TransactionType::Issuance && expected.authorized_issuance.contains_key(&index) {
        return Err("issuance authorization on a nonissuance transaction".into());
    }
    Ok(match tx.kind {
        TransactionType::Joinsplit => {
            if tx.statement[js::PI_MINT] != 0 {
                return Err("JoinSplit mint".into());
            }
            Policy::JoinSplit
        }
        TransactionType::HtlcRedeem | TransactionType::HtlcRefund => {
            if tx.statement[htlc::PI_HEIGHT] != expected.block_height
                || tx.statement[htlc::PI_MINT] != 0
            {
                return Err("HTLC height/mint differs from host policy".into());
            }
            let refund = tx.statement[htlc::PI_HASHLOCK..].iter().all(|v| *v == 0);
            if refund != (tx.kind == TransactionType::HtlcRefund) {
                return Err("HTLC redeem/refund label differs from statement".into());
            }
            Policy::Htlc {
                expected_height: expected.block_height,
            }
        }
        TransactionType::Issuance => {
            let authorized_mint = *expected
                .authorized_issuance
                .get(&index)
                .ok_or("missing independent issuance authorization")?;
            if tx.statement[js::PI_MINT] != authorized_mint {
                return Err("issuance differs from host authorization".into());
            }
            Policy::Issuance { authorized_mint }
        }
    })
}

fn verified_wallet(
    dir: &Path,
    body: &Body,
    index: usize,
    expected: &Expected,
) -> Result<WalletProof, Error> {
    let wallet: WalletProof = read_artifact(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
    let tx = body
        .transactions
        .get(index)
        .ok_or("wallet index outside body")?;
    if wallet.chain != expected.chain
        || body.chain != expected.chain
        || wallet
            .public
            .iter()
            .map(|v| v.as_canonical_u64())
            .collect::<Vec<_>>()
            != tx.statement
    {
        return Err("wallet differs from independently supplied body/context".into());
    }
    typed_recursive::verify_wallet(&wallet, policy(tx, index, expected)?)?;
    Ok(wallet)
}

#[derive(Clone, Copy, Debug)]
struct Task {
    level: u8,
    index: usize,
    mode: u64,
    summary: NodeSummary,
}

impl Task {
    fn name(&self) -> String {
        format!("node.{}.{}", self.level, self.index)
    }
    fn public(&self) -> [Val; programs::PUBLIC_VALUES] {
        programs::statement(self.summary, self.mode)
    }
}

fn task_priority(mode: u64, level: u8, index: usize) -> (u8, u64, u8, usize) {
    let (phase, kind) = match mode {
        programs::EMPTY => (1, 0),
        programs::MERGE => (2, 0),
        mode if FINALIZER && mode == FINALIZE_MODE => (3, 0),
        mode => (0, mode),
    };
    (phase, kind, level, index)
}

fn tasks(body: &Body, expected: &Expected) -> Result<Vec<Task>, Error> {
    validate_body(body)?;
    expected.validate()?;
    if body.chain != expected.chain || body.transactions.len() < expected.count as usize {
        return Err("body differs from expected chain/count".into());
    }
    let entries = body.transactions[..expected.count as usize]
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            policy(tx, i, expected)?;
            Ok(Entry {
                kind: tx.kind.kind(),
                statement_digest: commitment::statement_digest(
                    tx.kind.kind() as u8,
                    &tx.statement,
                )?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if commitment::root(expected.context(), &entries)? != expected.root {
        return Err("body differs from independently supplied ordered root".into());
    }
    fn visit(
        level: u8,
        index: usize,
        entries: &[Entry],
        body: &Body,
        context: Context,
        tasks: &mut Vec<Task>,
    ) -> Result<NodeSummary, Error> {
        let first = index << level;
        let (mode, summary) = if first >= entries.len() {
            (programs::EMPTY, commitment::empty_subtree(context, level)?)
        } else if PAIRED && level == 1 {
            let left = commitment::leaf(context, entries[first])?;
            let (right, right_mode) = if let Some(entry) = entries.get(first + 1) {
                (
                    commitment::leaf(context, *entry)?,
                    body.transactions[first + 1].kind.mode(),
                )
            } else {
                (
                    commitment::empty_subtree(context, 0)?,
                    body.transactions[first].kind.mode(),
                )
            };
            let mode = typed_pairs::mode_for([body.transactions[first].kind.mode(), right_mode])?;
            (mode, commitment::merge_nodes(left, right)?)
        } else if level == 0 {
            (
                body.transactions[index].kind.mode(),
                commitment::leaf(context, entries[index])?,
            )
        } else {
            let left = visit(level - 1, index * 2, entries, body, context, tasks)?;
            let right = visit(level - 1, index * 2 + 1, entries, body, context, tasks)?;
            (programs::MERGE, commitment::merge_nodes(left, right)?)
        };
        tasks.push(Task {
            level,
            index,
            mode,
            summary,
        });
        Ok(summary)
    }
    let mut tasks = Vec::new();
    let subtree_level = if PAIRED {
        typed_pairs::proof_plan(expected.count)?.subtree_level
    } else if FINALIZER {
        typed_finalizer::proof_plan(expected.count)?.subtree_level
    } else {
        commitment::DEPTH
    };
    let mut summary = visit(
        subtree_level,
        0,
        &entries,
        body,
        expected.context(),
        &mut tasks,
    )?;
    if subtree_level < commitment::DEPTH {
        while summary.level < commitment::DEPTH {
            let empty = commitment::empty_subtree(summary.context, summary.level)?;
            summary = commitment::merge_nodes(summary, empty)?;
        }
        tasks.push(Task {
            level: commitment::DEPTH,
            index: 0,
            mode: FINALIZE_MODE,
            summary,
        });
    }
    // Session holds one preprocessing program. Keep each wrapper type together,
    // then padding, then merges in increasing level, preserving tree positions.
    tasks.sort_by_key(|task| task_priority(task.mode, task.level, task.index));
    Ok(tasks)
}

fn fixture_body() -> Body {
    let statements = typed_fixture::statements();
    let kinds = [
        TransactionType::Joinsplit,
        TransactionType::HtlcRedeem,
        TransactionType::HtlcRefund,
        TransactionType::Issuance,
    ];
    Body {
        schema_version: 1,
        chain: typed_fixture::CHAIN,
        transactions: statements
            .into_iter()
            .enumerate()
            .map(|(i, statement)| Transaction {
                kind: kinds[i % 4],
                statement,
            })
            .collect(),
    }
}

fn fixture(dir: &Path) -> Result<(), Error> {
    fs::create_dir(dir)?;
    let body = fixture_body();
    write_json(&dir.join("body.json"), &body)?;
    for index in 0..64 {
        let started = Instant::now();
        let (wallet, _) = typed_fixture::wallet(index)?;
        write_artifact(&dir.join(format!("wallet.{index}")), WALLET_MAGIC, &wallet)?;
        println!(
            "{}",
            json!({"event":"fixture_leaf", "index":index, "seconds":started.elapsed().as_secs_f64()})
        );
    }
    Ok(())
}

fn fixture_policy(body: &Body) -> Expected {
    // These fixed policies apply only to the synthetic fixture command. Actual
    // proving and audit commands always read the independent Expected document.
    Expected {
        schema_version: 1,
        profile: [0; 32],
        chain: body.chain,
        root: [0; 4],
        count: 64,
        block_height: typed_fixture::HEIGHT,
        authorized_issuance: body
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| tx.kind == TransactionType::Issuance)
            .map(|(i, _)| (i, typed_fixture::MINT))
            .collect(),
    }
}

fn templates(dir: &Path) -> Result<[WalletProof; 3], Error> {
    let body = body(dir)?;
    let expected = fixture_policy(&body);
    let find = |kind| {
        body.transactions
            .iter()
            .position(|tx| tx.kind == kind)
            .ok_or("missing registration template type")
    };
    Ok([
        verified_wallet(dir, &body, find(TransactionType::Joinsplit)?, &expected)?,
        verified_wallet(dir, &body, find(TransactionType::HtlcRedeem)?, &expected)?,
        verified_wallet(dir, &body, find(TransactionType::Issuance)?, &expected)?,
    ])
}

fn expected(dir: &Path, count: u8, out: &Path) -> Result<(), Error> {
    if !(1..=64).contains(&count) {
        return Err("count must be 1..64".into());
    }
    let body = body(dir)?;
    let registry = registry(dir)?;
    if body.transactions.len() < count as usize {
        return Err("not enough fixture transactions".into());
    }
    let mut expected = fixture_policy(&body);
    expected.count = count;
    expected.profile = registry.id()?;
    expected
        .authorized_issuance
        .retain(|i, _| *i < count as usize);
    let entries = body.transactions[..count as usize]
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            verified_wallet(dir, &body, i, &expected)?;
            Ok(Entry {
                kind: tx.kind.kind(),
                statement_digest: commitment::statement_digest(
                    tx.kind.kind() as u8,
                    &tx.statement,
                )?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    expected.root = commitment::root(expected.context(), &entries)?;
    expected.validate()?;
    write_json(out, &expected)
}

fn audit(dir: &Path, expected: &Expected, public_body: &Body, root: &Path) -> Result<(), Error> {
    expected.validate()?;
    // The public body is independently supplied alongside the host's policy.
    // No wallet or intermediate proof is needed for this root/body audit.
    tasks(public_body, expected)?;
    let registry = registry(dir)?;
    let bytes = read_bytes(root, profile::MAX_PROOF_BYTES)?;
    let node = codec::decode_node(&bytes)?;
    registry.verify(expected.profile, &node, &expected.public())?;
    println!(
        "{}",
        json!({"event":"independent_cpu_root_audit", "count":expected.count, "root_bytes":bytes.len(), "depth":6, "passed":true, "production_ready":false})
    );
    Ok(())
}

/// A bounded CPU bootstrap is still an experiment, not phase admission. Require
/// an actual isolated cgroup before allocating full typed preprocessing. The
/// caller must reserve host/coordinator headroom separately, as for GPU runs.
fn require_cpu_limit(budget: u64) -> Result<(), Error> {
    if budget == 0 {
        return Err("missing CPU worker budget".into());
    }
    let cgroups = fs::read_to_string("/proc/self/cgroup")?;
    let relative = cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("CPU research proving requires cgroup v2")?
        .trim_start_matches('/');
    if relative.is_empty()
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err("CPU research proving requires a dedicated cgroup".into());
    }
    let group = Path::new("/sys/fs/cgroup").join(relative);
    if fs::read_to_string(group.join("memory.max"))?
        .trim()
        .parse::<u64>()?
        != budget
        || fs::read_to_string(group.join("memory.swap.max"))?.trim() != "0"
    {
        return Err("CPU research budget must equal enforced MemoryMax with swap disabled".into());
    }
    Ok(())
}

fn prove(dir: &Path, expected: &Expected, out: &Path, budget: u64, gpu: bool) -> Result<(), Error> {
    require_cpu_limit(budget)?;
    let started = Instant::now();
    let body = body(dir)?;
    let registry = registry(dir)?;
    let tasks = tasks(&body, expected)?;
    let mut session = Session::new(registry.clone(), expected.profile, budget)?;
    // Verify the complete candidate before allocating recursive preprocessing.
    let wallets = (0..expected.count as usize)
        .map(|i| verified_wallet(dir, &body, i, expected))
        .collect::<Result<Vec<_>, _>>()?;
    fs::create_dir(out)?;
    write_json(&out.join("expected.json"), expected)?;
    for task in &tasks {
        let stage = Instant::now();
        let node = match task.mode {
            programs::EMPTY => session.empty(expected.chain, task.level)?,
            programs::MERGE => {
                let child = |index| -> Result<NodeProof, Error> {
                    let planned = tasks
                        .iter()
                        .find(|t| t.level + 1 == task.level && t.index == index)
                        .ok_or("missing child task")?;
                    let bytes = read_bytes(&out.join(planned.name()), profile::MAX_PROOF_BYTES)?;
                    let node = codec::decode_node(&bytes)?;
                    registry.verify(expected.profile, &node, &planned.public())?;
                    Ok(node)
                };
                session.merge(&child(task.index * 2)?, &child(task.index * 2 + 1)?)?
            }
            mode if FINALIZER && mode == FINALIZE_MODE => {
                let level = if PAIRED {
                    typed_pairs::proof_plan(expected.count)?.subtree_level
                } else {
                    typed_finalizer::proof_plan(expected.count)?.subtree_level
                };
                let planned = tasks
                    .iter()
                    .find(|t| t.level == level && t.index == 0)
                    .ok_or("missing finalizer child task")?;
                let bytes = read_bytes(&out.join(planned.name()), profile::MAX_PROOF_BYTES)?;
                let child = codec::decode_node(&bytes)?;
                registry.verify(expected.profile, &child, &planned.public())?;
                session.finalize(&child)?
            }
            _ if PAIRED => {
                let left = task.index * 2;
                let right = if task.summary.count == 2 {
                    left + 1
                } else {
                    left
                };
                session.wrap_pair(
                    [&wallets[left], &wallets[right]],
                    [
                        policy(&body.transactions[left], left, expected)?,
                        policy(&body.transactions[right], right, expected)?,
                    ],
                    task.summary.count,
                )?
            }
            _ => session.wrap(
                &wallets[task.index],
                policy(&body.transactions[task.index], task.index, expected)?,
            )?,
        };
        registry.verify(expected.profile, &node, &task.public())?;
        let bytes = codec::encode_node(&node)?;
        println!(
            "{}",
            json!({"event":"fresh_typed_node", "level":task.level, "index":task.index, "mode":task.mode, "count":task.summary.count, "bytes":bytes.len(), "seconds":stage.elapsed().as_secs_f64()})
        );
        write_bytes(&out.join(task.name()), &bytes, profile::MAX_PROOF_BYTES)?;
    }
    write_json(
        &out.join("result.json"),
        &json!({
            "schema_version":1, "status":"proved_cpu_audit_pending", "count":expected.count,
            "construction":CONSTRUCTION, "registry_keys":KEY_COUNT,
            "fresh_proofs":tasks.len(), "seconds":started.elapsed().as_secs_f64(),
            "worker_memory_bytes":budget, "root_file":"node.6.0", "backend":if gpu {"gpu"} else {"cpu"},
            "durable_host_applied":false, "production_ready":false,
        }),
    )
}

fn run(args: &[String]) -> Result<(), Error> {
    // CPU auditing must not inherit a GPU/quotient backend from a shell. No
    // GPU initializer is called by this binary, including when GPU is compiled.
    for (key, value) in std::env::vars() {
        if (key.starts_with("LATTICA_V2_GPU_") || key.starts_with("LATTICA_V2_QUOTIENT_"))
            && value != "0"
        {
            return Err(
                format!("typed CPU probe requires an unconfigured GPU environment: {key}").into(),
            );
        }
    }
    run_inner(args, false)
}

/// CPU-only wallet authentication and native-body agreement, without a DAG or OS worker.
fn verify_wallet_inputs(dir: &Path, pinned: &Path, out: &Path) -> Result<(), Error> {
    if !PAIRED || cfg!(any(feature = "gpu", feature = "gpu-metal")) {
        return Err("wallet input verification requires a CPU-only paired probe".into());
    }
    let expected: Expected = read_json(pinned)?;
    expected.validate()?;
    let body = body(dir)?;
    if body.transactions.len() != expected.count as usize {
        return Err("wallet verification requires the entire expected body".into());
    }
    // Checks ordered commitments, root, chain, height and independent issuance policy.
    let _tasks = tasks(&body, &expected)?;
    for index in 0..expected.count as usize {
        verified_wallet(dir, &body, index, &expected)?;
    }
    write_json(
        out,
        &json!({"schema_version":1,"record_type":"typed_wallet_verification",
        "count":expected.count,"height":expected.block_height,"cpu_leaf_verified":true,
        "registry_keys":KEY_COUNT,"prover_jobs_started":0,"production_ready":false}),
    )
}

fn run_inner(args: &[String], gpu: bool) -> Result<(), Error> {
    let values: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match values.as_slice() {
        ["fixture", dir] => fixture(Path::new(dir)),
        ["fixture-statements", out] => write_json(Path::new(out), &fixture_body()),
        ["geometry", dir] => {
            let dir = Path::new(dir);
            let [js, htlc, issuance] = templates(dir)?;
            let height = if PAIRED { typed_recursive::common_height_paired([&js, &htlc, &issuance])? } else if FINALIZER { typed_recursive::common_height_finalized([&js, &htlc, &issuance])? } else { typed_recursive::common_height([&js, &htlc, &issuance])? };
            let report = analysis::analyze(&programs::shape(height)?).map_err(|e| format!("{e:?}"))?;
            write_json(&dir.join("height.json"), &height)?;
            println!("{}", json!({"event":"typed_geometry", "height":height, "construction":CONSTRUCTION, "registry_keys":KEY_COUNT,
                "main_width":report.main_width, "preprocessed_width":report.preprocessed_width,
                "retained_lde_lower_bound_bytes":report.retained_lde_bytes,
                "phase_admitted":false, "gpu_qualified":false}));
            Ok(())
        }
        ["register", dir, mode, budget] => {
            let dir = Path::new(dir);
            let mode: u64 = mode.parse()?;
            if !(1..=KEY_COUNT as u64).contains(&mode) { return Err("typed registration mode is outside this registry".into()); }
            let height: usize = read_json(&dir.join("height.json"))?;
            if !height.is_power_of_two() || !(1 << 18..=1 << 21).contains(&height) { return Err("typed height range".into()); }
            let budget = budget.parse()?;
            require_cpu_limit(budget)?;
            let wallets = templates(dir)?;
            let wallet = match mode { 1 => Some(&wallets[0]), 4 => Some(&wallets[1]), 5 => Some(&wallets[2]), _ => None };
            let cap = if PAIRED { typed_recursive::register_paired(height, mode, [&wallets[0], &wallets[1], &wallets[2]], budget)? } else if FINALIZER { typed_recursive::register_finalized(height, mode, wallet, budget)? } else { typed_recursive::register(height, mode, wallet, budget)? };
            write_artifact(&dir.join(format!("key.{mode}")), KEY_MAGIC, &cap)
        }
        #[cfg(feature = "block-v2-host")]
        ["export-host-registry", dir, out] => {
            if !PAIRED {
                return Err("host registry export requires the twelve-key paired construction".into());
            }
            let registered = registry(Path::new(dir))?;
            let caps = registered.caps.into_iter().collect::<Vec<_>>().try_into()
                .map_err(|_| "host registry requires twelve keys")?;
            let registered = typed_recursive::Registry::<12> { height: registered.height, caps };
            let bytes = lattica_prover_p3::block_v2::host::encode_registry(&registered)?;
            write_bytes(Path::new(out), &bytes, lattica_prover_p3::block_v2::host::MAX_REGISTRY_BYTES)
        }
        #[cfg(feature = "block-v2-host")]
        ["export-host-expected", input, out] => {
            if !PAIRED {
                return Err("host expectation export requires paired construction".into());
            }
            let expected: Expected = read_json(Path::new(input))?;
            expected.validate()?;
            let bytes = lattica_prover_p3::block_v2::host::Expected {
                context: expected.context(), root: expected.root, count: expected.count,
            }.encode()?;
            write_bytes(Path::new(out), &bytes, bytes.len())
        }
        ["expected", dir, count, out] => expected(Path::new(dir), count.parse()?, Path::new(out)),
        ["verify-wallets", dir, pinned, out] => verify_wallet_inputs(Path::new(dir), Path::new(pinned), Path::new(out)),
        #[cfg(all(target_os = "linux", feature = "stream"))]
        ["audit-preseal", dir, pinned, nodes, out] => execution::audit_preseal(Path::new(dir), Path::new(pinned), Path::new(nodes), Path::new(out)),
        #[cfg(all(target_os = "linux", feature = "stream"))]
        ["execution-plan", dir, pinned, out] => execution::plan(Path::new(dir), Path::new(pinned), Path::new(out)),
        #[cfg(all(target_os = "linux", feature = "stream", feature = "gpu"))]
        ["prove-fleet-gpu", dir, pinned, plan, out] => execution::prove_fleet(
            Path::new(dir), Path::new(pinned), Path::new(plan), Path::new(out)),
        #[cfg(all(target_os = "linux", feature = "stream"))]
        ["execution-audit", dir, pinned, nodes, head, out] => execution::audit(Path::new(dir), Path::new(pinned), Path::new(nodes), head, Path::new(out)),
        #[cfg(all(target_os = "linux", feature = "stream"))]
        ["execution-recover", dir, pinned, runtime, assignment, root, head, epoch, out] => execution::recover(
            Path::new(dir), Path::new(pinned), Path::new(runtime), Path::new(assignment),
            Path::new(root), head, epoch.parse()?, Path::new(out)),
        ["plan", dir, pinned] => {
            let expected: Expected = read_json(Path::new(pinned))?;
            let tasks = tasks(&body(Path::new(dir))?, &expected)?;
            println!("{}", json!({"count":expected.count, "depth":6, "fresh_proofs":tasks.len(), "construction":CONSTRUCTION, "registry_keys":KEY_COUNT,
                "tasks":tasks.iter().map(|t| json!({"file":t.name(), "mode":t.mode, "count":t.summary.count})).collect::<Vec<_>>(),
                "phase_admitted":false, "gpu_qualified":false}));
            Ok(())
        }
        ["prove-cpu", dir, pinned, out, budget] => prove(Path::new(dir), &read_json(Path::new(pinned))?, Path::new(out), budget.parse()?, gpu),
        ["audit-root", dir, pinned, body_file, root] => audit(Path::new(dir), &read_json(Path::new(pinned))?, &read_json(Path::new(body_file))?, Path::new(root)),
        _ => Err(concat!(
            "usage: block-v2-typed-probe fixture DIR | geometry DIR | register DIR MODE WORKER_BYTES | ",
            "expected DIR COUNT OUT | plan DIR EXPECTED | verify-wallets DIR EXPECTED OUT | prove-cpu DIR EXPECTED OUT WORKER_BYTES | ",
            "audit-root REGISTRY_DIR EXPECTED BODY ROOT; paired construction with block-v2-host also supports: ",
            "export-host-registry DIR OUT | export-host-expected EXPECTED_JSON OUT; ",
            "paired CPU-only Linux+stream diagnostics: execution-plan DIR EXPECTED OUT | ",
            "execution-audit DIR EXPECTED NODES HEAD_HEX OUT_DIRECTORY | ",
            "execution-recover DIR EXPECTED RUNTIME BUDGET ROOT HEAD_HEX NEXT_EPOCH OUT_DIRECTORY"
        ).into()),
    }
}

pub(crate) fn main() {
    let execute = || -> Result<(), Error> {
        let args: Vec<_> = std::env::args().collect();
        if matches!(
            args.get(1).map(String::as_str),
            Some(
                "register-gpu"
                    | "prove-gpu"
                    | "prove-execution-gpu"
                    | "prove-process-gpu"
                    | "serve-process-gpu"
                    | "serve-shared-process-gpu"
                    | "--gpu-inventory"
            )
        ) {
            #[cfg(feature = "gpu")]
            return typed_gpu::run(&args);
            #[cfg(not(feature = "gpu"))]
            return Err("typed GPU qualification requires a build with the gpu feature".into());
        }
        let available = std::thread::available_parallelism()?.get();
        let requested = std::env::var("RAYON_NUM_THREADS")
            .ok()
            .map(|v| v.parse::<usize>())
            .transpose()?
            .unwrap_or(available);
        if requested == 0 {
            return Err("Rayon thread count must be positive".into());
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(requested.min(available))
            .build_global()?;
        let profiler = lattica_prover_p3::block_v2::perf::Profiler::from_env()?;
        let result = run(&args);
        if let Some(profiler) = profiler {
            profiler.report("typed CPU process");
        }
        result
    };
    if let Err(error) = execute() {
        eprintln!("FAILED: typed research probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use std::collections::BTreeSet;

    fn candidate(count: u8) -> (Body, Expected) {
        let kinds = [
            TransactionType::Joinsplit,
            TransactionType::HtlcRedeem,
            TransactionType::HtlcRefund,
            TransactionType::Issuance,
        ];
        let body = Body {
            schema_version: 1,
            chain: typed_fixture::CHAIN,
            transactions: typed_fixture::statements()
                .into_iter()
                .enumerate()
                .map(|(i, statement)| Transaction {
                    kind: kinds[i % 4],
                    statement,
                })
                .collect(),
        };
        let mut expected = fixture_policy(&body);
        expected.profile = [42; 32];
        expected.count = count;
        expected
            .authorized_issuance
            .retain(|i, _| *i < count as usize);
        let entries: Vec<_> = body.transactions[..count as usize]
            .iter()
            .map(|tx| Entry {
                kind: tx.kind.kind(),
                statement_digest: commitment::statement_digest(tx.kind.kind() as u8, &tx.statement)
                    .unwrap(),
            })
            .collect();
        expected.root = commitment::root(expected.context(), &entries).unwrap();
        (body, expected)
    }

    #[test]
    fn all_contract_counts_have_ordered_depth_six_dependencies_and_fresh_work() {
        for count in [1, 2, 3, 4, 8, 16, 32, 63, 64] {
            let (body, expected) = candidate(count);
            let tasks = tasks(&body, &expected).unwrap();
            let mut finished = BTreeSet::new();
            let mut wraps = BTreeSet::new();
            for task in &tasks {
                if task.mode == programs::MERGE {
                    assert!(finished.contains(&(task.level - 1, task.index * 2)));
                    assert!(finished.contains(&(task.level - 1, task.index * 2 + 1)));
                } else if FINALIZER && task.mode == FINALIZE_MODE {
                    assert!(FINALIZER);
                    let level = if PAIRED {
                        typed_pairs::proof_plan(count).unwrap().subtree_level
                    } else {
                        typed_finalizer::proof_plan(count).unwrap().subtree_level
                    };
                    assert!(finished.contains(&(level, 0)));
                } else if task.mode == programs::EMPTY {
                    assert_eq!(task.summary.count, 0);
                    assert!(task.index << task.level >= count as usize);
                } else {
                    if PAIRED {
                        assert_eq!(task.level, 1);
                        assert!(matches!(task.summary.count, 1 | 2));
                        assert!(typed_pairs::leaf_modes(task.mode).is_ok());
                        for slot in 0..task.summary.count as usize {
                            assert!(wraps.insert(task.index * 2 + slot));
                        }
                    } else {
                        assert_eq!(task.level, 0);
                        assert!(wraps.insert(task.index));
                    }
                }
                assert!(finished.insert((task.level, task.index)));
            }
            assert_eq!(wraps, (0..count as usize).collect());
            if PAIRED {
                assert_eq!(
                    tasks.len(),
                    typed_pairs::proof_plan(count).unwrap().proposed_proofs as usize
                );
            } else if FINALIZER {
                assert_eq!(
                    tasks.len(),
                    typed_finalizer::proof_plan(count).unwrap().proposed_proofs as usize
                );
            }
            let root = tasks.last().unwrap();
            assert_eq!((root.level, root.index, root.summary.count), (6, 0, count));
            assert_eq!(root.summary.root, expected.root);
            assert_eq!(root.public(), expected.public());
            if count == 64 {
                assert_eq!(tasks.len(), if PAIRED { 63 } else { 127 });
            }
            if count == 1 {
                assert_eq!(tasks.len(), if FINALIZER { 2 } else { 13 });
            }
        }
    }

    #[test]
    fn host_expectation_rejects_reordered_body_wrong_context_and_policy() {
        let (mut body, expected) = candidate(8);
        body.transactions.swap(0, 4);
        assert!(tasks(&body, &expected).is_err());
        body.transactions.swap(0, 4);
        let mut wrong = expected.clone();
        wrong.chain[0] ^= 1;
        assert!(tasks(&body, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.root[0] ^= 1;
        assert!(tasks(&body, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.block_height += 1;
        assert!(tasks(&body, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.authorized_issuance.insert(3, 8);
        assert!(tasks(&body, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.authorized_issuance.remove(&3);
        assert!(tasks(&body, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.authorized_issuance.insert(0, 7);
        assert!(tasks(&body, &wrong).is_err());
        body.transactions[1].kind = TransactionType::HtlcRefund;
        assert!(tasks(&body, &expected).is_err());
    }

    #[test]
    fn malformed_expectations_fail_before_proving() {
        let (_, expected) = candidate(4);
        for count in [0, 65, 255] {
            let mut wrong = expected.clone();
            wrong.count = count;
            assert!(wrong.validate().is_err());
        }
        let mut wrong = expected.clone();
        wrong.root[0] = commitment::MODULUS;
        assert!(wrong.validate().is_err());
        let mut wrong = expected;
        wrong.authorized_issuance.insert(4, 7);
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn malformed_public_body_is_rejected_before_indexing_or_proving() {
        let (mut body, expected) = candidate(4);
        body.transactions[1].statement.clear();
        assert!(tasks(&body, &expected).is_err());
        let (mut body, expected) = candidate(4);
        body.transactions[0].statement[0] = commitment::MODULUS;
        assert!(tasks(&body, &expected).is_err());
        let (mut body, expected) = candidate(4);
        body.transactions.clear();
        assert!(tasks(&body, &expected).is_err());
    }

    #[test]
    fn key_artifacts_cannot_cross_registry_constructions() {
        let dir = std::env::temp_dir().join(format!(
            "lattica-typed-keys-{}-{KEY_COUNT}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let key = vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT];
        for (index, other) in [b"LBV2TK01", b"LBV2TF01", b"LBV2TP01"]
            .into_iter()
            .enumerate()
        {
            if other == KEY_MAGIC {
                continue;
            }
            let path = dir.join(format!("other-{index}"));
            write_artifact(&path, other, &key).unwrap();
            assert!(read_artifact::<Vec<[Val; 4]>>(&path, KEY_MAGIC).is_err());
        }
        write_artifact(&dir.join("matching"), KEY_MAGIC, &key).unwrap();
        assert_eq!(
            read_artifact::<Vec<[Val; 4]>>(&dir.join("matching"), KEY_MAGIC).unwrap(),
            key
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn artifacts_are_bounded_nonsymlink_and_exclusively_created() {
        let dir = std::env::temp_dir().join(format!("lattica-typed-io-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("data");
        write_bytes(&file, b"abc", 3).unwrap();
        assert_eq!(read_bytes(&file, 3).unwrap(), b"abc");
        assert!(read_bytes(&file, 2).is_err());
        assert!(read_bytes(&dir, 3).is_err());
        assert!(write_bytes(&file, b"def", 3).is_err());
        assert!(write_bytes(&dir.join("large"), b"abcd", 3).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_bytes(&link, 3).is_err());
        assert!(write_bytes(&link, b"abc", 3).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
