//! Fixed twelve-transaction research job: six paired wrappers, one level-two
//! empty proof, and six merges. The result is a level-four/count-twelve subtree.
//! This uses the existing circuits and never promotes a candidate registry.

use super::{
    CONSTRUCTION, Error, ExternalExpected, NodeProof, NodeSummary, Path, Profiler, Public,
    Registry, Val, WALLET_MAGIC, WalletProof, commitment, ensure_absent, fs, hex, js, programs,
    read, read_node, read_registry, recursive, report_node, write, write_node,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::{collections::BTreeSet, os::unix::fs::DirBuilderExt, time::Instant};

const COUNT: usize = 12;
const ROOT_FILE: &str = "node.4.0";

#[derive(Clone, Debug)]
struct PlannedNode {
    level: usize,
    index: usize,
    mode: u64,
    summary: NodeSummary,
}

impl PlannedNode {
    fn filename(&self) -> String {
        format!("node.{}.{}", self.level, self.index)
    }

    fn public(&self) -> Public {
        programs::statement(self.summary, self.mode)
    }
}

fn plan(leaves: &[NodeSummary]) -> Result<Vec<PlannedNode>, Error> {
    if leaves.len() != COUNT {
        return Err("twelve job requires exactly twelve ordered leaves".into());
    }
    for leaf in leaves {
        commitment::validate_summary(*leaf)?;
        if leaf.level != 0 || leaf.count != 1 {
            return Err("twelve job requires count-one wallet leaves".into());
        }
    }
    let mut nodes = Vec::with_capacity(13);
    let pairs: Vec<_> = leaves
        .chunks_exact(2)
        .map(|p| commitment::merge_nodes(p[0], p[1]))
        .collect::<Result<_, _>>()?;
    for (index, &summary) in pairs.iter().enumerate() {
        nodes.push(PlannedNode {
            level: 1,
            index,
            mode: programs::WRAPPER,
            summary,
        });
    }
    // Slots 12..16 are empty. Prove their canonical subtree directly, with the
    // same registered EMPTY program, instead of pretending there are 16 spends.
    let empty = commitment::empty_subtree(leaves[0].context, 2)?;
    nodes.push(PlannedNode {
        level: 2,
        index: 3,
        mode: programs::EMPTY,
        summary: empty,
    });
    let mut level_two = Vec::with_capacity(4);
    for (index, pair) in pairs.chunks_exact(2).enumerate() {
        let summary = commitment::merge_nodes(pair[0], pair[1])?;
        nodes.push(PlannedNode {
            level: 2,
            index,
            mode: programs::MERGE,
            summary,
        });
        level_two.push(summary);
    }
    level_two.push(empty);
    let mut current = level_two;
    for level in 3..=4 {
        let mut next = Vec::new();
        for (index, pair) in current.chunks_exact(2).enumerate() {
            let summary = commitment::merge_nodes(pair[0], pair[1])?;
            nodes.push(PlannedNode {
                level,
                index,
                mode: programs::MERGE,
                summary,
            });
            next.push(summary);
        }
        current = next;
    }
    if current.len() != 1 || current[0].level != 4 || current[0].count != 12 {
        return Err("invalid twelve-job tree".into());
    }
    Ok(nodes)
}

fn wallets(dir: &Path, chain: Option<[u8; 32]>) -> Result<Vec<WalletProof>, Error> {
    let names: BTreeSet<_> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .filter(|n| n.starts_with("wallet."))
        .collect();
    if names != (0..COUNT).map(|i| format!("wallet.{i}")).collect() {
        return Err("twelve fixture has a missing or extra wallet artifact".into());
    }
    let mut wallets: Vec<WalletProof> = Vec::with_capacity(COUNT);
    let mut nullifiers = BTreeSet::new();
    for index in 0..COUNT {
        let wallet: WalletProof = read(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
        recursive::verify_wallet(&wallet)?;
        if chain.is_some_and(|value| value != wallet.chain)
            || wallet.public[js::PI_MINT] != Val::ZERO
        {
            return Err("twelve fixture chain or issuance mismatch".into());
        }
        if let Some(first) = wallets.first() {
            if wallet.chain != first.chain
                || wallet.public[js::PI_ANCHOR..js::PI_NF] != first.public[js::PI_ANCHOR..js::PI_NF]
            {
                return Err("twelve fixture has mixed chains or anchors".into());
            }
        }
        for nf in wallet.public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
            if !nullifiers.insert(nf.iter().map(|v| v.as_canonical_u64()).collect::<Vec<_>>()) {
                return Err("twelve fixture has duplicate nullifiers".into());
            }
        }
        wallets.push(wallet);
    }
    Ok(wallets)
}

pub(super) fn prepare(dir: &Path) -> Result<(), Error> {
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join("scratch"))?;
    println!("twelve_preparation=UNAPPROVED wallets=12 production_ready=false");
    for index in 0..COUNT {
        let wallet = recursive::demo_wallet_twelve(index)?;
        write(&dir.join(format!("wallet.{index}")), WALLET_MAGIC, &wallet)?;
        println!("twelve_fixture_wallet_created index={index}");
    }
    wallets(dir, Some(recursive::DEMO_CHAIN))?;
    Ok(())
}

fn checked_plan(registry: &Registry, wallets: &[WalletProof]) -> Result<Vec<PlannedNode>, Error> {
    let leaves = wallets
        .iter()
        .map(|w| recursive::wallet_summary(registry, w))
        .collect::<Result<Vec<_>, _>>()?;
    plan(&leaves)
}

pub(super) fn describe(dir: &Path) -> Result<(), Error> {
    let registry = read_registry(dir)?;
    let wallets = wallets(dir, Some(recursive::DEMO_CHAIN))?;
    let nodes = checked_plan(&registry, &wallets)?;
    let root = nodes.last().ok_or("missing twelve root")?;
    let root_bytes: Vec<_> = root
        .summary
        .root
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    println!(
        "twelve_expectation {}",
        serde_json::json!({
            "profile": hex(&registry.id()?), "chain": hex(&wallets[0].chain),
            "root": hex(&root_bytes), "level": 4, "count": 12, "capacity": 16,
            "height": registry.height, "fresh_recursive_proofs": nodes.len(),
            "wrappers": 6, "empty_proofs": 1, "merges": 6, "approval": false
        })
    );
    Ok(())
}

fn expected_root(external: ExternalExpected) -> Result<Public, Error> {
    let summary = NodeSummary {
        context: commitment::Context {
            profile_id: external.profile,
            chain_id: external.chain,
        },
        level: 4,
        count: 12,
        root: external.root,
    };
    commitment::validate_summary(summary)?;
    Ok(programs::statement(summary, programs::MERGE))
}

fn child(
    dir: &Path,
    nodes: &[PlannedNode],
    registry: &Registry,
    external: ExternalExpected,
    level: usize,
    index: usize,
) -> Result<NodeProof, Error> {
    let expected = nodes
        .iter()
        .find(|n| n.level == level && n.index == index)
        .ok_or("missing planned twelve child")?;
    let node = read_node(&dir.join(expected.filename()))?;
    registry.verify(external.profile, &node, &expected.public())?;
    Ok(node)
}

pub(super) fn aggregate(
    dir: &Path,
    external: ExternalExpected,
    profiler: Option<&Profiler>,
) -> Result<(), Error> {
    let registry = read_registry(dir)?;
    if registry.id()? != external.profile {
        return Err("twelve registry differs from external profile".into());
    }
    let wallets = wallets(dir, Some(external.chain))?;
    let nodes = checked_plan(&registry, &wallets)?;
    let root = nodes.last().ok_or("missing twelve root")?;
    if root.filename() != ROOT_FILE || root.public() != expected_root(external)? {
        return Err("twelve ordered wallet tree differs from external expected root".into());
    }
    // This measured command never resumes existing proofs.
    for node in &nodes {
        ensure_absent(&dir.join(node.filename()))?;
    }
    let mut session = CONSTRUCTION.session(registry.clone(), external.profile)?;
    for expected in &nodes {
        let started = Instant::now();
        let node = match expected.mode {
            programs::WRAPPER => session.wrap_pair(
                &wallets[2 * expected.index],
                &wallets[2 * expected.index + 1],
            )?,
            programs::EMPTY => session.empty(external.chain, expected.level as u8)?,
            programs::MERGE => {
                let left = child(
                    dir,
                    &nodes,
                    &registry,
                    external,
                    expected.level - 1,
                    2 * expected.index,
                )?;
                let right = child(
                    dir,
                    &nodes,
                    &registry,
                    external,
                    expected.level - 1,
                    2 * expected.index + 1,
                )?;
                session.merge(&left, &right)?
            }
            _ => return Err("invalid twelve plan mode".into()),
        };
        registry.verify(external.profile, &node, &expected.public())?;
        write_node(&dir.join(expected.filename()), &node)?;
        report_node(&expected.filename(), started, false, &session, profiler);
    }
    println!(
        "twelve_aggregation=PROVED wallets=12 wrappers=6 empty_proofs=1 merges=6 fresh_recursive_proofs=13 root_level=4 root_count=12 production_ready=false"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves() -> Vec<NodeSummary> {
        (0..12)
            .map(|i| NodeSummary {
                context: commitment::Context {
                    profile_id: [1; 32],
                    chain_id: [2; 32],
                },
                level: 0,
                count: 1,
                root: [i + 1, 0, 0, 0],
            })
            .collect()
    }

    #[test]
    fn twelve_plan_matches_a_fully_padded_sixteen_leaf_tree() {
        let leaves = leaves();
        let nodes = plan(&leaves).unwrap();
        assert_eq!(nodes.len(), 13);
        for (mode, count) in [
            (programs::WRAPPER, 6),
            (programs::EMPTY, 1),
            (programs::MERGE, 6),
        ] {
            assert_eq!(nodes.iter().filter(|n| n.mode == mode).count(), count);
        }
        let mut padded = leaves.clone();
        padded.resize(16, commitment::empty_subtree(leaves[0].context, 0).unwrap());
        while padded.len() > 1 {
            padded = padded
                .chunks_exact(2)
                .map(|p| commitment::merge_nodes(p[0], p[1]).unwrap())
                .collect();
        }
        let root = nodes.last().unwrap();
        assert_eq!(root.summary, padded[0]);
        assert_eq!(root.filename(), ROOT_FILE);
        assert_eq!((root.summary.level, root.summary.count), (4, 12));
        let mut available = BTreeSet::new();
        for node in nodes {
            if node.mode == programs::MERGE {
                assert!(available.contains(&(node.level - 1, 2 * node.index)));
                assert!(available.contains(&(node.level - 1, 2 * node.index + 1)));
            }
            assert!(available.insert((node.level, node.index)));
        }
    }

    #[test]
    fn twelve_plan_rejects_wrong_counts_contexts_and_binds_order() {
        let leaves = leaves();
        assert!(plan(&leaves[..8]).is_err());
        let mut wrong = leaves.clone();
        wrong[0].context.chain_id[0] ^= 1;
        assert!(plan(&wrong).is_err());
        let original = plan(&leaves).unwrap().last().unwrap().summary;
        let mut reordered = leaves.clone();
        reordered.swap(0, 11);
        assert_ne!(plan(&reordered).unwrap().last().unwrap().summary, original);
        wrong = leaves;
        wrong[0].count = 0;
        assert!(plan(&wrong).is_err());
    }
}
