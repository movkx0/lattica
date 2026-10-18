//! Four public wallet proofs -> two pair wrappers -> one level-two root.
//! Fixed existing grouped-pair circuit, unchanged height and security profile.
use super::*;

fn wallets(dir: &Path, chain: Option<[u8; 32]>) -> Result<Vec<WalletProof>, Error> {
    let names: BTreeSet<_> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .filter(|n| n.starts_with("wallet."))
        .collect();
    if names != (0..4).map(|i| format!("wallet.{i}")).collect() {
        return Err("four fixture has a missing or extra wallet artifact".into());
    }
    let mut wallets: Vec<WalletProof> = Vec::with_capacity(4);
    let mut nullifiers = BTreeSet::new();
    for index in 0..4 {
        let wallet: WalletProof = read(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
        recursive::verify_wallet(&wallet)?;
        if chain.is_some_and(|value| value != wallet.chain)
            || wallet.public[js::PI_MINT] != Val::ZERO
        {
            return Err("four fixture chain or issuance mismatch".into());
        }
        if let Some(first) = wallets.first() {
            if wallet.chain != first.chain
                || wallet.public[js::PI_ANCHOR..js::PI_NF] != first.public[js::PI_ANCHOR..js::PI_NF]
            {
                return Err("four fixture has mixed chains or anchors".into());
            }
        }
        for nf in wallet.public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
            if !nullifiers.insert(nf.iter().map(|v| v.as_canonical_u64()).collect::<Vec<_>>()) {
                return Err("four fixture has duplicate nullifiers".into());
            }
        }
        wallets.push(wallet);
    }
    Ok(wallets)
}

fn plan(registry: &Registry, wallets: &[WalletProof]) -> Result<Vec<NodeSummary>, Error> {
    if wallets.len() != 4 {
        return Err("four-input wallet count".into());
    }
    let leaves = wallets
        .iter()
        .map(|w| recursive::wallet_summary(registry, w))
        .collect::<Result<Vec<_>, _>>()?;
    let left = commitment::merge_nodes(leaves[0], leaves[1])?;
    let right = commitment::merge_nodes(leaves[2], leaves[3])?;
    Ok(vec![left, right, commitment::merge_nodes(left, right)?])
}
fn expected_root(e: ExternalExpected) -> Result<Public, Error> {
    let summary = NodeSummary {
        context: Context {
            profile_id: e.profile,
            chain_id: e.chain,
        },
        level: 2,
        count: 4,
        root: e.root,
    };
    commitment::validate_summary(summary)?;
    Ok(programs::statement(summary, programs::MERGE))
}
pub(super) fn describe(dir: &Path) -> Result<(), Error> {
    let registry = read_registry(dir)?;
    let wallets = wallets(dir, None)?;
    let nodes = plan(&registry, &wallets)?;
    println!(
        "four_expectation {}",
        serde_json::json!({"profile":hex(&registry.id()?),"chain":hex(&wallets[0].chain),
        "root":hex(&commitment::digest_bytes(nodes[2].root)?),"count":4,"level":2,"height":registry.height,
        "fresh_recursive_proofs":3,"wrappers":2,"merges":1,"production_ready":false})
    );
    Ok(())
}
pub(super) fn aggregate(
    dir: &Path,
    external: ExternalExpected,
    profiler: Option<&Profiler>,
) -> Result<(), Error> {
    let registry = pinned_registry(dir, external)?;
    let wallets = wallets(dir, Some(external.chain))?;
    let nodes = plan(&registry, &wallets)?;
    if programs::statement(nodes[2], programs::MERGE) != expected_root(external)? {
        return Err("four-input ordered wallet root differs from external expectation".into());
    }
    if fs::read_dir(dir)?
        .any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("node.")))
    {
        return Err("four-input benchmark requires a fresh proof directory".into());
    }
    let mut session = ConstructionSession::new_with_memory_budget(CONSTRUCTION, registry.clone(), external.profile, 32u64 << 30)?;
    let mut children = Vec::new();
    for index in 0..2 {
        let start = Instant::now();
        let name = format!("node.1.{index}");
        let node = session.wrap_pair(&wallets[2 * index], &wallets[2 * index + 1])?;
        registry.verify(
            external.profile,
            &node,
            &programs::statement(nodes[index], programs::WRAPPER),
        )?;
        write_node(&dir.join(&name), &node)?;
        report_node(&name, start, false, &session, profiler);
        children.push(node);
    }
    let start = Instant::now();
    let root = session.merge(&children[0], &children[1])?;
    registry.verify(external.profile, &root, &expected_root(external)?)?;
    write_node(&dir.join("node.2.0"), &root)?;
    report_node("node.2.0", start, false, &session, profiler);
    println!("four_aggregation=PROVED wallets=4 wrappers=2 merges=1 fresh_recursive_proofs=3 root_level=2 root_count=4 production_ready=false");
    Ok(())
}
pub(super) fn verify_root(dir: &Path, external: ExternalExpected) -> Result<(), Error> {
    let names = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let required = ["height", "key.1", "key.2", "key.3", "node.2.0"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if names != required {
        return Err(
            "four-input CPU audit requires exactly the registry and root; no inner artifacts"
                .into(),
        );
    }
    let registry = pinned_registry(dir, external)?;
    registry.verify(
        external.profile,
        &read_node(&dir.join("node.2.0"))?,
        &expected_root(external)?,
    )?;
    println!("four_root_audit=PASS count=4 level=2 external_statement_checked=true root_only=true production_ready=false");
    Ok(())
}
