//! Controlled research runner, not a wallet/network codec or production CLI.
//! Each heavy stage is launched in its own hard memory-limited user service.
use lattica_prover_p3::{
    block_v2::{
        codec, commitment,
        machine::programs,
        perf::Profiler,
        profile,
        recursive::{self, NodeProof, ProverSession, Registry, WalletProof},
    },
    spill_alloc,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io::Read, path::Path, time::Instant};

type Error = recursive::Error;
const WALLET_MAGIC: &[u8; 8] = b"LBV2WL02";

fn write<T: Serialize>(path: &Path, magic: &[u8; 8], value: &T) -> Result<(), Error> {
    let mut bytes = magic.to_vec();
    bytes.extend(postcard::to_allocvec(value)?);
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err("artifact exceeds 2 MiB".into());
    }
    write_new_bytes(path, &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err("artifact exceeds 2 MiB".into());
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Error> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > profile::MAX_PROOF_BYTES as u64 {
        return Err("artifact size/type".into());
    }
    let mut bytes = Vec::new();
    file.take((profile::MAX_PROOF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err("artifact grew beyond limit".into());
    }
    Ok(bytes)
}

fn read<T: DeserializeOwned + Serialize>(path: &Path, magic: &[u8; 8]) -> Result<T, Error> {
    let bytes = read_bounded(path)?;
    if !bytes.starts_with(magic) {
        return Err("artifact envelope".into());
    }
    Ok(codec::decode(&bytes[8..])?)
}

fn write_node(path: &Path, node: &NodeProof) -> Result<(), Error> {
    write_new_bytes(path, &codec::encode_node(node)?)
}

fn read_node(path: &Path) -> Result<NodeProof, Error> {
    Ok(codec::decode_node(&read_bounded(path)?)?)
}

fn read_height(dir: &Path) -> Result<usize, Error> {
    let bytes = fs::read(dir.join("height"))?;
    let height =
        u32::from_le_bytes(bytes.as_slice().try_into().map_err(|_| "height encoding")?) as usize;
    programs::shape(height)?;
    Ok(height)
}

fn read_registry(dir: &Path) -> Result<Registry, Error> {
    let height = read_height(dir)?;
    let mut caps = core::array::from_fn(|_| Vec::new());
    for (i, cap) in caps.iter_mut().enumerate() {
        let bytes = fs::read(dir.join(format!("key.{}", i + 1)))?;
        if bytes.len() != (1 << profile::CAP_HEIGHT) * 32 {
            return Err("key size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut fields = [Val::ZERO; 4];
            for (out, word) in fields.iter_mut().zip(digest.chunks_exact(8)) {
                let value = u64::from_le_bytes(word.try_into().unwrap());
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn profile_arg(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected profile encoding".into());
    }
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

/// Derive every expected demo statement from public wallet artifacts. This also
/// authenticates each wallet proof; no wallet witness is read during resumption.
fn expected_nodes(
    dir: &Path,
    registry: &Registry,
) -> Result<Vec<(String, [Val; programs::PUBLIC_VALUES])>, Error> {
    let mut summaries = Vec::with_capacity(4);
    let mut nodes = Vec::with_capacity(7);
    for i in 0..4 {
        let wallet: WalletProof = read(&dir.join(format!("wallet.{i}")), WALLET_MAGIC)?;
        recursive::verify_wallet(&wallet)?;
        let summary = recursive::wallet_summary(registry, &wallet)?;
        nodes.push((
            format!("node.0.{i}"),
            programs::statement(summary, programs::WRAPPER),
        ));
        summaries.push(summary);
    }
    for level in 1..=2 {
        let mut parents = Vec::with_capacity(summaries.len() / 2);
        for (i, pair) in summaries.chunks_exact(2).enumerate() {
            let parent = commitment::merge_nodes(pair[0], pair[1])?;
            nodes.push((
                format!("node.{level}.{i}"),
                programs::statement(parent, programs::MERGE),
            ));
            parents.push(parent);
        }
        summaries = parents;
    }
    Ok(nodes)
}

fn run(args: &[String], profiler: Option<&Profiler>) -> Result<(), Error> {
    let command = args.first().ok_or("missing command")?;
    let dir = Path::new(args.get(1).ok_or("missing private job directory")?);
    let number = |i: usize| -> Result<usize, Error> {
        Ok(args.get(i).ok_or("missing numeric argument")?.parse()?)
    };
    match command.as_str() {
        "prepare" => {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(dir)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir.join("scratch"))?;
            for i in 0..4 {
                let wallet = recursive::demo_wallet(i)?;
                println!("wallet_verified index={i}");
                if i == 0 {
                    let height = recursive::common_height(&wallet)?;
                    fs::write(dir.join("height"), (height as u32).to_le_bytes())?;
                }
                write(&dir.join(format!("wallet.{i}")), WALLET_MAGIC, &wallet)?;
            }
        }
        "register" => {
            let mode = number(2)? as u64;
            let wallet: WalletProof = read(&dir.join("wallet.0"), WALLET_MAGIC)?;
            let cap = recursive::register(read_height(dir)?, mode, Some(&wallet))?;
            let mut bytes = Vec::new();
            for root in cap {
                for field in root {
                    bytes.extend(field.as_canonical_u64().to_le_bytes());
                }
            }
            fs::write(dir.join(format!("key.{mode}")), bytes)?;
            println!("registered mode={mode}");
        }
        "finish-registry" => {
            let registry = read_registry(dir)?;
            let nodes = expected_nodes(dir, &registry)?;
            let public = &nodes.last().ok_or("missing expected root")?.1;
            write(&dir.join("expected"), b"LBV2ST01", &public)?;
            fs::write(dir.join("profile.hex"), hex(&registry.id()?))?;
            println!(
                "registry_frozen_for_demo profile={} height={}",
                hex(&registry.id()?),
                registry.height
            );
        }
        "check-registered" => {
            let pin = profile_arg(args.get(2).ok_or("missing independently pinned profile")?)?;
            let registry = read_registry(dir)?;
            if registry.id()? != pin {
                return Err("checkpoint registry differs from pinned profile".into());
            }
            let nodes = expected_nodes(dir, &registry)?;
            let expected: [Val; programs::PUBLIC_VALUES] =
                read(&dir.join("expected"), b"LBV2ST01")?;
            if nodes.last().ok_or("missing expected root")?.1 != expected {
                return Err("checkpoint expected root differs from wallet statements".into());
            }
            let mut checked = 0;
            for (filename, public) in nodes {
                let path = dir.join(filename);
                if path.try_exists()? {
                    let node: NodeProof = read_node(&path)?;
                    registry.verify(pin, &node, &public)?;
                    checked += 1;
                }
            }
            println!("registered_checkpoint=PASS wallets=4 existing_nodes_verified={checked}");
        }
        "wrap" => {
            let index = number(2)?;
            if index >= 4 {
                return Err("wallet index".into());
            }
            let wallet: WalletProof = read(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
            let node = recursive::wrap(&read_registry(dir)?, &wallet)?;
            write_node(&dir.join(format!("node.0.{index}")), &node)?;
        }
        "wrap-all" => {
            let pin = profile_arg(args.get(2).ok_or("missing independently pinned profile")?)?;
            let registry = read_registry(dir)?;
            let mut session = ProverSession::new(registry.clone(), pin)?;
            for index in 0..4 {
                let started = Instant::now();
                let wallet: WalletProof = read(&dir.join(format!("wallet.{index}")), WALLET_MAGIC)?;
                let name = format!("node.0.{index}");
                let path = dir.join(&name);
                if path.try_exists()? {
                    let node: NodeProof = read_node(&path)?;
                    let expected = programs::statement(recursive::wallet_summary(&registry, &wallet)?, programs::WRAPPER);
                    registry.verify(pin, &node, &expected)?;
                } else {
                    let node = session.wrap(&wallet)?;
                    write_node(&path, &node)?;
                }
                println!("cached_node_complete artifact={name} elapsed_ms={} setups={} cache_hits={}", started.elapsed().as_millis(), session.stats().setups, session.stats().hits);
                if let Some(profiler) = profiler { profiler.report(&name); }
                #[cfg(feature = "gpu")]
                lattica_prover_p3::block_v2::gpu_hash::report(&name);
            }
        }
        "merge" => {
            let level = number(2)?;
            let index = number(3)?;
            if !(1..=2).contains(&level) || index >= (4 >> level) {
                return Err("demo merge coordinates".into());
            }
            let left: NodeProof = read_node(
                &dir.join(format!("node.{}.{}", level - 1, 2 * index)),
            )?;
            let right: NodeProof = read_node(
                &dir.join(format!("node.{}.{}", level - 1, 2 * index + 1)),
            )?;
            let node = recursive::merge(&read_registry(dir)?, &left, &right)?;
            write_node(
                &dir.join(format!("node.{level}.{index}")),
                &node,
            )?;
        }
        "merge-all" => {
            let pin = profile_arg(args.get(2).ok_or("missing independently pinned profile")?)?;
            let registry = read_registry(dir)?;
            let mut session = ProverSession::new(registry.clone(), pin)?;
            for level in 1..=2 {
                for index in 0..(4 >> level) {
                    let started = Instant::now();
                    let left: NodeProof = read_node(&dir.join(format!("node.{}.{}", level - 1, 2 * index)))?;
                    let right: NodeProof = read_node(&dir.join(format!("node.{}.{}", level - 1, 2 * index + 1)))?;
                    let name = format!("node.{level}.{index}");
                    let path = dir.join(&name);
                    if path.try_exists()? {
                        registry.verify(pin, &left, &left.public)?;
                        registry.verify(pin, &right, &right.public)?;
                        let expected = programs::statement(commitment::merge_nodes(recursive::summary(&left.public)?, recursive::summary(&right.public)?)?, programs::MERGE);
                        let node: NodeProof = read_node(&path)?;
                        registry.verify(pin, &node, &expected)?;
                    } else {
                        let node = session.merge(&left, &right)?;
                        write_node(&path, &node)?;
                    }
                    println!("cached_node_complete artifact={name} elapsed_ms={} setups={} cache_hits={}", started.elapsed().as_millis(), session.stats().setups, session.stats().hits);
                    if let Some(profiler) = profiler { profiler.report(&name); }
                    #[cfg(feature = "gpu")]
                    lattica_prover_p3::block_v2::gpu_hash::report(&name);
                }
            }
        }
        "remove-inners" => {
            for i in 0..4 {
                fs::remove_file(dir.join(format!("wallet.{i}")))?;
                fs::remove_file(dir.join(format!("node.0.{i}")))?;
            }
            for i in 0..2 {
                fs::remove_file(dir.join(format!("node.1.{i}")))?;
            }
            println!("inner_proof_artifacts_removed=10");
        }
        "verify-root" => {
            let expected_profile =
                profile_arg(args.get(2).ok_or("missing independently pinned profile")?)?;
            let registry = read_registry(dir)?;
            let expected: [Val; programs::PUBLIC_VALUES] =
                read(&dir.join("expected"), b"LBV2ST01")?;
            let node: NodeProof = read_node(&dir.join("node.2.0"))?;
            if expected[programs::LEVEL] != Val::from_u64(2)
                || expected[programs::COUNT] != Val::from_u64(4)
                || expected[programs::MODE] != Val::from_u64(programs::MERGE)
            {
                return Err("not the expected two-level/four-wallet statement".into());
            }
            registry.verify(expected_profile, &node, &expected)?;
            for i in [
                0,
                8,
                programs::MODE,
                programs::LEVEL,
                programs::COUNT,
                programs::ROOT,
            ] {
                let mut wrong = expected;
                wrong[i] += Val::ONE;
                if registry.verify(expected_profile, &node, &wrong).is_ok() {
                    return Err("accepted altered expected statement".into());
                }
            }
            let mut wrong_profile = expected_profile;
            wrong_profile[0] ^= 1;
            if registry.verify(wrong_profile, &node, &expected).is_ok() {
                return Err("accepted substituted registry".into());
            }
            let mut node = node;
            node.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
            if registry.verify(expected_profile, &node, &expected).is_ok() {
                return Err("accepted altered proof".into());
            }
            println!("two_level_recursive_verification=PASS inner_proofs_loaded=0 count=4 level=2 full_tree_security=UNREVIEWED production_ready=false");
        }
        _ => return Err(
            "commands: prepare, register, finish-registry, check-registered, wrap, wrap-all, merge, merge-all, remove-inners, verify-root"
                .into(),
        ),
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
    let started = Instant::now();
    let _spill = spill_alloc::SpillScope::arm();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let gpu_requested = match std::env::var("LATTICA_V2_GPU_HASH") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(v) if v == "0" => false,
        Ok(v) if v == "1" => true,
        _ => {
            eprintln!("FAILED: LATTICA_V2_GPU_HASH must be 0 or 1");
            std::process::exit(1);
        }
    };
    let resident_requested = match std::env::var("LATTICA_V2_GPU_RESIDENT_LDE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(v) if v == "0" => false,
        Ok(v) if v == "1" => true,
        _ => {
            eprintln!("FAILED: LATTICA_V2_GPU_RESIDENT_LDE must be 0 or 1");
            std::process::exit(1);
        }
    };
    let proving = args.first().is_some_and(|command| {
        matches!(
            command.as_str(),
            "prepare" | "register" | "wrap" | "wrap-all" | "merge" | "merge-all"
        )
    });
    if resident_requested && proving && !gpu_requested {
        eprintln!("FAILED: resident LDE proving requires LATTICA_V2_GPU_HASH=1");
        std::process::exit(1);
    }
    #[cfg(feature = "gpu")]
    if gpu_requested && proving {
        if let Err(error) = lattica_prover_p3::block_v2::gpu_hash::initialize_from_env() {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    }
    #[cfg(feature = "gpu")]
    if proving {
        match lattica_prover_p3::block_v2::gpu_hash::initialize_resident_from_env() {
            Ok(enabled) => {
                println!("resident_lde_research enabled={enabled} production_ready=false")
            }
            Err(error) => {
                eprintln!("FAILED: {error}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(feature = "gpu"))]
    if gpu_requested && proving {
        eprintln!("FAILED: LATTICA_V2_GPU_HASH requires the gpu feature");
        std::process::exit(1);
    }
    let profiler = match Profiler::from_env() {
        Ok(profiler) => profiler,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    };
    let result = run(&args, profiler.as_ref());
    if let Some(profiler) = &profiler {
        profiler.report("process remainder");
    }
    #[cfg(feature = "gpu")]
    lattica_prover_p3::block_v2::gpu_hash::report("process remainder");
    #[cfg(feature = "gpu")]
    if let Err(error) = lattica_prover_p3::block_v2::gpu_hash::shutdown() {
        eprintln!("FAILED: GPU shutdown: {error}");
        std::process::exit(1);
    }
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let rss = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap_or("VmHWM: unavailable");
    println!(
        "stage_elapsed_ms={} spill_peak_bytes={} {rss}",
        started.elapsed().as_millis(),
        spill_alloc::spill_peak_bytes()
    );
    if let Err(error) = result {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}
