//! CPU-only research: pad a verified level-three/count-eight subtree to level six.
//! Public proofs only. External profile, chain, source root and padded root are mandatory.
//! This is not full-count, mixed-transaction, deadline or production qualification.
//! Run heavy commands only inside the exclusive bounded research controller.
use lattica_prover_p3::{
    block_v2::{
        codec,
        commitment::{self, Context, NodeSummary},
        machine::programs,
        perf::Profiler,
        profile,
        recursive::{self, ConstructionSession, NodeProof, Registry, WrapperConstruction},
    },
    spill_alloc,
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
type Error = recursive::Error;
type Public = [Val; programs::PUBLIC_VALUES];
const ROOT_FILE: &str = "node.6.0";
const INNER_FILES: [&str; 6] = [
    "node.3.0", "empty.3", "empty.4", "empty.5", "node.4.0", "node.5.0",
];
const USAGE: &str = "block-v2-padding-probe (check|empty-all|merge-all|verify-root|remove-inners) DIR EXTERNAL_PROFILE EXTERNAL_CHAIN EXTERNAL_LEVEL3_ROOT EXTERNAL_PADDED_ROOT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Check,
    Empties,
    Merges,
    Verify,
    Prune,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct External {
    profile: [u8; 32],
    chain: [u8; 32],
    source_root: commitment::Digest,
    padded_root: commitment::Digest,
}
#[derive(Debug)]
struct Command {
    action: Action,
    dir: PathBuf,
    external: External,
}

fn parse_hex(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected exactly 64 ASCII hexadecimal characters".into());
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}
fn parse_command(args: &[String]) -> Result<Command, Error> {
    if args.len() != 6 {
        return Err(USAGE.into());
    }
    let action = match args[0].as_str() {
        "check" => Action::Check,
        "empty-all" => Action::Empties,
        "merge-all" => Action::Merges,
        "verify-root" => Action::Verify,
        "remove-inners" => Action::Prune,
        _ => return Err(USAGE.into()),
    };
    let external = External {
        profile: parse_hex(&args[2])?,
        chain: parse_hex(&args[3])?,
        source_root: commitment::digest_from_bytes(&parse_hex(&args[4])?)?,
        padded_root: commitment::digest_from_bytes(&parse_hex(&args[5])?)?,
    };
    // Reject inconsistent external expectations before any directory read or allocation.
    external.nodes()?;
    Ok(Command {
        action,
        dir: PathBuf::from(&args[1]),
        external,
    })
}
impl External {
    fn context(self) -> Context {
        Context {
            profile_id: self.profile,
            chain_id: self.chain,
        }
    }
    fn nodes(self) -> Result<[NodeSummary; 4], Error> {
        let source = NodeSummary {
            context: self.context(),
            level: 3,
            count: 8,
            root: self.source_root,
        };
        commitment::validate_summary(source)?;
        let mut nodes = [source; 4];
        for i in 0..3 {
            let empty = commitment::empty_subtree(self.context(), nodes[i].level)?;
            nodes[i + 1] = commitment::merge_nodes(nodes[i], empty)?;
        }
        if nodes[3].root != self.padded_root || nodes[3].level != 6 || nodes[3].count != 8 {
            return Err(
                "external padded root differs from ordered source-plus-empty commitment".into(),
            );
        }
        Ok(nodes)
    }
    fn empty_public(self, level: u8) -> Result<Public, Error> {
        if !(3..=5).contains(&level) {
            return Err("unsupported padding level".into());
        }
        Ok(programs::statement(
            commitment::empty_subtree(self.context(), level)?,
            programs::EMPTY,
        ))
    }
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("artifact is not a regular nonsymlink file".into());
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
fn ensure_absent(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err("refusing to overwrite or implicitly retry an existing output".into()),
    }
}
fn write_node(path: &Path, node: &NodeProof) -> Result<(), Error> {
    let bytes = codec::encode_node(node)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("artifact has no parent")?)?.sync_all()?;
    Ok(())
}
fn validate_directory(dir: &Path, root_only: bool) -> Result<(), Error> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err("job must be a private nonsymlink directory".into());
    }
    let mut allowed: BTreeSet<&str> = ["height", "key.1", "key.2", "key.3", ROOT_FILE]
        .into_iter()
        .collect();
    if !root_only {
        allowed.extend(INNER_FILES);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("non-UTF8 artifact name")?;
        if name == "scratch" {
            if !entry.file_type()?.is_dir()
                || entry.metadata()?.permissions().mode() & 0o077 != 0
                || fs::read_dir(entry.path())?.next().is_some()
            {
                return Err(
                    "scratch must be a private empty nonsymlink directory between stages".into(),
                );
            }
        } else if !allowed.contains(name) || !entry.file_type()?.is_file() {
            return Err("unexpected or nonregular job artifact".into());
        }
    }
    Ok(())
}
fn registry(dir: &Path, external: External) -> Result<Registry, Error> {
    let bytes = read_bounded(&dir.join("height"), 4)?;
    let height = u32::from_le_bytes(bytes.as_slice().try_into()?) as usize;
    // Only the already-admitted common heights; this tool does not approve new geometry.
    let admitted = if cfg!(feature = "block-v2-wide-lanes") {
        1 << 18
    } else {
        1 << 19
    };
    if height != admitted {
        return Err("height differs from selected research construction".into());
    }
    let cap_bytes = (1 << profile::CAP_HEIGHT) * 32;
    let mut caps = core::array::from_fn(|_| Vec::new());
    for (index, cap) in caps.iter_mut().enumerate() {
        let bytes = read_bounded(&dir.join(format!("key.{}", index + 1)), cap_bytes)?;
        if bytes.len() != cap_bytes {
            return Err("key size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut fields = [Val::ZERO; 4];
            for (field, bytes) in fields.iter_mut().zip(digest.chunks_exact(8)) {
                let value = u64::from_le_bytes(bytes.try_into()?);
                if value >= commitment::MODULUS {
                    return Err("noncanonical key".into());
                }
                *field = Val::from_u64(value);
            }
            cap.push(fields);
        }
    }
    let registry = Registry { height, caps };
    if registry.id()? != external.profile {
        return Err("registry differs from external profile".into());
    }
    Ok(registry)
}
fn verified_node(
    dir: &Path,
    file: &str,
    registry: &Registry,
    external: External,
    public: &Public,
) -> Result<NodeProof, Error> {
    let node = codec::decode_node(&read_bounded(&dir.join(file), profile::MAX_PROOF_BYTES)?)?;
    registry.verify(external.profile, &node, public)?;
    Ok(node)
}
fn verify_root(dir: &Path, registry: &Registry, external: External) -> Result<(), Error> {
    let nodes = external.nodes()?;
    verified_node(
        dir,
        ROOT_FILE,
        registry,
        external,
        &programs::statement(nodes[3], programs::MERGE),
    )?;
    Ok(())
}
fn report(
    file: &str,
    started: Instant,
    session: &ConstructionSession,
    profiler: Option<&Profiler>,
) {
    println!("padding_node_complete artifact={file} elapsed_ms={} setups={} cache_hits={} production_ready=false",
        started.elapsed().as_millis(), session.stats().setups, session.stats().hits);
    if let Some(profiler) = profiler {
        profiler.report(file);
    }
}
fn run(command: Command, profiler: Option<&Profiler>) -> Result<(), Error> {
    let Command {
        action,
        dir,
        external,
    } = command;
    validate_directory(&dir, action == Action::Verify)?;
    let nodes = external.nodes()?;
    let registry = registry(&dir, external)?;
    if matches!(action, Action::Verify | Action::Prune) {
        verify_root(&dir, &registry, external)?;
        if action == Action::Prune {
            let mut removed = 0;
            for name in INNER_FILES {
                let path = dir.join(name);
                match fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_file() => {
                        fs::remove_file(path)?;
                        removed += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err("prune encountered unexpected artifact".into()),
                }
            }
            fs::File::open(&dir)?.sync_all()?;
            validate_directory(&dir, true)?;
            verify_root(&dir, &registry, external)?;
            println!(
                "padding_inner_artifacts_removed={removed} pruning_does_not_approve_profile=true"
            );
        }
        println!("padding_root_verification=PASS level=6 count=8 inner_proofs_loaded=0 full_count_qualified=false full_tree_security=UNREVIEWED production_ready=false");
        return Ok(());
    }
    let mut left = verified_node(
        &dir,
        "node.3.0",
        &registry,
        external,
        &programs::statement(nodes[0], programs::MERGE),
    )?;
    if action == Action::Check {
        println!(
            "padding_input_check=PASS source_level=3 target_level=6 count=8 production_ready=false"
        );
        return Ok(());
    }
    let outputs: Vec<String> = match action {
        Action::Empties => (3..=5).map(|level| format!("empty.{level}")).collect(),
        Action::Merges => (4..=6).map(|level| format!("node.{level}.0")).collect(),
        _ => unreachable!(),
    };
    for name in &outputs {
        ensure_absent(&dir.join(name))?;
    }
    if action == Action::Merges {
        // Check every child before starting expensive work.
        for level in 3..=5 {
            verified_node(
                &dir,
                &format!("empty.{level}"),
                &registry,
                external,
                &external.empty_public(level)?,
            )?;
        }
    }
    let mut session = ConstructionSession::new(
        WrapperConstruction::GroupedPair,
        registry.clone(),
        external.profile,
    )?;
    for (index, file) in outputs.iter().enumerate() {
        let level = 3 + index as u8;
        let started = Instant::now();
        let node = if action == Action::Empties {
            session.empty(external.chain, level)?
        } else {
            let right = verified_node(
                &dir,
                &format!("empty.{level}"),
                &registry,
                external,
                &external.empty_public(level)?,
            )?;
            session.merge(&left, &right)?
        };
        let expected = if action == Action::Empties {
            external.empty_public(level)?
        } else {
            programs::statement(nodes[index + 1], programs::MERGE)
        };
        registry.verify(external.profile, &node, &expected)?;
        write_node(&dir.join(file), &node)?;
        report(file, started, &session, profiler);
        if action == Action::Merges {
            left = node;
        }
    }
    Ok(())
}
fn main() {
    let result = (|| -> Result<(), Error> {
        if cfg!(feature = "gpu") {
            return Err("padding research requires a CPU-only build".into());
        }
        if lattica_prover_p3::block_v2::quotient_pcs::initialize_research_from_env()? {
            return Err("padding baseline requires quotient fusion disabled".into());
        }
        if std::env::var("LATTICA_V2_GPU_HASH").is_ok_and(|s| s != "0") {
            return Err("padding baseline requires GPU hashing disabled".into());
        }
        let command = parse_command(&std::env::args().skip(1).collect::<Vec<_>>())?;
        let started = Instant::now();
        let _spill = spill_alloc::SpillScope::arm();
        let profiler = Profiler::from_env()?;
        let result = run(command, profiler.as_ref());
        if let Some(profiler) = profiler {
            profiler.report("padding process remainder");
        }
        println!(
            "padding_stage_elapsed_ms={} spill_peak_bytes={}",
            started.elapsed().as_millis(),
            spill_alloc::spill_peak_bytes()
        );
        result
    })();
    if let Err(error) = result {
        eprintln!("padding_probe=FAIL error={error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    fn fixture() -> External {
        let mut e = External {
            profile: [0x11; 32],
            chain: [0x22; 32],
            source_root: [1, 2, 3, 4],
            padded_root: [0; 4],
        };
        let mut summary = NodeSummary {
            context: e.context(),
            level: 3,
            count: 8,
            root: e.source_root,
        };
        while summary.level < 6 {
            summary = commitment::merge_nodes(
                summary,
                commitment::empty_subtree(e.context(), summary.level).unwrap(),
            )
            .unwrap();
        }
        e.padded_root = summary.root;
        e
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn args(action: &str) -> Vec<String> {
        let e = fixture();
        vec![
            action.into(),
            "job".into(),
            hex(&e.profile),
            hex(&e.chain),
            hex(&commitment::digest_bytes(e.source_root).unwrap()),
            hex(&commitment::digest_bytes(e.padded_root).unwrap()),
        ]
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "lattica-padding-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn all_actions_require_exact_external_inputs_and_no_implicit_defaults() {
        for action in [
            "check",
            "empty-all",
            "merge-all",
            "verify-root",
            "remove-inners",
        ] {
            let valid = args(action);
            assert!(parse_command(&valid).is_ok());
            for length in 0..6 {
                assert!(parse_command(&valid[..length]).is_err());
            }
            let mut extra = valid.clone();
            extra.push("witness".into());
            assert!(parse_command(&extra).is_err());
        }
        assert!(parse_command(&args("prove")).is_err());
    }
    #[test]
    fn all_external_fields_bind_padded_expectation_before_io() {
        for index in 2..=5 {
            let mut changed = args("check");
            let replacement = if changed[index].starts_with('0') {
                "1"
            } else {
                "0"
            };
            changed[index].replace_range(..1, replacement);
            assert!(parse_command(&changed).is_err());
        }
        let e = fixture();
        let nodes = e.nodes().unwrap();
        assert_eq!(nodes.map(|n| n.level), [3, 4, 5, 6]);
        assert_eq!(nodes.map(|n| n.count), [8; 4]);
        assert_ne!(nodes[0].root, nodes[3].root);
    }
    #[test]
    fn canonical_roots_and_exact_hex_are_required() {
        assert!(parse_hex("00").is_err());
        assert!(parse_hex(&"é".repeat(32)).is_err());
        let mut noncanonical = args("check");
        let bytes = commitment::MODULUS.to_le_bytes().repeat(4);
        noncanonical[4] = hex(&bytes);
        assert!(parse_command(&noncanonical).is_err());
        assert!(parse_hex(&"ff".repeat(32)).is_ok()); // Context bytes are not field limbs.
    }
    #[test]
    fn empty_statements_have_zero_count_and_fixed_level() {
        let e = fixture();
        for level in 3..=5 {
            let expected = programs::statement(
                commitment::empty_subtree(e.context(), level).unwrap(),
                programs::EMPTY,
            );
            assert_eq!(e.empty_public(level).unwrap(), expected);
        }
        assert!(e.empty_public(2).is_err());
        assert!(e.empty_public(6).is_err());
    }
    #[test]
    fn outputs_are_never_overwritten_or_implicitly_retried() {
        let temp = Temp::new();
        let path = temp.0.join("empty.3");
        assert!(ensure_absent(&path).is_ok());
        fs::write(&path, b"partial").unwrap();
        assert!(ensure_absent(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"partial");
    }
    #[test]
    fn directories_enforce_private_exact_regular_artifacts() {
        let temp = Temp::new();
        assert!(validate_directory(&temp.0, false).is_ok());
        fs::write(temp.0.join("node.3.0"), b"seed").unwrap();
        assert!(validate_directory(&temp.0, false).is_ok());
        assert!(validate_directory(&temp.0, true).is_err());
        fs::remove_file(temp.0.join("node.3.0")).unwrap();
        fs::write(temp.0.join("profile.hex"), b"untrusted").unwrap();
        assert!(validate_directory(&temp.0, false).is_err());
        fs::remove_file(temp.0.join("profile.hex")).unwrap();
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_directory(&temp.0, false).is_err());
    }
    #[test]
    fn bounded_reads_reject_oversize_symlink_and_nonregular_files() {
        let temp = Temp::new();
        let file = temp.0.join("height");
        fs::write(&file, [0u8; 5]).unwrap();
        assert!(read_bounded(&file, 4).is_err());
        assert!(read_bounded(&temp.0, 4).is_err());
        std::os::unix::fs::symlink(&file, temp.0.join("key.1")).unwrap();
        assert!(read_bounded(&temp.0.join("key.1"), 100).is_err());
        assert!(validate_directory(&temp.0, false).is_err());
    }
    #[test]
    fn wrong_geometry_and_truncated_height_fail_before_key_read() {
        let temp = Temp::new();
        fs::write(temp.0.join("height"), 8u32.to_le_bytes()).unwrap();
        assert!(registry(&temp.0, fixture()).is_err());
        fs::write(temp.0.join("height"), [0u8; 3]).unwrap();
        assert!(registry(&temp.0, fixture()).is_err());
    }
}
