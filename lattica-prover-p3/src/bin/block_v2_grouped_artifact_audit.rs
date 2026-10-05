//! Research grouped-eight CPU root auditor; not an independent security audit.
//! Separate from the unchanged four-wallet/level-two audit gate.
//! Only a level-three/count-eight subtree is demonstrated by this gate; this
//! does not qualify a level-six production block or approve a registry.
//! The profile, chain and ordered expected root MUST come from trusted external
//! inputs, never from this bundle or the proof's own public statement.
use lattica_prover_p3::block_v2::{
    codec, commitment,
    machine::{backend::RegisteredVerifier, programs},
    profile,
    recursive::{self, NodeProof, Registry},
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_symmetric::MerkleCap;
use std::{collections::BTreeSet, fs, io::Read, path::Path, time::Instant};

type Error = recursive::Error;

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    // Private frozen research bundles only. This rejects ordinary symlink and
    // nonregular inputs, but is not a hostile concurrent-filesystem sandbox.
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.len() > limit as u64 {
        return Err("artifact type/size".into());
    }
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("artifact type/size".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("artifact grew beyond limit".into());
    }
    Ok(bytes)
}

fn registry(dir: &Path) -> Result<Registry, Error> {
    let height = read_bounded(&dir.join("height"), 4)?;
    let height = u32::from_le_bytes(height.as_slice().try_into()?) as usize;
    // Bound geometry before constructing any verifier state.
    if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
        return Err("artifact height".into());
    }
    let mut caps = core::array::from_fn(|_| Vec::new());
    let length = (1 << profile::CAP_HEIGHT) * 32;
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

fn parse_profile(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected 64 hexadecimal profile characters".into());
    }
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

// These calls intentionally bypass Registry::verify's metadata comparison.
// They must fail at the native cryptographic verifier, not merely because the
// external expected statement differs from the artifact's public-value copy.
fn native_binding_checks(verifier: &RegisteredVerifier, node: &NodeProof) -> Result<usize, Error> {
    verifier.verify(&node.proof, &node.public)?;
    for slot in 0..programs::PUBLIC_VALUES {
        let mut wrong = node.public;
        wrong[slot] += Val::ONE;
        if verifier.verify(&node.proof, &wrong).is_ok() {
            return Err(format!("native verifier accepted changed public slot {slot}").into());
        }
    }
    let bytes = postcard::to_allocvec(node)?;
    const MUTATIONS: usize = 14;
    for mutation in 0..MUTATIONS {
        let mut wrong: NodeProof = codec::decode(&bytes)?;
        let p = &mut wrong.proof;
        let opened = &mut p.opened_values.instances[0];
        match mutation {
            0 => opened.base_opened_values.trace_local[0] += profile::Challenge::ONE,
            1 => {
                opened
                    .base_opened_values
                    .preprocessed_local
                    .as_mut()
                    .unwrap()[0] += profile::Challenge::ONE
            }
            2 => opened.base_opened_values.quotient_chunks[0][0] += profile::Challenge::ONE,
            3 => opened.permutation_local[0] += profile::Challenge::ONE,
            4 => opened.permutation_next[0] += profile::Challenge::ONE,
            5 => opened.base_opened_values.random.as_mut().unwrap()[0] += profile::Challenge::ONE,
            6 => p.opening_proof.0[0][0][0][0] += profile::Challenge::ONE,
            7 => p.opening_proof.1.final_poly[0] += profile::Challenge::ONE,
            8 => {
                p.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values[0] +=
                    profile::Challenge::ONE
            }
            9 => p.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE,
            10 => {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .1[0][0] += Val::ONE
            }
            11 => p.lookup_terminals[0].as_mut().unwrap().0 += profile::Challenge::ONE,
            12 => p.degree_bits[0] += 1,
            13 => {
                let mut roots = p.commitments.main.roots().to_vec();
                roots[0][0] += Val::ONE;
                p.commitments.main = MerkleCap::new(roots);
            }
            _ => unreachable!(),
        }
        if verifier.verify(p, &node.public).is_ok() {
            return Err(format!("native verifier accepted proof mutation {mutation}").into());
        }
    }
    Ok(programs::PUBLIC_VALUES + MUTATIONS)
}

const ROOT_FILE: &str = "node.3.0";
const BUNDLE_FILES: [&str; 5] = [ROOT_FILE, "height", "key.1", "key.2", "key.3"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootKind {
    SubtreeEight,
    PaddedEight,
}

impl RootKind {
    fn parse(command: &str) -> Result<Self, Error> {
        match command {
            "root-eight" => Ok(Self::SubtreeEight),
            "root-padded-eight" => Ok(Self::PaddedEight),
            _ => Err("unsupported externally selected root kind".into()),
        }
    }
    fn file(self) -> &'static str {
        match self {
            Self::SubtreeEight => ROOT_FILE,
            Self::PaddedEight => "node.6.0",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::SubtreeEight => "level3-count8-subtree",
            Self::PaddedEight => "level6-count8-padded",
        }
    }
    fn require_bundle(self, dir: &Path) -> Result<(), Error> {
        match self {
            Self::SubtreeEight => require_root_bundle(dir),
            Self::PaddedEight => require_root_bundle_with_name(dir, self.file()),
        }
    }
    fn expected(
        self,
        pinned: [u8; 32],
        chain: [u8; 32],
        root: commitment::Digest,
    ) -> Result<[Val; programs::PUBLIC_VALUES], Error> {
        match self {
            Self::SubtreeEight => trusted_expected(pinned, chain, root),
            Self::PaddedEight => trusted_expected_at(pinned, chain, root, 6),
        }
    }
}

/// This deliberately excludes even profile.hex/expected files: all acceptance
/// context is supplied by the caller, outside this root-only artifact bundle.
fn require_root_bundle(dir: &Path) -> Result<(), Error> {
    require_root_bundle_with_name(dir, ROOT_FILE)
}

fn require_root_bundle_with_name(dir: &Path, root_file: &str) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.file_type().is_dir() {
        return Err("root-only bundle is not a regular directory".into());
    }
    let mut names = BUNDLE_FILES;
    names[0] = root_file;
    let expected: BTreeSet<String> = names.iter().map(|name| (*name).to_owned()).collect();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 bundle entry")?;
        if !expected.contains(&name) || !entry.file_type()?.is_file() || !actual.insert(name) {
            return Err("unexpected or nonregular root-only bundle entry".into());
        }
    }
    if actual != expected {
        return Err("incomplete root-only bundle".into());
    }
    Ok(())
}

fn trusted_expected(
    pinned: [u8; 32],
    chain: [u8; 32],
    root: commitment::Digest,
) -> Result<[Val; programs::PUBLIC_VALUES], Error> {
    trusted_expected_at(pinned, chain, root, 3)
}

fn trusted_expected_at(
    pinned: [u8; 32],
    chain: [u8; 32],
    root: commitment::Digest,
    level: u8,
) -> Result<[Val; programs::PUBLIC_VALUES], Error> {
    let node = commitment::NodeSummary {
        context: commitment::Context {
            profile_id: pinned,
            chain_id: chain,
        },
        level,
        count: 8,
        root,
    };
    commitment::validate_summary(node)?;
    Ok(programs::statement(node, programs::MERGE))
}

fn parse_root(value: &str) -> Result<commitment::Digest, Error> {
    // The hexadecimal string represents the four canonical LE-u64 root limbs.
    Ok(commitment::digest_from_bytes(&parse_profile(value)?)?)
}

fn audit_root(
    kind: RootKind,
    dir: &Path,
    pinned: [u8; 32],
    chain: [u8; 32],
    root: commitment::Digest,
) -> Result<(), Error> {
    kind.require_bundle(dir)?;
    let expected = kind.expected(pinned, chain, root)?;
    let registry = registry(dir)?;
    let bytes = read_bounded(&dir.join(kind.file()), profile::MAX_PROOF_BYTES)?;
    let node = codec::decode_node(&bytes)?;
    registry.verify(pinned, &node, &expected)?;
    let verifier = registry.verifier(pinned, programs::MERGE)?;
    let native_rejections = native_binding_checks(&verifier, &node)?;

    // Independent native key binding: bypass registry-pin policy intentionally.
    let mut changed_key = registry.clone();
    changed_key.caps[(programs::MERGE - 1) as usize][0][0] += Val::ONE;
    let wrong_verifier = changed_key.verifier(changed_key.id()?, programs::MERGE)?;
    if wrong_verifier.verify(&node.proof, &node.public).is_ok() {
        return Err("native verifier accepted substituted preprocessing cap".into());
    }
    for key in 0..3 {
        let mut changed = registry.clone();
        changed.caps[key][0][0] += Val::ONE;
        if changed.verify(pinned, &node, &expected).is_ok() {
            return Err("accepted substituted registry key".into());
        }
    }
    let mut wrong_pin = pinned;
    wrong_pin[0] ^= 1;
    if registry.verify(wrong_pin, &node, &expected).is_ok() {
        return Err("accepted wrong profile pin".into());
    }

    // These are expected-block policy checks, separate from the 38 native
    // mutation checks; they must not be presented as additional cryptanalysis.
    let mut changed_chain = chain;
    changed_chain[0] ^= 1;
    let wrong_chain = kind.expected(pinned, changed_chain, root)?;
    let mut changed_root = root;
    changed_root[0] = (changed_root[0] + 1) % commitment::MODULUS;
    let wrong_root = kind.expected(pinned, chain, changed_root)?;
    for changed in [wrong_chain, wrong_root] {
        if registry.verify(pinned, &node, &changed).is_ok() {
            return Err("accepted changed external expected statement".into());
        }
    }
    println!(
        "grouped_artifact_audit=PASS kind={} proof_bytes={} native_mutation_rejections={} registry_policy_rejections=4 expected_statement_policy_rejections=2 bundle_files=5 inner_proofs_loaded=0 level6_qualified=false full_tree_security=UNREVIEWED production_ready=false",
        kind.label(), bytes.len(), native_rejections + 1
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), Error> {
    if args.len() != 5 {
        return Err("usage: block-v2-grouped-artifact-audit (root-eight|root-padded-eight) ROOT_ONLY_DIR EXTERNAL_PROFILE_HEX EXTERNAL_CHAIN_HEX EXTERNAL_EXPECTED_ROOT_HEX".into());
    }
    let kind = RootKind::parse(&args[0])?;
    audit_root(
        kind,
        Path::new(&args[1]),
        parse_profile(&args[2])?,
        parse_profile(&args[3])?,
        parse_root(&args[4])?,
    )
}

fn main() {
    let start = Instant::now();
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("grouped_artifact_audit=FAIL {error}");
        std::process::exit(1);
    }
    println!("grouped_audit_elapsed_ms={}", start.elapsed().as_millis());
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{
        backend::RegisteredProgram, MachineAir, ProgramBuilder,
    };
    use p3_field::PrimeField64;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempBundle(PathBuf);
    impl TempBundle {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let tick = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "lattica-grouped-audit-{}-{tick}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            for name in BUNDLE_FILES {
                fs::write(path.join(name), b"").unwrap();
            }
            Self(path)
        }
    }
    impl Drop for TempBundle {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn external_context_parsers_reject_noncanonical_and_malformed_inputs() {
        assert_eq!(parse_profile(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        for value in [
            "é".repeat(32),
            "z0".repeat(32),
            "0".repeat(63),
            "0".repeat(65),
        ] {
            assert!(parse_profile(&value).is_err());
            assert!(parse_root(&value).is_err());
        }
        assert_eq!(parse_root(&"00".repeat(32)).unwrap(), [0; 4]);
        let nonzero = "0100000000000000020000000000000003000000000000000400000000000000";
        assert_eq!(parse_root(nonzero).unwrap(), [1, 2, 3, 4]);
        let encoded_nonzero: String = commitment::digest_bytes([1, 2, 3, 4])
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(encoded_nonzero, nonzero);
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&commitment::MODULUS.to_le_bytes());
        let encoded: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(parse_root(&encoded).is_err());
    }

    #[test]
    fn external_expected_statement_is_fixed_level3_count8_and_binds_all_context() {
        let pin = [0x21; 32];
        let chain = [0x34; 32];
        let root = [1, 2, 3, 4];
        let public = trusted_expected(pin, chain, root).unwrap();
        let node = recursive::summary(&public).unwrap();
        assert_eq!((node.level, node.count, node.root), (3, 8, root));
        assert_eq!(node.context.profile_id, pin);
        assert_eq!(node.context.chain_id, chain);
        assert_eq!(public[programs::MODE].as_canonical_u64(), programs::MERGE);
        assert_ne!(public, trusted_expected([0x22; 32], chain, root).unwrap());
        assert_ne!(public, trusted_expected(pin, [0x35; 32], root).unwrap());
        assert_ne!(public, trusted_expected(pin, chain, [2, 2, 3, 4]).unwrap());
        assert!(trusted_expected(pin, chain, [commitment::MODULUS, 0, 0, 0]).is_err());
    }

    #[test]
    fn bundle_policy_requires_exact_regular_root_only_files() {
        let bundle = TempBundle::new();
        require_root_bundle(&bundle.0).unwrap();
        for name in [
            "wallet.0",
            "wallet.7",
            "node.1.0",
            "node.1.3",
            "node.2.0",
            "node.2.1",
            "node.0.0",
            "expected",
            "profile.hex",
            "unrelated",
        ] {
            let path = bundle.0.join(name);
            fs::write(&path, b"").unwrap();
            assert!(require_root_bundle(&bundle.0).is_err());
            fs::remove_file(path).unwrap();
        }
        fs::remove_file(bundle.0.join("height")).unwrap();
        assert!(require_root_bundle(&bundle.0).is_err());
        fs::create_dir(bundle.0.join("height")).unwrap();
        assert!(require_root_bundle(&bundle.0).is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversize_and_nonregular_artifacts() {
        let bundle = TempBundle::new();
        let path = bundle.0.join(ROOT_FILE);
        fs::write(&path, [1, 2, 3, 4, 5]).unwrap();
        assert!(read_bounded(&path, 4).is_err());
        assert_eq!(read_bounded(&path, 5).unwrap(), [1, 2, 3, 4, 5]);
        assert!(read_bounded(&bundle.0, 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bundle_policy_and_reader_reject_symlinks() {
        use std::os::unix::fs::symlink;
        let bundle = TempBundle::new();
        let path = bundle.0.join(ROOT_FILE);
        fs::remove_file(&path).unwrap();
        symlink("height", &path).unwrap();
        assert!(require_root_bundle(&bundle.0).is_err());
        assert!(read_bounded(&path, 1024).is_err());
        let alias = bundle.0.with_extension("symlink");
        symlink(&bundle.0, &alias).unwrap();
        assert!(require_root_bundle(&alias).is_err());
        fs::remove_file(alias).unwrap();
    }

    #[test]
    fn cli_requires_external_profile_chain_and_root_arguments() {
        assert!(run(&[]).is_err());
        assert!(run(&["root-eight".into(), "dir".into(), "00".repeat(32)]).is_err());
        assert!(run(&[
            "root".into(),
            "dir".into(),
            "00".repeat(32),
            "00".repeat(32),
            "00".repeat(32)
        ])
        .is_err());
        assert!(run(&[
            "root-eight".into(),
            "dir".into(),
            "00".repeat(32),
            "00".repeat(32),
            "00".repeat(32),
            "extra".into()
        ])
        .is_err());
    }

    #[test]
    fn real_small_execution_proof_exercises_native_mutations_only() {
        // This generic small proof is NOT grouped recursion or profile approval.
        let mut b = ProgramBuilder::new(programs::PUBLIC_VALUES).unwrap();
        for i in 0..programs::PUBLIC_VALUES {
            let public = b.public(i).unwrap();
            let value = b.input();
            b.assert_equal(public, value);
        }
        let registered =
            RegisteredProgram::new(MachineAir::new(b.finish(Some(32)).unwrap())).unwrap();
        let public = core::array::from_fn(|i| Val::from_usize(i + 1));
        let proof = registered.prove(&public, &public).unwrap();
        let verifier = registered.verifier();
        drop(registered);
        let node = NodeProof { public, proof };
        assert_eq!(native_binding_checks(&verifier, &node).unwrap(), 37);
    }

    #[test]
    fn synthetic_root_gate_binds_external_expectations_without_approving_grouped_keys() {
        for kind in [RootKind::SubtreeEight, RootKind::PaddedEight] {
            synthetic_root_gate(kind);
        }
    }

    fn synthetic_root_gate(kind: RootKind) {
        // A test-only public-value-copy program exercises the I/O and trust-pin
        // boundary. It is NOT a grouped verifier, approved registry, or recursion
        // demonstration. The real gate still needs independently approved caps.
        let mut b = ProgramBuilder::new(programs::PUBLIC_VALUES).unwrap();
        for i in 0..programs::PUBLIC_VALUES {
            let public = b.public(i).unwrap();
            let input = b.input();
            b.assert_equal(public, input);
        }
        let registered =
            RegisteredProgram::new(MachineAir::new(b.finish(Some(32)).unwrap())).unwrap();
        let mut registry = Registry {
            height: 32,
            caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
        };
        registry.caps[(programs::MERGE - 1) as usize] =
            registered.preprocessing_cap().roots().to_vec();
        let test_pin = registry.id().unwrap();
        let chain = [0x35; 32];
        let root = [10, 20, 30, 40];
        let public = kind.expected(test_pin, chain, root).unwrap();
        let proof = registered.prove(&public, &public).unwrap();
        drop(registered);
        let node = NodeProof { public, proof };
        let bundle = TempBundle::new();
        if kind == RootKind::PaddedEight {
            fs::remove_file(bundle.0.join(ROOT_FILE)).unwrap();
        }
        fs::write(bundle.0.join("height"), 32u32.to_le_bytes()).unwrap();
        for (i, cap) in registry.caps.iter().enumerate() {
            let bytes: Vec<u8> = cap
                .iter()
                .flat_map(|digest| digest.iter())
                .flat_map(|value| value.as_canonical_u64().to_le_bytes())
                .collect();
            fs::write(bundle.0.join(format!("key.{}", i + 1)), bytes).unwrap();
        }
        let mut encoded = codec::encode_node(&node).unwrap();
        fs::write(bundle.0.join(kind.file()), &encoded).unwrap();
        audit_root(kind, &bundle.0, test_pin, chain, root).unwrap();
        let mut wrong_pin = test_pin;
        wrong_pin[0] ^= 1;
        assert!(audit_root(kind, &bundle.0, wrong_pin, chain, root).is_err());
        assert!(audit_root(kind, &bundle.0, test_pin, [0x36; 32], root).is_err());
        assert!(audit_root(kind, &bundle.0, test_pin, chain, [11, 20, 30, 40]).is_err());
        encoded.push(0);
        fs::write(bundle.0.join(kind.file()), encoded).unwrap();
        assert!(audit_root(kind, &bundle.0, test_pin, chain, root).is_err());
    }

    #[test]
    fn root_kind_is_external_and_fixed_not_inferred_from_proof_or_header() {
        assert_eq!(
            RootKind::parse("root-eight").unwrap(),
            RootKind::SubtreeEight
        );
        assert_eq!(
            RootKind::parse("root-padded-eight").unwrap(),
            RootKind::PaddedEight
        );
        assert!(RootKind::parse("root").is_err());
        let old = RootKind::SubtreeEight
            .expected([1; 32], [2; 32], [3, 4, 5, 6])
            .unwrap();
        let padded = RootKind::PaddedEight
            .expected([1; 32], [2; 32], [3, 4, 5, 6])
            .unwrap();
        assert_ne!(old, padded);
        assert_eq!(
            padded,
            programs::statement(
                commitment::NodeSummary {
                    context: commitment::Context {
                        profile_id: [1; 32],
                        chain_id: [2; 32]
                    },
                    level: 6,
                    count: 8,
                    root: [3, 4, 5, 6],
                },
                programs::MERGE
            )
        );
    }

    #[test]
    fn padded_bundle_requires_exact_level_six_root_and_no_inner_artifacts() {
        let bundle = TempBundle::new();
        fs::remove_file(bundle.0.join(ROOT_FILE)).unwrap();
        for file in ["height", "key.1", "key.2", "key.3", "node.6.0"] {
            fs::write(bundle.0.join(file), []).unwrap();
        }
        assert!(RootKind::PaddedEight.require_bundle(&bundle.0).is_ok());
        assert!(RootKind::SubtreeEight.require_bundle(&bundle.0).is_err());
        fs::write(bundle.0.join("empty.3"), []).unwrap();
        assert!(RootKind::PaddedEight.require_bundle(&bundle.0).is_err());
        fs::remove_file(bundle.0.join("empty.3")).unwrap();
        fs::rename(bundle.0.join("node.6.0"), bundle.0.join(ROOT_FILE)).unwrap();
        assert!(RootKind::PaddedEight.require_bundle(&bundle.0).is_err());
        assert!(RootKind::SubtreeEight.require_bundle(&bundle.0).is_ok());
    }
}
