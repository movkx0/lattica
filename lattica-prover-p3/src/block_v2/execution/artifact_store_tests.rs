use super::*;
use crate::block_v2::execution::job::test_support::{node, wallet};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    process::Command,
};

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("lattica-artifact-test-{}", hex(&nonce)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn store(&self) -> PathBuf {
        self.path.join("store")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn limits() -> StoreLimits {
    StoreLimits {
        bytes: 32 * (1 << 20),
        entries: 128,
    }
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn private_store_has_one_owner_and_reopens_without_accepting_existing_path_as_new() {
    let temp = Temp::new();
    let store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    assert_eq!(
        fs::metadata(temp.store()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(ArtifactStore::create(&temp.store(), limits()).is_err());
    assert!(ArtifactStore::open(&temp.store(), limits()).is_err());
    assert!(!store.needs_recovery());
    drop(store);
    assert!(ArtifactStore::open(&temp.store(), limits()).is_ok());
}

#[test]
fn publication_binds_exact_kind_length_and_bytes_and_is_idempotent() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    let bytes = [7, 8, 9];
    let w = wallet(1, &bytes);
    let job = Job::wrap(0, w).unwrap();
    let n = node(&job, &bytes);
    assert!(store.put_wallet(w, &[7, 8]).is_err());
    assert!(store.put_node(n, &[7, 8, 0]).is_err());
    assert_eq!(store.usage(), StoreUsage::default());
    let wid = store.put_wallet(w, &bytes).unwrap();
    let nid = store.put_node(n, &bytes).unwrap();
    assert_ne!(wid, nid);
    assert_eq!(store.read_exact(wid).unwrap(), bytes);
    assert_eq!(store.read_exact(nid).unwrap(), bytes);
    let before = store.usage();
    assert_eq!(before.artifacts, 2);
    assert_eq!(before.artifact_bytes, 6);
    store.put_node(n, &bytes).unwrap();
    store.put_wallet(w, &bytes).unwrap();
    assert_eq!(store.usage(), before);
    drop(store);
    let reopened = ArtifactStore::open(&temp.store(), limits()).unwrap();
    assert_eq!(reopened.usage(), before);
    assert_eq!(reopened.inventory().len(), 2);
    assert_eq!(reopened.read_exact(wid).unwrap(), bytes);
    // Structural fixtures do not become CPU-valid because they are on disk.
    let invalid_registry = Registry {
        height: 0,
        caps: core::array::from_fn(|_| Vec::new()),
    };
    assert!(reopened
        .load_wallet(wid, job.pin(), &invalid_registry, [9; 32])
        .is_err());
    assert!(reopened.load_node(nid, &job, &invalid_registry).is_err());
    assert!(reopened.load_node(wid, &job, &invalid_registry).is_err());
}

#[test]
fn admission_counts_temporary_and_published_names_without_partial_writes() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(
        &temp.store(),
        StoreLimits {
            bytes: 6,
            entries: 128,
        },
    )
    .unwrap();
    let first = wallet(1, &[1, 2]);
    let second = wallet(2, &[3, 4]);
    store.put_wallet(first, &[1, 2]).unwrap();
    store.put_wallet(second, &[3, 4]).unwrap();
    assert!(store.put_wallet(wallet(3, &[5, 6]), &[5, 6]).is_err());
    assert_eq!(store.usage().artifact_bytes, 4);
    assert_eq!(store.usage().pending_files, 0);
    assert!(!store.needs_recovery());
    // Existing publication does not need another temporary reservation.
    store.put_wallet(first, &[1, 2]).unwrap();

    let other = Temp::new();
    let mut store = ArtifactStore::create(
        &other.store(),
        StoreLimits {
            bytes: 100,
            entries: 2,
        },
    )
    .unwrap();
    store.put_wallet(first, &[1, 2]).unwrap();
    assert!(store.put_wallet(second, &[3, 4]).is_err());
    assert_eq!(store.usage().artifacts, 1);
    assert_eq!(store.usage().pending_files, 0);
}

#[test]
fn every_publication_interruption_is_fail_closed_and_recoverable() {
    for stage in [
        Fault::AfterWrite,
        Fault::AfterFileSync,
        Fault::AfterPublish,
        Fault::AfterDirectorySync,
        Fault::AfterCleanup,
    ] {
        let temp = Temp::new();
        let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
        let ticket = wallet(1, &[11, 12]);
        store.fault = Some(stage);
        assert!(store.put_wallet(ticket, &[11, 12]).is_err());
        assert!(store.needs_recovery());
        assert!(store.put_wallet(ticket, &[11, 12]).is_err());
        assert!(store.recover_pending().is_err());
        drop(store);
        let mut reopened = ArtifactStore::open(&temp.store(), limits()).unwrap();
        let published = !matches!(stage, Fault::AfterWrite | Fault::AfterFileSync);
        let pending = stage != Fault::AfterCleanup;
        assert_eq!(reopened.usage().artifacts, usize::from(published));
        assert_eq!(reopened.usage().pending_files, usize::from(pending));
        if pending {
            assert!(reopened.put_wallet(ticket, &[11, 12]).is_err());
            assert!(reopened.read_exact(ticket.artifact()).is_err());
        }
        assert_eq!(reopened.recover_pending().unwrap(), usize::from(pending));
        assert!(!reopened.needs_recovery());
        reopened.put_wallet(ticket, &[11, 12]).unwrap();
        assert_eq!(reopened.read_exact(ticket.artifact()).unwrap(), [11, 12]);
        assert_eq!(reopened.usage().artifact_bytes, 2);
        assert_eq!(reopened.usage().artifacts, 1);
    }
}

#[test]
fn subprocess_crashes_release_owner_lock_and_preserve_only_atomic_publications() {
    let executable = std::env::current_exe().unwrap();
    for stage in 0..5 {
        let temp = Temp::new();
        let output = Command::new(&executable)
            .args([
                "block_v2::execution::artifact_store::tests::subprocess_publication_crash_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_V2_ARTIFACT_CRASH_DIRECTORY", temp.store())
            .env("LATTICA_V2_ARTIFACT_CRASH_STAGE", stage.to_string())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(73), "child output: {:?}", output);
        let mut reopened = ArtifactStore::open(&temp.store(), limits()).unwrap();
        assert_eq!(reopened.usage().artifacts, usize::from(stage >= 2));
        assert_eq!(reopened.recover_pending().unwrap(), usize::from(stage != 4));
        reopened
            .put_wallet(wallet(1, &[11, 12]), &[11, 12])
            .unwrap();
        assert_eq!(reopened.usage().artifacts, 1);
        assert_eq!(reopened.usage().pending_files, 0);
    }
}

#[test]
#[ignore = "subprocess-only abrupt-exit fixture; invoked by the crash test"]
fn subprocess_publication_crash_helper() {
    let path = PathBuf::from(std::env::var("LATTICA_V2_ARTIFACT_CRASH_DIRECTORY").unwrap());
    let stage: usize = std::env::var("LATTICA_V2_ARTIFACT_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let mut store = ArtifactStore::create(&path, limits()).unwrap();
    store.fault = Some(
        [
            Fault::AfterWrite,
            Fault::AfterFileSync,
            Fault::AfterPublish,
            Fault::AfterDirectorySync,
            Fault::AfterCleanup,
        ][stage],
    );
    store.crash = true;
    store.put_wallet(wallet(1, &[11, 12]), &[11, 12]).unwrap();
    panic!("crash injection did not execute");
}

#[test]
fn corrupted_missing_or_changed_artifacts_cannot_be_reused_or_overwritten() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    let ticket = wallet(1, &[1, 2, 3]);
    let identity = store.put_wallet(ticket, &[1, 2, 3]).unwrap();
    let path = temp.store().join(artifact_name(identity));
    fs::write(&path, [1, 2, 4]).unwrap();
    assert!(store.read_exact(identity).is_err());
    assert!(store.put_wallet(ticket, &[1, 2, 3]).is_err());
    assert_eq!(fs::read(&path).unwrap(), [1, 2, 4]);
    fs::write(&path, [1, 2]).unwrap();
    assert!(store.read_exact(identity).is_err());
    drop(store);
    let store = ArtifactStore::open(&temp.store(), limits()).unwrap();
    assert!(store.read_exact(identity).is_err());
    fs::remove_file(&path).unwrap();
    assert!(store.read_exact(identity).is_err());
}

#[test]
fn private_file_and_directory_checks_reject_links_public_modes_and_unknown_names() {
    let temp = Temp::new();
    let path = temp.store();
    let store = ArtifactStore::create(&path, limits()).unwrap();
    drop(store);
    let alias = temp.path.join("alias");
    symlink(&path, &alias).unwrap();
    assert!(ArtifactStore::open(&alias, limits()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(ArtifactStore::open(&path, limits()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let identity = wallet(1, &[1]).artifact();
    let outside = temp.path.join("outside");
    private_file(&outside, &[1]);
    let artifact = path.join(artifact_name(identity));
    symlink(&outside, &artifact).unwrap();
    assert!(ArtifactStore::open(&path, limits()).is_err());
    fs::remove_file(&artifact).unwrap();
    fs::hard_link(&outside, &artifact).unwrap();
    assert!(ArtifactStore::open(&path, limits()).is_err());
    fs::remove_file(&artifact).unwrap();
    private_file(&path.join("unknown"), &[1]);
    assert!(ArtifactStore::open(&path, limits()).is_err());
    assert_eq!(fs::read(outside).unwrap(), [1]);
}

#[test]
fn descriptor_parser_rejects_noncanonical_unicode_size_and_digest_inputs() {
    let identity = wallet(1, &[1]).artifact();
    let name = artifact_name(identity);
    assert_eq!(parse_name(&name, 1).unwrap(), identity);
    assert!(parse_name(&name, 0).is_err());
    assert!(parse_name(&name, MAX_PROOF_BYTES as u64 + 1).is_err());
    assert!(parse_name(&name, u64::MAX).is_err());
    assert!(parse_name(&format!("n-{}.proof", "f".repeat(64)), 1).is_err());
    assert!(parse_name(&name.to_uppercase(), 1).is_err());
    let unicode = format!("né{}", "0".repeat(69));
    assert_eq!(unicode.len(), 72);
    assert!(parse_name(&unicode, 1).is_err());
    assert!(!is_pending(".pending-../../outside"));
    assert!(StoreLimits {
        bytes: 1,
        entries: 2
    }
    .validate()
    .is_err());
    assert!(StoreLimits {
        bytes: MAX_STORE_BYTES + 1,
        entries: 2
    }
    .validate()
    .is_err());
    assert!(StoreLimits {
        bytes: 2,
        entries: MAX_ENTRIES + 1
    }
    .validate()
    .is_err());
}

#[test]
fn replaced_owner_lock_is_detected_before_any_further_publication() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    fs::remove_file(temp.store().join(LOCK)).unwrap();
    private_file(&temp.store().join(LOCK), &[]);
    assert!(store.put_wallet(wallet(1, &[1]), &[1]).is_err());
    assert!(store.recover_pending().is_err());
    assert_eq!(store.usage().artifacts, 0);
}

#[test]
fn directory_descriptor_keeps_publication_bound_after_path_replacement() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    let retained = temp.path.join("renamed-store");
    fs::rename(temp.store(), &retained).unwrap();
    DirBuilder::new().mode(0o700).create(temp.store()).unwrap();
    let ticket = wallet(1, &[1, 2]);
    store.put_wallet(ticket, &[1, 2]).unwrap();
    let name = artifact_name(ticket.artifact());
    assert!(retained.join(&name).is_file());
    assert!(!temp.store().join(&name).exists());
    assert_eq!(store.read_exact(ticket.artifact()).unwrap(), [1, 2]);
    drop(store);
    let reopened = ArtifactStore::open(&retained, limits()).unwrap();
    assert_eq!(reopened.read_exact(ticket.artifact()).unwrap(), [1, 2]);
}

#[test]
fn recovery_inventory_bounds_lengths_counts_and_zero_byte_pending_files() {
    let temp = Temp::new();
    drop(ArtifactStore::create(&temp.store(), limits()).unwrap());
    let pending = temp.store().join(format!("{PENDING}{}", "0".repeat(32)));
    private_file(&pending, &[]);
    let mut store = ArtifactStore::open(&temp.store(), limits()).unwrap();
    assert!(store.needs_recovery());
    assert_eq!(store.recover_pending().unwrap(), 1);
    assert_eq!(store.usage(), StoreUsage::default());
    drop(store);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)
        .unwrap();
    file.set_len(MAX_PROOF_BYTES as u64 + 1).unwrap();
    assert!(ArtifactStore::open(&temp.store(), limits()).is_err());
    fs::remove_file(&pending).unwrap();
    for i in 1..=3 {
        private_file(
            &temp
                .store()
                .join(artifact_name(wallet(i, &[i as u8]).artifact())),
            &[i as u8],
        );
    }
    assert!(ArtifactStore::open(
        &temp.store(),
        StoreLimits {
            bytes: 100,
            entries: 2
        }
    )
    .is_err());
    assert!(ArtifactStore::open(
        &temp.store(),
        StoreLimits {
            bytes: 2,
            entries: 128
        }
    )
    .is_err());
    let published = temp.store().join(artifact_name(wallet(1, &[1]).artifact()));
    fs::set_permissions(&published, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ArtifactStore::open(&temp.store(), limits()).is_err());
}

#[test]
#[ignore = "requires the independently pinned compact eight-wallet fixture and root-only bundle"]
fn cpu_recovery_reverifies_pinned_wallets_and_recursive_root() -> Result<(), Error> {
    use crate::block_v2::{
        commitment, machine::program::Val, profile, recursive::WrapperConstruction,
    };
    use p3_field::PrimeCharacteristicRing;

    fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
        let before = fs::symlink_metadata(path)?;
        if !before.is_file() || before.len() > limit as u64 {
            return Err("fixture type/size".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(path)?;
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
    fn fixed_hex(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }
    fn root_job(wallets: &[VerifiedWallet]) -> Result<Job, Error> {
        let pairs: Vec<_> = (0..4)
            .map(|i| Job::wrap_pair((i * 2) as u8, wallets[2 * i], wallets[2 * i + 1]))
            .collect::<Result<_, _>>()?;
        Job::merge(
            &Job::merge(&pairs[0], &pairs[1])?,
            &Job::merge(&pairs[2], &pairs[3])?,
        )
    }
    let inputs = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_INPUTS")?);
    let bundle = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_ROOT")?);
    let expected_profile =
        fixed_hex("8ec1bbde8ade9c60a90398a6a30f3bb095d5adc1f1fed881e7b72ea051bab3cb");
    let expected_root =
        fixed_hex("23ccda6b5581d09e8d0107be85d09c2795f3f767bfc844a9b5168e7f4a9c20e8");
    let chain = [0x5a; 32];
    let height =
        u32::from_le_bytes(read(&inputs.join("height"), 4)?.as_slice().try_into()?) as usize;
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
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits())?;
    let mut wallets = Vec::new();
    let mut identities = Vec::new();
    for i in 0..8 {
        let bytes = read(&inputs.join(format!("wallet.{i}")), MAX_PROOF_BYTES)?;
        let ticket = VerifiedWallet::verify(pin, &registry, chain, &bytes)?;
        identities.push(store.put_wallet(ticket, &bytes)?);
        wallets.push(ticket);
    }
    let job = root_job(&wallets)?;
    assert_eq!(
        commitment::digest_bytes(job.expected().root)?,
        expected_root
    );
    let root_bytes = read(&bundle.join("node.3.0"), MAX_PROOF_BYTES)?;
    let ticket = VerifiedNode::verify(&job, &registry, &root_bytes)?;
    let root_identity = store.put_node(ticket, &root_bytes)?;
    assert_eq!(store.usage().artifacts, 9);
    drop(store);
    let recovered = ArtifactStore::open(&temp.store(), limits())?;
    assert!(!recovered.needs_recovery());
    let mut rechecked = Vec::new();
    for identity in &identities {
        let (ticket, bytes) = recovered.load_wallet(*identity, pin, &registry, chain)?;
        assert_eq!(ticket.artifact(), *identity);
        identity.check_bytes(&bytes)?;
        rechecked.push(ticket);
    }
    assert!(recovered
        .load_wallet(identities[0], pin, &registry, [0x5b; 32])
        .is_err());
    let expected = root_job(&rechecked)?;
    assert_eq!(expected.id(), job.id());
    let (rechecked_node, bytes) = recovered.load_node(root_identity, &expected, &registry)?;
    assert_eq!(rechecked_node.job(), job.id());
    assert_eq!(bytes, root_bytes);
    rechecked.swap(0, 1);
    assert!(recovered
        .load_node(root_identity, &root_job(&rechecked)?, &registry)
        .is_err());

    // Only this temporary store is modified; the independent fixtures remain.
    let root_path = temp.store().join(artifact_name(root_identity));
    let mut changed = root_bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&root_path, &changed)?;
    assert!(recovered
        .load_node(root_identity, &expected, &registry)
        .is_err());
    fs::write(&root_path, &root_bytes)?;
    for identity in identities {
        fs::remove_file(temp.store().join(artifact_name(identity)))?;
    }
    let (_, after_pruning) = recovered.load_node(root_identity, &expected, &registry)?;
    assert_eq!(after_pruning, root_bytes);
    Ok(())
}
