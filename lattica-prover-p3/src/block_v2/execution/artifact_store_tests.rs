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

#[test]
fn inventory_bounds_cover_full_published_pending_and_pruned_states() {
    let temp = Temp::new();
    let limits = StoreLimits {
        bytes: 4096,
        entries: 64,
    };
    let mut store = ArtifactStore::create(&temp.store(), limits).unwrap();
    let bound = limits.inventory_storage().unwrap();
    let check = |store: &ArtifactStore| {
        assert!(store.inventory_storage_bytes().unwrap() <= bound.retained_bytes);
        assert!(store
            .inventory
            .artifacts
            .keys()
            .all(|n| n.capacity() == n.len()));
        assert!(store
            .inventory
            .pending
            .iter()
            .all(|n| n.capacity() == n.len()));
    };
    check(&store);
    let mut retained = Vec::new();
    for i in 0..64u8 {
        let identity = wallet(u64::from(i) + 1, &[i + 1]).artifact();
        let name = artifact_name(identity);
        assert_eq!(name.len(), storage::ARTIFACT_NAME_BYTES);
        assert_eq!(name.capacity(), name.len());
        assert_eq!(name, format!("w-{}.proof", hex(&identity.digest_bytes())));
        private_file(&temp.store().join(name), &[i + 1]);
        retained.push(identity);
    }
    store.refresh().unwrap();
    assert_eq!(store.usage().artifacts, 64);
    check(&store);
    // A caller can repeat identities; the keep-map still has at most the
    // inventory entry count, and refreshed inventory coexists with it.
    retained.extend_from_within(..);
    assert_eq!(store.prune_to(&retained).unwrap(), 0);
    check(&store);
    assert_eq!(store.prune_to(&retained[..16]).unwrap(), 48);
    check(&store);
    assert_eq!(store.prune_to(&[]).unwrap(), 16);
    check(&store);
    for i in 0..64u64 {
        private_file(&temp.store().join(format!("{PENDING}{i:032x}")), &[1]);
    }
    store.refresh().unwrap();
    assert_eq!(store.usage().pending_files, 64);
    check(&store);
    assert_eq!(store.recover_pending().unwrap(), 64);
    check(&store);
}

#[test]
fn inventory_component_admission_validates_limits_and_exact_threshold() {
    for (name, limits) in [
        (
            "cli",
            StoreLimits {
                bytes: 256 << 20,
                entries: 512,
            },
        ),
        (
            "hard",
            StoreLimits {
                bytes: MAX_STORE_BYTES,
                entries: MAX_ENTRIES,
            },
        ),
    ] {
        let bound = limits.inventory_storage().unwrap();
        assert!(bound.refresh_prune_bytes > 2 * bound.retained_bytes);
        bound.admit(bound.refresh_prune_bytes).unwrap();
        assert!(bound.admit(bound.refresh_prune_bytes - 1).is_err());
        println!(
            "coordinator_inventory_storage profile={name} retained_bytes={} refresh_prune_bytes={}",
            bound.retained_bytes, bound.refresh_prune_bytes
        );
    }
    for limits in [
        StoreLimits {
            bytes: 1,
            entries: 2,
        },
        StoreLimits {
            bytes: MAX_STORE_BYTES,
            entries: MAX_ENTRIES + 1,
        },
    ] {
        assert!(limits.inventory_storage().is_err());
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
fn cache_advice_reports_descriptor_errors() {
    use std::os::fd::OwnedFd;
    let (reader, _writer) = std::io::pipe().unwrap();
    // Production callers validate regular files before reaching this helper.
    // A non-file descriptor exercises POSIX's direct error-number return.
    let file = File::from(OwnedFd::from(reader));
    let error = retire_public_pages(&file).unwrap_err().to_string();
    assert!(error.starts_with("immutable proof page-cache advice: "));
}

#[test]
#[ignore = "bounded file-cache diagnostic; requires a fresh private directory on a disk filesystem"]
fn disk_cache_lifetime_preserves_public_bytes_and_rejects_corruption() {
    use std::time::Instant;

    // mincore observes page-cache residency without faulting file pages into
    // this mapping. No system cache, driver cache or cgroup peak is reset.
    fn resident_bytes(path: &Path) -> usize {
        let file = File::open(path).unwrap();
        let len = usize::try_from(file.metadata().unwrap().len()).unwrap();
        // SAFETY: sysconf takes no pointer and returns the configured page size.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        assert!(page.is_power_of_two());
        let mut residency = vec![0u8; len.div_ceil(page)];
        // SAFETY: the owned descriptor is live, offset zero is aligned, and no
        // pointer into this PROT_NONE mapping is dereferenced.
        let mapping = unsafe {
            libc::mmap(std::ptr::null_mut(), len, libc::PROT_NONE, libc::MAP_PRIVATE,
                file.as_raw_fd(), 0)
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        // SAFETY: residency has one initialized byte for every mapped page.
        let observed = unsafe { libc::mincore(mapping, len, residency.as_mut_ptr()) };
        // SAFETY: exactly the successful mapping above, with no live references.
        let unmapped = unsafe { libc::munmap(mapping, len) };
        assert_eq!(observed, 0);
        assert_eq!(unmapped, 0);
        residency.iter().filter(|&&v| v & 1 != 0).count() * page
    }

    let directory = PathBuf::from(std::env::var_os("LATTICA_ARTIFACT_CACHE_DIAGNOSTIC").unwrap());
    assert!(directory.is_absolute());
    let path = directory.join("store");
    let mut store = ArtifactStore::create(&path,
        StoreLimits { bytes: 256 << 20, entries: 256 }).unwrap();
    const COUNT: usize = 96;
    const BYTES: usize = 1 << 20;
    let mut identities = Vec::with_capacity(COUNT);
    let mut bytes = vec![0x5a; BYTES];
    let started = Instant::now();
    for index in 0..COUNT {
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let ticket = wallet(index as u64 + 1, &bytes);
        identities.push(store.put_wallet(ticket, &bytes).unwrap());
    }
    let published_ms = started.elapsed().as_millis();
    let residency = || identities.iter()
        .map(|identity| resident_bytes(&path.join(artifact_name(*identity))))
        .sum::<usize>();
    let published_resident_bytes = residency();
    // Ordinary reads model the old file-cache retention behavior. They do not
    // constitute a matched whole-workflow control or generate any proofs.
    for identity in &identities {
        identity.check_bytes(&fs::read(path.join(artifact_name(*identity))).unwrap()).unwrap();
    }
    let warmed_resident_bytes = residency();
    let started = Instant::now();
    for identity in &identities {
        let copy = store.read_exact(*identity).unwrap();
        identity.check_bytes(&copy).unwrap();
        assert_eq!(copy.len(), BYTES);
    }
    let read_ms = started.elapsed().as_millis();
    let read_resident_bytes = residency();
    let usage = store.usage();
    drop(store);
    let store = ArtifactStore::open(&path,
        StoreLimits { bytes: 256 << 20, entries: 256 }).unwrap();
    assert_eq!(store.usage(), usage);
    for identity in &identities { store.read_exact(*identity).unwrap(); }
    let first = identities[0];
    bytes[..8].copy_from_slice(&999u64.to_le_bytes());
    fs::write(path.join(artifact_name(first)), &bytes).unwrap();
    assert!(store.read_exact(first).is_err());
    assert!(!store.needs_recovery());
    // Keep observation separate from proof/storage assertions: successful
    // advice is not a portable guarantee that the kernel evicts these pages.
    println!("artifact_cache_lifetime {}", serde_json::json!({
        "artifacts":COUNT,"public_bytes":COUNT*BYTES,"published_ms":published_ms,
        "published_resident_bytes":published_resident_bytes,
        "ordinary_read_resident_bytes":warmed_resident_bytes,
        "store_read_resident_bytes":read_resident_bytes,"store_read_ms":read_ms,
        "reopen_bytes_verified":true,"corruption_rejected":true,
        "proofs_generated":0,"native_blocks_applied":0,"is_workflow_qualification":false
    }));
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
fn owned_wallet_publication_checks_all_identities_before_writing_and_rechecks_disk() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    use crate::block_v2::execution::job::test_support::{typed_wallet, typed_pin};
    let left = typed_wallet(1, 1, &[1, 2]);
    let right = typed_wallet(2, 1, &[3, 4]);
    let job = Job::typed_pair(0, left, Some(right)).unwrap();
    let inputs = [
        VerifiedWalletPayload::new(left, vec![1, 2]).unwrap(),
        VerifiedWalletPayload::new(right, vec![3, 4]).unwrap(),
    ];
    let incorrect = [inputs[0].clone(), inputs[0].clone()];
    assert!(store.put_verified_job_inputs(&job, &incorrect).is_err());
    assert!(store.put_verified_job_inputs(&job, &inputs[..1]).is_err());
    let empty = Job::empty(typed_pin(), [9; 32], 0, 1).unwrap();
    assert!(store.put_verified_job_inputs(&empty, &inputs).is_err());
    assert_eq!(store.usage().artifacts, 0);
    assert!(!store.needs_recovery());
    store.put_verified_job_inputs(&job, &inputs).unwrap();
    let usage = store.usage();
    store.put_verified_job_inputs(&job, &inputs).unwrap();
    assert_eq!(store.usage(), usage);
    for input in &inputs {
        assert_eq!(store.read_exact(input.ticket().artifact()).unwrap(), input.bytes());
    }
    fs::write(temp.store().join(artifact_name(right.artifact())), [3, 0]).unwrap();
    assert!(store.put_verified_job_inputs(&job, &inputs).is_err());
    assert!(store.read_exact(right.artifact()).is_err());
    assert_eq!(inputs[1].bytes(), [3, 4]);
}

#[test]
fn owned_wallet_publication_preserves_interruption_and_recovery_boundaries() {
    for stage in [Fault::AfterWrite, Fault::AfterFileSync, Fault::AfterPublish, Fault::AfterDirectorySync, Fault::AfterCleanup] {
        let temp = Temp::new();
        let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
        let ticket = wallet(1, &[2, 3]);
        let job = Job::wrap(0, ticket).unwrap();
        let inputs = [VerifiedWalletPayload::new(ticket, vec![2, 3]).unwrap()];
        store.fault = Some(stage);
        assert!(store.put_verified_job_inputs(&job, &inputs).is_err());
        assert!(store.needs_recovery());
        assert!(store.put_verified_job_inputs(&job, &inputs).is_err());
        drop(store);
        let mut reopened = ArtifactStore::open(&temp.store(), limits()).unwrap();
        reopened.recover_pending().unwrap();
        reopened.put_verified_job_inputs(&job, &inputs).unwrap();
        assert_eq!(reopened.read_exact(ticket.artifact()).unwrap(), inputs[0].bytes());
        assert!(!reopened.needs_recovery());
    }
}

#[test]
fn owned_publication_retains_disk_integrity_checks_and_exact_bytes() {
    let temp = Temp::new();
    let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
    let job = Job::wrap(0, wallet(1, &[1])).unwrap();
    let bytes = vec![7, 8, 9];
    let ticket = node(&job, &bytes);
    let payload = VerifiedNodePayload::bind(ticket, bytes.clone()).unwrap();
    let identity = store.put_verified_node(&payload).unwrap();
    assert_eq!(identity, ticket.artifact());
    assert_eq!(store.read_exact(identity).unwrap(), bytes);
    let usage = store.usage();
    store.put_verified_node(&payload).unwrap();
    assert_eq!(store.usage(), usage);
    // Owning a valid source buffer never approves a changed disk artifact.
    fs::write(temp.store().join(artifact_name(identity)), [7, 8, 0]).unwrap();
    assert!(store.put_verified_node(&payload).is_err());
    assert!(store.read_exact(identity).is_err());
    assert_eq!(payload.bytes(), bytes);
}

#[test]
fn owned_publication_preserves_all_interruption_and_recovery_boundaries() {
    for stage in [
        Fault::AfterWrite,
        Fault::AfterFileSync,
        Fault::AfterPublish,
        Fault::AfterDirectorySync,
        Fault::AfterCleanup,
    ] {
        let temp = Temp::new();
        let mut store = ArtifactStore::create(&temp.store(), limits()).unwrap();
        let job = Job::wrap(0, wallet(1, &[1])).unwrap();
        let payload = VerifiedNodePayload::bind(node(&job, &[2, 3]), vec![2, 3]).unwrap();
        store.fault = Some(stage);
        assert!(store.put_verified_node(&payload).is_err());
        assert!(store.needs_recovery());
        assert!(store.put_verified_node(&payload).is_err());
        drop(store);
        let mut reopened = ArtifactStore::open(&temp.store(), limits()).unwrap();
        reopened.recover_pending().unwrap();
        let identity = reopened.put_verified_node(&payload).unwrap();
        assert_eq!(reopened.read_exact(identity).unwrap(), payload.bytes());
        assert!(!reopened.needs_recovery());
    }
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
