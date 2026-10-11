#![cfg(not(any(feature = "gpu", feature = "gpu-metal")))]

use super::*;
use crate::block_v2::{
    codec,
    execution::{
        artifact_store::StoreLimits,
        job::{TypedRegistryContext, TYPED_WALLET_MAGIC},
        journal::{DurableDag, JournalLimits, SnapshotLog},
        resources::Resources,
        worker_budget,
    },
    machine::{programs, typed_pairs},
    profile, recursive,
    typed_recursive::{self, Policy},
};
use crate::config::Val;
use crate::spill_alloc::allocation_requests::{measure, measure_all};
use p3_field::PrimeCharacteristicRing;
use rand::TryRng;
use std::{
    cell::Cell,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lattica-recovery-registry-{}",
            crate::block_v2::execution::artifact_store::hex(&nonce)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn encoded_identity(identity: ArtifactRef) -> Vec<u8> {
    let mut encoded = vec![match identity.kind() {
        ArtifactKind::Wallet => 1,
        ArtifactKind::Node => 2,
    }];
    encoded.extend(identity.byte_len().to_le_bytes());
    encoded.extend(identity.digest_bytes());
    encoded
}

#[test]
#[ignore = "fresh CPU wallet/node proofs and actual typed snapshot/journal recovery"]
fn fresh_typed_recovery_reuses_identity_and_preserves_full_checks() {
    // Keep allocation-request comparisons independent of Rayon work splitting.
    // The normal execution suites separately exercise the four-thread runtime.
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(fresh_recovery);
}

fn fresh_recovery() {
    let temp = Temp::new();
    let height = 2048;
    let budget = 512 << 20;
    let compiled = typed_pairs::compile_registration(height, programs::EMPTY, None).unwrap();
    let air = crate::block_v2::machine::MachineAir::new(compiled.program.pad_to(height).unwrap());
    let registered =
        crate::block_v2::machine::backend::RegisteredProgram::new_with_memory_budget(air, budget)
            .unwrap();
    let mut registry = typed_recursive::Registry::<12> {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    registry.caps[1] = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    let profile_id = registry.id().unwrap();
    let pin = RegistryPin::new_typed(&registry, profile_id).unwrap();
    let wallet = recursive::demo_wallet(0).unwrap();
    let chain = wallet.chain;
    let mut wallet_bytes = TYPED_WALLET_MAGIC.to_vec();
    wallet_bytes.extend(postcard::to_allocvec(&wallet).unwrap());
    let wallet_ticket =
        VerifiedWallet::verify_typed(pin, &registry, chain, Policy::JoinSplit, &wallet_bytes)
            .unwrap();
    let mut session = typed_recursive::Session::new(registry.clone(), profile_id, budget).unwrap();
    let mut node = session.empty(chain, 1).unwrap();
    let node_job = Job::empty(pin, chain, 2, 1).unwrap();
    let node_bytes = codec::encode_node(&node).unwrap();
    let node_ticket = VerifiedNode::verify_typed(&node_job, &registry, &node_bytes).unwrap();

    let store_limits = StoreLimits {
        bytes: 32 << 20,
        entries: 32,
    };
    let store_path = temp.0.join("artifacts");
    let mut store = ArtifactStore::create(&store_path, store_limits).unwrap();
    store.put_wallet(wallet_ticket, &wallet_bytes).unwrap();
    let node_identity = store.put_node(node_ticket, &node_bytes).unwrap();
    let journal_limits = JournalLimits {
        snapshot_bytes: 1 << 20,
    };
    let journal_path = temp.0.join("journal");
    let mut journal = SnapshotLog::create(&journal_path, journal_limits).unwrap();
    let limits = Limits {
        jobs: 32,
        candidates: 4,
        attempts: 32,
        artifact_bytes: 16 << 20,
        recovery_window_ms: 1000,
        workers: Resources {
            ram_bytes: 1 << 30,
            threads: 2,
            ..Resources::default()
        },
    };
    TypedRegistryContext::admit_recovery_storage(worker_budget::COORDINATOR_JOB_BYTES).unwrap();
    let mut dag = Dag::new(pin, chain, 1, limits).unwrap();
    dag.pin_launch_journal(journal.identity().unwrap()).unwrap();
    let mut root = Job::typed_pair(0, wallet_ticket, None).unwrap();
    dag.admit(
        root.clone(),
        vec![wallet_bytes.clone(), wallet_bytes.clone()],
        0,
    )
    .unwrap();
    for level in 1..DEPTH {
        let right = Job::empty(pin, chain, 1 << level, level).unwrap();
        dag.admit(right.clone(), vec![], 0).unwrap();
        root = Job::merge(&root, &right).unwrap();
        dag.admit(root.clone(), vec![], 0).unwrap();
    }
    dag.attach(root.id(), [7; 32], 1000, 0).unwrap();
    let lease = dag
        .lease(
            node_job.id(),
            WorkerId(1),
            Resources {
                ram_bytes: worker_budget::COORDINATOR_JOB_BYTES,
                threads: 1,
                ..Resources::default()
            },
            1,
            100,
            0,
        )
        .unwrap();
    dag.worker_stopped(lease, 1).unwrap();
    dag.begin_verification(lease, 1).unwrap();
    assert_eq!(
        dag.finish_verification(lease, Some((node_ticket, node_bytes.clone())), 2)
            .unwrap(),
        Completion::Accepted
    );
    let snapshot = dag.snapshot().unwrap();
    journal.commit(&snapshot).unwrap();

    let wallet_calls = Cell::new(0usize);
    let node_calls = Cell::new(0usize);
    let reference = || -> Result<Restored, Error> {
        pin.check_typed(&registry)?;
        restore_with(
            &snapshot,
            pin,
            chain,
            2,
            limits,
            |identity| {
                wallet_calls.set(wallet_calls.get() + 1);
                store.load_typed_wallet(identity, pin, &registry, chain, Policy::JoinSplit)
            },
            |job, identity| {
                node_calls.set(node_calls.get() + 1);
                store.load_typed_node(identity, job, &registry)
            },
        )
    };
    let approved = || {
        restore_typed(&snapshot, pin, &registry, chain, 2, limits, &store, |_| {
            Ok(Policy::JoinSplit)
        })
    };
    // Warm verifier/runtime internals before measuring the complete restoration.
    reference().unwrap();
    approved().unwrap();
    wallet_calls.set(0);
    node_calls.set(0);
    let (_, identity) = measure(|| registry.id().unwrap());
    let (context, setup) = measure(|| TypedRegistryContext::for_pin(&registry, pin));
    context.unwrap();
    let (direct, direct_requests) = measure_all(reference);
    let (reused, reused_requests) = measure_all(approved);
    let direct = direct.unwrap();
    let reused = reused.unwrap();
    assert_eq!(wallet_calls.get(), 2);
    assert_eq!(node_calls.get(), 1);
    // Each restoration fences previous attempts with a fresh session. Only
    // that nonce may differ between otherwise identical restored snapshots.
    assert_ne!(direct.dag.session, dag.session);
    assert_ne!(reused.dag.session, dag.session);
    assert_ne!(direct.dag.session, reused.dag.session);
    let direct_snapshot = direct.dag.snapshot().unwrap();
    let mut reused_snapshot = reused.dag.snapshot().unwrap();
    let session_start = 8 + 32 + 1 + 32; // magic, profile, construction, chain
    let session_end = session_start + 32;
    assert_eq!(
        &direct_snapshot[session_start..session_end],
        &direct.dag.session
    );
    assert_eq!(
        &reused_snapshot[session_start..session_end],
        &reused.dag.session
    );
    reused_snapshot[session_start..session_end].copy_from_slice(&direct.dag.session);
    assert_eq!(direct_snapshot, reused_snapshot);
    assert_eq!(
        reused.dag.status(node_job.id()).unwrap(),
        JobStatus::Completed
    );
    assert!(
        !identity.overflow
            && !setup.overflow
            && !direct_requests.overflow
            && !reused_requests.overflow
    );
    let reference_identities = 1 + wallet_calls.get() + 2 * node_calls.get();
    eprintln!("recovery_registry_requests rayon_threads=1 direct_bytes={} reused_bytes={} identity_bytes={} setup_bytes={} direct_calls={} reused_calls={} identity_calls={} setup_calls={}", direct_requests.bytes, reused_requests.bytes, identity.bytes, setup.bytes, direct_requests.calls, reused_requests.calls, identity.calls, setup.calls);
    assert_eq!(
        direct_requests.bytes + setup.bytes,
        reused_requests.bytes + reference_identities * identity.bytes
    );
    assert_eq!(
        direct_requests.calls + setup.calls,
        reused_requests.calls + reference_identities * identity.calls
    );

    assert!(
        restore_typed(&snapshot, pin, &registry, chain, 2, limits, &store, |_| Ok(
            Policy::Issuance { authorized_mint: 7 }
        ))
        .is_err()
    );
    let mut changed_registry = registry.clone();
    changed_registry.caps[0][0][0] += Val::ONE;
    assert!(restore_typed(
        &snapshot,
        pin,
        &changed_registry,
        chain,
        2,
        limits,
        &store,
        |_| Ok(Policy::JoinSplit)
    )
    .is_err());
    node.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    let changed = codec::encode_node(&node).unwrap();
    let changed_identity = ArtifactRef::from_bytes(ArtifactKind::Node, &changed).unwrap();
    let name = format!(
        "n-{}.proof",
        crate::block_v2::execution::artifact_store::hex(&changed_identity.digest_bytes())
    );
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(store_path.join(name))
        .unwrap();
    file.write_all(&changed).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let original = encoded_identity(node_identity);
    let replacement = encoded_identity(changed_identity);
    let offsets: Vec<_> = snapshot
        .windows(original.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == original).then_some(i))
        .collect();
    assert_eq!(offsets.len(), 1);
    let mut corrupted = snapshot.clone();
    corrupted[offsets[0]..offsets[0] + original.len()].copy_from_slice(&replacement);
    drop(store);
    let store = ArtifactStore::open(&store_path, store_limits).unwrap();
    assert!(restore_typed(
        &corrupted,
        pin,
        &registry,
        chain,
        2,
        limits,
        &store,
        |_| Ok(Policy::JoinSplit)
    )
    .is_err());
    // Both outer journal hashing and artifact hashing are valid here; the proof fails.
    journal.commit(&corrupted).unwrap();
    drop(journal);
    assert!(DurableDag::recover_typed(
        &journal_path,
        journal_limits,
        store,
        pin,
        &registry,
        chain,
        2,
        limits,
        |_| Ok(Policy::JoinSplit)
    )
    .is_err());
    let (mut journal, _) = SnapshotLog::open(&journal_path, journal_limits).unwrap();
    journal.commit(&snapshot).unwrap();
    drop(journal);
    let store = ArtifactStore::open(&store_path, store_limits).unwrap();
    let recovery = DurableDag::recover_typed(
        &journal_path,
        journal_limits,
        store,
        pin,
        &registry,
        chain,
        2,
        limits,
        |_| Ok(Policy::JoinSplit),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), 1);
    assert!(recovery.unresolved_attempts().is_empty());
    let owner = recovery
        .resume(|_| panic!("released attempt resurrected"), || 10)
        .unwrap();
    assert_eq!(
        owner.verified_node_bytes(node_job.id()).unwrap().unwrap(),
        node_bytes
    );
    eprintln!("recovery_registry_fresh cpu_wallet_proofs=1 cpu_node_proofs=1 height={height} wallet_loads=2 node_loads=1 snapshot_equal=true policy_rejected=true registry_rejected=true rehashed_opening_rejected=true durable_reopen=true original_identities={reference_identities} direct_bytes={} reused_bytes={} identity_bytes={} setup_bytes={} direct_calls={} reused_calls={} identity_calls={} setup_calls={}", direct_requests.bytes, reused_requests.bytes, identity.bytes, setup.bytes, direct_requests.calls, reused_requests.calls, identity.calls, setup.calls);
}
