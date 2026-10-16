//! Replay an archived public proof through verification, completion and recovery.
use super::*;
use crate::block_v2::{
    codec,
    execution::{job::VerifiedWallet, test_fixture::read},
    profile, typed_fixture,
    typed_recursive::Policy,
};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "CPU replay of pinned full-size public wallet/node proofs; no GPU or proving worker"]
fn accepted_completion_survives_deadline_rejection() {
    // Worker-local reports are optional and untrusted. Even extreme values
    // must not change coordinator admission, verification, or durable recovery.
    for timings in [
        None,
        Some(WorkerTimings {
            input_verification_ms: u64::MAX,
            proving_ms: u64::MAX,
            serialization_ms: u64::MAX,
        }),
    ] {
        check_accepted_completion(timings);
    }
}

fn check_accepted_completion(worker_timings: Option<WorkerTimings>) {
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    assert!(!crate::block_v2::gpu_hash::is_enabled());
    let inputs = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let proofs = PathBuf::from(std::env::var_os("LATTICA_POOL_COMPLETION_PROOFS").unwrap());
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&inputs.join("height.json"), 32).unwrap()).unwrap(),
        caps: std::array::from_fn(|index| {
            let bytes = read(&inputs.join(format!("key.{}", index + 1)), 4096).unwrap();
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    assert_eq!(registry.height, 1 << 18);
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let mut policies = Vec::new();
    let inputs: Vec<_> = [
        Policy::JoinSplit,
        Policy::Htlc {
            expected_height: typed_fixture::HEIGHT,
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(index, policy)| {
        let bytes = read(
            &inputs.join(format!("wallet.{index}")),
            profile::MAX_PROOF_BYTES,
        )
        .unwrap();
        let wallet =
            VerifiedWallet::verify_typed(pin, &registry, typed_fixture::CHAIN, policy, &bytes)
                .unwrap();
        policies.push((wallet.artifact(), policy));
        PublicInput::new(wallet, bytes).unwrap()
    })
    .collect();
    let context = PolicyContext::new([42; 32], policies).unwrap();
    let selection = Selection::new(pin, typed_fixture::CHAIN, &inputs).unwrap();
    assert_eq!(selection.jobs().len(), 2);
    let pair = selection.jobs().next().unwrap();
    let mut matching = None;
    for entry in fs::read_dir(proofs).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_name().to_str().unwrap().starts_with("n-") {
            continue;
        }
        let bytes = read(&entry.path(), profile::MAX_PROOF_BYTES).unwrap();
        let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
        let node = storage.node(&bytes).unwrap();
        if node.public == pair.expected_public() {
            assert!(
                matching.replace(bytes).is_none(),
                "ambiguous public fixture"
            );
        }
    }
    let proof = matching.expect("archived proof of wallets 0 and 1");
    VerifiedNode::verify_typed(pair, &registry, &proof).unwrap();
    let proof_len = proof.len();
    let temp = Temp::new();
    let store_limits = StoreLimits {
        bytes: 32 << 20,
        entries: 16,
    };
    let journal_limits = JournalLimits {
        snapshot_bytes: 1 << 20,
    };
    let resources = Resources {
        ram_bytes: 512 << 20,
        threads: 1,
        ..Resources::default()
    };
    let limits = Limits {
        jobs: 8,
        candidates: 2,
        attempts: 8,
        artifact_bytes: 32 << 20,
        recovery_window_ms: 1000,
        workers: resources,
    };
    let owner = DurableDag::create(
        &temp.0.join("journal"),
        journal_limits,
        ArtifactStore::create(&temp.0.join("artifacts"), store_limits).unwrap(),
        pin,
        typed_fixture::CHAIN,
        1,
        limits,
    )
    .unwrap();
    let state = Rc::new(RefCell::new(Observed::default()));
    let endpoint = SimulatedEndpoint {
        cap: WorkerCapabilities {
            worker: WorkerId(2),
            profile: pin.profile(),
            resources,
            resident_mode: None,
            timing_identity: None,
            forecast_retained_mode: false,
            dispatch_deadline_ms: Some(1_000_000),
        },
        state: state.clone(),
    };
    let mut pool =
        PoolCoordinator::new(owner, registry.clone(), vec![Box::new(endpoint)], 180_000).unwrap();
    // A logical clock exercises a slow but still live completion. This is a
    // correctness test, not a measured candidate or calibration observation.
    let candidate = pool
        .submit(&selection, context.clone(), [3; 32], 400_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    assert!(pool.step(1).unwrap().is_empty());
    let lease = state.borrow().last_lease.unwrap();
    assert_eq!(lease.job(), pair.id());
    state.borrow_mut().result = Some(WorkerResult {
        lease,
        proof,
        worker_timings,
    });
    let completions = pool.step(250_000).unwrap();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].job, pair.id());
    assert_eq!(completions[0].worker, WorkerId(2));
    assert_eq!(completions[0].proof_bytes, proof_len);
    assert!(completions[0].elapsed_ms > 0);
    assert!(completions[0].elapsed_ms < u64::MAX);
    assert_eq!(completions[0].worker_timings, worker_timings);
    assert_eq!(pool.owner.status(pair.id()).unwrap(), JobStatus::Completed);
    assert_eq!(pool.owner.ready().unwrap(), vec![selection.root().id()]);
    assert_eq!(state.borrow().dispatches, 1);
    assert_eq!(state.borrow().closed, 0);
    assert!(pool.idle() && !pool.workers_closed());
    assert_eq!(pool.owner.resource_use().unwrap(), Resources::default());
    assert!(pool.root(candidate, [3; 32], 260_000).unwrap().is_none());
    // The completion is returned once; the same admission failure must remain
    // visible on subsequent polls without dispatching the inadmissible parent.
    for now in [260_000, 270_000] {
        assert_eq!(
            pool.step(now).err().unwrap().to_string(),
            "pool has no deadline-admissible placement"
        );
        assert_eq!(state.borrow().dispatches, 1);
        assert_eq!(state.borrow().closed, 0);
    }
    pool.close(280_000).unwrap();
    drop(pool);
    let recovery = DurableDag::recover_typed(
        &temp.0.join("journal"),
        journal_limits,
        ArtifactStore::open(&temp.0.join("artifacts"), store_limits).unwrap(),
        pin,
        &registry,
        typed_fixture::CHAIN,
        2,
        limits,
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert!(recovery.unresolved_attempts().is_empty());
    assert!(recovery.unresolved_workspaces().is_empty());
    let owner = recovery
        .resume(|_| panic!("no outstanding worker"), || 280_001)
        .unwrap();
    assert_eq!(owner.status(pair.id()).unwrap(), JobStatus::Completed);
    let bytes = owner.verified_node_bytes(pair.id()).unwrap().unwrap();
    assert_eq!(bytes.len(), proof_len);
    VerifiedNode::verify_typed(pair, &registry, bytes).unwrap();
    assert!(owner
        .verified_node_bytes(selection.root().id())
        .unwrap()
        .is_none());
    println!("pool_completion_deadline verified=1 returned_once=true dispatched=1 next_poll_rejected=true recovered=true root_available=false");
}
