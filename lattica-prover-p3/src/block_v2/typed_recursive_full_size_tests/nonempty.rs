use super::*;

// Two nonempty, contiguous pair jobs use four distinct archived transactions.
// Job ranges describe their positions in this four-transaction block, not their
// indices in the larger public fixture from which the wallets were selected.
fn fixture(registry: &Registry<12>) -> ([WalletProof; 4], [Job; 4]) {
    let profile = registry.id().unwrap();
    let pin = RegistryPin::new_typed(registry, profile).unwrap();
    let indices = [0, 4, 8, 12];
    let wallets = indices.map(|index| wallet(index, Policy::JoinSplit, "joinsplit"));
    let verified = indices.map(|index| {
        VerifiedWallet::verify_typed(
            pin,
            registry,
            typed_fixture::CHAIN,
            Policy::JoinSplit,
            &read(&directory().join(format!("wallet.{index}"))),
        )
        .unwrap()
    });
    for left in 0..4 {
        for right in left + 1..4 {
            assert_ne!(wallets[left].public, wallets[right].public);
            assert_ne!(
                verified[left].summary().root,
                verified[right].summary().root
            );
        }
    }
    let left = Job::typed_pair(0, verified[0], Some(verified[1])).unwrap();
    let right = Job::typed_pair(2, verified[2], Some(verified[3])).unwrap();
    let merge = Job::merge(&left, &right).unwrap();
    let finalizer = Job::finalize(&merge).unwrap();
    assert_eq!((merge.expected().count, merge.expected().level), (4, 2));
    assert_eq!(
        (finalizer.expected().count, finalizer.expected().level),
        (4, commitment::DEPTH)
    );
    (wallets, [left, right, merge, finalizer])
}

fn mode() -> (u64, usize) {
    let mode = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    let index = match mode {
        programs::WRAPPER => 1,
        programs::MERGE => 2,
        typed_pairs::FINALIZE => 3,
        _ => panic!("unsupported nonempty qualification mode"),
    };
    (mode, index)
}

fn verify_node(registry: &Registry<12>, job: &Job, bytes: &[u8]) {
    // Backend selection remains enabled after shutdown; absence of the engine
    // proves these checks run without a surviving GPU context or allocations.
    assert!(gpu_hash::report("nonempty CPU verification start").is_none());
    let profile = registry.id().unwrap();
    let decoded = codec::decode_node(bytes).unwrap();
    let expected = job.expected_public();
    registry.verify(profile, &decoded, &expected).unwrap();
    for index in [0, programs::LEVEL, programs::COUNT, programs::ROOT] {
        let mut altered = expected;
        altered[index] += Val::ONE;
        assert!(registry.verify(profile, &decoded, &altered).is_err());
    }
    assert!(gpu_hash::report("nonempty CPU verification complete").is_none());
}

#[test]
#[ignore = "full-size four-distinct-wallet pair/merge/finalizer under owned GPU admission"]
fn full_size_nonempty_gpu_proof_matches_archived_registry() {
    assert!(!gpu_hash::is_enabled());
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    let registry = registry();
    let profile = registry.id().unwrap();
    let (wallets, jobs) = fixture(&registry);
    let (mode, index) = mode();
    let load = |name: &str, job: &Job| {
        let path = PathBuf::from(std::env::var_os(name).unwrap());
        let node = codec::decode_node(&read(&path)).unwrap();
        registry
            .verify(profile, &node, &job.expected_public())
            .unwrap();
        node
    };
    let dependencies = match mode {
        programs::WRAPPER => vec![],
        programs::MERGE => vec![
            load("LATTICA_FULL_SIZE_PAIR", &jobs[0]),
            load("LATTICA_FULL_SIZE_RIGHT_PAIR", &jobs[1]),
        ],
        typed_pairs::FINALIZE => vec![load("LATTICA_FULL_SIZE_MERGE", &jobs[2])],
        _ => unreachable!(),
    };
    let mut session = Session::new(registry.clone(), profile, 3 << 30).unwrap();
    let proof = match mode {
        programs::WRAPPER => {
            session.wrap_pair([&wallets[2], &wallets[3]], [Policy::JoinSplit; 2], 2)
        }
        programs::MERGE => session.merge(&dependencies[0], &dependencies[1]),
        typed_pairs::FINALIZE => session.finalize(&dependencies[0]),
        _ => unreachable!(),
    }
    .unwrap();
    assert_eq!(proof.public, jobs[index].expected_public());
    let bytes = codec::encode_node(&proof).unwrap();
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 0 }
    );
    assert!(gpu_hash::report("nonempty GPU proof complete").is_some());
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    verify_node(&registry, &jobs[index], &bytes);
    fs::write(output(), bytes).unwrap();
    println!("full_size_nonempty_gpu_verified rows={} transactions={} mode={mode} level={} wallets=0,4,8,12 archived_registry=true cpu_verified_after_shutdown=true altered_statements_rejected=4", registry.height, jobs[index].expected().count, jobs[index].expected().level);
}

#[test]
#[ignore = "independent CPU verification of a persisted nonempty proof after its GPU process exits"]
fn full_size_nonempty_proof_verifies_after_worker_exit() {
    assert!(!gpu_hash::is_enabled());
    let registry = registry();
    let (_, jobs) = fixture(&registry);
    let (mode, index) = mode();
    verify_node(&registry, &jobs[index], &read(&output()));
    println!("full_size_nonempty_cpu_verified rows={} transactions={} mode={mode} level={} gpu_initialized=false altered_statements_rejected=4", registry.height, jobs[index].expected().count, jobs[index].expected().level);
}
