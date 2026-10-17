//! Full-size ordered wallet-policy pairs from the pinned public fixture.

use super::*;

fn selection() -> (u64, bool) {
    let mode = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    typed_pairs::leaf_modes(mode).unwrap();
    let refund = match std::env::var("LATTICA_FULL_SIZE_HTLC_REFUND").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(_) => false,
        _ => panic!("invalid HTLC fixture selection"),
    };
    (mode, refund)
}

fn fixture(
    registry: &Registry<12>,
    mode: u64,
    refund: bool,
) -> ([WalletProof; 2], [Policy; 2], Job) {
    fixture_at(registry, mode, refund, 0)
}

fn fixture_at(
    registry: &Registry<12>,
    mode: u64,
    refund: bool,
    start: u8,
) -> ([WalletProof; 2], [Policy; 2], Job) {
    let kinds = typed_pairs::leaf_modes(mode).unwrap();
    let choices = kinds.map(|kind| match kind {
        programs::WRAPPER => (0, Policy::JoinSplit, "joinsplit"),
        typed_programs::HTLC => (
            if refund { 2 } else { 1 },
            Policy::Htlc {
                expected_height: typed_fixture::HEIGHT,
            },
            if refund { "htlc_refund" } else { "htlc_redeem" },
        ),
        typed_programs::ISSUANCE => (
            3,
            Policy::Issuance {
                authorized_mint: typed_fixture::MINT,
            },
            "issuance",
        ),
        _ => unreachable!(),
    });
    let policies = choices.map(|(_, policy, _)| policy);
    // The second fixture group contains distinct wallets with the same policy.
    let indices = [choices[0].0, choices[1].0 + 4];
    let wallets =
        std::array::from_fn(|slot| wallet(indices[slot], policies[slot], choices[slot].2));
    let pin = RegistryPin::new_typed(registry, registry.id().unwrap()).unwrap();
    let verified: [_; 2] = std::array::from_fn(|slot| {
        VerifiedWallet::verify_typed(
            pin,
            registry,
            typed_fixture::CHAIN,
            policies[slot],
            &read(&directory().join(format!("wallet.{}", indices[slot]))),
        )
        .unwrap()
    });
    assert_ne!(verified[0].summary().root, verified[1].summary().root);
    let job = Job::typed_pair(start, verified[0], Some(verified[1])).unwrap();
    assert_eq!(job.expected_public()[programs::MODE], Val::from_u64(mode));
    assert_eq!((job.expected().count, job.expected().level), (2, 1));
    (wallets, policies, job)
}

fn verify(registry: &Registry<12>, job: &Job, bytes: &[u8]) {
    // Shutdown removes the engine while retaining the selected backend policy.
    assert!(gpu_hash::report("mixed pair CPU verification start").is_none());
    let proof = codec::decode_node(bytes).unwrap();
    let expected = job.expected_public();
    let profile = registry.id().unwrap();
    registry.verify(profile, &proof, &expected).unwrap();
    for index in [0, programs::LEVEL, programs::COUNT, programs::ROOT] {
        let mut altered = expected;
        altered[index] += Val::ONE;
        assert!(registry.verify(profile, &proof, &altered).is_err());
    }
    assert!(gpu_hash::report("mixed pair CPU verification complete").is_none());
}

#[test]
#[ignore = "full-size ordered typed pair under pinned fixture and bounded GPU admission"]
fn full_size_mixed_pair_gpu_proof_matches_archived_registry() {
    assert!(!gpu_hash::is_enabled());
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    let registry = registry();
    let profile = registry.id().unwrap();
    let (mode, refund) = selection();
    let (wallets, policies, job) = fixture(&registry, mode, refund);
    let mut session = Session::new(registry.clone(), profile, 3 << 30).unwrap();
    let proof = session
        .wrap_pair([&wallets[0], &wallets[1]], policies, 2)
        .unwrap();
    assert_eq!(proof.public, job.expected_public());
    let bytes = codec::encode_node(&proof).unwrap();
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 0 }
    );
    assert!(gpu_hash::report("mixed pair GPU proof complete").is_some());
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    verify(&registry, &job, &bytes);
    fs::write(output(), bytes).unwrap();
    println!("full_size_mixed_pair_verified rows={} transactions=2 mode={mode} refund={refund} cpu_verified_after_shutdown=true altered_statements_rejected=4", registry.height);
}

#[test]
#[ignore = "CPU-only verification of a saved mixed pair after GPU worker exit"]
fn full_size_mixed_pair_saved_proof_verifies_without_gpu() {
    assert!(!gpu_hash::is_enabled());
    let registry = registry();
    let (mode, refund) = selection();
    let (_, _, job) = fixture(&registry, mode, refund);
    verify(&registry, &job, &read(&output()));
    println!("full_size_mixed_pair_cpu_verified rows={} transactions=2 mode={mode} refund={refund} gpu_initialized=false altered_statements_rejected=4", registry.height);
}

#[path = "mixed_pairs/tree.rs"]
mod tree;
