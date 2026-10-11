use super::*;
use crate::block_v2::{codec, gpu_hash, quotient_pcs};

#[test]
#[ignore = "requires GPU-required OpenCL, stage reports and a <=3 GiB zero-swap service"]
fn explicit_budget_gpu_session_reuses_evicts_and_verifies_after_shutdown() {
    // The controller checks every emitted scope, including all 16 arithmetic
    // stages on the three whole requests. Debug CPU audits cannot qualify.
    assert!(!cfg!(debug_assertions));
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").unwrap(),
        "gpu-required"
    );
    assert_eq!(std::env::var("LATTICA_PROVING_REPORT").unwrap(), "1");
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(quotient_pcs::gpu_witness_enabled());
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());

    let height = 2048;
    let budget = 1 << 30;
    let mut registry = Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let compiled = programs::empty(height, &registry.caps).unwrap();
    let registered = RegisteredProgram::new_with_memory_budget(
        MachineAir::new(compiled.program.pad_to(height).unwrap()),
        storage::active_memory_bytes(budget).unwrap(),
    )
    .unwrap();
    registry.caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    let pin = registry.id().unwrap();

    let before = gpu_hash::report("legacy short budget before").unwrap();
    assert!(profile::preprocessing_config_with_host_budget(0).is_err());
    assert!(profile::make_proving_config_with_host_budget(0).is_err());
    for short in [
        0,
        storage::SESSION_HOST_BYTES,
        storage::STARTUP_HOST_BYTES - 1,
    ] {
        assert!(ProverSession::new_with_memory_budget(registry.clone(), pin, short).is_err());
    }
    let after = gpu_hash::report("legacy short budget after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);

    let mut session = ProverSession::new_with_memory_budget(registry.clone(), pin, budget).unwrap();
    assert_eq!(session.memory_budget_bytes(), budget);
    let mut encoded = Vec::new();
    for _ in 0..2 {
        encoded.push(codec::encode_node(&session.empty(DEMO_CHAIN, 0).unwrap()).unwrap());
    }
    assert_eq!(session.stats(), CacheStats { setups: 1, hits: 1 });
    // Compare fresh encodings of identical statements, not different levels.
    assert_ne!(encoded[0], encoded[1]);
    session.clear();
    assert!(session.cached.is_none());
    encoded.push(codec::encode_node(&session.empty(DEMO_CHAIN, 5).unwrap()).unwrap());
    assert_eq!(session.stats(), CacheStats { setups: 2, hits: 1 });
    // Session approval remains tied to its registry through cache reuse and
    // eviction. Numerical verification is CPU work outside the proving scope.
    for bytes in &encoded {
        let mut proof = codec::decode_node(bytes).unwrap();
        let approved = session.registry_approval();
        approved.verify(&proof, &proof.public).unwrap();
        let mut wrong = proof.public;
        wrong[programs::ROOT] += Val::ONE;
        assert!(approved.verify(&proof, &wrong).is_err());
        proof.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
        assert!(approved.verify(&proof, &proof.public).is_err());
    }
    eprintln!("legacy_session_gpu_approval fresh_proofs=3 retained_approval_accepts=true public_and_opening_mutations_reject=true cache_setups=2 cache_hits=1");
    drop(session);
    gpu_hash::shutdown().unwrap();

    // Reference arithmetic and numerical acceptance run after device shutdown.
    for (bytes, level) in encoded.iter().zip([0, 0, 5]) {
        let proof = codec::decode_node(bytes).unwrap();
        let reference = commitment::empty_subtree(
            Context {
                profile_id: pin,
                chain_id: DEMO_CHAIN,
            },
            level,
        )
        .unwrap();
        assert_eq!(
            proof.public,
            programs::statement(reference, programs::EMPTY)
        );
        registry.verify(pin, &proof, &proof.public).unwrap();

        let mut wrong = proof.public;
        wrong[programs::ROOT] += Val::ONE;
        assert!(registry.verify(pin, &proof, &wrong).is_err());

        let mut changed_public = codec::decode_node(bytes).unwrap();
        changed_public.public[programs::COUNT] += Val::ONE;
        summary(&changed_public.public).unwrap();
        assert!(registry
            .verify(pin, &changed_public, &changed_public.public)
            .is_err());

        let mut changed_opening = codec::decode_node(bytes).unwrap();
        changed_opening.proof.opened_values.instances[0].permutation_local[0] +=
            profile::Challenge::ONE;
        assert!(registry
            .verify(pin, &changed_opening, &changed_opening.public)
            .is_err());
    }
    eprintln!(
        "legacy_gpu_budget_result {}",
        serde_json::json!({
            "proofs": encoded.len(), "height": height, "assigned_bytes": budget,
            "active_bytes": storage::active_memory_bytes(budget).unwrap(),
            "short_budget_rejections": 3, "short_config_rejections": 2,
            "cache_setups": 2, "cache_hits": 1,
            "fresh_same_statement_encodings": true, "verified_after_shutdown": true,
            "wrong_expected_root_rejections": 3, "changed_public_rejections": 3,
            "changed_opening_rejections": 3,
        })
    );
}
