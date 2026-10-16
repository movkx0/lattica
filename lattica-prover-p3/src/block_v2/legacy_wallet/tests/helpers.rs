use super::*;

#[test]
#[ignore = "requires release owned OpenCL proving in a bounded zero-swap service"]
fn gpu_wallet_convenience_helpers_prove_and_independently_verify() {
    assert!(
        !cfg!(debug_assertions),
        "strict GPU coverage requires release mode"
    );
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(is_selected());

    // CPU computations here are explicit test oracles for the verifier inputs.
    // Every proving helper independently derives its own statement on GPU.
    let spend = js::demo_witness();
    let redeem = htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100);
    let js_public = js::public_values(&spend);
    let htlc_public = htlc::public_values(&redeem);
    let _policy = Env::set("LATTICA_PROVING_POLICY", "gpu-required");
    let _reports = Env::set("LATTICA_PROVING_REPORT", "1");

    let before = gpu_hash::report("wallet_helper_admission_before").unwrap();
    {
        let _denied = Env::set("LATTICA_PROVING_POLICY", "cpu-required");
        assert!(js::prove_verify(&spend).is_err());
        assert!(js::prove_verify_with(&spend, &js_public).is_err());
        assert!(js::prove_real_verify_with(&spend, &js_public).is_err());
        assert!(htlc::prove_verify(&redeem).is_err());
        assert!(htlc::prove_verify_with(&redeem, &htlc_public).is_err());
        assert!(htlc::prove_real_verify_with(&redeem, &htlc_public).is_err());
        assert!(std::panic::catch_unwind(|| js::measure(&spend)).is_err());
        assert!(std::panic::catch_unwind(|| htlc::measure(&redeem)).is_err());
    }
    let after = gpu_hash::report("wallet_helper_admission_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);

    js::prove_verify(&spend).unwrap();
    js::prove_verify_with(&spend, &js_public).unwrap();
    js::prove_real_verify_with(&spend, &js_public).unwrap();
    htlc::prove_verify(&redeem).unwrap();
    htlc::prove_verify_with(&redeem, &htlc_public).unwrap();
    htlc::prove_real_verify_with(&redeem, &htlc_public).unwrap();
    for (bytes, _, _, proven) in [js::measure(&spend), htlc::measure(&redeem)] {
        assert!(0 < bytes && bytes <= crate::MAX_PROOF_LEN);
        assert!(proven >= 100);
    }

    // A successful GPU proof must still fail verification against changed
    // public values. The helper's success result includes the separate audit.
    let mut wrong_js = js_public.clone();
    wrong_js[js::PI_FEE] += Val::ONE;
    let mut wrong_htlc = htlc_public.clone();
    wrong_htlc[htlc::PI_HEIGHT] += Val::ONE;
    assert!(js::prove_verify_with(&spend, &wrong_js).is_err());
    assert!(js::prove_real_verify_with(&spend, &wrong_js).is_err());
    assert!(htlc::prove_verify_with(&redeem, &wrong_htlc).is_err());
    assert!(htlc::prove_real_verify_with(&redeem, &wrong_htlc).is_err());

    gpu_hash::shutdown().unwrap();
    assert!(js::prove_verify(&spend).is_err());
    assert!(js::prove_verify_with(&spend, &js_public).is_err());
    assert!(js::prove_real_verify_with(&spend, &js_public).is_err());
    assert!(htlc::prove_verify(&redeem).is_err());
    assert!(htlc::prove_verify_with(&redeem, &htlc_public).is_err());
    assert!(htlc::prove_real_verify_with(&redeem, &htlc_public).is_err());
    assert!(std::panic::catch_unwind(|| js::measure(&spend)).is_err());
    assert!(std::panic::catch_unwind(|| htlc::measure(&redeem)).is_err());
}
