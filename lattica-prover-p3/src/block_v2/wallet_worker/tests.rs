use super::*;

#[test]
#[ignore = "requires a release build in a bounded wallet-owned RTX service"]
fn wallet_worker_direct_requests_cannot_bypass_admission() {
    use crate::block_v2::{commitment::Context, gpu_hash, leaf, profile, typed_leaf};
    use crate::proving::{Backend, Capabilities, Profile, Run, Stage};
    use crate::{config::Val, htlc_air as htlc, joinsplit_air as js};
    use p3_field::PrimeCharacteristicRing;
    assert!(is_assigned());
    let required = Request::from_env().unwrap();
    assert_eq!(required.policy, Policy::GpuRequired);
    let mut capabilities = Capabilities::cpu(Profile::LegacyQuadratic, true, false);
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        capabilities.set(stage, Backend::OpenCl);
    }
    assert!(Run::new(
        "wallet_worker_before_startup",
        required,
        capabilities.clone()
    )
    .is_err());
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 0);
    assert!(admit(required).is_ok());
    for policy in [Policy::Compatible, Policy::CpuRequired] {
        let request = Request {
            policy,
            emit_report: false,
        };
        assert!(request.admit(&capabilities).is_err());
        assert!(Run::new("wallet_worker_direct_policy", request, capabilities.clone()).is_err());
        assert!(admit(request).is_err());
    }
    // The environment alone cannot attest a caller's actual Rayon pool size.
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap()
        .install(|| {
            assert!(admit(required).is_err());
        });
    assert!(super::super::native_gpu::reject_after_engine_for_test(false).is_err());
    assert_eq!(crate::native_gpu::lattica_gpu_drain(), 0);
    assert!(admit(required).is_ok());
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x53; 32],
    };
    let spend = js::demo_witness();
    let htlc = htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100);
    let mut issue = js::demo_witness();
    issue.mint = 17;
    issue.fee = 0;
    issue.outputs[0].value = issue.mint;
    issue.outputs[1].value = issue.inputs.iter().map(|v| v.value).sum();
    let before = gpu_hash::report("wallet_worker_private_rejection_before").unwrap();
    let compatible = Request::compatible();
    assert!(leaf::prove_joinsplit_with_request(&spend, &context, compatible).is_err());
    assert!(leaf::prove_joinsplit_with_gpu_witness(&spend, &context, compatible, 1 << 30).is_err());
    assert!(typed_leaf::prove_htlc_with_request(&htlc, &context, compatible).is_err());
    assert!(typed_leaf::prove_issuance_with_request(&issue, &context, 17, compatible).is_err());
    let after = gpu_hash::report("wallet_worker_private_rejection_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    let spend_proof = leaf::prove_joinsplit_with_request(&spend, &context, required).unwrap();
    let htlc_proof = typed_leaf::prove_htlc_with_request(&htlc, &context, required).unwrap();
    let issue_proof =
        typed_leaf::prove_issuance_with_request(&issue, &context, 17, required).unwrap();
    assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 0);
    leaf::verify_joinsplit_research(&spend_proof, &context, &js::public_values(&spend)).unwrap();
    typed_leaf::verify_htlc_research(
        &htlc_proof,
        &context,
        &htlc::public_values(&htlc),
        htlc.current_height,
    )
    .unwrap();
    typed_leaf::verify_issuance_research(&issue_proof, &context, &js::public_values(&issue), 17)
        .unwrap();
    assert!(Request::compatible().admit(&capabilities).is_err());
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 0);
    assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 0);
    eprintln!("wallet_worker_direct_admission_matched proofs=3 startup_pin=true explicit_requests=true actual_rayon=true borrowed_engine=true rejected_uploads=0");
}

fn assignment() -> serde_json::Value {
    serde_json::json!({
        "schema": "lattica-wallet-local-gpu-v1",
        "service": "lattica-wallet-unit.service",
        "gpu_uuid": "GPU-00000000-0000-0000-0000-000000000000",
        "host_bytes": 3u64 << 30,
        "threads": 4,
        "managed_gpu_bytes": 1u64 << 30,
        "context_gpu_bytes": 4u64 << 30,
        "host_output_bytes": 1u64 << 30,
    })
}

#[test]
fn wallet_assignment_is_closed_and_bounded() {
    let valid = assignment();
    let budget: Budget = serde_json::from_value(valid.clone()).unwrap();
    budget.validate().unwrap();
    for (key, value) in [
        ("schema", serde_json::json!("public-recursive-v1")),
        (
            "service",
            serde_json::json!("lattica-public-worker.service"),
        ),
        ("service", serde_json::json!("lattica-wallet-.service")),
        (
            "service",
            serde_json::json!("lattica-wallet-../unit.service"),
        ),
        ("gpu_uuid", serde_json::json!("GPU-invalid")),
        ("host_bytes", serde_json::json!(0)),
        ("host_bytes", serde_json::json!(u64::MAX)),
        ("threads", serde_json::json!(0)),
        ("threads", serde_json::json!(257)),
        ("managed_gpu_bytes", serde_json::json!(0)),
        ("managed_gpu_bytes", serde_json::json!(9u64 << 30)),
        ("context_gpu_bytes", serde_json::json!((512u64 << 20) - 1)),
        ("context_gpu_bytes", serde_json::json!(u64::MAX)),
        ("host_output_bytes", serde_json::json!(0)),
        ("host_output_bytes", serde_json::json!(4u64 << 30)),
    ] {
        let mut changed = valid.clone();
        changed[key] = value;
        assert!(
            serde_json::from_value::<Budget>(changed).is_ok_and(|b| b.validate().is_err()),
            "{key}"
        );
    }
    let mut private_payload = valid.clone();
    private_payload["witness"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<Budget>(private_payload).is_err());
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("host_output_bytes");
    assert!(serde_json::from_value::<Budget>(missing).is_err());
    let duplicate = serde_json::to_string(&valid)
        .unwrap()
        .replacen('{', "{\"threads\":4,", 1);
    assert!(serde_json::from_str::<Budget>(&duplicate).is_err());
}

#[test]
fn wallet_worker_requires_finite_cpu_and_memory_limits() {
    assert_eq!(finite("3221225472\n").unwrap(), 3u64 << 30);
    assert_eq!(finite("0").unwrap(), 0);
    for value in [
        "max",
        "",
        "-1",
        "+1",
        "1 2",
        " 1",
        "1\n\n",
        "18446744073709551616",
    ] {
        assert!(finite(value).is_err(), "{value:?}");
    }
    cpu_limit("400000 100000\n", 4).unwrap();
    cpu_limit("200000 100000", 4).unwrap();
    for value in [
        "max 100000",
        "0 100000",
        "400001 100000",
        "4 0",
        "4 999",
        "400000 100000 extra",
    ] {
        assert!(cpu_limit(value, 4).is_err(), "{value:?}");
    }
}
