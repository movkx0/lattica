//! Saved outputs contain only public fixtures. The CPU-only audit runs in a
//! separate process without any GPU feature or private-wallet assignment.
use super::*;

fn directory() -> std::path::PathBuf {
    let path =
        std::path::PathBuf::from(std::env::var_os("LATTICA_CUDA_WALLET_ARTIFACT_DIR").unwrap());
    assert!(path.is_absolute() && path.is_dir());
    path
}

fn audit_legacy(kind: usize, proof: &[u8], public: &[u8]) {
    let (expected, verified) = if kind == 0 {
        let expected =
            crate::encode_joinsplit_public_inputs(&js::public_values(&js::demo_witness())).unwrap();
        let values = crate::parse_joinsplit_public_inputs(public).unwrap();
        (expected, js::verify_bytes(proof, &values))
    } else {
        let expected =
            crate::encode_htlc_public_inputs(&htlc::public_values(&htlc::demo_htlc_witness()))
                .unwrap();
        let values = crate::parse_htlc_public_inputs(public).unwrap();
        (expected, htlc::verify_bytes(proof, &values))
    };
    assert_eq!(expected, public);
    assert!(verified);
    let mut changed = proof.to_vec();
    // Mutating a transcript claim preserves the encoding shape but must fail
    // verification, independently of whether random byte damage would parse.
    let mut decoded: p3_uni_stark::Proof<crate::config::MyConfig> =
        postcard::from_bytes(proof).unwrap();
    decoded.opened_values.trace_local[0] += crate::config::Challenge::ONE;
    changed.clear();
    changed.extend(postcard::to_allocvec(&decoded).unwrap());
    let mut statement = if kind == 0 {
        crate::parse_joinsplit_public_inputs(public).unwrap()
    } else {
        crate::parse_htlc_public_inputs(public).unwrap()
    };
    let verifier = if kind == 0 {
        js::verify_bytes
    } else {
        htlc::verify_bytes
    };
    assert!(!verifier(&changed, &statement));
    statement[0] += Val::ONE;
    assert!(!verifier(proof, &statement));
}

fn audit_context(index: usize, bytes: &[u8]) {
    let fixtures = fixtures();
    let (_, _, expected, policy) = &fixtures[index];
    verify_export(bytes, expected, *policy);
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let mut wallet: WalletProof = codec::decode(&bytes[24..16 + length]).unwrap();
    wallet.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(typed_recursive::verify_wallet(&wallet, *policy).is_err());
}

#[cfg(not(any(feature = "gpu", feature = "gpu-cuda", feature = "gpu-metal")))]
#[test]
#[ignore = "independent CPU-only process auditing saved CUDA wallet outputs"]
fn saved_cuda_wallet_outputs_pass_independent_cpu_audit() {
    assert_eq!(
        crate::proving::Request::from_env().unwrap().policy,
        crate::proving::Policy::CpuRequired
    );
    assert!(std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_none());
    assert!(std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_none());
    let dir = directory();
    for kind in 0..2 {
        for repetition in 0..2 {
            audit_legacy(
                kind,
                &std::fs::read(dir.join(format!("legacy-{kind}-{repetition}.proof"))).unwrap(),
                &std::fs::read(dir.join(format!("legacy-{kind}-{repetition}.public"))).unwrap(),
            );
        }
    }
    for index in 0..4 {
        audit_context(
            index,
            &std::fs::read(dir.join(format!("context-{index}.bin"))).unwrap(),
        );
    }
    audit_context(0, &std::fs::read(dir.join("context-repeat.bin")).unwrap());
    eprintln!("cuda_wallet_cpu_audit accepted=9 altered_statements_rejected=9 altered_proofs_rejected=9 altered_contexts_rejected=5");
}

#[cfg(all(feature = "gpu-cuda", feature = "stream", target_os = "linux"))]
#[test]
#[ignore = "fresh bounded CUDA private-wallet service with immutable assignment"]
fn native_cuda_wallet_routes_are_admitted_audited_and_retired() {
    use crate::{block_v2::cuda_wallet, native_gpu::*};
    use cuda_wallet::tests::{snapshot, Boundary};
    let dir = directory();
    assert!(!dir.join("context-0.bin").exists());
    // Build public reference fixtures before enabling decode boundary probes.
    let fixtures = fixtures();
    let legacy = [
        crate::encode_joinsplit_witness(&js::demo_witness()),
        crate::encode_htlc_witness(&htlc::demo_htlc_witness()),
    ];
    let original = std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").unwrap();
    let oracle_before = crate::proving::cpu_witness_oracle_calls();
    assert!(prove(&[], &[])
        .unwrap_err()
        .downcast_ref::<crate::proving::Error>()
        .is_some());
    let start = std::time::Instant::now();
    assert_eq!(lattica_gpu_initialize_from_env(), 0);
    assert_eq!(lattica_gpu_initialize_from_env(), 0);
    let startup_seconds = start.elapsed().as_secs_f64();
    let baseline = snapshot();
    let probe = Boundary::new();
    // Environment/resource changes must fail at admission, before decoding.
    for (name, value) in [
        ("LATTICA_V2_WORKER_BUDGET", "/invalid-public-assignment"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "1"),
        ("LATTICA_V2_GPU_MANAGED_BYTES", "1"),
        (
            "LATTICA_GPU_DEVICE_UUID",
            "GPU-00000000-0000-0000-0000-000000000000",
        ),
        ("LATTICA_PROVING_POLICY", "compatible"),
        ("RAYON_NUM_THREADS", "1"),
    ] {
        let old = std::env::var_os(name);
        std::env::set_var(name, value);
        assert!(prove(&[], &[])
            .unwrap_err()
            .downcast_ref::<crate::proving::Error>()
            .is_some());
        match old {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
    std::env::remove_var("LATTICA_WALLET_WORKER_BUDGET");
    assert!(prove(&[], &[])
        .unwrap_err()
        .downcast_ref::<crate::proving::Error>()
        .is_some());
    std::env::set_var("LATTICA_WALLET_WORKER_BUDGET", &original);
    assert_eq!(probe.calls(), 0);
    assert_eq!(snapshot(), baseline);
    // Unsupported batch/tree routes must not borrow the single-wallet permit.
    type Batch = unsafe extern "C" fn(
        *const u8,
        usize,
        usize,
        *mut u8,
        usize,
        *mut usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> i32;
    for (call, input) in [
        (crate::lattica_batch_prove as Batch, &legacy[0]),
        (crate::lattica_htlc_batch_prove as Batch, &legacy[1]),
        (crate::lattica_joinsplit_tree_prove as Batch, &legacy[0]),
    ] {
        let mut proof = [0xa5; 8];
        let mut public = [0xa5; 32];
        let mut proof_len = 123;
        let mut public_len = 123;
        assert_eq!(
            unsafe {
                call(
                    input.as_ptr(),
                    input.len(),
                    1,
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut proof_len,
                    public.as_mut_ptr(),
                    public.len(),
                    &mut public_len,
                )
            },
            1
        );
        assert_eq!(proof, [0xa5; 8]);
        assert_eq!(public, [0xa5; 32]);
    }
    assert_eq!(probe.calls(), 0);
    let mut timings = Vec::new();
    type Single = unsafe extern "C" fn(
        *const u8,
        usize,
        *mut u8,
        usize,
        *mut usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> i32;
    for (kind, call) in [
        crate::lattica_joinsplit_prove as Single,
        crate::lattica_htlc_prove as Single,
    ]
    .into_iter()
    .enumerate()
    {
        let mut prior = Vec::new();
        for repetition in 0..2 {
            let mut proof = vec![0; 2 << 20];
            let mut public = vec![0; 1024];
            let mut proof_len = 0;
            let mut public_len = 0;
            let started = std::time::Instant::now();
            assert_eq!(
                unsafe {
                    call(
                        legacy[kind].as_ptr(),
                        legacy[kind].len(),
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        public.as_mut_ptr(),
                        public.len(),
                        &mut public_len,
                    )
                },
                0
            );
            timings.push((
                format!("legacy-{kind}-{repetition}"),
                started.elapsed().as_secs_f64(),
            ));
            proof.truncate(proof_len);
            public.truncate(public_len);
            assert_ne!(prior, proof);
            prior = proof.clone();
            std::fs::write(dir.join(format!("legacy-{kind}-{repetition}.proof")), proof).unwrap();
            std::fs::write(
                dir.join(format!("legacy-{kind}-{repetition}.public")),
                public,
            )
            .unwrap();
        }
    }
    for (index, (request, witness, _, _)) in fixtures.iter().enumerate() {
        let started = std::time::Instant::now();
        let bytes = export(request, witness);
        timings.push((format!("context-{index}"), started.elapsed().as_secs_f64()));
        std::fs::write(dir.join(format!("context-{index}.bin")), &bytes).unwrap();
        if index == 0 {
            let repeated = export(request, witness);
            assert_ne!(bytes, repeated);
            std::fs::write(dir.join("context-repeat.bin"), repeated).unwrap();
        }
    }
    assert_eq!(probe.calls(), 9);
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), oracle_before);
    // Policy and malformed witness failures return no export; a healthy engine
    // must keep only its public preparation after those attempts.
    let wrong_height = request(2, 98, 0);
    assert!(prove(&wrong_height, &fixtures[2].1).is_err());
    assert!(prove(&request(1, 0, 0), &fixtures[1].1).is_err());
    assert!(prove(&request(3, 0, 8), &fixtures[1].1).is_err());
    let mut invalid = js::demo_witness();
    invalid.fee += 1;
    let bad = crate::encode_joinsplit_witness(&invalid);
    let before_invalid = crate::proving::cpu_witness_oracle_calls();
    assert!(prove(&fixtures[0].0, &bad).is_err());
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), before_invalid);
    let after = snapshot();
    assert_eq!(after.live_bytes, baseline.live_bytes);
    assert_eq!(after.allocations, baseline.allocations);
    assert_eq!(after.modules, baseline.modules);
    assert_eq!(after.public_programs, baseline.public_programs);
    assert_eq!(after.pending_commands, 0);
    drop(probe);
    for kind in 0..2 {
        for repetition in 0..2 {
            audit_legacy(
                kind,
                &std::fs::read(dir.join(format!("legacy-{kind}-{repetition}.proof"))).unwrap(),
                &std::fs::read(dir.join(format!("legacy-{kind}-{repetition}.public"))).unwrap(),
            );
        }
    }
    for index in 0..4 {
        audit_context(
            index,
            &std::fs::read(dir.join(format!("context-{index}.bin"))).unwrap(),
        );
    }
    audit_context(0, &std::fs::read(dir.join("context-repeat.bin")).unwrap());
    assert_eq!(lattica_gpu_drain(), 0);
    assert_eq!(lattica_gpu_shutdown(), 0);
    assert_eq!(lattica_gpu_shutdown(), 0);
    assert_eq!(lattica_gpu_initialize_from_env(), 1);
    assert!(prove(&[], &[])
        .unwrap_err()
        .downcast_ref::<crate::proving::Error>()
        .is_some());
    std::env::remove_var("LATTICA_WALLET_WORKER_BUDGET");
    std::env::set_var("LATTICA_PROVING_POLICY", "compatible");
    assert!(prove(&[], &[])
        .unwrap_err()
        .downcast_ref::<crate::proving::Error>()
        .is_some());
    std::fs::write(
        dir.join("measurements.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "startup_seconds": startup_seconds, "calls_seconds": timings,
            "peak": after, "accepted_proofs": 9, "independent_cpu_audit_pending": true,
            "boundary": "native single-wallet/export latency; not block throughput"
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("native_cuda_wallet_qualified proofs=9 private_decode_pinned=true concurrent_call_rejected=true cpu_witness_oracle_calls=0 unsupported_batch_tree_rejected=true retired=true");
}
