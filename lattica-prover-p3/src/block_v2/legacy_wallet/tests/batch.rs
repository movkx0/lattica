use super::*;
use crate::{batch_htlc_air as bh, batch_joinsplit_air as bj};

fn initialize() {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(is_selected());
}

fn policy() -> Policy {
    if cfg!(debug_assertions) {
        Policy::Compatible
    } else {
        Policy::GpuRequired
    }
}

fn witnesses() -> (Vec<js::Witness>, Vec<htlc::Witness>) {
    (
        vec![
            js::demo_witness(),
            issuance(17),
            issuance((1u64 << js::BITS) - 1),
        ],
        vec![
            htlc::demo_witness(),
            htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100),
            htlc::tests::htlc_witness(false, 100, [Val::ONE; 4], 100),
        ],
    )
}

#[test]
#[ignore = "requires complete owned OpenCL path and bounded zero-swap service"]
fn gpu_legacy_batch_proofs_verify_after_shutdown_with_unchanged_cpu_verifiers() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let (js, htlc) = witnesses();
    let before = gpu_hash::report("legacy_batch_admission_before").unwrap();
    assert!(bj::prove_batch_to_bytes_with_request(&js, request(Policy::CpuRequired)).is_err());
    assert!(bh::prove_batch_to_bytes_with_request(&htlc, request(Policy::CpuRequired)).is_err());
    if cfg!(debug_assertions) {
        assert!(bj::prove_batch_to_bytes_with_request(&js, request(Policy::GpuRequired)).is_err());
        assert!(
            bh::prove_batch_to_bytes_with_request(&htlc, request(Policy::GpuRequired)).is_err()
        );
    }
    for (name, value) in [
        ("LATTICA_V2_WORKER_BUDGET", "private-batch-not-admitted"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "4096"),
    ] {
        let _env = Env::set(name, value);
        assert!(bj::prove_batch_to_bytes_with_request(&js, request(policy())).is_err());
        assert!(bh::prove_batch_to_bytes_with_request(&htlc, request(policy())).is_err());
    }
    let oversized: Vec<_> = (0..=crate::batch_common::MAX_BATCH_TILES)
        .map(|_| bj::dummy_witness())
        .collect();
    assert!(bj::prove_batch_to_bytes_with_request(&oversized, request(policy())).is_err());
    let after = gpu_hash::report("legacy_batch_admission_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    let mut invalid = js.clone();
    invalid[1].fee += 1;
    assert!(bj::prove_batch_to_bytes_with_request(&invalid, request(policy())).is_err());
    let mut invalid_htlc = htlc.clone();
    invalid_htlc[0].mint = 1;
    invalid_htlc[0].outputs[0].value += 1;
    assert!(bh::prove_batch_to_bytes_with_request(&invalid_htlc, request(policy())).is_err());
    let mut results = Vec::new();
    for count in [0usize, 1, 3, 3] {
        let (bytes, report) =
            bj::prove_batch_to_bytes_with_request(&js[..count], request(policy())).unwrap();
        check_report(&report);
        results.push((false, count, bytes, bj::batch_root(&js[..count])));
    }
    for count in [0usize, 1, 3, 3] {
        let (bytes, report) =
            bh::prove_batch_to_bytes_with_request(&htlc[..count], request(policy())).unwrap();
        check_report(&report);
        results.push((true, count, bytes, bh::batch_root(&htlc[..count])));
    }
    assert_ne!(results[2].2, results[3].2);
    assert_ne!(results[6].2, results[7].2);
    gpu_hash::shutdown().unwrap();
    assert!(bj::prove_batch_to_bytes_with_request(&js, request(Policy::Compatible)).is_err());
    assert!(bh::prove_batch_to_bytes_with_request(&htlc, request(Policy::Compatible)).is_err());
    for (htlc, count, bytes, root) in results {
        let verify = if htlc {
            bh::verify_batch_bytes
        } else {
            bj::verify_batch_bytes
        };
        assert!(verify(&bytes, &root));
        let mut wrong_root = root;
        wrong_root[0] += Val::ONE;
        assert!(!verify(&bytes, &wrong_root));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(!verify(&trailing, &root));
        let mut damaged = bytes.clone();
        let i = damaged.len() / 2;
        damaged[i] ^= 1;
        assert!(!verify(&damaged, &root));
        eprintln!(
            "legacy_batch_cpu_verified kind={} count={count} after_shutdown=true",
            if htlc { "htlc" } else { "joinsplit" }
        );
    }
}

type BatchAbi = unsafe extern "C" fn(
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

#[test]
#[ignore = "requires complete owned OpenCL path and bounded zero-swap service"]
fn gpu_legacy_batch_abi_returns_device_roots_and_cpu_verifies_after_shutdown() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let _policy = Env::set(
        "LATTICA_PROVING_POLICY",
        if cfg!(debug_assertions) {
            "compatible"
        } else {
            "gpu-required"
        },
    );
    let (js, htlc) = witnesses();
    let witnesses = [
        js.iter()
            .map(crate::encode_joinsplit_witness)
            .collect::<Vec<_>>(),
        htlc.iter()
            .map(crate::encode_htlc_witness)
            .collect::<Vec<_>>(),
    ];
    let provers: [BatchAbi; 2] = [crate::lattica_batch_prove, crate::lattica_htlc_batch_prove];
    let verifiers: [VerifyAbi; 2] = [
        crate::lattica_batch_verify,
        crate::lattica_htlc_batch_verify,
    ];
    let mut proof = vec![0xa5; 4 << 20];
    let mut root = [0x5a; 32];
    let before = gpu_hash::report("legacy_batch_abi_admission_before").unwrap();
    for (name, value) in [
        ("LATTICA_PROVING_POLICY", "cpu-required"),
        ("LATTICA_PROVING_POLICY", "invalid"),
        ("LATTICA_V2_WORKER_BUDGET", "private-batch-not-admitted"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "4096"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "invalid"),
    ] {
        let _env = Env::set(name, value);
        for kind in 0..2 {
            let (mut proof_len, mut root_len) = (123, 456);
            assert_eq!(
                unsafe {
                    provers[kind](
                        witnesses[kind][0].as_ptr(),
                        witnesses[kind][0].len(),
                        1,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut root_len,
                    )
                },
                1
            );
            assert_eq!((proof_len, root_len), (123, 456));
        }
    }
    for kind in 0..2 {
        for count in [0usize, usize::MAX] {
            let (mut proof_len, mut root_len) = (123, 456);
            assert_eq!(
                unsafe {
                    provers[kind](
                        witnesses[kind][0].as_ptr(),
                        witnesses[kind][0].len(),
                        count,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut root_len,
                    )
                },
                1
            );
            assert_eq!((proof_len, root_len), (123, 456));
        }
    }
    assert!(proof.iter().all(|&b| b == 0xa5));
    assert_eq!(root, [0x5a; 32]);
    let after = gpu_hash::report("legacy_batch_abi_admission_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    let mut results = Vec::new();
    for kind in 0..2 {
        for count in [1usize, 3] {
            let encoded = witnesses[kind][..count].concat();
            let (mut proof_len, mut root_len) = (0, 0);
            assert_eq!(
                unsafe {
                    provers[kind](
                        encoded.as_ptr(),
                        encoded.len(),
                        count,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut root_len,
                    )
                },
                0
            );
            assert_eq!(root_len, 32);
            let expected = if kind == 0 {
                bj::batch_root(&js[..count])
            } else {
                bh::batch_root(&htlc[..count])
            };
            assert_eq!(root.as_slice(), crate::encode_digest(&expected));
            results.push((kind, count, proof[..proof_len].to_vec(), root));
        }
    }
    gpu_hash::shutdown().unwrap();
    {
        let _compatible = Env::set("LATTICA_PROVING_POLICY", "compatible");
        let saved_proof = proof.clone();
        let saved_root = root;
        for kind in 0..2 {
            let (mut proof_len, mut root_len) = (123, 456);
            assert_eq!(
                unsafe {
                    provers[kind](
                        witnesses[kind][0].as_ptr(),
                        witnesses[kind][0].len(),
                        1,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut root_len,
                    )
                },
                1
            );
            assert_eq!((proof_len, root_len), (123, 456));
        }
        assert_eq!(proof, saved_proof);
        assert_eq!(root, saved_root);
    }
    for (kind, count, proof, root) in results {
        assert_eq!(
            unsafe { verifiers[kind](proof.as_ptr(), proof.len(), root.as_ptr(), root.len()) },
            0
        );
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert_eq!(
            unsafe {
                verifiers[kind](
                    proof.as_ptr(),
                    proof.len(),
                    wrong_root.as_ptr(),
                    wrong_root.len(),
                )
            },
            1
        );
        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            unsafe {
                verifiers[kind](trailing.as_ptr(), trailing.len(), root.as_ptr(), root.len())
            },
            1
        );
        eprintln!(
            "legacy_batch_abi_cpu_verified kind={} count={count} after_shutdown=true",
            if kind == 0 { "joinsplit" } else { "htlc" }
        );
    }
}
