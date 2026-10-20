use super::*;
use crate::{htlc_air as htlc, joinsplit_air as js};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;

#[path = "host_wallet_cuda_tests.rs"]
mod cuda;

fn request(kind: u64, height: u64, mint: u64) -> [u8; REQUEST_BYTES] {
    let mut bytes = [0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(REQUEST_MAGIC);
    bytes[8..40].fill(0x6d);
    bytes[40..48].copy_from_slice(&kind.to_le_bytes());
    bytes[48..56].copy_from_slice(&height.to_le_bytes());
    bytes[56..].copy_from_slice(&mint.to_le_bytes());
    bytes
}

fn fixtures() -> Vec<([u8; REQUEST_BYTES], Vec<u8>, Vec<Val>, Policy)> {
    let spend = js::demo_witness();
    let mut issue = spend.clone();
    issue.mint = 7;
    issue.fee = 0;
    issue.outputs[0].value = 7;
    issue.outputs[1].value = issue.inputs.iter().map(|input| input.value).sum();
    let redeem = htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100);
    let refund = htlc::tests::htlc_witness(false, 100, [Val::ONE; 4], 100);
    vec![
        (
            request(1, 0, 0),
            crate::encode_joinsplit_witness(&spend),
            js::public_values(&spend),
            Policy::JoinSplit,
        ),
        (
            request(3, 0, 7),
            crate::encode_joinsplit_witness(&issue),
            js::public_values(&issue),
            Policy::Issuance { authorized_mint: 7 },
        ),
        (
            request(2, 99, 0),
            crate::encode_htlc_witness(&redeem),
            htlc::public_values(&redeem),
            Policy::Htlc {
                expected_height: 99,
            },
        ),
        (
            request(2, 100, 0),
            crate::encode_htlc_witness(&refund),
            htlc::public_values(&refund),
            Policy::Htlc {
                expected_height: 100,
            },
        ),
    ]
}

fn export(request: &[u8], witness: &[u8]) -> Vec<u8> {
    let mut output = vec![0xa5; MAX_EXPORT_BYTES];
    let mut written = usize::MAX;
    // SAFETY: live disjoint buffers; lengths and capacities match their allocations.
    let code = unsafe {
        lattica_v2_research_wallet_prove_v1(
            request.as_ptr(),
            request.len(),
            witness.as_ptr(),
            witness.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        )
    };
    assert_eq!(code, 0);
    assert!((16..=MAX_EXPORT_BYTES).contains(&written));
    output.truncate(written);
    output
}

fn verify_export(bytes: &[u8], expected: &[Val], policy: Policy) {
    assert_eq!(&bytes[..8], EXPORT_MAGIC);
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    assert_eq!(count, expected.len());
    assert_eq!(bytes.len(), 16 + length + 8 * count);
    assert_eq!(&bytes[16..24], b"LBV2TW01");
    let mut wallet: WalletProof = codec::decode(&bytes[24..16 + length]).unwrap();
    assert_eq!(wallet.chain, [0x6d; 32]);
    assert_eq!(wallet.public, expected);
    for (encoded, value) in bytes[16 + length..].chunks_exact(8).zip(expected) {
        assert_eq!(
            u64::from_le_bytes(encoded.try_into().unwrap()),
            value.as_canonical_u64()
        );
    }
    typed_recursive::verify_wallet(&wallet, policy).unwrap();
    wallet.public[0] += Val::ONE;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
    wallet.public[0] -= Val::ONE;
    wallet.chain[0] ^= 1;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
}

fn child(case: &str, policy: &str, report: &str) -> std::process::Output {
    // libtest selectors omit the crate name included by module_path!().
    let selector = format!(
        "{}::native_export_child",
        module_path!().split_once("::").unwrap().1
    );
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &selector, "--nocapture"])
        .env("LATTICA_NATIVE_EXPORT_CASE", case)
        .env("LATTICA_PROVING_POLICY", policy)
        .env("LATTICA_PROVING_REPORT", report)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("test result: ok. 1 passed; 0 failed;"),
        "child must execute exactly one successful test: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

#[test]
fn native_export_admission_precedes_request_and_witness_decode() {
    for (policy, report) in [
        ("gpu-required", "1"),
        ("invalid-policy", "1"),
        ("compatible", "invalid-report"),
    ] {
        let result = child("admission", policy, report);
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!String::from_utf8_lossy(&result.stderr).contains("proving_stage_report "));
    }
}

#[test]
#[ignore = "full CPU reference proofs; run in a bounded serial service"]
fn native_export_cpu_and_compatible_references_verify() {
    for policy in ["cpu-required", "compatible"] {
        let result = child("reference", policy, "1");
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn native_export_child() {
    let Ok(case) = std::env::var("LATTICA_NATIVE_EXPORT_CASE") else {
        return;
    };
    match case.as_str() {
        "admission" => {
            let before = crate::proving::cpu_witness_oracle_calls();
            assert!(prove(&[], &[])
                .unwrap_err()
                .downcast_ref::<crate::proving::Error>()
                .is_some());
            let request = request(1, 0, 0);
            let mut output = [0xa5; 64];
            let witness = [0];
            let mut written = 123;
            // SAFETY: live buffers of the supplied lengths; policy rejects before parsing.
            assert_eq!(
                unsafe {
                    lattica_v2_research_wallet_prove_v1(
                        request.as_ptr(),
                        request.len(),
                        witness.as_ptr(),
                        witness.len(),
                        output.as_mut_ptr(),
                        output.len(),
                        &mut written,
                    )
                },
                -2
            );
            assert_eq!(written, 0);
            assert_eq!(output, [0xa5; 64]);
            assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
        }
        "reference" => {
            for (request, witness, expected, policy) in fixtures() {
                let before = crate::proving::cpu_witness_oracle_calls();
                let bytes = export(&request, &witness);
                assert!(crate::proving::cpu_witness_oracle_calls() > before);
                verify_export(&bytes, &expected, policy);
            }
        }
        _ => panic!("unknown child case"),
    }
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "complete owned OpenCL path; full VRAM admission and bounded serial worker required"]
fn native_export_gpu_reuses_device_publics_and_verifies_after_shutdown() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    assert!(
        !cfg!(debug_assertions),
        "GPU-required native export requires a release build"
    );
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(leaf::gpu_wallet_selected());
    assert_eq!(
        crate::proving::Request::from_env().unwrap().policy,
        crate::proving::Policy::GpuRequired
    );
    let cases = fixtures(); // Explicit CPU oracle outside the proving request.
    crate::block_v2::wallet_worker::admission_tests::denied_resources(|| {
        let error = prove(&[], &[]).unwrap_err();
        assert!(error.downcast_ref::<crate::proving::Error>().is_some());
    });
    let probe = crate::block_v2::wallet_worker::admission_tests::PrivateInputProbe::start();
    let mut outputs = Vec::new();
    for (request, witness, _, _) in &cases {
        let before = crate::proving::cpu_witness_oracle_calls();
        outputs.push(export(request, witness));
        assert_eq!(
            crate::proving::cpu_witness_oracle_calls(),
            before,
            "native GPU export recomputed public values through a CPU witness oracle"
        );
    }
    probe.finish(4);
    gpu_hash::shutdown().unwrap();
    for (bytes, (_, _, expected, policy)) in outputs.iter().zip(&cases) {
        verify_export(bytes, expected, *policy);
    }
    let before = crate::proving::cpu_witness_oracle_calls();
    assert!(prove(&cases[0].0, &cases[0].1).is_err());
    assert_eq!(
        crate::proving::cpu_witness_oracle_calls(),
        before,
        "shutdown must not fall back to the CPU oracle"
    );
    assert!(gpu_hash::report("native_export_after_shutdown").is_none());
}
