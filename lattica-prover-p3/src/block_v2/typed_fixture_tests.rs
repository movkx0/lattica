use super::*;
use std::collections::BTreeSet;

// This observes synthetic input preparation separately from the existing
// public-value/trace oracle counter. Neither counter is production telemetry.
thread_local! {
    static PREPARATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(super) fn record_preparation() {
    #[cfg(feature = "gpu")]
    super::super::wallet_worker::admission_tests::private_input_boundary();
    PREPARATIONS.with(|count| count.set(count.get() + 1));
}

fn preparations() -> u64 {
    PREPARATIONS.with(std::cell::Cell::get)
}

#[test]
fn all_fixture_statements_share_anchor_and_have_unique_spends_and_outputs() {
    let statements = statements();
    let anchor = &statements[0][..4];
    let mut nullifiers = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    for (i, public) in statements.iter().enumerate() {
        assert_eq!(&public[..4], anchor);
        for nf in public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
            assert!(nullifiers.insert(nf.to_vec()));
        }
        for cm in public[js::PI_OUTCM..js::PI_FEE].chunks_exact(4) {
            assert!(outputs.insert(cm.to_vec()));
        }
        assert_eq!(public[js::PI_MINT], if i % 4 == 3 { MINT } else { 0 });
        if i % 4 == 1 || i % 4 == 2 {
            assert_eq!(public[htlc::PI_HEIGHT], HEIGHT);
            let hashlock = &public[htlc::PI_HASHLOCK..];
            assert_eq!(hashlock.iter().all(|v| *v == 0), i % 4 == 2);
        }
    }
    assert_eq!(
        nullifiers.len(),
        2 * crate::block_v2::profile::MAX_TRANSACTIONS
    );
    assert_eq!(
        outputs.len(),
        2 * crate::block_v2::profile::MAX_TRANSACTIONS
    );
}

fn verify(mut wallet: WalletProof, policy: Policy, expected: &[u64], index: usize) {
    assert_eq!(wallet.chain, CHAIN);
    assert_eq!(
        wallet
            .public
            .iter()
            .map(Val::as_canonical_u64)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(matches!(
        (index, policy),
        (0, Policy::JoinSplit)
            | (
                1 | 2,
                Policy::Htlc {
                    expected_height: HEIGHT
                }
            )
            | (
                3,
                Policy::Issuance {
                    authorized_mint: MINT
                }
            )
    ));
    typed_recursive::verify_wallet(&wallet, policy).unwrap();
    let wrong_policy = match policy {
        Policy::JoinSplit => Policy::Issuance {
            authorized_mint: MINT,
        },
        Policy::Htlc { .. } => Policy::Htlc {
            expected_height: HEIGHT + 1,
        },
        Policy::Issuance { .. } => Policy::JoinSplit,
    };
    assert!(typed_recursive::verify_wallet(&wallet, wrong_policy).is_err());
    wallet.public[0] += Val::ONE;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
    wallet.public[0] -= Val::ONE;
    wallet.chain[0] ^= 1;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
}

fn child(case: &str, policy: &str, report: &str, assigned: bool) {
    let selector = format!(
        "{}::fixture_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &selector, "--nocapture"])
        .env("LATTICA_TYPED_FIXTURE_CASE", case)
        .env("LATTICA_PROVING_POLICY", policy)
        .env("LATTICA_PROVING_REPORT", report)
        .env_remove("LATTICA_WALLET_WORKER_BUDGET");
    if assigned {
        command.env("LATTICA_WALLET_WORKER_BUDGET", "must-not-be-read.json");
    }
    let result = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "child must execute exactly one successful test: {stdout}\n{stderr}"
    );
    if case == "admission" {
        assert!(!stderr.contains("proving_stage_report "));
    }
}

#[test]
fn fixture_admission_precedes_synthetic_preparation() {
    for (policy, report, assigned) in [
        ("gpu-required", "1", false),
        ("invalid-policy", "1", false),
        ("compatible", "invalid-report", false),
        ("cpu-required", "1", true),
        ("compatible", "1", true),
    ] {
        child("admission", policy, report, assigned);
    }
}

#[test]
#[ignore = "eight CPU reference proofs; run in a bounded serial service"]
fn each_fixture_type_has_a_valid_context_bound_proof() {
    for policy in ["cpu-required", "compatible"] {
        child("reference", policy, "1", false);
    }
}

#[test]
fn fixture_child() {
    let Ok(case) = std::env::var("LATTICA_TYPED_FIXTURE_CASE") else {
        return;
    };
    match case.as_str() {
        "admission" => {
            let before = (preparations(), crate::proving::cpu_witness_oracle_calls());
            for index in [0, 64] {
                let error = wallet(index).err().expect("policy must reject");
                assert!(error.downcast_ref::<crate::proving::Error>().is_some());
            }
            assert_eq!(
                (preparations(), crate::proving::cpu_witness_oracle_calls()),
                before
            );
        }
        "reference" => {
            let expected = statements(); // Independent CPU oracle, outside each request.
            for (index, expected) in expected.iter().enumerate().take(4) {
                let before = crate::proving::cpu_witness_oracle_calls();
                let (wallet, policy) = wallet(index).unwrap();
                assert!(crate::proving::cpu_witness_oracle_calls() > before);
                verify(wallet, policy, expected, index);
            }
            let before = preparations();
            assert!(wallet(64).is_err());
            assert_eq!(preparations(), before);
        }
        _ => panic!("unknown fixture child case"),
    }
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "complete OpenCL path; full VRAM admission and bounded serial worker required"]
fn fixture_gpu_reuses_device_publics_and_verifies_after_shutdown() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    assert!(
        !cfg!(debug_assertions),
        "GPU-required fixture needs a release build"
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
    let expected = statements(); // Explicit CPU oracle outside the proving requests.
    super::super::wallet_worker::admission_tests::denied_resources(|| {
        let before = (preparations(), crate::proving::cpu_witness_oracle_calls());
        assert!(wallet(0).is_err());
        assert_eq!(
            (preparations(), crate::proving::cpu_witness_oracle_calls()),
            before
        );
    });
    let probe = super::super::wallet_worker::admission_tests::PrivateInputProbe::start();
    let mut outputs = Vec::new();
    for index in 0..4 {
        let before = crate::proving::cpu_witness_oracle_calls();
        let prepared = preparations();
        outputs.push(wallet(index).unwrap());
        assert_eq!(
            preparations(),
            prepared + 1,
            "synthetic inputs still use CPU construction"
        );
        assert_eq!(
            crate::proving::cpu_witness_oracle_calls(),
            before,
            "GPU fixture export recomputed the statement through a CPU witness oracle"
        );
    }
    let before = preparations();
    assert!(wallet(64).is_err());
    assert_eq!(preparations(), before);
    probe.finish(4);
    gpu_hash::shutdown().unwrap();
    for (index, (wallet, policy)) in outputs.into_iter().enumerate() {
        verify(wallet, policy, &expected[index], index);
    }
    let before = (preparations(), crate::proving::cpu_witness_oracle_calls());
    assert!(
        wallet(0).is_err(),
        "shutdown must reject before preparation"
    );
    assert_eq!(
        (preparations(), crate::proving::cpu_witness_oracle_calls()),
        before
    );
    assert!(gpu_hash::report("fixture_after_shutdown").is_none());
}
