use super::*;
use crate::block_v2::quotient_pcs;
use crate::proving::Policy;
use crate::{htlc_air as htlc, joinsplit_air as js};

mod batch;
mod helpers;

struct Env(&'static str, Option<std::ffi::OsString>);
impl Env {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = Self(name, std::env::var_os(name));
        std::env::set_var(name, value);
        previous
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        match &self.1 {
            Some(value) => std::env::set_var(self.0, value),
            None => std::env::remove_var(self.0),
        }
    }
}

fn request(policy: Policy) -> Request {
    Request {
        policy,
        emit_report: true,
    }
}

fn issuance(mint: u64) -> js::Witness {
    let mut witness = js::demo_witness();
    witness.mint = mint;
    witness.fee = 0;
    witness.outputs[0].value = mint;
    witness.outputs[1].value = witness.inputs.iter().map(|input| input.value).sum();
    witness
}

fn check_report(report: &Report) {
    assert!(report.succeeded && report.stage_coverage_complete);
    assert!(!report.completion_rejected);
    assert_eq!(report.observation_errors, 0);
    assert_eq!(
        serde_json::to_value(&report.capabilities).unwrap()["profile"],
        "legacy_quadratic"
    );
    for observed in &report.observations {
        if observed.stage == Stage::Serialization
            || (cfg!(debug_assertions) && observed.stage == Stage::ConstraintAudit)
        {
            assert_eq!(observed.backend, Backend::Cpu);
        } else {
            assert_eq!(observed.backend, Backend::OpenCl);
            assert!(observed.device_calls > 0);
        }
    }
}

#[test]
#[ignore = "requires complete owned OpenCL path, 1 GiB managed GPU and bounded zero-swap service"]
fn gpu_legacy_wallet_entrypoints_verify_with_unchanged_cpu_verifiers_after_shutdown() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(is_selected());
    let spend = js::demo_witness();
    let redeem = htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100);
    let refund = htlc::tests::htlc_witness(false, 100, [Val::ONE; 4], 100);
    let policy = if cfg!(debug_assertions) {
        Policy::Compatible
    } else {
        Policy::GpuRequired
    };
    let before = gpu_hash::report("legacy_wallet_admission_before").unwrap();
    for denied in [Policy::CpuRequired]
        .into_iter()
        .chain(cfg!(debug_assertions).then_some(Policy::GpuRequired))
    {
        assert!(matches!(
            js::prove_to_bytes_with_request(&spend, request(denied)),
            Err(Error::Unsupported { .. })
        ));
        assert!(matches!(
            htlc::prove_to_bytes_with_request(&redeem, request(denied)),
            Err(Error::Unsupported { .. })
        ));
    }
    for (name, value) in [
        ("LATTICA_V2_WORKER_BUDGET", "private-wallet-not-admitted"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "4096"),
    ] {
        let _env = Env::set(name, value);
        assert!(matches!(
            js::prove_to_bytes_with_request(&spend, request(policy)),
            Err(Error::ComponentRejected)
        ));
        assert!(matches!(
            htlc::prove_to_bytes_with_request(&redeem, request(policy)),
            Err(Error::ComponentRejected)
        ));
    }
    let after = gpu_hash::report("legacy_wallet_admission_after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    let mut invalid = spend.clone();
    invalid.fee += 1;
    assert!(matches!(
        js::prove_to_bytes_with_request(&invalid, request(policy)),
        Err(Error::ComponentRejected)
    ));

    let mut artifacts = Vec::new();
    for (case, witness) in [
        spend.clone(),
        spend.clone(),
        issuance(17),
        issuance((1 << js::BITS) - 1),
    ]
    .into_iter()
    .enumerate()
    {
        let public = js::public_values(&witness);
        let (bytes, report) = js::prove_to_bytes_with_request(&witness, request(policy)).unwrap();
        check_report(&report);
        artifacts.push((false, case, bytes, public));
    }
    assert_ne!(
        artifacts[0].2, artifacts[1].2,
        "fresh legacy join-split hiding entropy"
    );
    for (case, witness) in [htlc::demo_witness(), redeem.clone(), redeem.clone(), refund]
        .into_iter()
        .enumerate()
    {
        let public = htlc::public_values(&witness);
        let (bytes, report) = htlc::prove_to_bytes_with_request(&witness, request(policy)).unwrap();
        check_report(&report);
        artifacts.push((true, case, bytes, public));
    }
    assert_ne!(
        artifacts[5].2, artifacts[6].2,
        "fresh legacy HTLC hiding entropy"
    );
    gpu_hash::shutdown().unwrap();
    assert!(matches!(
        js::prove_to_bytes_with_request(&spend, request(Policy::Compatible)),
        Err(Error::ComponentRejected)
    ));
    assert!(matches!(
        htlc::prove_to_bytes_with_request(&redeem, request(Policy::Compatible)),
        Err(Error::ComponentRejected)
    ));
    for (is_htlc, case, bytes, public) in artifacts {
        let verify: fn(&[u8], &[Val]) -> bool = if is_htlc {
            htlc::verify_bytes
        } else {
            js::verify_bytes
        };
        assert!(
            verify(&bytes, &public),
            "legacy proof failed after GPU shutdown"
        );
        let mut changed = public.clone();
        changed[0] += Val::ONE;
        assert!(!verify(&bytes, &changed));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(!verify(&trailing, &public));
        let mut proof: p3_uni_stark::Proof<crate::config::MyConfig> =
            postcard::from_bytes(&bytes).unwrap();
        proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
        assert!(!verify(&postcard::to_allocvec(&proof).unwrap(), &public));
        eprintln!(
            "legacy_wallet_cpu_verified kind={} case={case} after_shutdown=true",
            if is_htlc { "htlc" } else { "joinsplit" }
        );
    }
}

type ProveAbi = unsafe extern "C" fn(
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
    *mut u8,
    usize,
    *mut usize,
) -> i32;
type DemoAbi = unsafe extern "C" fn(*mut u8, usize, *mut usize, *mut u8, usize, *mut usize) -> i32;
type VerifyAbi = unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> i32;

#[test]
#[ignore = "requires complete owned OpenCL path, 1 GiB managed GPU and bounded zero-swap service"]
fn gpu_legacy_c_abi_returns_gpu_publics_and_cpu_verifies_after_shutdown() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let _policy = Env::set(
        "LATTICA_PROVING_POLICY",
        if cfg!(debug_assertions) {
            "compatible"
        } else {
            "gpu-required"
        },
    );
    let js = js::demo_witness();
    let htlc = htlc::demo_htlc_witness();
    let witnesses = [
        crate::encode_joinsplit_witness(&js),
        crate::encode_htlc_witness(&htlc),
    ];
    let publics = [
        crate::encode_joinsplit_public_inputs(&js::public_values(&js)).unwrap(),
        crate::encode_htlc_public_inputs(&htlc::public_values(&htlc)).unwrap(),
    ];
    let provers: [ProveAbi; 2] = [crate::lattica_joinsplit_prove, crate::lattica_htlc_prove];
    let demos: [DemoAbi; 2] = [
        crate::lattica_joinsplit_prove_demo,
        crate::lattica_htlc_prove_demo,
    ];
    let verifiers: [VerifyAbi; 2] = [crate::lattica_joinsplit_verify, crate::lattica_htlc_verify];
    let mut proof = vec![0xa5; 2 << 20];
    let mut public = vec![0x5a; 512];
    let before = gpu_hash::report("legacy_abi_admission_before").unwrap();
    for (name, value) in [
        ("LATTICA_PROVING_POLICY", "cpu-required"),
        ("LATTICA_PROVING_POLICY", "invalid"),
        ("LATTICA_V2_WORKER_BUDGET", "private-wallet-not-admitted"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "4096"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "invalid"),
    ] {
        let _env = Env::set(name, value);
        for i in 0..2 {
            let (mut proof_len, mut public_len) = (123, 456);
            assert_eq!(
                unsafe {
                    provers[i](
                        witnesses[i].as_ptr(),
                        witnesses[i].len(),
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
            assert_eq!((proof_len, public_len), (123, 456));
            assert_eq!(
                unsafe {
                    demos[i](
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
            assert_eq!((proof_len, public_len), (123, 456));
        }
    }
    assert!(proof.iter().all(|x| *x == 0xa5));
    assert!(public.iter().all(|x| *x == 0x5a));
    let after = gpu_hash::report("legacy_abi_admission_after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    let mut artifacts = Vec::new();
    let probe = crate::block_v2::wallet_worker::admission_tests::PrivateInputProbe::start();
    for i in 0..2 {
        for demo in [false, true] {
            let (mut proof_len, mut public_len) = (0, 0);
            let result = unsafe {
                if demo {
                    demos[i](
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        public.as_mut_ptr(),
                        public.len(),
                        &mut public_len,
                    )
                } else {
                    provers[i](
                        witnesses[i].as_ptr(),
                        witnesses[i].len(),
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut proof_len,
                        public.as_mut_ptr(),
                        public.len(),
                        &mut public_len,
                    )
                }
            };
            assert_eq!(result, 0);
            assert_eq!(&public[..public_len], &publics[i]);
            artifacts.push((
                i,
                demo,
                proof[..proof_len].to_vec(),
                public[..public_len].to_vec(),
            ));
        }
    }
    probe.finish(2);
    gpu_hash::shutdown().unwrap();
    {
        let _compatible = Env::set("LATTICA_PROVING_POLICY", "compatible");
        for i in 0..2 {
            let (mut proof_len, mut public_len) = (123, 456);
            assert_eq!(
                unsafe {
                    provers[i](
                        witnesses[i].as_ptr(),
                        witnesses[i].len(),
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
            assert_eq!((proof_len, public_len), (123, 456));
            assert_eq!(
                unsafe {
                    demos[i](
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
        }
    }
    for (i, demo, proof, public) in artifacts {
        assert_eq!(
            unsafe { verifiers[i](proof.as_ptr(), proof.len(), public.as_ptr(), public.len()) },
            0
        );
        let mut changed = public.clone();
        changed[0] ^= 1;
        assert_ne!(
            unsafe { verifiers[i](proof.as_ptr(), proof.len(), changed.as_ptr(), changed.len()) },
            0
        );
        let mut trailing = proof.clone();
        trailing.push(0);
        assert_ne!(
            unsafe {
                verifiers[i](
                    trailing.as_ptr(),
                    trailing.len(),
                    public.as_ptr(),
                    public.len(),
                )
            },
            0
        );
        eprintln!(
            "legacy_wallet_abi_cpu_verified kind={} demo={demo} after_shutdown=true",
            if i == 0 { "joinsplit" } else { "htlc" }
        );
    }
}
