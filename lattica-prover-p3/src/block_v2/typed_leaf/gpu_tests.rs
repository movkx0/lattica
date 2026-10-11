use super::*;
use crate::block_v2::{gpu_hash, leaf, quotient_pcs};
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_field::PrimeField64;

struct Env(&'static str, Option<std::ffi::OsString>);
impl Env {
    fn set(key: &'static str, value: &str) -> Self {
        let old = Self(key, std::env::var_os(key));
        std::env::set_var(key, value);
        old
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
    witness.outputs[1].value = witness.inputs.iter().map(|v| v.value).sum();
    witness
}

#[test]
#[ignore = "requires OpenCL GPU in a <=3 GiB zero-swap service"]
fn gpu_issuance_trace_and_publics_match_cpu_at_mint_boundaries() {
    use gpu_hash::device::DeviceSession;
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    for mint in [1, 17, (1 << js::BITS) - 1] {
        let witness = issuance(mint);
        let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, false, false).scoped(
            CoverageScope::Operation,
            &[Stage::WitnessTrace, Stage::PublicValues],
        );
        caps.set(Stage::WitnessTrace, Backend::OpenCl);
        caps.set(Stage::PublicValues, Backend::OpenCl);
        let run = Run::new("gpu_issuance_trace", request(Policy::GpuRequired), caps).unwrap();
        let before = session.stats();
        let frame = session.joinsplit_witness(&witness, 4 << 20, &run).unwrap();
        assert_eq!(
            session.stats().downloaded_bytes - before.downloaded_bytes,
            8
        );
        let (trace, public) = frame.readback(&session, 4 << 20).unwrap();
        assert_eq!(
            trace,
            js::build_trace(&witness)
                .values
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            public,
            js::public_values(&witness)
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        assert_eq!(public[js::PI_MINT], mint);
        drop(frame);
        let report = run.finish(true).unwrap();
        assert!(report.stage_coverage_complete);
        assert_eq!(
            report
                .observations
                .iter()
                .map(|o| o.device_calls)
                .sum::<u64>(),
            3
        );
    }
}

#[test]
#[ignore = "requires complete owned OpenCL path, 1 GiB managed GPU and <=3 GiB zero-swap service"]
fn gpu_candidate_wallet_entrypoints_and_issuance_verify_after_shutdown() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(leaf::gpu_wallet_selected());
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x57; 32],
    };
    let spend = js::demo_witness();
    let htlc = htlc::tests::htlc_witness(true, 99, [Val::ONE; 4], 100);
    let issue = issuance(17);
    let policy = if cfg!(debug_assertions) {
        Policy::Compatible
    } else {
        Policy::GpuRequired
    };
    let before = gpu_hash::report("candidate_wallet_admission_before").unwrap();
    for denied in [Policy::CpuRequired]
        .into_iter()
        .chain(cfg!(debug_assertions).then_some(Policy::GpuRequired))
    {
        assert_eq!(
            leaf::prove_joinsplit_with_request(&spend, &context, request(denied)),
            Err(LeafError::ProvingPolicy)
        );
        assert_eq!(
            prove_htlc_with_request(&htlc, &context, request(denied)),
            Err(LeafError::ProvingPolicy.into())
        );
        assert_eq!(
            prove_issuance_with_request(&issue, &context, 17, request(denied)),
            Err(LeafError::ProvingPolicy.into())
        );
    }
    for amount in [0, 1, 1 << js::BITS, u64::MAX] {
        assert_eq!(
            prove_issuance_with_request(&issue, &context, amount, request(policy)),
            Err(Error::UnauthorizedIssuance)
        );
    }
    for amount in [0, 1 << js::BITS] {
        assert_eq!(
            prove_issuance_on_gpu(&issuance(amount), &context, amount, request(policy)),
            Err(Error::UnauthorizedIssuance)
        );
    }
    let mut wrong = context.clone();
    wrong.profile_id[0] ^= 1;
    assert_eq!(
        prove_issuance_with_request(&issue, &wrong, 17, request(policy)),
        Err(LeafError::WrongProfile.into())
    );
    assert_eq!(
        leaf::prove_joinsplit_with_request(&issue, &context, request(policy)),
        Err(LeafError::IssuanceNotSupported)
    );
    let mut unauthorized_htlc = htlc.clone();
    unauthorized_htlc.mint = 17;
    assert_eq!(
        prove_htlc_with_request(&unauthorized_htlc, &context, request(policy)),
        Err(Error::UnauthorizedIssuance)
    );
    {
        let _budget = Env::set(
            "LATTICA_V2_WORKER_BUDGET",
            "public-jobs-cannot-authorize-issuance",
        );
        assert_eq!(
            prove_issuance_with_request(&issue, &context, 17, request(policy)),
            Err(LeafError::GpuFailure.into())
        );
    }
    let after = gpu_hash::report("candidate_wallet_admission_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    let mut unbalanced = issue.clone();
    unbalanced.fee = 1;
    assert_eq!(
        prove_issuance_with_request(&unbalanced, &context, 17, request(policy)),
        Err(LeafError::GpuFailure.into())
    );

    let _policy = Env::set(
        "LATTICA_PROVING_POLICY",
        if cfg!(debug_assertions) {
            "compatible"
        } else {
            "gpu-required"
        },
    );
    let _report = Env::set("LATTICA_PROVING_REPORT", "1");
    let joinsplit = [
        leaf::prove_joinsplit_with_request(&spend, &context, request(policy)).unwrap(),
        leaf::prove_joinsplit_research(&spend, &context).unwrap(),
    ];
    let htlc_proofs = [
        prove_htlc_with_request(&htlc, &context, request(policy)).unwrap(),
        prove_htlc_research(&htlc, &context).unwrap(),
    ];
    let maximum = issuance((1 << js::BITS) - 1);
    let issuance_proofs = [
        prove_issuance_on_gpu(&issue, &context, issue.mint, request(policy)).unwrap(),
        prove_issuance_with_request(&issue, &context, issue.mint, request(policy)).unwrap(),
        prove_issuance_research(&maximum, &context, maximum.mint).unwrap(),
    ];
    assert_ne!(joinsplit[0], joinsplit[1]);
    assert_ne!(htlc_proofs[0], htlc_proofs[1]);
    assert_ne!(issuance_proofs[0], issuance_proofs[1]);
    gpu_hash::shutdown().unwrap();
    // Shutdown retires the engine, not the configured backend selection. A
    // later request must fail instead of falling through to the CPU prover.
    assert!(leaf::gpu_wallet_selected());
    assert!(gpu_hash::report("candidate_wallet_after_shutdown").is_none());
    for proof in &joinsplit {
        leaf::verify_joinsplit_research(proof, &context, &js::public_values(&spend)).unwrap();
    }
    for proof in &htlc_proofs {
        verify_htlc_research(
            proof,
            &context,
            &htlc::public_values(&htlc),
            htlc.current_height,
        )
        .unwrap();
    }
    for (proof, witness) in issuance_proofs.iter().zip([&issue, &issue, &maximum]) {
        let statement = js::public_values(witness);
        verify_issuance_research(proof, &context, &statement, witness.mint).unwrap();
        assert_eq!(
            verify_issuance_research(proof, &context, &statement, witness.mint + 1),
            Err(Error::UnauthorizedIssuance)
        );
        for index in [
            js::PI_NF,
            js::PI_OUTCM,
            js::PI_FEE,
            js::PI_MINT,
            js::PI_TXBIND,
        ] {
            let mut changed = statement.clone();
            changed[index] += Val::ONE;
            assert!(verify_issuance_research(proof, &context, &changed, witness.mint).is_err());
        }
        let mut wrong = context.clone();
        wrong.chain_id[0] ^= 1;
        let mut relabeled = proof.clone();
        relabeled[40..72].copy_from_slice(&wrong.chain_id);
        assert!(verify_issuance_research(&relabeled, &wrong, &statement, witness.mint).is_err());
        assert!(verify_issuance_research(
            &proof[..proof.len() - 1],
            &context,
            &statement,
            witness.mint
        )
        .is_err());
        let mut spend_statement = statement.clone();
        spend_statement[js::PI_MINT] = Val::ZERO;
        assert_eq!(
            leaf::verify_joinsplit_research(proof, &context, &spend_statement),
            Err(LeafError::InvalidEncoding)
        );
    }
    let mut forged = js::public_values(&spend);
    forged[js::PI_MINT] = Val::from_u64(17);
    assert_eq!(
        verify_issuance_research(&joinsplit[0], &context, &forged, 17),
        Err(LeafError::InvalidEncoding.into())
    );
    assert_eq!(
        leaf::prove_joinsplit_with_request(&spend, &context, request(Policy::GpuRequired)),
        Err(LeafError::GpuFailure)
    );
    assert_eq!(
        prove_htlc_with_request(&htlc, &context, request(Policy::GpuRequired)),
        Err(LeafError::GpuFailure.into())
    );
    assert_eq!(
        prove_issuance_with_request(&issue, &context, 17, request(Policy::GpuRequired)),
        Err(LeafError::GpuFailure.into())
    );
    assert_eq!(
        prove_issuance_with_request(&issue, &context, 17, request(Policy::Compatible)),
        Err(LeafError::GpuFailure.into())
    );
    assert!(gpu_hash::report("candidate_wallet_no_fallback_after_shutdown").is_none());
    eprintln!("candidate_wallet_entrypoints_gpu_verified joinsplit=2 htlc=2 issuance=3");
}
