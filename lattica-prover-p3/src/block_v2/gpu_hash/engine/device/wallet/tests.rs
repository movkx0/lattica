use super::*;
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_field::PrimeCharacteristicRing;

#[test]
fn wallet_plan_covers_staging_and_both_outputs() {
    let host = (INPUT_WORDS + GEOMETRY_WORDS + 1) * 8;
    assert!(Plan::new(host - 1).is_err());
    let plan = Plan::new(host).unwrap();
    assert_eq!(plan.trace.words(), js::HEIGHT * js::WIDTH);
    assert_eq!(plan.public.words(), js::N_PUBLIC);
    assert_eq!(
        plan.specs()
            .unwrap()
            .iter()
            .map(|s| s.bytes())
            .sum::<usize>(),
        plan.trace.bytes() + plan.public.bytes() + host
    );
    let words = input_words(&js::demo_witness()).unwrap();
    assert_eq!(words.0.len(), INPUT_WORDS);
    assert_eq!(words.0.capacity(), INPUT_WORDS);
    assert!(staging_words(usize::MAX).is_err());
}

fn run() -> Run {
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    caps.set(Stage::WitnessTrace, Backend::OpenCl);
    caps.set(Stage::PublicValues, Backend::OpenCl);
    Run::new(
        "gpu_wallet_trace",
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        },
        caps,
    )
    .unwrap()
}

fn witness(case: usize) -> js::Witness {
    let mut w = js::demo_witness();
    if case == 0 {
        return w;
    }
    if case == 1 {
        let bound = 1u64 << js::BITS;
        w.inputs[0].value = bound - 1;
        w.inputs[1].value = 1;
        w.outputs[0].value = bound - 2;
        w.outputs[1].value = 1;
        w.fee = 1;
        w.inputs[0].nk = [0, GOLDILOCKS_MODULUS];
        w.inputs[1].nk = [GOLDILOCKS_MODULUS + 1, u64::MAX];
        for input in &mut w.inputs {
            input.asset = -Val::ONE;
            input.div = -Val::ONE;
        }
        for output in &mut w.outputs {
            output.asset = -Val::ONE;
        }
    } else {
        for input in &mut w.inputs {
            input.value = 0;
        }
        w.outputs[0].value = 1000;
        w.outputs[1].value = 2000;
        w.fee = 12;
        w.mint = 3012;
    }
    let cms: Vec<_> = w
        .inputs
        .iter()
        .map(|v| {
            js::commit(
                js::recipient_of(Val::from_u64(v.nk[0]), Val::from_u64(v.nk[1]), v.div),
                Val::from_u64(v.value),
                v.rho,
                v.rcm,
                v.asset,
            )
        })
        .collect();
    for i in 0..js::N_IN {
        w.inputs[i].sib[0] = cms[1 - i];
        w.inputs[i].bits[0] = i == 1;
        for d in 1..js::DEPTH {
            w.inputs[i].sib[d] =
                core::array::from_fn(|k| Val::from_u64(((d + 1) * (k + 1) * 17) as u64));
            w.inputs[i].bits[d] = d % 2 == 1;
        }
    }
    w.tx_binding = [
        Val::ZERO,
        Val::ONE,
        -Val::ONE,
        Val::from_u64(0x1234567890abcdef),
    ];
    w
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected OpenCL GPU and <=3 GiB zero-swap service"]
fn gpu_joinsplit_trace_and_publics_match_cpu_without_intermediate_readback() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    for case in 0..3 {
        let witness = witness(case);
        let reference_trace = js::build_trace(&witness);
        let reference_public = js::public_values(&witness);
        let run = run();
        let before = session.stats();
        let frame = { session.joinsplit_witness(&witness, 1 << 20, &run).unwrap() };
        let generated = session.stats();
        assert_eq!(generated.downloaded_bytes - before.downloaded_bytes, 8);
        assert_eq!(
            generated.uploaded_bytes - before.uploaded_bytes,
            ((INPUT_WORDS + GEOMETRY_WORDS) * 8) as u64
        );
        assert_eq!(frame.trace().spec().words(), js::HEIGHT * js::WIDTH);
        assert_eq!(frame.public().spec().words(), js::N_PUBLIC);
        let bytes = (js::HEIGHT * js::WIDTH + js::N_PUBLIC) * 8;
        let pre_rejection = session.stats();
        assert!(frame.readback(&session, bytes - 1).is_err());
        assert_eq!(
            session.stats().downloaded_bytes,
            pre_rejection.downloaded_bytes
        );
        let foreign = DeviceSession::new().unwrap();
        assert!(frame.readback(&foreign, bytes).is_err());
        assert_eq!(foreign.stats().downloaded_bytes, 0);
        drop(foreign);
        let (trace, public) = frame.readback(&session, bytes).unwrap();
        let expected: Vec<_> = reference_trace
            .values
            .iter()
            .map(|v| v.as_canonical_u64())
            .collect();
        for (index, (&actual, &expected)) in trace.iter().zip(&expected).enumerate() {
            assert_eq!(
                actual,
                expected,
                "case={case} row={} col={}",
                index / js::WIDTH,
                index % js::WIDTH
            );
        }
        assert_eq!(
            public,
            reference_public
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        let report = run.finish(true).unwrap();
        assert!(report.stage_coverage_complete);
        assert_eq!(
            report
                .observations
                .iter()
                .find(|o| o.stage == Stage::WitnessTrace)
                .unwrap()
                .device_calls,
            2
        );
        assert_eq!(
            report
                .observations
                .iter()
                .find(|o| o.stage == Stage::PublicValues)
                .unwrap()
                .device_calls,
            1
        );
    }
    let before = session.stats();
    let allocation_before = gpu_hash::report("wallet before host admission").unwrap();
    assert!(session
        .joinsplit_witness(
            &witness(0),
            (INPUT_WORDS + GEOMETRY_WORDS + 1) * 8 - 1,
            &run()
        )
        .is_err());
    assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(
        gpu_hash::report("wallet after host admission")
            .unwrap()
            .allocations,
        allocation_before.allocations
    );
    for case in 0..5 {
        let mut invalid = witness(0);
        match case {
            0 => invalid.inputs[1].asset += Val::ONE,
            1 => invalid.outputs[1].asset += Val::ONE,
            2 => invalid.inputs[1].sib[31][0] += Val::ONE,
            3 => invalid.fee += 1,
            _ => {
                invalid.inputs[0].value = 1 << js::BITS;
                invalid.outputs[0].value = 1 << js::BITS;
            }
        }
        let run = run();
        {
            assert!(session.joinsplit_witness(&invalid, 1 << 20, &run).is_err());
        }
        let report = run.finish(false).unwrap();
        assert!(!report.succeeded && !report.stage_coverage_complete);
        assert_eq!(
            report
                .observations
                .iter()
                .map(|o| o.device_calls)
                .sum::<u64>(),
            3
        );
    }
    drop(session);
    gpu_hash::shutdown().unwrap();
}

#[cfg(all(feature = "gpu", not(debug_assertions)))]
#[test]
#[ignore = "requires selected OpenCL GPU and <=3 GiB zero-swap service"]
fn gpu_wallet_witness_feeds_unchanged_leaf_proof_and_cpu_verifier() {
    use crate::block_v2::{commitment::Context, gpu_hash, leaf, profile};
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x39; 32],
    };
    let w = witness(0);
    let public = js::public_values(&w);
    let before = gpu_hash::report("wallet policy before work").unwrap();
    for policy in [Policy::CpuRequired, Policy::GpuRequired] {
        assert_eq!(
            leaf::prove_joinsplit_with_gpu_witness(
                &w,
                &context,
                Request {
                    policy,
                    emit_report: true
                },
                2 << 20
            ),
            Err(leaf::LeafError::ProvingPolicy)
        );
    }
    assert_eq!(
        leaf::prove_joinsplit_with_gpu_witness(&w, &context, Request::compatible(), 1),
        Err(leaf::LeafError::GpuFailure)
    );
    {
        struct RestoreAssignment(Option<std::ffi::OsString>);
        impl Drop for RestoreAssignment {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("LATTICA_V2_WORKER_BUDGET", value),
                    None => std::env::remove_var("LATTICA_V2_WORKER_BUDGET"),
                }
            }
        }
        let _restore = RestoreAssignment(std::env::var_os("LATTICA_V2_WORKER_BUDGET"));
        std::env::set_var(
            "LATTICA_V2_WORKER_BUDGET",
            "public-worker-is-not-a-private-wallet-assignment",
        );
        assert_eq!(
            leaf::prove_joinsplit_with_gpu_witness(&w, &context, Request::compatible(), 2 << 20),
            Err(leaf::LeafError::GpuFailure)
        );
    }
    let mut bad_context = context;
    bad_context.profile_id[0] ^= 1;
    assert_eq!(
        leaf::prove_joinsplit_with_gpu_witness(&w, &bad_context, Request::compatible(), 2 << 20),
        Err(leaf::LeafError::WrongProfile)
    );
    let mut issuance = w.clone();
    issuance.mint = 1;
    assert_eq!(
        leaf::prove_joinsplit_with_gpu_witness(&issuance, &context, Request::compatible(), 2 << 20),
        Err(leaf::LeafError::IssuanceNotSupported)
    );
    let after = gpu_hash::report("wallet policy after rejection").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    let mut artifacts = Vec::new();
    for _ in 0..2 {
        artifacts.push(
            leaf::prove_joinsplit_with_gpu_witness(
                &w,
                &context,
                Request {
                    policy: Policy::Compatible,
                    emit_report: true,
                },
                2 << 20,
            )
            .unwrap(),
        );
    }
    assert_ne!(
        artifacts[0], artifacts[1],
        "fresh blinding must change wallet proof bytes"
    );
    gpu_hash::shutdown().unwrap();
    for proof in artifacts {
        leaf::verify_joinsplit_research(&proof, &context, &public).unwrap();
        let mut changed = public.clone();
        changed[js::PI_FEE] += Val::ONE;
        assert!(leaf::verify_joinsplit_research(&proof, &context, &changed).is_err());
        let mut changed_context = context;
        changed_context.chain_id[0] ^= 1;
        assert!(leaf::verify_joinsplit_research(&proof, &changed_context, &public).is_err());
        assert!(
            leaf::verify_joinsplit_research(&proof[..proof.len() - 1], &context, &public).is_err()
        );
    }
}
