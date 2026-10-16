use super::*;
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_field::PrimeCharacteristicRing;

fn request() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    }
}
fn run() -> Run {
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    caps.set(Stage::WitnessTrace, Backend::OpenCl);
    caps.set(Stage::PublicValues, Backend::OpenCl);
    Run::new("gpu_htlc_trace", request(), caps).unwrap()
}
fn paths(w: &mut htlc::Witness) {
    let cms: Vec<_> = w
        .inputs
        .iter()
        .map(|v| {
            let owner = if v.note_type == Val::ONE {
                htlc::htlc_root(
                    v.redeem_tag,
                    v.refund_tag,
                    v.hashlock,
                    Val::from_u64(v.timeout),
                )
            } else {
                htlc::recipient_of(Val::from_u64(v.nk[0]), Val::from_u64(v.nk[1]), v.div)
            };
            htlc::commit(
                owner,
                Val::from_u64(v.value),
                v.rho,
                v.rcm,
                v.asset,
                v.note_type,
            )
        })
        .collect();
    let (_, paths) = htlc::build_paths(&cms);
    for (v, (sib, bits)) in w.inputs.iter_mut().zip(paths) {
        v.sib = sib;
        v.bits = bits;
    }
}
fn fixture(case: usize) -> htlc::Witness {
    let hashlock = [Val::from_u64(11), Val::ZERO, Val::from_u64(31), Val::ONE];
    match case {
        0 => htlc::demo_witness(),
        1 => htlc::tests::htlc_witness(true, 99, hashlock, 100),
        2 => htlc::tests::htlc_witness(false, 100, hashlock, 100),
        3 => htlc::tests::htlc_witness(
            true,
            (1 << htlc::BITS) - 2,
            [Val::ZERO, Val::ZERO, Val::ZERO, -Val::ONE],
            (1 << htlc::BITS) - 1,
        ),
        4 => {
            let mut w = htlc::demo_witness();
            let bound = 1u64 << htlc::BITS;
            w.inputs[0].nk = [GOLDILOCKS_MODULUS, u64::MAX];
            w.inputs[1].nk = [0, GOLDILOCKS_MODULUS + 1];
            w.inputs[0].value = bound - 1;
            w.inputs[1].value = 1;
            for v in &mut w.inputs {
                v.asset = -Val::ONE;
                v.div = -Val::ONE;
            }
            for v in &mut w.outputs {
                v.asset = -Val::ONE;
            }
            w.outputs[0].note_type = Val::ONE;
            w.outputs[0].value = bound - 2;
            w.outputs[1].value = 1;
            w.fee = 1;
            paths(&mut w);
            w
        }
        _ => {
            let mut w = fixture(1);
            let rho = w.inputs[1].rho;
            let rcm = w.inputs[1].rcm;
            w.inputs[1] = w.inputs[0].clone();
            w.inputs[1].rho = rho;
            w.inputs[1].rcm = rcm;
            w.inputs[1].value = 0;
            paths(&mut w);
            w
        }
    }
}

#[test]
fn htlc_plan_covers_raw_inputs_and_air_geometry() {
    let required = (INPUT_WORDS + GEOMETRY_WORDS + 1) * 8;
    assert!(plan(required - 1).is_err());
    let p = plan(required).unwrap();
    assert_eq!(
        p.specs().unwrap().iter().map(|s| s.bytes()).sum::<usize>(),
        p.trace.bytes() + p.public.bytes() + required
    );
    let words = input_words(&fixture(1)).unwrap();
    assert_eq!(words.0.len(), INPUT_WORDS);
    assert_eq!(words.0.capacity(), INPUT_WORDS);
    assert_eq!((htlc::HEIGHT, htlc::WIDTH, htlc::N_PUBLIC), (4096, 36, 31));
}

#[test]
#[ignore = "requires selected OpenCL GPU and <=3 GiB zero-swap service"]
fn gpu_htlc_trace_and_publics_match_cpu_for_plain_redeem_refund_and_boundaries() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    let mut statements = Vec::new();
    for case in 0..6 {
        let w = fixture(case);
        let run = run();
        let before = session.stats();
        let frame = session.htlc_witness(&w, 4 << 20, &run).unwrap();
        let generated = session.stats();
        assert_eq!(generated.uploaded_bytes - before.uploaded_bytes, 3504);
        assert_eq!(generated.downloaded_bytes - before.downloaded_bytes, 8);
        let bytes = frame.trace().spec().bytes() + frame.public().spec().bytes();
        assert!(frame.readback(&session, bytes - 1).is_err());
        let foreign = DeviceSession::new().unwrap();
        assert!(frame.readback(&foreign, bytes).is_err());
        drop(foreign);
        assert_eq!(session.stats().downloaded_bytes, generated.downloaded_bytes);
        let (trace, public) = frame.readback(&session, bytes).unwrap();
        assert_eq!(
            trace
                .iter()
                .zip(htlc::build_trace(&w).values.iter())
                .position(|(&a, b)| a != b.as_canonical_u64()),
            None,
            "trace case {case}"
        );
        assert_eq!(
            public,
            htlc::public_values(&w)
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            session.stats().downloaded_bytes - generated.downloaded_bytes,
            bytes as u64
        );
        statements.push(public);
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
    assert_eq!(
        &statements[1][htlc::PI_NF..htlc::PI_NF + 4],
        &statements[2][htlc::PI_NF..htlc::PI_NF + 4]
    );
    {
        let before = session.stats();
        let run = run();
        assert!(session.htlc_witness(&fixture(1), 1, &run).is_err());
        assert_eq!(before, session.stats());
        run.finish(false).unwrap();
    }
    for case in 0..14 {
        let mut w = fixture(1);
        match case {
            0 => w.inputs[1].asset += Val::ONE,
            1 => w.outputs[0].asset += Val::ONE,
            2 => w.inputs[1].sib[31][0] += Val::ONE,
            3 => w.fee += 1,
            4 => w.inputs[0].value = 1 << htlc::BITS,
            5 => w.inputs[0].note_type = Val::from_u64(2),
            6 => w.inputs[0].mode = Val::from_u64(2),
            7 => w.inputs[0].nk[0] += 1,
            8 => w.current_height = 100,
            9 => {
                w = fixture(2);
                w.current_height = 99;
            }
            10 => w = htlc::tests::htlc_witness(true, 99, [Val::ZERO; 4], 100),
            11 => {
                w = fixture(5);
                w.inputs[1].hashlock[0] += Val::ONE;
                paths(&mut w);
            }
            12 => w.current_height = 1 << htlc::BITS,
            _ => w.mint = 1,
        }
        let run = run();
        assert!(
            session.htlc_witness(&w, 4 << 20, &run).is_err(),
            "invalid case {case}"
        );
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

#[test]
#[ignore = "requires full owned OpenCL path, 1 GiB managed GPU and <=3 GiB zero-swap service"]
fn gpu_owned_htlc_redeem_refund_and_two_input_proofs_verify_after_shutdown() {
    use crate::block_v2::{
        commitment::Context, gpu_hash, leaf::LeafError, profile, quotient_pcs, typed_leaf,
    };
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x36; 32],
    };
    let w = fixture(1);
    let before = gpu_hash::report("htlc_admission_before").unwrap();
    let req = |policy| Request {
        policy,
        emit_report: true,
    };
    assert_eq!(
        typed_leaf::prove_htlc_on_gpu(&w, &context, req(Policy::CpuRequired)),
        Err(LeafError::ProvingPolicy.into())
    );
    #[cfg(debug_assertions)]
    assert_eq!(
        typed_leaf::prove_htlc_on_gpu(&w, &context, request()),
        Err(LeafError::ProvingPolicy.into())
    );
    let mut issuance = w.clone();
    issuance.mint = 1;
    assert_eq!(
        typed_leaf::prove_htlc_on_gpu(&issuance, &context, req(Policy::Compatible)),
        Err(typed_leaf::Error::UnauthorizedIssuance)
    );
    let mut wrong = context.clone();
    wrong.profile_id[0] ^= 1;
    assert_eq!(
        typed_leaf::prove_htlc_on_gpu(&w, &wrong, req(Policy::Compatible)),
        Err(LeafError::WrongProfile.into())
    );
    {
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("LATTICA_V2_WORKER_BUDGET", v),
                    None => std::env::remove_var("LATTICA_V2_WORKER_BUDGET"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("LATTICA_V2_WORKER_BUDGET"));
        std::env::set_var(
            "LATTICA_V2_WORKER_BUDGET",
            "public-worker-is-not-private-wallet-admission",
        );
        assert_eq!(
            typed_leaf::prove_htlc_on_gpu(&w, &context, req(Policy::Compatible)),
            Err(LeafError::GpuFailure.into())
        );
    }
    let after = gpu_hash::report("htlc_admission_after").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    let mut invalid = w.clone();
    invalid.current_height = 100;
    assert_eq!(
        typed_leaf::prove_htlc_on_gpu(&invalid, &context, req(Policy::Compatible)),
        Err(LeafError::GpuFailure.into())
    );
    let mut artifacts = Vec::new();
    for case in [1, 1, 2, 5] {
        let w = fixture(case);
        let policy = if cfg!(debug_assertions) {
            Policy::Compatible
        } else {
            Policy::GpuRequired
        };
        let proof = typed_leaf::prove_htlc_on_gpu(&w, &context, req(policy)).unwrap();
        artifacts.push((proof, htlc::public_values(&w), w.current_height));
    }
    assert_ne!(
        artifacts[0].0, artifacts[1].0,
        "fresh hiding must not replay HTLC proof bytes"
    );
    assert_eq!(
        &artifacts[0].1[htlc::PI_NF..htlc::PI_NF + 4],
        &artifacts[2].1[htlc::PI_NF..htlc::PI_NF + 4]
    );
    gpu_hash::shutdown().unwrap();
    for (proof, public, height) in artifacts {
        typed_leaf::verify_htlc_research(&proof, &context, &public, height).unwrap();
        assert_eq!(
            typed_leaf::verify_htlc_research(&proof, &context, &public, height + 1),
            Err(typed_leaf::Error::HeightMismatch)
        );
        for index in [
            htlc::PI_NF,
            htlc::PI_HASHLOCK,
            htlc::PI_HEIGHT,
            htlc::PI_FEE,
        ] {
            let mut altered = public.clone();
            altered[index] += Val::ONE;
            assert!(typed_leaf::verify_htlc_research(&proof, &context, &altered, height).is_err());
        }
        let mut wrong = context.clone();
        wrong.chain_id[0] ^= 1;
        assert!(typed_leaf::verify_htlc_research(&proof, &wrong, &public, height).is_err());
        assert!(typed_leaf::verify_htlc_research(
            &proof[..proof.len() - 1],
            &context,
            &public,
            height
        )
        .is_err());
    }
}
