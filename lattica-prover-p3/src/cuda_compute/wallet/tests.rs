use super::*;
mod benchmark;
mod reporting;
use crate::config::{Challenge, Val};
use crate::cuda_compute::{Limits, Randoms, Specialization, StarkRandomness, Starks};
use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
use crate::{htlc_air as htlc, joinsplit_air as js};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn open_runtime(limits: Limits) -> Runtime {
    Runtime::new(&std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(), limits).unwrap()
}

fn limits() -> Limits {
    Limits {
        managed_bytes: 256 << 20,
        max_allocation_bytes: 64 << 20,
        ..Limits::default()
    }
}

fn run() -> Run {
    let mut capabilities = Capabilities::cpu(Profile::LegacyQuadratic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    for stage in [Stage::WitnessTrace, Stage::PublicValues] {
        capabilities.set(stage, Backend::Cuda);
    }
    Run::new(
        "cuda_wallet_witness",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap()
}

fn finish(run: Run) {
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.capabilities.scope(), CoverageScope::Operation);
    assert_eq!(
        report
            .observations
            .iter()
            .map(|o| o.device_calls)
            .sum::<u64>(),
        3
    );
    assert!(report
        .observations
        .iter()
        .all(|o| o.backend == Backend::Cuda));
}

fn joinsplit(case: usize) -> js::Witness {
    let mut w = js::demo_witness();
    if case == 1 {
        let bound = 1u64 << js::BITS;
        w.inputs[0].value = bound - 1;
        w.inputs[1].value = 1;
        w.outputs[0].value = bound - 2;
        w.outputs[1].value = 1;
        w.fee = 1;
        w.inputs[0].nk = [0, crate::GOLDILOCKS_ORDER];
        w.inputs[1].nk = [crate::GOLDILOCKS_ORDER + 1, u64::MAX];
        for input in &mut w.inputs {
            input.asset = -Val::ONE;
            input.div = -Val::ONE;
        }
        for output in &mut w.outputs {
            output.asset = -Val::ONE;
        }
    } else if case == 2 {
        for input in &mut w.inputs {
            input.value = 0;
        }
        w.outputs[0].value = 1000;
        w.outputs[1].value = 2000;
        w.fee = 12;
        w.mint = 3012;
    }
    let commitments: Vec<_> = w
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
        w.inputs[i].sib[0] = commitments[1 - i];
        w.inputs[i].bits[0] = i == 1;
        for depth in 1..js::DEPTH {
            w.inputs[i].sib[depth] =
                std::array::from_fn(|k| Val::from_u64(((depth + 1) * (k + 1) * 17) as u64));
            w.inputs[i].bits[depth] = depth % 2 == 1;
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

fn htlc(case: usize) -> htlc::Witness {
    let hashlock = [Val::from_u64(11), Val::ZERO, Val::from_u64(31), Val::ONE];
    match case {
        0 => htlc::demo_witness(),
        1 => htlc::tests::htlc_witness(true, 99, hashlock, 100),
        2 => htlc::tests::htlc_witness(false, 100, hashlock, 100),
        _ => htlc::tests::htlc_witness(
            true,
            (1 << htlc::BITS) - 2,
            [Val::ZERO, Val::ZERO, Val::ZERO, -Val::ONE],
            (1 << htlc::BITS) - 1,
        ),
    }
}

fn compare(runtime: &Runtime, frame: NativeWalletTrace, trace: Vec<Val>, public: Vec<Val>) {
    let mut actual = vec![0; frame.trace.spec.words()];
    frame.trace.buffer.read(0, &mut actual).unwrap();
    assert_eq!(actual.len(), trace.len());
    assert_eq!(
        actual
            .iter()
            .zip(&trace)
            .position(|(&a, b)| a != b.as_canonical_u64()),
        None
    );
    let mut statement = vec![0; public.len()];
    frame.public.read(0, &mut statement).unwrap();
    assert_eq!(
        statement,
        public
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(runtime.snapshot().pending_commands, 0);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_traces_and_public_values_match_cpu_without_intermediate_readback() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    for case in 0..3 {
        let witness = joinsplit(case);
        let before = runtime.snapshot();
        let witness_run = run();
        let frame = wallets.joinsplit(&witness, 1 << 20, &witness_run).unwrap();
        finish(witness_run);
        let generated = runtime.snapshot();
        assert_eq!(generated.downloaded_bytes - before.downloaded_bytes, 8);
        assert_eq!(
            generated.uploaded_bytes - before.uploaded_bytes,
            ((gpu_wallet::INPUT_WORDS + gpu_wallet::GEOMETRY_WORDS) * 8) as u64
        );
        assert_eq!(generated.completed_commands - before.completed_commands, 3);
        assert_eq!(
            generated.live_bytes - before.live_bytes,
            frame.trace.spec.bytes() + js::N_PUBLIC * 8
        );
        compare(
            &runtime,
            frame,
            js::build_trace(&witness).values,
            js::public_values(&witness),
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
    for case in 0..4 {
        let witness = htlc(case);
        let before = runtime.snapshot();
        let witness_run = run();
        let frame = wallets.htlc(&witness, 1 << 20, &witness_run).unwrap();
        finish(witness_run);
        let generated = runtime.snapshot();
        assert_eq!(generated.downloaded_bytes - before.downloaded_bytes, 8);
        assert_eq!(generated.uploaded_bytes - before.uploaded_bytes, 3504);
        assert_eq!(generated.completed_commands - before.completed_commands, 3);
        assert_eq!(
            generated.live_bytes - before.live_bytes,
            frame.trace.spec.bytes() + htlc::N_PUBLIC * 8
        );
        compare(
            &runtime,
            frame,
            htlc::build_trace(&witness).values,
            htlc::public_values(&witness),
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_admission_preserves_state_and_invalid_witnesses_release_storage() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    let before = runtime.snapshot();
    assert!(wallets.joinsplit(&joinsplit(0), 1, &run()).is_err());
    assert!(wallets.htlc(&htlc(1), 1, &run()).is_err());
    assert_eq!(runtime.snapshot(), before);
    let cpu_run = Run::new(
        "cpu_policy_rejects_cuda_witness",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        Capabilities::cpu(Profile::LegacyQuadratic, false, false).scoped(
            CoverageScope::Operation,
            &[Stage::WitnessTrace, Stage::PublicValues],
        ),
    )
    .unwrap();
    assert!(wallets.joinsplit(&joinsplit(0), 1 << 20, &cpu_run).is_err());
    assert_eq!(runtime.snapshot(), before);
    cpu_run.finish(false).unwrap();
    for case in 0..5 {
        let mut w = joinsplit(0);
        match case {
            0 => w.inputs[1].asset += Val::ONE,
            1 => w.outputs[0].asset += Val::ONE,
            2 => w.inputs[1].sib[31][0] += Val::ONE,
            3 => w.fee += 1,
            _ => w.inputs[0].value = 1 << js::BITS,
        }
        let before = runtime.snapshot();
        assert!(wallets.joinsplit(&w, 1 << 20, &run()).is_err());
        let after = runtime.snapshot();
        assert_eq!(after.live_bytes, before.live_bytes);
        assert_eq!(after.allocations, before.allocations);
        assert_eq!(after.pending_commands, 0);
        assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
    }
    for case in 0..11 {
        let mut w = htlc(1);
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
                w = htlc(2);
                w.current_height = 99;
            }
            _ => w.mint = 1,
        }
        let before = runtime.snapshot();
        assert!(wallets.htlc(&w, 1 << 20, &run()).is_err());
        let after = runtime.snapshot();
        assert_eq!(after.live_bytes, before.live_bytes);
        assert_eq!(after.allocations, before.allocations);
        assert_eq!(after.pending_commands, 0);
        assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
    }
    drop(wallets);
    drop(runtime);
    let runtime = open_runtime(Limits {
        managed_bytes: 1 << 20,
        max_allocation_bytes: 1 << 20,
        ..limits()
    });
    let wallets = Wallets::new(&runtime).unwrap();
    let before = runtime.snapshot();
    assert!(wallets.htlc(&htlc(1), 1 << 20, &run()).is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(wallets);
    drop(runtime);
    let runtime = open_runtime(Limits {
        max_allocations: 8,
        ..limits()
    });
    let wallets = Wallets::new(&runtime).unwrap();
    let before = runtime.snapshot();
    assert!(wallets.joinsplit(&joinsplit(0), 1 << 20, &run()).is_err());
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_witnesses_feed_native_starks_and_pass_production_cpu_verification() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    let starks = Starks::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    // This path uses no CPU witness builder. Public-value reconstruction and
    // CPU verification run only after the complete native proof is produced.
    macro_rules! prove {
        ($w:expr, $generate:ident, $air:expr, $height:expr, $public:path) => {{
            let witness = $w;
            let prepared = starks
                .prepare::<Challenge, _>(&$air, $height.ilog2(), 256 << 20, Specialization::Prefer)
                .unwrap();
            let before = runtime.snapshot();
            let witness_run = run();
            let frame = wallets.$generate(&witness, 1 << 20, &witness_run).unwrap();
            finish(witness_run);
            assert_eq!(
                runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                8
            );
            let masks = randoms.import(ChaCha20Rng::from_seed([31; 32])).unwrap();
            let salts = randoms.import(ChaCha20Rng::from_seed([71; 32])).unwrap();
            let fri = randoms.import(ChaCha20Rng::from_seed([91; 32])).unwrap();
            let proof = starks
                .prove(
                    &prepared,
                    &frame.trace,
                    Some(&frame.public),
                    StarkRandomness {
                        masks: &masks,
                        commitments: &salts,
                        fri: &fri,
                    },
                    64 << 20,
                )
                .unwrap();
            let statement = $public(&witness);
            let mut device_statement = vec![0; statement.len()];
            frame.public.read(0, &mut device_statement).unwrap();
            assert_eq!(
                device_statement,
                statement
                    .iter()
                    .map(PrimeField64::as_canonical_u64)
                    .collect::<Vec<_>>()
            );
            let before_verify = runtime.snapshot();
            p3_uni_stark::verify(&crate::config::make_config(), &$air, &proof, &statement).unwrap();
            let mut invalid = statement;
            invalid[0] += Val::ONE;
            assert!(
                p3_uni_stark::verify(&crate::config::make_config(), &$air, &proof, &invalid)
                    .is_err()
            );
            assert_eq!(runtime.snapshot(), before_verify);
            drop((frame, masks, salts, fri));
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
        }};
    }
    prove!(
        joinsplit(1),
        joinsplit,
        js::JoinSplitAir,
        js::HEIGHT,
        js::public_values
    );
    prove!(
        htlc(1),
        htlc,
        htlc::HtlcAir,
        htlc::HEIGHT,
        htlc::public_values
    );
    prove!(
        htlc(2),
        htlc,
        htlc::HtlcAir,
        htlc::HEIGHT,
        htlc::public_values
    );
}

#[test]
#[ignore = "requires CUDA NVRTC"]
fn cuda_wallet_kernels_compile_for_volta_and_blackwell() {
    for target in [70, 120] {
        assert!(!super::super::compiler::compile(&source(), target)
            .unwrap()
            .is_empty());
    }
}
