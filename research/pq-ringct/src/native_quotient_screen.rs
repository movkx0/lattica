//! Stage-local native proofs using public synthetic operands. These runs do
//! not create RingCT transactions or qualify complete-workflow performance.
use crate::{
    aes_lane_air::{AesLaneAir, Descriptor},
    affine_air::{AffineAir, AffineInput, AffineKind},
    opencl::{Limits, Session},
    rust_verify::{D, Q, QHAT},
};
use lattica_prover_p3::{
    block_v2::{
        native_gpu::{self, ProvedNative},
        profile,
    },
    proving::{Backend, Policy, Report, Request, Stage},
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use serde::Serialize;
use std::time::Instant;

const HOST: usize = 24 << 30;
const REQUEST: Request = Request {
    policy: Policy::GpuRequired,
    emit_report: false,
};

#[derive(Serialize)]
struct Measurement<'a> {
    schema: &'static str,
    round: usize,
    case: usize,
    family: &'static str,
    variant: u64,
    count: usize,
    rows: usize,
    operation_host_bytes: usize,
    proof_wall_ns: u128,
    verification_ns: u128,
    verified: bool,
    mutation_rejected: bool,
    public_synthetic_inputs: bool,
    complete_workflow: bool,
    report: &'a Report,
}

fn record(
    round: usize,
    case: usize,
    family: &'static str,
    variant: u64,
    count: usize,
    rows: usize,
    proof_wall_ns: u128,
    proved: &ProvedNative,
    verify: impl Fn(&[Val]) -> bool,
) {
    let report = &proved.report;
    assert_eq!(report.policy, Policy::GpuRequired);
    assert!(report.succeeded && report.stage_coverage_complete && !report.completion_rejected);
    assert_eq!(report.observation_errors, 0);
    assert!(report.components.is_empty());
    assert!(report.elapsed_ns <= proof_wall_ns);
    assert_eq!(proved.proof.degree_bits, rows.ilog2() as usize + 1);
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        assert!(report.observations.iter().any(|o| o.stage == stage
            && o.backend == Backend::OpenCl
            && o.device_calls > 0
            && o.calls == o.completed_calls));
    }
    let started = Instant::now();
    assert!(verify(&proved.public_values));
    let mut changed = proved.public_values.clone();
    changed[0] += Val::ONE;
    assert!(!verify(&changed));
    let verification_ns = started.elapsed().as_nanos();
    eprintln!(
        "NATIVE_QUOTIENT_SCREEN {}",
        serde_json::to_string(&Measurement {
            schema: "ringct-native-quotient-screen-v1",
            round,
            case,
            family,
            variant,
            count,
            rows,
            operation_host_bytes: HOST,
            proof_wall_ns,
            verification_ns,
            verified: true,
            mutation_rejected: true,
            public_synthetic_inputs: true,
            complete_workflow: false,
            report,
        })
        .unwrap()
    );
}

#[test]
#[ignore = "exact guarded native quotient screen; exclusive OpenCL, host trees and fresh proof randomness"]
fn native_quotient_compilation_and_execution_verify_small_and_large_shapes() {
    assert_eq!(
        std::env::var("LATTICA_RINGCT_NATIVE_QUOTIENT_SCREEN").as_deref(),
        Ok("1")
    );
    // Raw operands are public test data; proof entropy is still drawn by the
    // ordinary GPU proving configuration. No proof or witness is reused.
    for round in 0..2 {
        let mut case = 0;
        for blocks in [8, 64] {
            for domain in [17, 29] {
                let air = AesLaneAir::new(Descriptor {
                    domain,
                    start_counter: 0,
                    output_len: blocks * 16,
                })
                .unwrap();
                let session = Session::start(Limits {
                    host_bytes: 32 << 30,
                    device_bytes: 8 << 30,
                    max_rows: 1 << 20,
                })
                .unwrap();
                let key = [0x5a; 32];
                let started = Instant::now();
                let proved = air.prove_gpu(&key, HOST, REQUEST).unwrap();
                let proof_wall_ns = started.elapsed().as_nanos();
                record(
                    round,
                    case,
                    "aes",
                    domain,
                    blocks,
                    air.height,
                    proof_wall_ns,
                    &proved,
                    |public| {
                        p3_uni_stark::verify(
                            &profile::make_cpu_config(),
                            &air,
                            &proved.proof,
                            public,
                        )
                        .is_ok()
                    },
                );
                drop(proved);
                session.close_without_completion().unwrap();
                case += 1;
            }
        }
        for count in [8, 64] {
            for (variant, kind, modulus) in [
                (0, AffineKind::Add, Q),
                (1, AffineKind::Sub, QHAT),
                (2, AffineKind::SignedToCanonical { bound: 565 }, Q),
                (3, AffineKind::SignedToCanonical { bound: 565 }, QHAT),
            ] {
                let air = AffineAir::new(kind, modulus, count).unwrap();
                let one = if kind.is_conversion() {
                    AffineInput::Signed(core::array::from_fn(|i| [-565, 0, 565][i % 3]))
                } else {
                    AffineInput::Binary {
                        left: [37; D],
                        right: [19; D],
                    }
                };
                let inputs = vec![one; count];
                let session = Session::start(Limits {
                    host_bytes: 32 << 30,
                    device_bytes: 8 << 30,
                    max_rows: 1 << 20,
                })
                .unwrap();
                let started = Instant::now();
                let proved = native_gpu::prove(
                    "ringct_native_quotient_affine_screen",
                    &air,
                    &air,
                    air.height(),
                    HOST,
                    REQUEST,
                    |context| air.generate_gpu(context, &inputs),
                )
                .unwrap();
                let proof_wall_ns = started.elapsed().as_nanos();
                record(
                    round,
                    case,
                    "affine",
                    variant,
                    count,
                    air.height(),
                    proof_wall_ns,
                    &proved,
                    |public| {
                        p3_uni_stark::verify(
                            &profile::make_cpu_config(),
                            &air,
                            &proved.proof,
                            public,
                        )
                        .is_ok()
                    },
                );
                drop(proved);
                session.close_without_completion().unwrap();
                case += 1;
            }
        }
        assert_eq!(case, 12);
    }
    eprintln!(
        "NATIVE_QUOTIENT_SCREEN_COMPLETE rounds=2 cases_per_round=12 proofs=24 verified=24 mutations_rejected=24 complete_workflow=false"
    );
}
