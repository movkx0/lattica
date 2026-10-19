use super::*;
mod guards;
mod resident;
use crate::{
    config::Val,
    cuda_compute::Limits,
    proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run},
};
use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpression, SymbolicVariable};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{logup::LogUpGadget, Kind, LookupProtocol};
use p3_matrix::dense::RowMajorMatrix;

fn runtime(limits: Limits) -> Runtime {
    Runtime::new(&std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(), limits).unwrap()
}
fn limits() -> Limits {
    Limits {
        managed_bytes: 128 << 20,
        max_allocation_bytes: 64 << 20,
        ..Limits::default()
    }
}
fn run() -> Run {
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, false, true)
        .scoped(CoverageScope::Operation, &[Stage::Lookup]);
    caps.set(Stage::Lookup, Backend::Cuda);
    Run::new(
        "cuda_lookup",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        caps,
    )
    .unwrap()
}
fn words<F: ExtensionField<Val>>(values: &[F]) -> Vec<u64> {
    values
        .iter()
        .flat_map(|v| {
            v.as_basis_coefficients_slice()
                .iter()
                .map(PrimeField64::as_canonical_u64)
        })
        .collect()
}
fn upload(runtime: &Runtime, matrix: &RowMajorMatrix<Val>, order: RowOrder) -> Matrix {
    let log = (matrix.values.len() / matrix.width).ilog2();
    let mut encoded = vec![0; matrix.values.len()];
    for row in 0usize..1 << log {
        let physical = if order == RowOrder::BitReversed && log != 0 {
            row.reverse_bits() >> (usize::BITS - log)
        } else {
            row
        };
        for col in 0..matrix.width {
            encoded[physical * matrix.width + col] =
                matrix.values[row * matrix.width + col].as_canonical_u64();
        }
    }
    runtime
        .upload_matrix(
            MatrixSpec::new(log, matrix.width, Extension::Base, order, 1).unwrap(),
            &encoded,
        )
        .unwrap()
}

type Expr = SymbolicExpression<Val>;

fn variable(entry: BaseEntry, index: usize) -> Expr {
    SymbolicVariable::new(entry, index).into()
}

fn lookup_fixture() -> (AirLayout, Vec<Lookup<Val>>) {
    let layout = AirLayout {
        main_width: 3,
        preprocessed_width: 2,
        num_public_values: 2,
        ..Default::default()
    };
    let m = variable(BaseEntry::Main { offset: 0 }, 0);
    let n = variable(BaseEntry::Main { offset: 1 }, 1);
    let p = variable(BaseEntry::Preprocessed { offset: 0 }, 0);
    let q = variable(BaseEntry::Preprocessed { offset: 1 }, 1);
    let public = variable(BaseEntry::Public, 0);
    let shared = (m.clone() + p.clone()) * (n.clone() - q.clone());
    let first = Expr::Leaf(BaseLeaf::IsFirstRow);
    let last = Expr::Leaf(BaseLeaf::IsLastRow);
    let transition = Expr::Leaf(BaseLeaf::IsTransition);
    // Shared subexpressions survive multiple stores and lookup boundaries.
    let lookups = vec![
        Lookup {
            kind: Kind::Local,
            elements: vec![
                vec![m.clone(), n + p, public],
                vec![],
                vec![Val::NEG_ONE.into()],
                vec![shared.clone(), shared.clone() * shared.clone()],
            ],
            multiplicities: vec![transition, -first, last, -shared.clone()],
            count_weight: 0,
            column: 0,
        },
        Lookup {
            kind: Kind::Global("test".into()),
            elements: vec![
                vec![shared.clone(), q, variable(BaseEntry::Public, 1)],
                vec![m],
            ],
            multiplicities: vec![shared, Expr::ZERO],
            count_weight: 1,
            column: 1,
        },
        Lookup {
            kind: Kind::Local,
            elements: vec![],
            multiplicities: vec![],
            count_weight: 0,
            column: 2,
        },
    ];
    (layout, lookups)
}

macro_rules! differential {
    ($name:ident, $config:ty, $field:ty, $extension:expr) => {
        #[test]
        #[ignore = "requires CUDA; serial bounded service"]
        fn $name() {
            let runtime = runtime(limits());
            let engine = Lookups::new(&runtime).unwrap();
            let (layout, lookups) = lookup_fixture();
            let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
            let public = [Val::NEG_ONE, Val::from_u64(71)];
            let public_gpu = runtime.allocate(public.len()).unwrap();
            public_gpu
                .write(0, &public.map(|v| v.as_canonical_u64()))
                .unwrap();
            for log in [0, 1, 6, 7, 8, 11, 15] {
                let rows = 1usize << log;
                let matrix = |width, salt| {
                    RowMajorMatrix::new(
                        (0..rows * width)
                            .map(|i| match (i + salt) % 5 {
                                0 => Val::ZERO,
                                1 => Val::NEG_ONE,
                                2 => Val::ONE,
                                _ => Val::from_u64((i * 19 + salt * 37) as u64),
                            })
                            .collect(),
                        width,
                    )
                };
                let main = matrix(layout.main_width, 3);
                let pre = Some(matrix(layout.preprocessed_width, 7));
                let challenges: Vec<$field> = (0..lookups.len() * 2)
                    .map(|i| {
                        <$field>::from_basis_coefficients_fn(|j| {
                            Val::from_u64(17 + (i * 7 + j * 13 + log) as u64)
                        })
                    })
                    .collect();
                let challenge_gpu = runtime
                    .allocate(challenges.len() * $extension.degree())
                    .unwrap();
                challenge_gpu.write(0, &words(&challenges)).unwrap();
                let (expected, terminal) = LogUpGadget::new().generate_permutation::<$config>(
                    &main,
                    &pre,
                    &public,
                    &lookups,
                    &challenges,
                );
                for main_order in [RowOrder::Natural, RowOrder::BitReversed] {
                    for pre_order in [RowOrder::Natural, RowOrder::BitReversed] {
                        let main_gpu = upload(&runtime, &main, main_order);
                        let pre_gpu = upload(&runtime, pre.as_ref().unwrap(), pre_order);
                        let before = runtime.snapshot();
                        let attempt = run();
                        let witness = runtime
                            .reported(&attempt, || {
                                engine.generate(
                                    &prepared,
                                    &main_gpu,
                                    Some(&pre_gpu),
                                    Some(&public_gpu),
                                    &challenge_gpu,
                                    $extension,
                                )
                            })
                            .unwrap();
                        let after = runtime.snapshot();
                        let report = attempt.finish(true).unwrap();
                        assert!(report.stage_coverage_complete);
                        assert_eq!(report.observations.len(), 1);
                        assert_eq!(report.observations[0].stage, Stage::Lookup);
                        assert_eq!(
                            report.observations[0].device_calls,
                            after.completed_commands - before.completed_commands
                        );
                        assert_eq!(
                            report.observations[0].device_ns,
                            after.device_ns - before.device_ns
                        );
                        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                        assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
                        assert_eq!(
                            witness.trace.read(64 << 20).unwrap(),
                            words(&expected.values),
                            "height={rows}, main={main_order:?}, pre={pre_order:?}"
                        );
                        let mut end = vec![0; $extension.degree()];
                        witness.terminal().buffer.read(0, &mut end).unwrap();
                        assert_eq!(end, words(&[terminal.as_ref().unwrap().0]));
                        drop(witness);
                        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
                        assert_eq!(runtime.snapshot().allocations, before.allocations);
                        assert_eq!(runtime.snapshot().pending_commands, 0);
                    }
                }
            }
            drop((public_gpu, prepared, engine));
            assert_eq!(runtime.snapshot().live_bytes, 0);
            assert_eq!(runtime.snapshot().public_programs, 0);
            assert_eq!(runtime.snapshot().public_program_bytes, 0);
        }
    };
}

differential!(
    cuda_quadratic_lookup_matches_cpu_with_resident_inputs_and_stage_receipts,
    crate::config::MyConfig,
    crate::config::Challenge,
    Extension::Quadratic
);
differential!(
    cuda_cubic_lookup_matches_cpu_with_resident_inputs_and_stage_receipts,
    crate::block_v2::profile::Config,
    crate::block_v2::profile::Challenge,
    Extension::Cubic
);

fn simple(multiplicity: Expr) -> (AirLayout, Vec<Lookup<Val>>) {
    (
        AirLayout {
            main_width: 1,
            ..Default::default()
        },
        vec![Lookup {
            kind: Kind::Local,
            column: 0,
            count_weight: 0,
            elements: vec![vec![Expr::ONE]],
            multiplicities: vec![multiplicity],
        }],
    )
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_zero_denominators_reject_only_active_tuples_and_release_private_storage() {
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    let main = runtime
        .upload_matrix(
            MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &[1; 256],
        )
        .unwrap();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let challenges = runtime.allocate(2 * extension.degree()).unwrap();
        challenges.write(0, &[1]).unwrap(); // alpha=1; beta=0; tuple value=1.
        for active in [false, true] {
            let (layout, lookups) = simple(if active { Expr::ONE } else { Expr::ZERO });
            let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
            let before = runtime.snapshot();
            let attempt = run();
            let result = runtime.reported(&attempt, || {
                engine.generate(&prepared, &main, None, None, &challenges, extension)
            });
            if active {
                assert!(result.is_err());
                let report = attempt.finish(false).unwrap();
                assert!(report.observation_errors > 0);
                assert!(report.observations[0].device_calls > 0);
            } else {
                let witness = result.unwrap();
                assert!(attempt.finish(true).unwrap().stage_coverage_complete);
                assert!(witness.trace.read(1 << 20).unwrap().iter().all(|&v| v == 0));
                let mut end = vec![1; extension.degree()];
                witness.terminal().buffer.read(0, &mut end).unwrap();
                assert!(end.iter().all(|&v| v == 0));
            }
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
        }
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_admission_rejects_before_upload_or_launch() {
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    let (layout, mut lookups) = simple(Expr::ONE);
    let before = runtime.snapshot();
    assert!(engine.prepare(layout, &lookups, 1).is_err());
    assert_eq!(runtime.snapshot(), before);
    lookups[0].column = 1;
    assert!(engine.prepare(layout, &lookups, 256 << 20).is_err());
    assert_eq!(runtime.snapshot(), before);
    lookups[0].column = 0;
    let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
    let main = runtime
        .upload_matrix(
            MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &[1; 256],
        )
        .unwrap();
    let challenge = runtime.allocate(6).unwrap();
    let public = runtime.allocate(1).unwrap();
    let before = runtime.snapshot();
    for extension in [Extension::Base, Extension::Quadratic] {
        assert!(engine
            .generate(&prepared, &main, None, None, &challenge, extension)
            .is_err());
    }
    assert!(engine
        .generate(
            &prepared,
            &main,
            Some(&main),
            None,
            &challenge,
            Extension::Cubic
        )
        .is_err());
    assert!(engine
        .generate(
            &prepared,
            &main,
            None,
            Some(&public),
            &challenge,
            Extension::Cubic
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    drop((main, public, challenge, prepared, engine, runtime));
    for limits in [
        Limits {
            max_allocations: 8,
            ..self::limits()
        },
        Limits {
            managed_bytes: 16 << 10,
            max_allocation_bytes: 16 << 10,
            ..self::limits()
        },
        Limits {
            max_allocation_bytes: 8 << 10,
            ..self::limits()
        },
    ] {
        let runtime = self::runtime(limits);
        let engine = Lookups::new(&runtime).unwrap();
        let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
        let main = runtime
            .upload_matrix(
                MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
                &[1; 256],
            )
            .unwrap();
        let challenge = runtime.allocate(6).unwrap();
        let before = runtime.snapshot();
        assert!(engine
            .generate(&prepared, &main, None, None, &challenge, Extension::Cubic)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
}

#[test]
#[ignore = "requires CUDA NVRTC"]
fn cuda_lookup_kernels_compile_for_volta_and_blackwell() {
    for target in [70, 120] {
        assert!(!super::super::compiler::compile(&source(), target)
            .unwrap()
            .is_empty());
    }
}
