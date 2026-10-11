use super::*;
use crate::block_v2::gpu_quotient_prover::{lookup_program::LookupProgram, program};
use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpression, SymbolicVariable};
use p3_lookup::{Kind, Lookup};

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

#[test]
fn lookup_compiler_bounds_inputs_and_preserves_scalar_store_lifetimes() {
    let (layout, lookups) = lookup_fixture();
    let compiled = LookupProgram::compile(layout, &lookups).unwrap();
    assert_eq!(compiled.lookup_count(), 3);
    assert_eq!(compiled.tuple_count(), 6);
    assert_eq!(compiled.boundaries, [0, 4, 6, 6]);
    let stores: Vec<_> = compiled
        .instructions
        .chunks_exact(5)
        .filter(|op| op[0] == program::STORE_BASE)
        .collect();
    assert_eq!(stores.len(), compiled.expression_words);
    assert_eq!(
        stores.iter().map(|op| op[3] as usize).collect::<Vec<_>>(),
        (0..compiled.expression_words).collect::<Vec<_>>()
    );
    assert!(stores
        .iter()
        .all(|op| (op[2] as usize) < compiled.registers));
    assert!(compiled.registers < compiled.instructions.len() / 5);
    for bad in [
        AirLayout {
            num_periodic_columns: 1,
            ..layout
        },
        AirLayout {
            permutation_width: 1,
            ..layout
        },
        AirLayout {
            num_permutation_challenges: 1,
            ..layout
        },
        AirLayout {
            num_permutation_values: 1,
            ..layout
        },
        AirLayout {
            num_public_values: program::MAX_ROW_WORDS + 1,
            ..layout
        },
        AirLayout {
            main_width: usize::MAX,
            ..layout
        },
    ] {
        assert!(LookupProgram::compile(bad, &lookups).is_err());
    }
    assert!(LookupProgram::compile(layout, &[]).is_err());
    for entry in [
        BaseEntry::Main { offset: 2 },
        BaseEntry::Preprocessed { offset: 2 },
        BaseEntry::Periodic,
    ] {
        let mut bad = lookups.clone();
        bad[0].elements[0][0] = variable(entry, 0);
        assert!(LookupProgram::compile(layout, &bad).is_err());
    }
    for (entry, index) in [
        (BaseEntry::Main { offset: 0 }, 3),
        (BaseEntry::Preprocessed { offset: 0 }, 2),
        (BaseEntry::Public, 2),
    ] {
        let mut bad = lookups.clone();
        bad[0].elements[0][0] = variable(entry, index);
        assert!(LookupProgram::compile(layout, &bad).is_err());
    }
    let mut bad = lookups.clone();
    bad[0].column = 1;
    assert!(LookupProgram::compile(layout, &bad).is_err());
    bad = (0..=super::super::lookup_program::MAX_LOOKUPS)
        .map(|column| Lookup {
            column,
            ..lookups[2].clone()
        })
        .collect();
    assert!(LookupProgram::compile(layout, &bad).is_err());
    bad = lookups.clone();
    bad[0].multiplicities.pop();
    assert!(LookupProgram::compile(layout, &bad).is_err());
    bad = lookups.clone();
    bad[0].elements = vec![vec![]; super::super::lookup_program::MAX_TUPLES + 1];
    bad[0].multiplicities = vec![Expr::ONE; bad[0].elements.len()];
    assert!(LookupProgram::compile(layout, &bad).is_err());
    bad = lookups.clone();
    bad[0].elements[0] = vec![Expr::ONE; program::MAX_ROW_WORDS];
    assert!(LookupProgram::compile(layout, &bad).is_err());
    let empty = Lookup {
        column: 0,
        ..lookups[2].clone()
    };
    let compiled = LookupProgram::compile(layout, &[empty]).unwrap();
    assert_eq!((compiled.expression_words, compiled.registers), (0, 0));
    assert!(compiled.instructions.is_empty());
}

macro_rules! lookup_differential_test {
    ($name:ident, $config:ty, $challenge:ty, $degree:literal) => {
        #[test]
        #[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
        fn $name() {
            type LookupConfig = $config;
            type LookupChallenge = $challenge;
            const DEGREE: usize = $degree;
            use crate::block_v2::gpu_hash::{
                device::{DeviceSession, Extension, MatrixSpec, RowOrder},
                initialize_quotient_test_engine, shutdown, Limits, TestShutdownGuard,
            };
            use p3_field::PrimeField64;
            use p3_matrix::dense::RowMajorMatrix;
            use std::sync::Arc;
            let _shutdown = TestShutdownGuard;
            initialize_quotient_test_engine(Limits {
                managed_bytes: 64 << 20,
                tile_bytes: 2 << 20,
                staging_bytes: 64 << 10,
            })
            .unwrap();
            let (layout, lookups) = lookup_fixture();
            let program = Arc::new(LookupProgram::compile(layout, &lookups).unwrap());
            let setup = DeviceSession::new().unwrap();
            let prepared = setup.prepare_lookup(program.clone()).unwrap();
            assert_eq!(setup.stats().prepared_lookup_programs, 1);
            drop(setup); // Immutable program must remain usable by fresh sessions.
            let live_bytes = |session: &DeviceSession| {
                session
                    .plan_outputs(&[
                        MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1).unwrap()
                    ])
                    .unwrap()
                    .live_bytes
            };
            let canonical = |v: &Val| v.as_canonical_u64();
            let flatten = |values: &[LookupChallenge]| {
                values
                    .iter()
                    .flat_map(|v| v.as_basis_coefficients_slice().iter().map(canonical))
                    .collect::<Vec<_>>()
            };
            let public = [Val::NEG_ONE, Val::from_u64(0xffff_fffe_0000_0001)];
            for log_rows in [0, 1, 6, 7, 8, 10, 11, 15] {
                let rows = 1usize << log_rows;
                let matrix = |width, salt| {
                    RowMajorMatrix::new(
                        (0..rows * width)
                            .map(|i| match (i + salt) % 5 {
                                0 => Val::ZERO,
                                1 => Val::NEG_ONE,
                                2 => Val::from_u64(0xffff_fffe_0000_0001),
                                _ => Val::from_u64((i + salt) as u64 * 37),
                            })
                            .collect(),
                        width,
                    )
                };
                let main = matrix(layout.main_width, 3);
                let pre = Some(matrix(layout.preprocessed_width, 7));
                let challenges: Vec<_> = (0..lookups.len() * 2)
                    .map(|i| {
                        LookupChallenge::from_basis_coefficients_fn(|j| {
                            Val::from_u64(17 + (i * 7 + j * 13 + log_rows as usize) as u64)
                        })
                    })
                    .collect();
                let challenge_words: Vec<[u64; DEGREE]> = challenges
                    .iter()
                    .map(|c| {
                        let coeffs: &[Val] = c.as_basis_coefficients_slice();
                        std::array::from_fn(|j| coeffs[j].as_canonical_u64())
                    })
                    .collect();
                let (cpu, terminal) = LogUpGadget::new().generate_permutation::<LookupConfig>(
                    &main,
                    &pre,
                    &public,
                    &lookups,
                    &challenges,
                );
                for main_order in [RowOrder::Natural, RowOrder::BitReversed] {
                    for pre_order in [RowOrder::Natural, RowOrder::BitReversed] {
                        let session = DeviceSession::new().unwrap();
                        let base = live_bytes(&session);
                        let upload = |m: &RowMajorMatrix<Val>, order| {
                            let mut words = vec![0u64; m.values.len()];
                            for row in 0..rows {
                                let physical = if order == RowOrder::BitReversed && log_rows != 0 {
                                    row.reverse_bits() >> (usize::BITS - log_rows)
                                } else {
                                    row
                                };
                                for col in 0..m.width {
                                    words[physical * m.width + col] =
                                        m.values[row * m.width + col].as_canonical_u64();
                                }
                            }
                            session
                                .upload(
                                    MatrixSpec::new(log_rows, m.width, Extension::Base, order, 1)
                                        .unwrap(),
                                    &words,
                                )
                                .unwrap()
                        };
                        let main_gpu = upload(&main, main_order);
                        let pre_gpu = upload(pre.as_ref().unwrap(), pre_order);
                        let before = session.stats();
                        let (permutation, end) = session
                            .lookup_permutation(
                                &prepared,
                                &main_gpu,
                                Some(&pre_gpu),
                                &public.map(|v| v.as_canonical_u64()),
                                &challenge_words,
                            )
                            .unwrap();
                        let after = session.stats();
                        assert_eq!(permutation.spec().extension().degree(), DEGREE);
                        assert_eq!(
                            after.downloaded_bytes - before.downloaded_bytes,
                            ((DEGREE + 1) * 8) as u64
                        );
                        assert_eq!(after.lookup_generations - before.lookup_generations, 1);
                        assert_eq!(
                            after.uploaded_bytes - before.uploaded_bytes,
                            ((public.len() + challenges.len() * DEGREE) * 8) as u64
                        );
                        assert_eq!(end.as_slice(), flatten(&[terminal.as_ref().unwrap().0]));
                        assert_eq!(
                            session
                                .read(&permutation, permutation.spec().bytes())
                                .unwrap(),
                            flatten(&cpu.values),
                            "height={rows}, main={main_order:?}, pre={pre_order:?}"
                        );
                        let foreign = DeviceSession::new().unwrap();
                        assert!(foreign
                            .lookup_permutation(
                                &prepared,
                                &main_gpu,
                                Some(&pre_gpu),
                                &public.map(|v| v.as_canonical_u64()),
                                &challenge_words
                            )
                            .is_err());
                        drop(foreign);
                        drop(permutation);
                        drop(pre_gpu);
                        drop(main_gpu);
                        assert_eq!(live_bytes(&session), base);
                    }
                }
            }
            // A zero active denominator is an error, but a zero multiplicity bypasses it.
            let session = DeviceSession::new().unwrap();
            let base = live_bytes(&session);
            let simple_layout = AirLayout {
                main_width: 1,
                ..Default::default()
            };
            let main = RowMajorMatrix::new(vec![Val::ONE; 256], 1);
            let main_gpu = session
                .upload(
                    MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
                    &[1; 256],
                )
                .unwrap();
            for mode in 0..3 {
                let lookup = Lookup {
                    kind: Kind::Local,
                    column: 0,
                    count_weight: 0,
                    elements: if mode == 2 {
                        vec![]
                    } else {
                        vec![vec![Expr::ONE]]
                    },
                    multiplicities: if mode == 2 {
                        vec![]
                    } else {
                        vec![if mode == 0 { Expr::ONE } else { Expr::ZERO }]
                    },
                };
                let prepared = session
                    .prepare_lookup(Arc::new(
                        LookupProgram::compile(simple_layout, &[lookup.clone()]).unwrap(),
                    ))
                    .unwrap();
                let baseline = live_bytes(&session);
                let admission = session.stats();
                assert!(session
                    .lookup_permutation::<1>(&prepared, &main_gpu, None, &[], &[[1]; 2])
                    .err()
                    .unwrap()
                    .contains("quadratic or cubic"));
                assert!(session
                    .lookup_permutation::<4>(&prepared, &main_gpu, None, &[], &[[1; 4]; 2])
                    .err()
                    .unwrap()
                    .contains("quadratic or cubic"));
                let mut malformed = [[1u64; DEGREE]; 2];
                malformed[0][0] = Val::ORDER_U64;
                assert!(session
                    .lookup_permutation(&prepared, &main_gpu, None, &[], &malformed)
                    .is_err());
                assert!(session
                    .lookup_permutation::<DEGREE>(&prepared, &main_gpu, None, &[], &[])
                    .is_err());
                assert_eq!(session.stats(), admission);
                assert_eq!(live_bytes(&session), baseline);
                let before = session.stats().downloaded_bytes;
                let result = session.lookup_permutation(
                    &prepared,
                    &main_gpu,
                    None,
                    &[],
                    &[
                        std::array::from_fn::<_, DEGREE, _>(|j| u64::from(j == 0)),
                        std::array::from_fn(|j| 2 + j as u64),
                    ],
                );
                if mode == 0 {
                    assert!(result.err().unwrap().contains("denominator is zero"));
                    assert_eq!(session.stats().downloaded_bytes - before, 8);
                } else {
                    let (output, terminal) = result.unwrap();
                    let (cpu, cpu_terminal) = LogUpGadget::new()
                        .generate_permutation::<LookupConfig>(
                            &main,
                            &None,
                            &[],
                            &[lookup],
                            &[
                                LookupChallenge::ONE,
                                LookupChallenge::from_basis_coefficients_fn(|j| {
                                    Val::from_u64(2 + j as u64)
                                }),
                            ],
                        );
                    assert_eq!(
                        session.stats().downloaded_bytes - before,
                        ((DEGREE + 1) * 8) as u64
                    );
                    assert_eq!(terminal.as_slice(), flatten(&[cpu_terminal.unwrap().0]));
                    assert_eq!(
                        session.read(&output, output.spec().bytes()).unwrap(),
                        flatten(&cpu.values)
                    );
                }
                assert_eq!(live_bytes(&session), baseline);
            }
            drop(main_gpu);
            assert_eq!(live_bytes(&session), base);
            drop(session);
            drop(prepared);
            shutdown().unwrap();
        }
    };
}

lookup_differential_test!(
    device_lookup_matches_logup_windows_scan_boundaries_and_failure_rules,
    profile::Config,
    profile::Challenge,
    3
);
lookup_differential_test!(
    device_quadratic_lookup_matches_logup_windows_scan_boundaries_and_failure_rules,
    crate::config::MyConfig,
    crate::config::Challenge,
    2
);
