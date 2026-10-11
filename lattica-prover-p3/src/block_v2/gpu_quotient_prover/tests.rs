use super::{evaluate, program::Program};
use crate::{
    block_v2::{
        machine::{MachineAir, ProgramBuilder},
        profile,
    },
    config::Val,
};
use p3_air::{symbolic::AirLayout, Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::{logup::LogUpGadget, InteractionBuilder, LookupProtocol, Lookups};

mod device_pipeline;
mod extensions;
mod lookup;

/// Add next-row reads and interleaved base/extension assertions to the native
/// machine AIR. These checks intentionally need not hold on the random matrices
/// below: comparing nonzero quotient values exercises the complete evaluator.
struct WindowsAndExtensions(MachineAir);
impl BaseAir<Val> for WindowsAndExtensions {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
}
impl<AB> Air<AB> for WindowsAndExtensions
where
    AB: PermutationAirBuilder<F = Val, EF = profile::Challenge> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let local = main.current_slice();
        let next = main.next_slice();
        let prep = pre.current_slice();
        let prep_next = pre.next_slice();
        let x: AB::Expr = local[0].into();
        builder.assert_zero((x.clone() - next[1]) * (prep[0].into() + prep_next[1]));
        builder.when_first_row().assert_zero(-x.clone() + next[2]);
        let random: AB::ExprEF = builder.permutation_randomness()[0].into();
        let terminal: AB::ExprEF = builder.permutation_values()[0].clone().into();
        let constant =
            profile::Challenge::from_basis_coefficients_fn(|i| Val::from_u64(11 + i as u64));
        builder
            .assert_zero_ext(-(random.clone() + terminal) * (random - AB::ExprEF::from(constant)));
        // A base constraint after an extension constraint tests global ordering.
        builder.when_last_row().assert_zero(x + prep_next[2]);
        builder
            .when_transition()
            .assert_zero(next[0].into() - prep[1]);
    }
}

struct Hinted {
    degree: Option<usize>,
    count: Option<usize>,
}
impl BaseAir<Val> for Hinted {
    fn width(&self) -> usize {
        1
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.degree
    }
    fn num_constraints(&self) -> Option<usize> {
        self.count
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Hinted {
    fn eval(&self, builder: &mut AB) {
        let x: AB::Expr = builder.main().current_slice()[0].into();
        let constant = AB::Expr::from(Val::from_u64(3)) + AB::Expr::from(Val::from_u64(4));
        builder.assert_zero(x.clone() * x + constant);
    }
}

fn fixture() -> (WindowsAndExtensions, Lookups<Val>) {
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    let public = builder.public(0).unwrap();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let layout = AirLayout::from_air::<Val>(&air);
    let gadget = LogUpGadget::new();
    let lookups = Lookups::<Val>::from_air::<profile::Challenge, _>(&air);
    let log_chunks =
        p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
            &air, layout, &lookups, 1, &gadget,
        );
    let lookups = lookups.pack_same_bus(&gadget, 1 << log_chunks);
    assert!(!lookups.is_empty());
    (WindowsAndExtensions(air), lookups)
}

#[test]
fn compiled_native_constraints_reuse_scratch_and_reject_unsupported_layouts() {
    let (air, lookups) = fixture();
    let layout = AirLayout::from_air::<Val>(&air);
    let program = Program::compile(&air, layout, &lookups, &LogUpGadget::new()).unwrap();
    assert!(program.constraints > 0);
    assert!(program.registers < program.instruction_count() / 2);
    assert_eq!(
        program.instructions.len() % super::program::WORDS_PER_INSTRUCTION,
        0
    );
    let invalid = AirLayout {
        num_periodic_columns: 1,
        ..layout
    };
    assert!(Program::compile(&air, invalid, &lookups, &LogUpGadget::new()).is_err());
    let invalid = AirLayout {
        main_width: usize::MAX,
        ..layout
    };
    assert!(Program::compile(&air, invalid, &lookups, &LogUpGadget::new()).is_err());
}

#[cfg(feature = "gpu")]
#[test]
fn normalized_quotient_ir_matches_native_and_batch_memory_is_bounded() {
    use super::compile::Batch;
    use crate::block_v2::machine::{compiler_constants::Constants, symbolic};
    let (air, lookups) = fixture();
    let layout = AirLayout::from_air::<Val>(&air);
    let gadget = LogUpGadget::new();
    let constraints =
        symbolic::batch_with_layout(&air, layout, &lookups, &gadget, Constants::cpu()).unwrap();
    let normalized = symbolic::batch_layout(layout, &lookups, &gadget).unwrap();
    let program = Program::from_constraints(normalized, &constraints).unwrap();
    let native = Program::compile(&air, layout, &lookups, &gadget).unwrap();
    assert_same_ir(&program, &native);
    for hiding in [0, 1] {
        assert_eq!(
            symbolic::batch_log_chunks(&air, &constraints, &lookups, &gadget, hiding).unwrap(),
            p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
                &air, layout, &lookups, hiding, &gadget
            )
        );
    }
    assert!(symbolic::batch_log_chunks(&air, &constraints, &lookups, &gadget, 2).is_err());
    for degree in [None, Some(3)] {
        let air = Hinted {
            degree,
            count: Some(1),
        };
        let layout = AirLayout::from_air::<Val>(&air);
        let constraints =
            symbolic::batch_with_layout(&air, layout, &[], &gadget, Constants::cpu()).unwrap();
        let program = Program::from_constraints(layout, &constraints).unwrap();
        assert_same_ir(
            &program,
            &Program::compile(&air, layout, &[], &gadget).unwrap(),
        );
        for hiding in [0, 1] {
            assert_eq!(
                symbolic::batch_log_chunks(&air, &constraints, &[], &gadget, hiding).unwrap(),
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                    Val,
                    profile::Challenge,
                    _,
                    _,
                >(&air, layout, &[], hiding, &gadget)
            );
        }
    }
    let allowance = symbolic::HOST_BYTES as usize;
    assert!(Batch::new(1, allowance - 1).is_err());
    assert!(Batch::new(usize::MAX, allowance).is_err());
    let mut batch = Batch::new(2, allowance).unwrap();
    batch.push(program, 1, constraints.base.len()).unwrap();
    batch.push(native, 1, constraints.base.len()).unwrap();
    assert_same_ir(&batch.get(0).program, &batch.get(1).program);
    assert!(batch
        .push(
            Program::compile(&air, layout, &lookups, &gadget).unwrap(),
            1,
            0
        )
        .is_err());
    let mut huge = Program::compile(&air, layout, &lookups, &gadget).unwrap();
    huge.instructions = Vec::with_capacity(16 << 17);
    assert!(Batch::new(1, allowance).unwrap().push(huge, 1, 0).is_err());
}

fn assert_same_ir(actual: &Program, expected: &Program) {
    assert_eq!(actual.instructions, expected.instructions);
    assert_eq!(actual.registers, expected.registers);
    assert_eq!(actual.constraints, expected.constraints);
    assert_eq!(actual.row_words, expected.row_words);
    assert_eq!(actual.parameter_words, expected.parameter_words);
    assert_eq!(
        format!("{:?}", actual.layout),
        format!("{:?}", expected.layout)
    );
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
fn gpu_quotients_match_reference_on_nonzero_constraints_domains_and_tile_boundaries() {
    use crate::block_v2::gpu_hash::{shutdown, Limits, TestShutdownGuard};
    use p3_field::coset::TwoAdicMultiplicativeCoset as Domain;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::StarkGenericConfig;
    use std::time::Instant;
    let _shutdown = TestShutdownGuard;
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 16 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let (air, lookups) = fixture();
    let gadget = LogUpGadget::new();
    let layout = AirLayout::from_air::<Val>(&air);
    let config = profile::make_config();
    let session = crate::block_v2::gpu_hash::device::DeviceSession::new().unwrap();
    let mut capabilities =
        crate::proving::Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, true);
    capabilities.set(
        crate::proving::Stage::Preprocessing,
        crate::proving::Backend::OpenCl,
    );
    let run = crate::proving::Run::new(
        "gpu_quotient_compiler_conformance",
        crate::proving::Request::compatible(),
        capabilities,
    )
    .unwrap();
    let (compiled, log_chunks, _) =
        super::compile::air(&session, &run, &air, layout, &lookups, 1).unwrap();
    assert_same_ir(
        &compiled,
        &Program::compile(&air, layout, &lookups, &gadget).unwrap(),
    );
    assert_eq!(
        log_chunks,
        p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
            &air, layout, &lookups, 1, &gadget
        )
    );
    for degree in [None, Some(3)] {
        let air = Hinted {
            degree,
            count: Some(1),
        };
        let layout = AirLayout::from_air::<Val>(&air);
        for hiding in [0, 1] {
            let (program, chunks, count) =
                super::compile::air(&session, &run, &air, layout, &[], hiding).unwrap();
            assert_same_ir(
                &program,
                &Program::compile(&air, layout, &[], &gadget).unwrap(),
            );
            assert_eq!(count, 1);
            assert_eq!(
                chunks,
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                    Val,
                    profile::Challenge,
                    _,
                    _,
                >(&air, layout, &[], hiding, &gadget)
            );
        }
    }
    for (degree, count) in [(Some(1), None), (None, Some(2))] {
        let bad = Hinted { degree, count };
        assert!(super::compile::air(
            &session,
            &run,
            &bad,
            AirLayout::from_air::<Val>(&bad),
            &[],
            1
        )
        .is_err());
    }
    let before = session.stats();
    for bad in [
        AirLayout {
            main_width: usize::MAX,
            ..layout
        },
        AirLayout {
            num_periodic_columns: 1,
            ..layout
        },
    ] {
        assert!(super::compile::air(&session, &run, &air, bad, &lookups, 1).is_err());
    }
    assert_eq!(session.stats(), before);
    let report = run.finish(true).unwrap();
    assert!(report.observations.iter().any(|o| o.completed_calls > 0));
    assert!(report
        .observations
        .iter()
        .all(|o| o.backend == crate::proving::Backend::OpenCl));
    drop(session);

    let challenges: Vec<_> = (0..lookups.len() * gadget.num_challenges())
        .map(|i| {
            profile::Challenge::from_basis_coefficients_fn(|j| {
                Val::from_u64((i * 19 + j + 7) as u64)
            })
        })
        .collect();
    let terminals = [profile::Challenge::from_basis_coefficients_fn(|i| {
        Val::from_u64(29 + i as u64)
    })];
    for (log_trace, log_quotient) in [(0, 3), (3, 5), (4, 12)] {
        let height = 1usize << log_quotient;
        let matrix = |width, salt: u64| {
            RowMajorMatrix::new(
                (0..height * width)
                    .map(|i| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xffff_ffff_0000_0000)
                                .wrapping_add(salt),
                        )
                    })
                    .collect(),
                width,
            )
        };
        let main = matrix(air.width(), 17);
        let prep = matrix(air.preprocessed_width(), 19);
        let permutation = matrix((lookups.len() + 1) * 3, 23);
        let trace_domain = Domain::new(Val::ONE, log_trace).unwrap();
        let quotient_domain = Domain::new(Val::from_u64(7), log_quotient).unwrap();
        for (alpha_id, alpha) in [
            profile::Challenge::ZERO,
            profile::Challenge::ONE,
            profile::Challenge::from_basis_coefficients_fn(|i| Val::from_u64(31 + i as u64)),
        ]
        .into_iter()
        .enumerate()
        {
            let started = Instant::now();
            let expected = p3_batch_stark::prover::quotient_values::<profile::Config, _, _, _>(
                config.pcs(),
                &air,
                &[Val::ONE],
                layout,
                trace_domain,
                quotient_domain,
                &main,
                Some(&permutation),
                &lookups,
                &terminals,
                &gadget,
                &challenges,
                Some(&prep),
                alpha,
            );
            let cpu_ns = started.elapsed().as_nanos();
            let started = Instant::now();
            let actual = evaluate::quotient_values(
                &compiled,
                &[Val::ONE],
                trace_domain,
                quotient_domain,
                &main,
                Some(&permutation),
                &terminals,
                &challenges,
                Some(&prep),
                alpha,
            )
            .unwrap();
            assert_eq!(
                actual, expected,
                "log_trace={log_trace} log_quotient={log_quotient} alpha={alpha_id}"
            );
            assert!(actual.iter().any(|v| *v != profile::Challenge::ZERO));
            eprintln!(
                "quotient_comparison rows={height} alpha_id={alpha_id} cpu_ns={cpu_ns} gpu_ns={}",
                started.elapsed().as_nanos()
            );
        }
        let overlap = Domain::new(Val::ONE, log_quotient).unwrap();
        assert!(evaluate::quotient_values(
            &compiled,
            &[Val::ONE],
            trace_domain,
            overlap,
            &main,
            Some(&permutation),
            &terminals,
            &challenges,
            Some(&prep),
            profile::Challenge::ONE
        )
        .is_err());
    }
    shutdown().unwrap();
}
