use super::*;
use crate::{
    block_v2::machine::{MachineAir, ProgramBuilder},
    config::Val,
    cuda_compute::Limits,
    proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run},
};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

fn limits() -> Limits {
    Limits {
        managed_bytes: 128 << 20,
        max_allocation_bytes: 64 << 20,
        ..Limits::default()
    }
}
fn runtime(limits: Limits) -> Runtime {
    Runtime::new(&std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(), limits).unwrap()
}
fn run(stages: &[Stage]) -> Run {
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true)
        .scoped(CoverageScope::Operation, stages);
    for &stage in stages {
        capabilities.set(stage, Backend::Cuda);
    }
    Run::new(
        "cuda_machine",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap()
}
fn words(values: &[Val]) -> Vec<u64> {
    values.iter().map(PrimeField64::as_canonical_u64).collect()
}

fn fixture(branches: usize, depth: usize, publics: usize) -> Program {
    let mut b = ProgramBuilder::new(publics).unwrap();
    let one = b.constant(Val::ONE);
    let zero = b.constant(Val::ZERO);
    let mut hash = core::array::from_fn(|_| b.input());
    let bit = b.input();
    b.assert_bool(bit);
    for _ in 0..branches {
        let a = core::array::from_fn(|_| b.input());
        let z = core::array::from_fn(|_| b.input());
        let sum = b.add(a[0], z[0]);
        let product = b.mul(sum, z[1]);
        let inverse = b.inverse(product);
        let identity = b.mul(product, inverse);
        b.assert_equal(identity, one);
        let selected = b.select(bit, a[0], product);
        let high = b.bit_hint(selected, 63);
        let low = b.bit_hint(inverse, 0);
        b.assert_bool(high);
        b.assert_bool(low);
        let hint = b.select_hint(vec![a[0], selected, product, inverse], &[low, high]);
        b.add(hint, selected);
        let product = b.cubic_mul(a, z);
        let inverse = b.cubic_inverse(product);
        let identity = b.cubic_mul(product, inverse);
        b.assert_equal(identity[0], one);
        b.assert_equal(identity[1], zero);
        b.assert_equal(identity[2], zero);
    }
    for _ in 0..depth {
        hash = b.poseidon(hash);
    }
    if publics > 0 {
        b.add(hash[0], b.public(0).unwrap());
    }
    b.finish(None).unwrap()
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_witness_and_preprocessing_match_cpu_with_complete_component_receipts() {
    let runtime = runtime(limits());
    let engine = Witnesses::new(&runtime).unwrap();
    let mut programs = vec![
        ProgramBuilder::new(0).unwrap().finish(None).unwrap(),
        ProgramBuilder::new(64).unwrap().finish(Some(256)).unwrap(),
    ];
    for (branches, depth, publics) in [(1, 1, 1), (7, 4, 33), (23, 9, 64), (257, 65, 64)] {
        programs.push(fixture(branches, depth, publics));
    }
    for program in programs {
        let prepared = engine.prepare(&program, 64 << 20).unwrap();
        let air = MachineAir::new(program.clone());
        let before = runtime.snapshot();
        let attempt = run(&[Stage::Preprocessing]);
        let pre = runtime
            .reported(&attempt, || engine.preprocessing(&prepared))
            .unwrap();
        assert!(attempt.finish(true).unwrap().stage_coverage_complete);
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
        assert_eq!(
            pre.matrix().read(64 << 20).unwrap(),
            words(&air.preprocessed_trace().unwrap().values)
        );
        for offset in [7u64, 31, 100] {
            let public: Vec<_> = (0..program.public_values())
                .map(|i| 0xffff_ffff_0000_0000 - i as u64)
                .collect();
            let mut witness: Vec<_> = (0..program.witness_values())
                .map(|i| (i as u64 * 7 + offset) % 117 + 1)
                .collect();
            if !witness.is_empty() {
                witness[8] = offset & 1;
                witness[0] = 0xffff_ffff_0000_0000;
                witness[1] = 0;
            }
            let expected = air
                .trace(
                    &public
                        .iter()
                        .copied()
                        .map(Val::from_u64)
                        .collect::<Vec<_>>(),
                    &witness
                        .iter()
                        .copied()
                        .map(Val::from_u64)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            let stages = if public.is_empty() {
                vec![Stage::WitnessTrace]
            } else {
                vec![Stage::WitnessTrace, Stage::PublicValues]
            };
            let attempt = run(&stages);
            let before = runtime.snapshot();
            let result = runtime
                .reported(&attempt, || {
                    engine.generate(&prepared, &public, &witness, 64 << 20)
                })
                .unwrap();
            let after = runtime.snapshot();
            let report = attempt.finish(true).unwrap();
            assert!(report.stage_coverage_complete);
            assert_eq!(
                report
                    .observations
                    .iter()
                    .map(|o| o.device_calls)
                    .sum::<u64>(),
                after.completed_commands - before.completed_commands
            );
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                ((public.len() + witness.len()) * 8) as u64
            );
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
            assert_eq!(
                result.trace.read(64 << 20).unwrap(),
                words(&expected.values)
            );
            if let Some(values) = &result.public {
                let mut actual = vec![0; public.len()];
                values.read(0, &mut actual).unwrap();
                assert_eq!(actual, public);
            } else {
                assert!(public.is_empty());
            }
            drop(result);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
        }
    }
    drop(engine);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().public_programs, 0);
    assert_eq!(runtime.snapshot().public_program_bytes, 0);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_execution_failures_release_private_storage_and_preserve_fresh_attempts() {
    let runtime = runtime(limits());
    let engine = Witnesses::new(&runtime).unwrap();
    for kind in 0..6 {
        let mut b = ProgramBuilder::new(0).unwrap();
        let a = b.input();
        let one = b.constant(Val::ONE);
        let zero = b.constant(Val::ZERO);
        match kind {
            0 => b.assert_equal(a, one),
            1 => b.assert_bool(a),
            2 => {
                b.inverse(a);
            }
            3 => {
                b.cubic_inverse([a, zero, zero]);
            }
            4 => {
                b.select_hint(vec![one, a], &[a]);
            }
            _ => {
                b.select(a, zero, one);
            }
        }
        let program = b.finish(None).unwrap();
        let prepared = engine.prepare(&program, 1 << 20).unwrap();
        let bad = if kind == 2 || kind == 3 { 0 } else { 2 };
        assert!(program.evaluate(&[], &[Val::from_u64(bad)]).is_err());
        let before = runtime.snapshot();
        let attempt = run(&[Stage::WitnessTrace]);
        assert!(runtime
            .reported(&attempt, || engine.generate(
                &prepared,
                &[],
                &[bad],
                1 << 20
            ))
            .is_err());
        assert!(attempt.finish(false).unwrap().observation_errors > 0);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        let before = runtime.snapshot();
        assert!(engine.generate(&prepared, &[], &[1], 0).is_err());
        assert!(engine.generate(&prepared, &[1], &[1], 1 << 20).is_err());
        assert!(engine.generate(&prepared, &[], &[], 1 << 20).is_err());
        assert!(engine
            .generate(&prepared, &[], &[0xffff_ffff_0000_0001], 1 << 20)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
        let attempt = run(&[Stage::WitnessTrace]);
        let good = runtime
            .reported(&attempt, || engine.generate(&prepared, &[], &[1], 1 << 20))
            .unwrap();
        assert!(attempt.finish(true).unwrap().stage_coverage_complete);
        drop(good);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_admission_rejects_before_private_transfers_or_arithmetic() {
    let runtime = runtime(limits());
    let engine = Witnesses::new(&runtime).unwrap();
    let program = ProgramBuilder::new(0)
        .unwrap()
        .finish(Some(1 << 20))
        .unwrap();
    let before = runtime.snapshot();
    assert!(engine.prepare(&program, 1).is_err());
    assert_eq!(runtime.snapshot(), before);
    let prepared = engine.prepare(&program, 1 << 20).unwrap();
    let before = runtime.snapshot();
    assert!(engine.preprocessing(&prepared).is_err());
    assert!(engine.generate(&prepared, &[], &[], 8).is_err());
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires CUDA NVRTC"]
fn cuda_machine_kernels_compile_for_volta_and_blackwell() {
    for target in [70, 120] {
        assert!(!super::super::compiler::compile(&source(), target)
            .unwrap()
            .is_empty());
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_resident_traces_feed_logup_without_intermediate_readback() {
    use crate::block_v2::machine::{compiler_constants::Constants, symbolic};
    use crate::cuda_compute::Lookups;
    use p3_air::symbolic::AirLayout;
    use p3_field::BasedVectorSpace;
    use p3_lookup::{logup::LogUpGadget, LookupProtocol};
    type F = crate::block_v2::profile::Challenge;
    let runtime = runtime(limits());
    let engine = Witnesses::new(&runtime).unwrap();
    let lookups = Lookups::new(&runtime).unwrap();
    let program = fixture(3, 3, 1);
    let prepared = engine.prepare(&program, 64 << 20).unwrap();
    let public = [41];
    let mut witness: Vec<_> = (0..program.witness_values())
        .map(|i| (i as u64 * 7 + 9) % 117 + 1)
        .collect();
    witness[8] = 1;
    let air = MachineAir::new(program);
    let (lookup_layout, _) = symbolic::prepare_machine(&air, Constants::cpu())
        .unwrap()
        .into_parts();
    let compiled = lookups
        .prepare(
            AirLayout::from_air::<Val>(&air),
            &lookup_layout.lookups,
            256 << 20,
        )
        .unwrap();
    let challenges: Vec<F> = (0..lookup_layout.lookups.len() * 2)
        .map(|i| F::from_basis_coefficients_fn(|j| Val::from_usize(43 + (i % 2) * 13 + j * 7)))
        .collect();
    let challenge_words: Vec<u64> = challenges
        .iter()
        .flat_map(|v| words(v.as_basis_coefficients_slice()))
        .collect();
    let resident_challenges = runtime.allocate(challenge_words.len()).unwrap();
    resident_challenges.write(0, &challenge_words).unwrap();
    let public_fields = public.map(Val::from_u64);
    let expected_main = air
        .trace(
            &public_fields,
            &witness
                .iter()
                .copied()
                .map(Val::from_u64)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let expected_pre = air.preprocessed_trace();
    let (expected, terminal) = LogUpGadget::new()
        .generate_permutation::<crate::block_v2::profile::Config>(
            &expected_main,
            &expected_pre,
            &public_fields,
            &lookup_layout.lookups,
            &challenges,
        );
    let attempt = run(&[
        Stage::Preprocessing,
        Stage::WitnessTrace,
        Stage::PublicValues,
        Stage::Lookup,
    ]);
    let before = runtime.snapshot();
    let result = runtime
        .reported(&attempt, || {
            let pre = engine.preprocessing(&prepared)?;
            let main = engine.generate(&prepared, &public, &witness, 64 << 20)?;
            lookups.generate(
                &compiled,
                &main.trace,
                Some(pre.matrix()),
                main.public.as_ref(),
                &resident_challenges,
                Extension::Cubic,
            )
        })
        .unwrap();
    let after = runtime.snapshot();
    assert!(attempt.finish(true).unwrap().stage_coverage_complete);
    assert_eq!(
        after.uploaded_bytes - before.uploaded_bytes,
        ((public.len() + witness.len()) * 8) as u64
    );
    assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 16);
    let expected_words: Vec<_> = expected
        .values
        .iter()
        .flat_map(|v| words(v.as_basis_coefficients_slice()))
        .collect();
    assert_eq!(result.trace.read(64 << 20).unwrap(), expected_words);
    let mut actual_terminal = [0; 3];
    result
        .terminal()
        .buffer
        .read(0, &mut actual_terminal)
        .unwrap();
    let expected_terminal: &[Val] = terminal.as_ref().unwrap().0.as_basis_coefficients_slice();
    assert_eq!(actual_terminal.as_slice(), words(expected_terminal));
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_allocation_count_is_admitted_before_witness_upload() {
    let runtime = runtime(Limits {
        max_allocations: 8,
        ..limits()
    });
    let engine = Witnesses::new(&runtime).unwrap();
    let mut b = ProgramBuilder::new(0).unwrap();
    b.input();
    let program = b.finish(None).unwrap();
    let prepared = engine.prepare(&program, 1 << 20).unwrap();
    let before = runtime.snapshot();
    assert!(engine.generate(&prepared, &[], &[1], 1 << 20).is_err());
    assert_eq!(runtime.snapshot(), before);
}
