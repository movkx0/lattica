use super::super::{
    compile_with_representation_diagnostics, CompilerCapacityProfile, CompilerRepresentation,
};
use super::*;
use crate::{ring, Context};
use lattica_pq_ringct_research::rust_verify::constraints_crypto::CryptoObligations;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder},
    MachineAir,
};
use std::time::Instant;

fn builder(publics: usize) -> ProgramBuilder {
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: super::super::PROGRAM_BYTES,
            max_wires: super::super::MAX_WIRES,
            max_input_values: super::super::MAX_INPUTS.min(super::super::MAX_WIRES - publics),
        },
    )
    .unwrap()
}

#[test]
fn public_transform_has_exact_native_basis_for_every_lane_and_coordinate() {
    let transform = PublicTransform::derive();
    for column in 0..WIDTH {
        for lane in 0..LANES {
            let mut input = [0; D];
            input[column * LANES + lane] = 1;
            let expected = generic::ntt_residues(&mut native::Native, &input, Q);
            for index in 0..D {
                let coefficient = if index % LANES == lane {
                    transform.coefficients[index / LANES][column]
                } else {
                    0
                };
                assert_eq!(
                    coefficient, expected[index],
                    "column={column} lane={lane} output={index}"
                );
            }
        }
    }
}

#[test]
fn dense_dot_extremes_are_exact_and_hints_cannot_change_the_result() {
    for (coefficients, values) in [
        ([0; WIDTH], [Q - 1; WIDTH]),
        ([Q - 1; WIDTH], [Q - 1; WIDTH]),
        (std::array::from_fn(|i| (17 * i as u64) % Q), [Q / 2; WIDTH]),
    ] {
        let mut builder = builder(1);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let expected = coefficients
            .iter()
            .zip(values)
            .map(|(&a, x)| u128::from(a) * u128::from(x))
            .sum::<u128>();
        assert!(expected <= SUM_BOUND);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let input = values.map(|value| c.residue(value, Q));
            let output = dot(&mut c, &coefficients, &input, "ntt_dot_test").unwrap();
            let public = c.builder.public(0).unwrap();
            c.builder.assert_equal(output.constrained.wire(), public);
        }
        let public = [Val::from_u64((expected % u128::from(Q)) as u64)];
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&public, &witness).unwrap();
        for index in [witness.len() - 2, witness.len() - 1] {
            let mut wrong = witness.clone();
            wrong[index] += Val::ONE;
            assert!(air.trace(&public, &wrong).is_err());
        }
        assert!(air.trace(&[public[0] + Val::ONE], &witness).is_err());
    }
}

#[derive(Debug)]
struct Metrics {
    wires: usize,
    active_rows: usize,
    padded_rows: usize,
    requested_peak_before_finish: usize,
    hints: usize,
    public_table_seconds: f64,
}

fn fixture() -> native::Signed {
    let (_, witness) = ring::fixture(Context([19; 32])).unwrap();
    witness.input_openings[0][0]
}

/// Every NTT output remains constrained. Diagnostic mode additionally binds
/// the first 192 outputs to native constants, then exposes the last 64 publicly
/// to respect the machine's public-input limit. Shape tests omit those 192
/// oracle constants, so the program has no witness-dependent constants.
fn component(
    input: &native::Signed,
    expected: &native::Poly,
    fused: bool,
    bind_all: bool,
) -> (Program, Vec<Val>, [Val; 64], Metrics) {
    let start = Instant::now();
    let transform = fused.then(PublicTransform::derive);
    let public_table_seconds = if fused {
        start.elapsed().as_secs_f64()
    } else {
        0.0
    };
    let mut builder = builder(64);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let signed = input.map(|value| c.signed(value, 1));
        let result = if let Some(transform) = transform {
            transform
                .ntt(&mut c, &signed, "ntt_component_fused")
                .unwrap()
        } else {
            native::ntt(
                &mut budget::Limited(&mut c, "ntt_component_inline"),
                &signed,
            )
        };
        for index in 0..D {
            let oracle = if index >= D - 64 {
                Some(c.builder.public(index - (D - 64)).unwrap())
            } else if bind_all {
                Some(c.builder.constant(Val::from_u64(expected[index])))
            } else {
                None
            };
            if let Some(oracle) = oracle {
                c.builder
                    .assert_equal(result[index].constrained.wire(), oracle);
            }
        }
    }
    assert!(crypto.ntt.is_empty());
    let counters = builder.construction_counters();
    assert!(!counters.resource_failed);
    let program = builder.finish(None).unwrap();
    let metrics = Metrics {
        wires: program.wire_count(),
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        requested_peak_before_finish: counters.requested_bytes_peak,
        hints: witness.len(),
        public_table_seconds,
    };
    let public = std::array::from_fn(|i| Val::from_u64(expected[D - 64 + i]));
    (program, witness, public, metrics)
}

#[test]
fn complete_ntt_matches_current_inline_schedule_and_native_reference() {
    let input = fixture();
    let expected = native::ntt(&mut native::Native, &input);
    for fused in [false, true] {
        let (program, witness, public, _) = component(&input, &expected, fused, true);
        let air = MachineAir::new(program);
        air.trace(&public, &witness).unwrap();
        for index in [0, 1, 63, 64, 127, 128, 191, 192, 255] {
            let mut wrong = witness.clone();
            wrong[index] += Val::ONE;
            assert!(air.trace(&public, &wrong).is_err());
        }
        let mut wrong = public;
        wrong[63] += Val::ONE;
        assert!(air.trace(&wrong, &witness).is_err());
    }
}

#[test]
fn dense_ntt_shape_is_independent_of_private_ternary_values() {
    let input = fixture();
    let other = input.map(|value| -value);
    let expected = native::ntt(&mut native::Native, &input);
    let other_expected = native::ntt(&mut native::Native, &other);
    let (program, witness, public, _) = component(&input, &expected, true, false);
    let (second, second_witness, second_public, _) =
        component(&other, &other_expected, true, false);
    assert_eq!(program, second);
    let air = MachineAir::new(program);
    air.trace(&public, &witness).unwrap();
    air.trace(&second_public, &second_witness).unwrap();
}

#[test]
fn wrong_ternary_domain_is_rejected_before_transform_hints() {
    let transform = PublicTransform::derive();
    for (value, bound) in [(2, 1), (0, 2)] {
        let mut builder = builder(0);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let signed = std::array::from_fn(|_| c.signed(value, bound));
        let before = c.witness.len();
        assert!(matches!(
            transform.ntt(&mut c, &signed, "ntt_domain_test"),
            Err(Error::Range)
        ));
        assert_eq!(before, c.witness.len());
    }
}

#[test]
fn ntt_selector_preserves_default_and_reports_pre_arithmetic_refusals() {
    let selected = CompilerRepresentation::FusedPublicNttV1;
    assert_eq!(
        selected.name().parse::<CompilerRepresentation>().unwrap(),
        selected
    );
    assert_eq!(
        CompilerRepresentation::default(),
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2
    );
    for invalid in ["fused-ntt", "fused-public-ntt-v2", "auto"] {
        assert!(invalid.parse::<CompilerRepresentation>().is_err());
    }
    let capacity = CompilerCapacityProfile::default();
    let allowance = capacity.limits().required_host_bytes as usize;
    let context = Context([19; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    for (expected, allowance) in [(context, allowance - 1), (Context([20; 32]), allowance)] {
        let failure = compile_with_representation_diagnostics(
            &statement, &witness, expected, capacity, selected, allowance,
        )
        .err()
        .unwrap();
        assert_eq!(failure.representation, selected.name());
        assert_eq!(failure.wires, None);
        assert!(!failure.cryptographic_proof_started);
    }
}

#[test]
#[ignore = "serialized NTT component screening; no cryptographic proof or workflow throughput"]
fn alternating_ntt_component_screen() {
    let input = fixture();
    let expected = native::ntt(&mut native::Native, &input);
    for pair in 0..3 {
        let order = if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for fused in order {
            let start = Instant::now();
            let (program, witness, public, metrics) = component(&input, &expected, fused, true);
            let compile_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let air = MachineAir::new(program);
            let trace = air.trace(&public, &witness).unwrap();
            let evaluation_seconds = start.elapsed().as_secs_f64();
            eprintln!("fused_ntt_component pair={pair} representation={} baseline_ntt_shared_by_inline_and_linear=true wires={} active_rows={} padded_rows={} builder_requested_peak_before_finish={} hints={} public_table_seconds={:.9} compile_seconds={compile_seconds:.9} host_evaluation_seconds={evaluation_seconds:.9} proof_started=false complete_workflow=false",
                if fused { "fused-public-ntt-v1" } else { "fused-public-linear-v1" },
                metrics.wires, metrics.active_rows, metrics.padded_rows, metrics.requested_peak_before_finish,
                metrics.hints, metrics.public_table_seconds);
            drop(trace);
            drop(air);
            drop(witness);
        }
    }
}
