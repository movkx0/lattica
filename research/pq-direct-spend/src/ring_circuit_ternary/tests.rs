use super::super::{
    compile_with_representation_diagnostics, CompilerCapacityProfile, CompilerRepresentation,
};
use super::*;
use crate::{ring, ring_native as native, Context, Profile};
use lattica_pq_ringct_research::rust_verify::constraints_crypto::CryptoObligations;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder},
    MachineAir,
};
use p3_field::PrimeField64;
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
fn biased_dot_boundaries_are_exact_and_reject_changed_hints_or_output() {
    for coefficients in [
        [0; WIDTH],
        [Q - 1; WIDTH],
        std::array::from_fn(|i| if i % 2 == 0 { 0 } else { Q - 1 }),
        std::array::from_fn(|i| 17 * i as u64),
    ] {
        let coefficient_sum = coefficients
            .iter()
            .map(|&value| i128::from(value))
            .sum::<i128>();
        let bias = (coefficient_sum + i128::from(Q) - 1) / i128::from(Q) * i128::from(Q);
        for value in [-1, 0, 1] {
            let mut builder = builder(1);
            let mut witness = Vec::new();
            let mut crypto = CryptoObligations::new([0; 32]);
            let expected = bias + coefficient_sum * i128::from(value);
            assert!(expected >= 0 && expected as u128 <= SUM_BOUND);
            {
                let mut c = ConstraintContext {
                    builder: &mut builder,
                    witness: &mut witness,
                    crypto: &mut crypto,
                };
                let input = std::array::from_fn(|_| c.signed(value, 1));
                let output = dot(&mut c, &coefficients, &input, "ternary_dot_boundary").unwrap();
                let public = c.builder.public(0).unwrap();
                c.builder.assert_equal(output.constrained.wire(), public);
            }
            let quotient = witness.len() - 2;
            let remainder = witness.len() - 1;
            assert_eq!(
                witness[quotient].as_canonical_u64(),
                (expected / i128::from(Q)) as u64
            );
            assert!(witness[quotient].as_canonical_u64() <= QUOTIENT_BOUND);
            let public = [Val::from_u64((expected % i128::from(Q)) as u64)];
            let air = MachineAir::new(builder.finish(None).unwrap());
            air.trace(&public, &witness).unwrap();
            for index in [quotient, remainder] {
                let mut wrong = witness.clone();
                wrong[index] += Val::ONE;
                assert!(air.trace(&public, &wrong).is_err());
            }
            assert!(air.trace(&[public[0] + Val::ONE], &witness).is_err());
            // Even an all-zero public row must retain its original signed
            // input constraints. Dropping zero terms cannot admit x = +/-2.
            for invalid in [Val::from_u64(2), -Val::from_u64(2)] {
                let mut wrong = witness.clone();
                wrong[0] = invalid;
                assert!(air.trace(&public, &wrong).is_err());
            }
        }
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
    let (_, witness) = ring::fixture(Context([29; 32])).unwrap();
    witness.input_openings[0][0]
}

/// All 256 outputs are bound in diagnostic mode: 192 to oracle constants and
/// 64 to public inputs. Shape tests omit the diagnostic constants so that no
/// private value can contribute to the program. Native output generation is
/// outside this function and outside each timed measurement.
fn component(
    input: &native::Signed,
    expected: &native::Poly,
    ternary: bool,
    bind_all: bool,
) -> (Program, Vec<Val>, [Val; 64], Metrics) {
    let start = Instant::now();
    let transform = PublicTransform::derive();
    let public_table_seconds = start.elapsed().as_secs_f64();
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
        let result = if ternary {
            ntt(&mut c, &signed, &transform, "ternary_component_candidate").unwrap()
        } else {
            transform
                .ntt(&mut c, &signed, "ternary_component_baseline")
                .unwrap()
        };
        for index in 0..D {
            assert_eq!(result[index].value, expected[index]);
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
fn complete_ternary_ntt_matches_fused_ntt_and_native_reference() {
    let input = fixture();
    let expected = native::ntt(&mut native::Native, &input);
    for ternary in [false, true] {
        let (program, witness, public, _) = component(&input, &expected, ternary, true);
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
fn ternary_program_shape_is_independent_of_private_signed_values() {
    let input = fixture();
    let expected = native::ntt(&mut native::Native, &input);
    let (program, witness, public, _) = component(&input, &expected, true, false);
    for other in [input.map(|value| -value), [0; D], [-1; D], [1; D]] {
        let other_expected = native::ntt(&mut native::Native, &other);
        let (second, second_witness, second_public, _) =
            component(&other, &other_expected, true, false);
        assert!(
            program == second,
            "private ternary values changed program shape"
        );
        let air = MachineAir::new(second);
        air.trace(&public, &witness).unwrap();
        air.trace(&second_public, &second_witness).unwrap();
    }
}

#[test]
fn invalid_domains_coefficients_and_batches_are_rejected_before_hints() {
    let transform = PublicTransform::derive();
    for (value, bound) in [(2, 1), (-2, 1), (0, 2), (0, 0)] {
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
            ntt(&mut c, &signed, &transform, "ternary_bad_domain"),
            Err(Error::Range)
        ));
        assert_eq!(before, c.witness.len());
    }
    let mut builder = builder(0);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut builder,
        witness: &mut witness,
        crypto: &mut crypto,
    };
    let signed = std::array::from_fn(|_| c.signed(0, 1));
    let before = c.witness.len();
    assert!(matches!(
        dot(&mut c, &[Q; WIDTH], &signed, "ternary_bad_coefficients"),
        Err(Error::NonCanonical)
    ));
    assert_eq!(before, c.witness.len());
    let signed = [signed[0]; D];
    assert!(matches!(
        ntt_many::<0>(&mut c, &[], &transform, "ternary_empty_batch"),
        Err(Error::Geometry)
    ));
    assert!(matches!(
        ntt_many(&mut c, &[signed; 10], &transform, "ternary_large_batch"),
        Err(Error::Geometry)
    ));
    let mut batch = [signed; 9];
    batch[8][D - 1].value = 2;
    assert!(matches!(
        ntt_many(&mut c, &batch, &transform, "ternary_bad_last_polynomial"),
        Err(Error::Range)
    ));
    assert_eq!(before, c.witness.len());
}

#[test]
fn ternary_selector_is_explicit_and_reports_pre_arithmetic_refusals() {
    let selected = CompilerRepresentation::FusedTernaryNttV1;
    assert_eq!(
        selected.name().parse::<CompilerRepresentation>().unwrap(),
        selected
    );
    assert_eq!(
        serde_json::to_string(&selected).unwrap(),
        "\"fused-ternary-ntt-v1\""
    );
    assert_eq!(
        CompilerRepresentation::default(),
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2
    );
    for invalid in [
        "ternary",
        "fused-ternary-ntt-v2",
        "auto",
        "fused-ternary-ntt-v1 ",
    ] {
        assert!(invalid.parse::<CompilerRepresentation>().is_err());
    }
    let capacity = CompilerCapacityProfile::default();
    let allowance = capacity.limits().required_host_bytes as usize;
    let context = Context([29; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    for (expected, allowance) in [(context, allowance - 1), (Context([30; 32]), allowance)] {
        let failure = compile_with_representation_diagnostics(
            &statement, &witness, expected, capacity, selected, allowance,
        )
        .err()
        .unwrap();
        assert_eq!(failure.representation, selected.name());
        assert_eq!(failure.wires, None);
        assert!(!failure.cryptographic_proof_started);
    }
    let mut wrong_profile = statement.clone();
    wrong_profile.profile = Profile::PrivateNoteDirectV1;
    let failure = compile_with_representation_diagnostics(
        &wrong_profile,
        &witness,
        context,
        capacity,
        selected,
        allowance,
    )
    .err()
    .unwrap();
    assert_eq!(failure.error, Error::Profile);
    assert_eq!(failure.representation, selected.name());
    assert_eq!(failure.wires, None);
}

#[test]
#[ignore = "serialized ternary NTT component screening; no cryptographic proof or workflow throughput"]
fn alternating_ternary_ntt_component_screen() {
    let input = fixture();
    let expected = native::ntt(&mut native::Native, &input);
    for pair in 0..3 {
        let order = if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for ternary in order {
            let start = Instant::now();
            let (program, witness, public, metrics) = component(&input, &expected, ternary, true);
            let compile_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let air = MachineAir::new(program);
            let trace = air.trace(&public, &witness).unwrap();
            let evaluation_seconds = start.elapsed().as_secs_f64();
            eprintln!("ternary_ntt_component pair={pair} representation={} wires={} active_rows={} padded_rows={} builder_requested_peak_before_finish={} hints={} public_table_seconds={:.9} compile_seconds={compile_seconds:.9} host_evaluation_seconds={evaluation_seconds:.9} proof_started=false complete_workflow=false",
                if ternary { "fused-ternary-ntt-v1" } else { "fused-public-ntt-v1" },
                metrics.wires, metrics.active_rows, metrics.padded_rows, metrics.requested_peak_before_finish,
                metrics.hints, metrics.public_table_seconds);
            drop(trace);
            drop(air);
            drop(witness);
        }
    }
}
