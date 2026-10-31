use super::super::{
    compile_with_capacity_diagnostics, compile_with_representation_diagnostics,
    CompilerCapacityProfile, CompilerRepresentation,
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
            max_input_values: super::super::MAX_INPUTS,
        },
    )
    .unwrap()
}

fn scalar(coefficients: &[u64], values: &[u64], addends: &[u64]) -> (Program, Vec<Val>, Val) {
    let mut builder = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let expected = coefficients
        .iter()
        .zip(values)
        .map(|(&a, &x)| u128::from(a) * u128::from(x))
        .sum::<u128>()
        + addends.iter().map(|&x| u128::from(x)).sum::<u128>();
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let terms: Vec<_> = coefficients
            .iter()
            .zip(values)
            .map(|(&coefficient, &value)| (coefficient, c.residue(value, Q)))
            .collect();
        let addends: Vec<_> = addends.iter().map(|&value| c.residue(value, Q)).collect();
        let result = dot(&mut c, &terms, &addends, "scalar_test").unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(result.constrained.wire(), public);
    }
    assert!(!builder.construction_counters().resource_failed);
    (
        builder.finish(None).unwrap(),
        witness,
        Val::from_u64((expected % u128::from(Q)) as u64),
    )
}

#[test]
fn fixed_q_dot_matches_exact_integer_boundaries() {
    for (coefficients, values, addends) in [
        (vec![], vec![], vec![]),
        (vec![Q - 1; 20], vec![Q - 1; 20], vec![Q - 1; 2]),
        (vec![0, 1, Q - 1], vec![Q - 1, 19, 23], vec![7]),
        (vec![17; 20], vec![Q / 2; 20], vec![0, Q - 1]),
    ] {
        let (program, witness, expected) = scalar(&coefficients, &values, &addends);
        let air = MachineAir::new(program);
        air.trace(&[expected], &witness).unwrap();
        assert!(air.trace(&[expected + Val::ONE], &witness).is_err());
    }
}

#[test]
fn fused_program_is_independent_of_private_values_and_binds_public_coefficients() {
    let (program, witness, expected) = scalar(&[3, 7, 11], &[0, 1, 2], &[4]);
    let (other, _, _) = scalar(&[3, 7, 11], &[Q - 1, Q - 2, Q - 3], &[Q - 1]);
    assert_eq!(program, other);
    let (changed_public, _, _) = scalar(&[3, 7, 12], &[0, 1, 2], &[4]);
    assert_ne!(program, changed_public);
    assert!(MachineAir::new(changed_public)
        .trace(&[expected], &witness)
        .is_err());
}

#[test]
fn representation_is_explicit_and_survives_admission_and_context_refusals() {
    assert_eq!(
        CompilerRepresentation::default(),
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2
    );
    let capacity = CompilerCapacityProfile::default();
    let required = capacity.limits().required_host_bytes as usize;
    let context = Context([19; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    for representation in [
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2,
        CompilerRepresentation::FusedPublicLinearV1,
    ] {
        assert_eq!(
            representation
                .name()
                .parse::<CompilerRepresentation>()
                .unwrap(),
            representation
        );
        for (expected, allowance) in [(context, required - 1), (Context([20; 32]), required)] {
            let failure = compile_with_representation_diagnostics(
                &statement,
                &witness,
                expected,
                capacity,
                representation,
                allowance,
            )
            .err()
            .expect("admission/semantic refusal precedes arithmetic");
            assert_eq!(failure.representation, representation.name());
            assert!(!failure.cryptographic_proof_started);
            assert_eq!(failure.wires, None);
        }
    }
    for invalid in ["", "fused", "auto", "fused-public-linear-v2"] {
        assert!(invalid.parse::<CompilerRepresentation>().is_err());
    }
    let legacy =
        compile_with_capacity_diagnostics(&statement, &witness, context, capacity, required - 1)
            .err()
            .unwrap();
    assert_eq!(legacy.representation, super::super::REPRESENTATION);
}

struct Fixture {
    block: usize,
    public: [native::Poly; 5],
    private: [native::Poly; 5],
    base: native::Poly,
    expected: [Val; 4],
}

fn fixture(block: usize) -> Fixture {
    let (statement, witness) = ring::fixture(Context([19; 32])).unwrap();
    let params = native::parameters(&statement.setup_seed).unwrap();
    let transformed = witness.input_openings[0]
        .each_ref()
        .map(|p| native::ntt(&mut native::Native, p));
    let public = std::array::from_fn(|i| params.mat1[i][0]);
    let private = std::array::from_fn(|i| transformed[4 + i]);
    let base = transformed[0];
    let mut expected = base;
    for i in 0..5 {
        native::multiply_add(&mut native::Native, &mut expected, &public[i], &private[i]);
    }
    Fixture {
        block,
        public,
        private,
        base,
        expected: std::array::from_fn(|i| Val::from_u64(expected[block * 4 + i])),
    }
}

#[derive(Debug)]
struct Metrics {
    wires: usize,
    active_rows: usize,
    padded_rows: usize,
    requested_peak: usize,
    hints: usize,
}

/// One quartic block of the original commitment's five-column public matrix
/// equation. NTT states are canonical private diagnostic inputs, not a new
/// decomposition or a proof of their derivation. The native oracle above
/// evaluates the untouched complete polynomial products independently.
fn component(f: &Fixture, fused: bool) -> (Program, Vec<Val>, Metrics) {
    let mut builder = builder(4);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let private: [[ResidueValue; 4]; 5] = std::array::from_fn(|column| {
            std::array::from_fn(|i| c.residue(f.private[column][f.block * 4 + i], Q))
        });
        let base: [ResidueValue; 4] =
            std::array::from_fn(|i| c.residue(f.base[f.block * 4 + i], Q));
        let mut result = base;
        if fused {
            for output in 0..4 {
                let terms: [(u64, ResidueValue); 20] = std::array::from_fn(|index| {
                    let (column, input) = (index / 4, index % 4);
                    (
                        coefficient(&f.public[column], f.block, output, input).unwrap(),
                        private[column][input],
                    )
                });
                result[output] = dot(&mut c, &terms, &[base[output]], "component_fused").unwrap();
            }
        } else {
            let zero = public_constant_in_phase(&mut c, 0, Q, "component_baseline").unwrap();
            let (negative, position) = MUL_Q[f.block];
            let omega =
                public_constant_in_phase(&mut c, OMEGA_Q[position], Q, "component_baseline")
                    .unwrap();
            for column in 0..5 {
                let public: [ResidueValue; 4] = std::array::from_fn(|i| {
                    public_constant_in_phase(
                        &mut c,
                        f.public[column][f.block * 4 + i],
                        Q,
                        "component_baseline",
                    )
                    .unwrap()
                });
                let mut product = [zero; 4];
                for i in 0..4 {
                    for j in 0..4 {
                        let mut value = montgomery::mont(
                            &mut c,
                            public[i],
                            private[column][j],
                            Q,
                            "component_baseline",
                        );
                        let degree = i + j;
                        if degree >= 4 {
                            value = montgomery::mont(&mut c, value, omega, Q, "component_baseline");
                        }
                        let target = product[degree % 4];
                        product[degree % 4] = if degree >= 4 && negative {
                            c.sub(target, value, Q)
                        } else {
                            c.add(target, value, Q)
                        };
                    }
                }
                for i in 0..4 {
                    result[i] = c.add(result[i], product[i], Q);
                }
            }
        }
        for (i, result) in result.iter().enumerate() {
            let public = c.builder.public(i).unwrap();
            c.builder.assert_equal(result.constrained.wire(), public);
        }
    }
    let counters = builder.construction_counters();
    assert!(!counters.resource_failed);
    let program = builder.finish(None).unwrap();
    let metrics = Metrics {
        wires: program.wire_count(),
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        requested_peak: counters.requested_bytes_peak,
        hints: witness.len(),
    };
    (program, witness, metrics)
}

#[test]
fn quartic_matrix_component_matches_baseline_and_native_for_both_wrap_signs() {
    for block in [0, 4] {
        let f = fixture(block);
        let mut baseline_wires = None;
        for fused in [false, true] {
            let (program, witness, metrics) = component(&f, fused);
            let air = MachineAir::new(program);
            air.trace(&f.expected, &witness).unwrap();
            let mut wrong = f.expected;
            wrong[0] += Val::ONE;
            assert!(air.trace(&wrong, &witness).is_err());
            if fused {
                assert!(metrics.wires < baseline_wires.unwrap());
            } else {
                baseline_wires = Some(metrics.wires);
            }
        }
    }
}

#[test]
fn full_matrix_routing_matches_native_for_two_four_and_five_columns() {
    let f = fixture(4);
    let extra = native::serial_image(&[31; 32]).unwrap()[0];
    for (count, with_extra) in [(2, false), (4, true), (5, false)] {
        let mut expected = f.base;
        for i in 0..count {
            native::multiply_add(
                &mut native::Native,
                &mut expected,
                &f.public[i],
                &f.private[i],
            );
        }
        if with_extra {
            for i in 0..D {
                expected[i] = (expected[i] + extra[i]) % Q;
            }
        }
        // The machine accepts at most 64 public values. Bind all 256 expected
        // oracle coefficients as constants in this diagnostic-only program.
        let mut builder = builder(0);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let base = f.base.map(|value| c.residue(value, Q));
            let private: Vec<_> = f.private[..count]
                .iter()
                .map(|poly| poly.map(|value| c.residue(value, Q)))
                .collect();
            let extra = extra
                .map(|value| public_constant_in_phase(&mut c, value, Q, "matrix_routing").unwrap());
            let columns: Vec<_> = (0..count).map(|i| (&f.public[i], &private[i])).collect();
            let result = matrix_poly(
                &mut c,
                &base,
                &columns,
                with_extra.then_some(&extra),
                "matrix_routing",
            )
            .unwrap();
            for (i, value) in result.iter().enumerate() {
                let oracle = c.builder.constant(Val::from_u64(expected[i]));
                c.builder.assert_equal(value.constrained.wire(), oracle);
            }
        }
        assert!(!builder.construction_counters().resource_failed);
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&[], &witness).unwrap();
        for index in [0, witness.len() - 1] {
            let mut wrong = witness.clone();
            wrong[index] += Val::ONE;
            assert!(air.trace(&[], &wrong).is_err());
        }
    }
}

#[test]
#[ignore = "serialized component screening; not a transaction/proof throughput measurement"]
fn alternating_matrix_component_screen() {
    let f = fixture(4);
    for pair in 0..3 {
        let order = if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for fused in order {
            let start = Instant::now();
            let (program, witness, metrics) = component(&f, fused);
            let compile_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let air = MachineAir::new(program);
            let trace = air.trace(&f.expected, &witness).unwrap();
            let evaluation_seconds = start.elapsed().as_secs_f64();
            eprintln!("fused_matrix_component pair={pair} representation={} wires={} active_rows={} padded_rows={} builder_requested_peak_before_finish={} hints={} compile_seconds={compile_seconds:.9} host_evaluation_seconds={evaluation_seconds:.9} proof_started=false complete_workflow=false",
                if fused { "fused-public-linear-v1" } else { super::super::REPRESENTATION },
                metrics.wires, metrics.active_rows, metrics.padded_rows, metrics.requested_peak, metrics.hints);
            drop(trace);
            drop(air);
            drop(witness);
        }
    }
}
