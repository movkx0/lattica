use super::*;
use p3_air::check_all_constraints;
fn accepts(air: &LinearMapAir, witness: &LinearMapWitness) -> bool {
    check_all_constraints(air, &witness.trace, &witness.public_values, Some(4))
        .failures
        .is_empty()
}
fn canonical_fixture(q: u64) -> (LinearMapDescriptor, Vec<LinearMapInput>) {
    let kind = PolynomialKind::Canonical { modulus: q };
    let coefficients = [1, -2, 1, 1, -1].map(|value| [value; D]).to_vec();
    let descriptor = LinearMapDescriptor::new(
        vec![kind; 5],
        kind,
        coefficients,
        core::array::from_fn(|i| (i % 7) as i64 - 3),
    )
    .unwrap();
    let inputs = (0..5)
        .map(|j| {
            LinearMapInput::Canonical(core::array::from_fn(|i| {
                if (i + j) % 3 == 0 {
                    q - 1
                } else {
                    ((i + 1) as u64 * (j + 1) as u64 * 7919) % q
                }
            }))
        })
        .collect();
    (descriptor, inputs)
}
fn signed_fixture() -> (LinearMapDescriptor, Vec<LinearMapInput>) {
    let mut kinds = vec![PolynomialKind::Signed { bound: 565 }; 10];
    kinds[0] = PolynomialKind::Signed { bound: 1 };
    let mut coefficients = vec![[-1; D]; 10];
    coefficients[0] = [1; D];
    let descriptor = LinearMapDescriptor::new(
        kinds,
        PolynomialKind::Signed { bound: 5086 },
        coefficients,
        [0; D],
    )
    .unwrap();
    let inputs = (0..10)
        .map(|j| {
            LinearMapInput::Signed(core::array::from_fn(|i| {
                let bound = if j == 0 { 1 } else { 565 };
                if i % 3 == 0 {
                    0
                } else if (i % 3 == 1) == (j == 0) {
                    bound
                } else {
                    -bound
                }
            }))
        })
        .collect();
    (descriptor, inputs)
}

#[test]
fn coefficientwise_linear_maps_prove_signed_extrema_and_canonical_wraps() {
    for (descriptor, inputs) in [
        canonical_fixture(Q),
        canonical_fixture(QHAT),
        signed_fixture(),
    ] {
        let air = LinearMapAir::new(descriptor);
        let witness = air.generate(&inputs).unwrap();
        assert!(accepts(&air, &witness), "kind={:?}", air.descriptor.output);
        assert!(air.width() < 400);
        assert!(air.height() <= 1024);
        assert!(air
            .metadata()
            .iter()
            .all(|column| column.len().is_power_of_two()));
        for index in 0..D {
            let sum = air.descriptor.coefficients.iter().zip(&inputs).fold(
                i128::from(air.descriptor.constant[index]),
                |sum, (coefficient, input)| {
                    let value = match input {
                        LinearMapInput::Canonical(values) => i128::from(values[index]),
                        LinearMapInput::Signed(values) => i128::from(values[index]),
                    };
                    sum + i128::from(coefficient[index]) * value
                },
            );
            match &witness.output {
                LinearMapInput::Canonical(values) => {
                    let PolynomialKind::Canonical { modulus } = air.descriptor.output else {
                        panic!()
                    };
                    assert_eq!(
                        i128::from(values[index]),
                        sum.rem_euclid(i128::from(modulus))
                    );
                }
                LinearMapInput::Signed(values) => assert_eq!(i128::from(values[index]), sum),
            }
        }
    }
}
#[test]
fn linear_map_input_output_integer_bound_and_commitment_mutations_fail() {
    for (descriptor, inputs) in [canonical_fixture(QHAT), signed_fixture()] {
        let air = LinearMapAir::new(descriptor);
        let mut witness = air.generate(&inputs).unwrap();
        let mut mutations = vec![
            (0, 0),
            (1, 1),
            (air.inputs(), 3),
            (air.inputs(), air.range(0)),
            (0, air.range(1) + 1),
            (0, air.range(0) + 1 + air.bits()),
            (1, air.acc()),
            (air.height() - 1, air.acc() + 4 * air.inputs()),
            (0, air.poseidon()),
            (air.inputs(), air.poseidon() + 4),
        ];
        if matches!(air.descriptor.output, PolynomialKind::Canonical { .. }) {
            mutations.push((air.inputs(), air.quotient(0)));
        }
        for (row, column) in mutations {
            let index = row * air.width() + column;
            witness.trace.values[index] += Val::ONE;
            assert!(
                !accepts(&air, &witness),
                "kind={:?} row={row} column={column}",
                air.descriptor.output
            );
            witness.trace.values[index] -= Val::ONE;
        }
        for index in [0, 4, witness.public_values.len() - 1] {
            witness.public_values[index] += Val::ONE;
            assert!(!accepts(&air, &witness));
            witness.public_values[index] -= Val::ONE;
        }
    }
}
#[test]
fn linear_map_shapes_and_source_bounds_are_checked() {
    let (descriptor, mut inputs) = signed_fixture();
    inputs[0] = LinearMapInput::Signed([2; D]);
    assert!(LinearMapAir::new(descriptor).generate(&inputs).is_err());
    let signed = PolynomialKind::Signed { bound: 1 };
    let canonical = PolynomialKind::Canonical { modulus: Q };
    assert!(LinearMapDescriptor::new(vec![], signed, vec![], [0; D]).is_err());
    assert!(LinearMapDescriptor::new(vec![signed], canonical, vec![[1; D]], [0; D]).is_err());
    assert!(LinearMapDescriptor::new(
        vec![PolynomialKind::Signed {
            bound: i32::MAX as u32
        }],
        signed,
        vec![[i64::MAX; D]],
        [0; D]
    )
    .is_err());
}

#[test]
#[cfg(feature = "native-matrict")]
fn all_ten_committed_maps_match_real_component_roots() {
    use crate::rust_verify::{
        committed_backend::{lower_unproved, Operation, PolynomialValues},
        Proof, Statement,
    };
    let context = [71; 32];
    let setup = [29; 32];
    let fixture = crate::native::generate_fixture_with_setup_seed(
        context,
        setup,
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    let graph = lower_unproved(
        setup,
        &context,
        &Statement::decode(&fixture.statement).unwrap(),
        &Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap();
    let mut linear = 0;
    let mut permutation = 0;
    for (position, operation) in graph.operations().iter().enumerate() {
        if let Ok(map) = graph_operation(&graph, position) {
            let input: Vec<_> = map
                .inputs
                .iter()
                .map(|id| graph.polynomial(*id).values.clone())
                .collect();
            let air = LinearMapAir::new(map.descriptor);
            let witness = air.generate(&input).unwrap();
            assert!(accepts(&air, &witness));
            let expected: Vec<_> = map
                .inputs
                .iter()
                .chain(std::iter::once(&map.output))
                .flat_map(|id| graph.polynomial(*id).commitment)
                .collect();
            assert_eq!(witness.public_values, expected);
            eprintln!(
                "graph linear map position={position} inputs={} kind={:?} width={} height={}",
                map.inputs.len(),
                air.descriptor.output,
                air.width(),
                air.height()
            );
            linear += 1;
        } else if let Ok((kind, input, output)) =
            crate::permutation_air::graph::graph_operation(&graph, position)
        {
            let input = match &graph.polynomial(input).values {
                PolynomialValues::Canonical(values) => {
                    crate::permutation_air::PermutationInput::Canonical(*values)
                }
                PolynomialValues::Signed(values) => {
                    crate::permutation_air::PermutationInput::Signed(*values)
                }
            };
            let air = crate::permutation_air::PermutationAir::new(kind);
            let witness = air.generate(&input).unwrap();
            assert!(
                check_all_constraints(&air, &witness.trace, &witness.public_values, Some(4))
                    .failures
                    .is_empty()
            );
            assert_eq!(
                &witness.public_values[4..],
                &graph.polynomial(output).commitment
            );
            permutation += 1;
        } else {
            assert!(
                !matches!(
                    operation,
                    Operation::CanonicalMap { .. }
                        | Operation::SignedMap { .. }
                        | Operation::AutomorphismQ { .. }
                ),
                "uncovered map {position}"
            );
        }
    }
    assert_eq!((linear, permutation), (7, 3));
}

#[test]
#[ignore = "actual linear-map STARKs and typed recursive traces; guarded release window"]
fn linear_map_actual_proofs_and_typed_joins() {
    use lattica_prover_p3::block_v2::machine::{verifier::ProofInputs, MachineAir, ProgramBuilder};
    for (descriptor, input) in [canonical_fixture(QHAT), signed_fixture()] {
        let registration = RegisteredLinearMapAir::new(descriptor.clone());
        let started = std::time::Instant::now();
        let mut artifact = registration.prove(&input).unwrap();
        eprintln!(
            "linear map child kind={:?} inputs={} width={} height={} elapsed_ms={}",
            descriptor.output,
            descriptor.inputs.len(),
            registration.air().width(),
            registration.air().height(),
            started.elapsed().as_millis()
        );
        let mut builder = ProgramBuilder::new(0).unwrap();
        let roots: Vec<[Val; 4]> = artifact
            .public_values
            .chunks_exact(4)
            .map(|root| root.try_into().unwrap())
            .collect();
        let request = PendingLinearMap {
            descriptor: descriptor.clone(),
            input_commitments: roots[..roots.len() - 1]
                .iter()
                .map(|root| root.map(|value| builder.constant(value)))
                .collect(),
            output_commitment: roots.last().unwrap().map(|value| builder.constant(value)),
        };
        let mut inputs = ProofInputs::default();
        let mut wrong = request.clone();
        wrong.input_commitments.pop();
        assert!(registration
            .compile_join(&mut builder, &mut inputs, &wrong, &artifact)
            .is_err());
        wrong = request.clone();
        wrong.descriptor.constant[0] += 1;
        assert!(registration
            .compile_join(&mut builder, &mut inputs, &wrong, &artifact)
            .is_err());
        registration
            .compile_join(&mut builder, &mut inputs, &request, &artifact)
            .unwrap();
        let machine = MachineAir::new(builder.finish(None).unwrap());
        machine.trace(&[], &inputs.values).unwrap();
        eprintln!(
            "linear map typed join wires={} active_rows={} height={}",
            machine.program().wire_count(),
            machine.program().active_rows(),
            machine.program().height()
        );
        for index in [0, inputs.values.len() / 2, inputs.values.len() - 1] {
            inputs.values[index] += Val::ONE;
            assert!(machine.trace(&[], &inputs.values).is_err());
            inputs.values[index] -= Val::ONE;
        }
        artifact.public_values[0] += Val::ONE;
        assert!(registration.verify(&artifact).is_err());
        artifact.public_values[0] -= Val::ONE;
        artifact.proof.opened_values.trace_local[0] +=
            lattica_prover_p3::block_v2::profile::Challenge::ONE;
        assert!(registration.verify(&artifact).is_err());
    }
}
