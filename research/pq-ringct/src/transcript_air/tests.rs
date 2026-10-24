use super::*;
use p3_air::check_all_constraints;
fn accepts(air: &TranscriptAir, witness: &TranscriptWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(2));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}
fn fixture() -> (TranscriptAir, Vec<PartValues>) {
    let air = TranscriptAir::new(vec![
        PartKind::Bytes32,
        PartKind::PolynomialQ,
        PartKind::PolynomialQhat,
        PartKind::Bytes32,
        PartKind::PolynomialQ,
    ])
    .unwrap();
    let values = air
        .parts()
        .iter()
        .enumerate()
        .map(|(i, &kind)| {
            if kind == PartKind::Bytes32 {
                PartValues::Bytes32(core::array::from_fn(|j| (i * 13 + j * 29) as u8))
            } else {
                PartValues::Polynomial(core::array::from_fn(|j| {
                    if j == 0 {
                        kind.modulus() - 1
                    } else {
                        (i * 17 + j * 31) as u64
                    }
                }))
            }
        })
        .collect();
    (air, values)
}
#[test]
fn transcript_serialization_matches_universal_roots_and_exact_le_bytes() {
    let (air, values) = fixture();
    let witness = air.generate(&values).unwrap();
    let roots = values
        .iter()
        .zip(air.parts())
        .map(|(value, &kind)| value.root(kind).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(&witness.public_values[..4], &air.bundle(&roots).unwrap());
    assert_eq!(
        &witness.public_values[4..],
        &commit_bytes(SHAKE_INPUT_DOMAIN, &air.serialize(&values).unwrap())
    );
    assert!(accepts(&air, &witness));
    assert!(air.periodic_columns().iter().all(|p| p.len() <= 128));
}
#[test]
fn transcript_rejects_canonicality_order_descriptor_and_trace_mutations() {
    let (air, values) = fixture();
    let mut witness = air.generate(&values).unwrap();
    let width = air.width();
    for (row, column) in [
        (0, BITS),
        (0, PREFIX),
        (1, BUFFER),
        (3, air.byte_acc()),
        (4, WORD),
        (127, air.bundle_acc()),
        (128, COUNTER),
        (128, EVENTS),
        (129, air.inverse()),
        (256, air.class()),
        (639, air.source_acc()),
        (700, air.byte_acc()),
    ] {
        witness.trace.values[row * width + column] += Val::ONE;
        assert!(!accepts(&air, &witness), "row={row} column={column}");
        witness.trace.values[row * width + column] -= Val::ONE;
    }
    for i in 0..PUBLIC_VALUES {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
    let mut bad = values.clone();
    let PartValues::Polynomial(poly) = &mut bad[1] else {
        unreachable!()
    };
    poly[0] = Q;
    assert!(!accepts(&air, &air.generate(&bad).unwrap()));
    let mut kinds = air.parts().to_vec();
    kinds.swap(1, 2);
    let changed = TranscriptAir::new(kinds).unwrap();
    assert!(!accepts(&changed, &witness));
}

#[cfg(feature = "native-matrict")]
fn native_graph() -> UnprovedRelationGraph {
    let context = [73; 32];
    let setup = [91; 32];
    let fixture = crate::native::generate_fixture_with_setup_seed(
        context,
        setup,
        4,
        crate::native::FixtureAmounts {
            input: [19, 31],
            output: [23, 27],
        },
    )
    .unwrap();
    assert!(crate::rust_verify::verify(&context, &fixture.statement, &fixture.proof).unwrap());
    crate::rust_verify::committed_backend::lower_unproved(
        setup,
        &context,
        &crate::rust_verify::Statement::decode(&fixture.statement).unwrap(),
        &crate::rust_verify::Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap()
}
#[test]
#[cfg(feature = "native-matrict")]
fn transcript_full_native_hash_alpha_and_hash_x_order_and_sizes_match() {
    let graph = native_graph();
    let mut checked = 0;
    for operation in graph.operations() {
        if !matches!(
            operation,
            Operation::HashAlpha { .. } | Operation::HashX { .. }
        ) {
            continue;
        }
        let (air, values, roots) = TranscriptAir::from_graph_operation(&graph, operation).unwrap();
        let witness = air.generate(&values).unwrap();
        let bytes = air.serialize(&values).unwrap();
        assert_eq!(&witness.public_values[..4], &air.bundle(&roots).unwrap());
        assert_eq!(
            &witness.public_values[4..],
            &commit_bytes(SHAKE_INPUT_DOMAIN, &bytes)
        );
        match operation {
            Operation::HashAlpha { output, .. } => {
                assert_eq!((air.parts().len(), air.byte_len()), (228, 230_496));
                assert_eq!(
                    air.parts()
                        .iter()
                        .filter(|&&k| k == PartKind::Bytes32)
                        .count(),
                    3
                );
                assert_eq!(
                    crate::rust_verify::primitives::shake(&bytes, 32),
                    graph.byte_string(*output).values
                );
            }
            Operation::HashX { output, .. } => {
                assert_eq!((air.parts().len(), air.byte_len()), (17, 16_416));
                let challenge =
                    crate::sparse_air::SparseAir::new(crate::sparse_air::Kind::ChallengeX44)
                        .generate(&crate::rust_verify::primitives::shake(&bytes, 137))
                        .unwrap();
                let PolynomialValues::Signed(expected) = graph.polynomial(*output).values else {
                    unreachable!()
                };
                assert_eq!(challenge.polynomial, expected);
            }
            _ => unreachable!(),
        }
        assert!(accepts(&air, &witness));
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "full transcript child proofs plus recursive traces; reserve an 8GiB memory window"]
fn transcript_full_native_actual_proofs_and_typed_recursive_geometry() {
    use lattica_prover_p3::block_v2::{
        machine::{analysis, verifier::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    let graph = native_graph();
    for operation in graph.operations() {
        let label = match operation {
            Operation::HashAlpha { .. } => "HashAlpha",
            Operation::HashX { .. } => "HashX",
            _ => continue,
        };
        let (air, values, roots) = TranscriptAir::from_graph_operation(&graph, operation).unwrap();
        let witness = air.generate(&values).unwrap();
        let proof = p3_uni_stark::prove(
            &profile::make_config(),
            &air,
            witness.trace,
            &witness.public_values,
        );
        let mut artifact = join::TranscriptArtifact {
            public_values: witness.public_values,
            proof,
        };
        join::verify_native(&air, &artifact).unwrap();
        artifact.public_values[0] += Val::ONE;
        assert!(join::verify_native(&air, &artifact).is_err());
        artifact.public_values[0] -= Val::ONE;
        artifact.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
        assert!(join::verify_native(&air, &artifact).is_err());
        artifact.proof.opened_values.trace_local[0] -= profile::Challenge::ONE;
        artifact.proof.degree_bits += 1;
        assert!(join::verify_native(&air, &artifact).is_err());
        artifact.proof.degree_bits -= 1;
        let mut builder = ProgramBuilder::new(4).unwrap();
        let mut inputs = ProofInputs::default();
        let root_wires = roots
            .iter()
            .map(|root| {
                inputs
                    .bases(&mut builder, root)
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let shake_input = core::array::from_fn(|i| builder.public(i).unwrap());
        join::verify_serialization(
            &mut builder,
            &mut inputs,
            &air,
            &root_wires,
            &shake_input,
            &artifact,
        )
        .unwrap();
        let machine = MachineAir::new(builder.finish(None).unwrap());
        let geometry = analysis::analyze(&machine).unwrap();
        eprintln!("transcript {label} parts={} bytes={} child_width={} child_height={}; recursive rows={} height={} wires={} retained_lde_bytes={}", air.parts().len(), air.byte_len(), air.width(), air.height(), machine.program().active_rows(), machine.program().height(), machine.program().wire_count(), geometry.retained_lde_bytes);
        let expected = &artifact.public_values[4..];
        machine.trace(expected, &inputs.values).unwrap();
        let mut changed = expected.to_vec();
        changed[0] += Val::ONE;
        assert!(machine.trace(&changed, &inputs.values).is_err());
        inputs.values[0] += Val::ONE;
        assert!(machine.trace(expected, &inputs.values).is_err());
        inputs.values[0] -= Val::ONE;
        for i in 0..4 {
            inputs.values.swap(i, 4 + i);
        }
        assert!(machine.trace(expected, &inputs.values).is_err());
    }
}
