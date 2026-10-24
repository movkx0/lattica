use super::*;

#[test]
fn graph_handles_and_variable_scalar_products_fail_closed() {
    let mut first = CommittedBackend::new([1; 32]);
    let mut second = CommittedBackend::new([1; 32]);
    assert!(!first.graph.has_unproved_obligations());
    let id = first.canonical_node([7; D], Q, Source::StatementPolynomial { position: 0 });
    let values = first.canonical_refs(id);
    assert!(first.graph.has_unproved_obligations());
    assert!(std::panic::catch_unwind(|| second.graph.polynomial(id)).is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        second.add(values[0], values[1], Q)
    }))
    .is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        first.mont(values[0], values[1], Q)
    }))
    .is_err());
    let constant = first.constant(7, Q);
    let scaled = first.mont(values[0], constant, Q);
    assert!(matches!(
        first.graph.expressions[scaled.expr],
        Expression::Scale { .. }
    ));
}

#[test]
fn equality_and_norm_are_obligations_even_for_false_hints() {
    let mut backend = CommittedBackend::new([1; 32]);
    let a = backend.signed_node([10; D], 10, Source::ProofPolynomial { position: 0 });
    let b = backend.signed_node([0; D], 10, Source::ProofPolynomial { position: 1 });
    let a = backend.signed_refs(a);
    let b = backend.signed_refs(b);
    backend.equal_signed(&a, &b).unwrap();
    backend.norm(&[a], 1).unwrap();
    let x = backend.import_bytes([0; 32], Source::Context);
    let y = backend.import_bytes([1; 32], Source::ProofAlpha);
    backend.equal_bytes(&x, &y).unwrap();
    assert!(matches!(
        backend.graph.operations.as_slice(),
        [
            Operation::EqualSigned { .. },
            Operation::Norm { maximum: 1, .. },
            Operation::EqualBytes { .. }
        ]
    ));
    assert!(backend.into_unproved_graph().has_unproved_obligations());
}

#[test]
fn materialization_preserves_exact_expression_dependencies() {
    let mut backend = CommittedBackend::new([1; 32]);
    let a = backend.canonical_node([3; D], Q, Source::StatementPolynomial { position: 0 });
    let b = backend.canonical_node([5; D], Q, Source::StatementPolynomial { position: 1 });
    let mut values = backend.canonical_refs(a);
    let other = backend.canonical_refs(b);
    values[0] = backend.add(values[0], other[1], Q);
    values.swap(7, 8);
    let output = backend.canonical_id(&values, Q);
    assert_eq!(backend.canonical_id(&values, Q), output);
    match &backend.graph.operations[0] {
        Operation::CanonicalMap {
            inputs,
            expressions,
            output: actual,
            ..
        } => {
            assert_eq!(inputs, &[a, b]);
            assert_eq!(expressions, &values.map(|value| value.expr));
            assert_eq!(*actual, output);
        }
        _ => panic!("materialization must be an explicit obligation"),
    }
    assert_eq!(backend.graph.operations.len(), 1);
}

#[cfg(feature = "native-matrict")]
pub(super) fn fixture() -> (Statement, Proof, Vec<u8>) {
    let fixture = crate::native::generate_fixture_with_setup_seed(
        [71; 32],
        [29; 32],
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    assert!(super::super::verify(&[71; 32], &fixture.statement, &fixture.proof).unwrap());
    (
        Statement::decode(&fixture.statement).unwrap(),
        Proof::decode(&fixture.proof).unwrap(),
        fixture.statement,
    )
}

#[cfg(feature = "native-matrict")]
fn shape(graph: &UnprovedRelationGraph) -> String {
    // Owner is a process-local misuse guard, never trusted protocol metadata.
    let normalized =
        |value: String| value.replace(&format!("owner: {},", graph.owner), "owner: 0,");
    let polynomial_shape: Vec<_> = graph
        .polynomials
        .iter()
        .map(|node| {
            (
                node.kind,
                &node.source,
                &node.expressions,
                matches!(node.source, Source::Fixed).then_some(node.commitment),
            )
        })
        .collect();
    normalized(format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}",
        graph.setup_seed,
        polynomial_shape,
        graph
            .bytes
            .iter()
            .map(|node| &node.source)
            .collect::<Vec<_>>(),
        graph.expressions,
        graph.operations
    ))
}

#[cfg(feature = "native-matrict")]
fn equality_hints_match(graph: &UnprovedRelationGraph) -> bool {
    graph.operations.iter().all(|operation| match operation {
        Operation::EqualBytes { left, right } => {
            graph.byte_string(*left).values == graph.byte_string(*right).values
        }
        Operation::EqualSigned { left, right } => {
            let PolynomialValues::Signed(a) = &graph.polynomial(*left).values else {
                panic!()
            };
            let PolynomialValues::Signed(b) = &graph.polynomial(*right).values else {
                panic!()
            };
            a == b
        }
        _ => true,
    })
}

#[cfg(feature = "native-matrict")]
fn operation_name(operation: &Operation) -> &'static str {
    match operation {
        Operation::CanonicalMap { .. } => "canonical_map",
        Operation::SignedMap { .. } => "signed_map",
        Operation::Add { .. } => "add",
        Operation::Sub { .. } => "sub",
        Operation::AutomorphismQ { .. } => "automorphism",
        Operation::SignedToCanonical { .. } => "signed_to_canonical",
        Operation::Ntt { .. } => "ntt",
        Operation::Mul { .. } => "mul",
        Operation::Norm { .. } => "norm",
        Operation::GBound { .. } => "g_bound",
        Operation::EqualBytes { .. } => "equal_bytes",
        Operation::EqualSigned { .. } => "equal_signed",
        Operation::ByteMap { .. } => "byte_map",
        Operation::ParametersPp { .. } => "parameters_pp",
        Operation::SampleG { .. } => "sample_g",
        Operation::ExpandAlpha { .. } => "expand_alpha",
        Operation::HashAlpha { .. } => "hash_alpha",
        Operation::HashX { .. } => "hash_x",
    }
}

#[cfg(feature = "native-matrict")]
fn assert_derived_sources_are_exact(graph: &UnprovedRelationGraph) {
    let mut claimed_polynomials = std::collections::BTreeSet::new();
    let mut claimed_bytes = std::collections::BTreeSet::new();
    for (position, operation) in graph.operations.iter().enumerate() {
        let mut polynomial = |id: PolyId| {
            assert_eq!(
                graph.polynomial(id).source,
                Source::Derived {
                    operation: position
                }
            );
            assert!(claimed_polynomials.insert(id.index()));
        };
        let mut bytes = |id: BytesId| {
            assert_eq!(
                graph.byte_string(id).source,
                Source::Derived {
                    operation: position
                }
            );
            assert!(claimed_bytes.insert(id.index()));
        };
        match operation {
            Operation::CanonicalMap { output, .. }
            | Operation::SignedMap { output, .. }
            | Operation::Add { output, .. }
            | Operation::Sub { output, .. }
            | Operation::AutomorphismQ { output, .. }
            | Operation::SignedToCanonical { output, .. }
            | Operation::Ntt { output, .. }
            | Operation::Mul { output, .. }
            | Operation::HashX { output, .. } => polynomial(*output),
            Operation::ByteMap { output, .. }
            | Operation::ParametersPp { output, .. }
            | Operation::HashAlpha { output, .. } => bytes(*output),
            Operation::SampleG { output, .. } => output.iter().for_each(|id| polynomial(*id)),
            Operation::ExpandAlpha {
                canonical, signed, ..
            } => {
                canonical.iter().for_each(|id| polynomial(*id));
                polynomial(*signed);
            }
            Operation::Norm { .. }
            | Operation::GBound { .. }
            | Operation::EqualBytes { .. }
            | Operation::EqualSigned { .. } => {}
        }
    }
    for (index, node) in graph.polynomials.iter().enumerate() {
        assert_eq!(
            claimed_polynomials.contains(&index),
            matches!(node.source, Source::Derived { .. })
        );
    }
    for (index, node) in graph.bytes.iter().enumerate() {
        assert_eq!(
            claimed_bytes.contains(&index),
            matches!(node.source, Source::Derived { .. })
        );
    }
}

#[test]
#[cfg(feature = "native-matrict")]
fn complete_graph_matches_native_source_bundles_and_is_witness_independent() {
    let (statement, proof, encoded) = fixture();
    let started = std::time::Instant::now();
    let graph = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    let elapsed = started.elapsed();
    let public_bundle =
        crate::statement_air::bundle::StatementBundle::from_bytes(&encoded).unwrap();
    let private_bundle = crate::proof_air::ProofValues::from_proof(&proof)
        .unwrap()
        .bundle()
        .unwrap();
    let mut public_count = 0;
    let mut private_count = 0;
    for polynomial in graph.polynomials() {
        match polynomial.source {
            Source::StatementPolynomial { position } => {
                assert_eq!(
                    polynomial.commitment,
                    public_bundle.polynomial_roots[position]
                );
                public_count += 1;
            }
            Source::ProofPolynomial { position } => {
                assert_eq!(polynomial.commitment, private_bundle.roots[position]);
                private_count += 1;
            }
            _ => {}
        }
    }
    assert_eq!((public_count, private_count), (198, 91));
    for bytes in graph.bytes() {
        match bytes.source {
            Source::StatementSeed => assert_eq!(bytes.values, public_bundle.setup_seed),
            Source::StatementSerial { position } => {
                let words: [u32; 8] = core::array::from_fn(|i| {
                    u32::from_le_bytes(bytes.values[4 * i..4 * i + 4].try_into().unwrap())
                });
                assert_eq!(
                    &words,
                    &public_bundle.serial_words[8 * position..8 * position + 8]
                );
            }
            Source::ProofAlpha => {
                let words: [u32; 8] = core::array::from_fn(|i| {
                    u32::from_le_bytes(bytes.values[4 * i..4 * i + 4].try_into().unwrap())
                });
                assert_eq!(words, private_bundle.alpha);
            }
            _ => {}
        }
    }
    // These are the six groups proved by the private-source AIR. A future
    // discharge adapter must constrain these exact ordered roots and bounds.
    let norm_groups: Vec<_> = graph
        .operations
        .iter()
        .filter_map(|operation| {
            let Operation::Norm { inputs, maximum } = operation else {
                return None;
            };
            let positions = inputs
                .iter()
                .map(|id| {
                    let Source::ProofPolynomial { position } = graph.polynomial(*id).source else {
                        panic!()
                    };
                    position
                })
                .collect::<Vec<_>>();
            Some((positions, *maximum))
        })
        .collect();
    assert_eq!(
        norm_groups,
        vec![
            ((13..22).collect::<Vec<_>>(), 135_519_727_172),
            ((22..31).collect(), 135_519_727_172),
            ((31..40).collect(), 135_519_727_172),
            ((40..51).collect(), 165_635_222_099),
            ((51..62).collect(), 165_635_222_099),
            ((83..91).collect(), 3_161_803_581_581_766),
        ]
    );
    assert!(graph.has_unproved_obligations());
    assert!(equality_hints_match(&graph));
    assert_derived_sources_are_exact(&graph);
    let ntt = graph
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::Ntt { .. }))
        .count();
    let mul = graph
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::Mul { .. }))
        .count();
    assert_eq!((ntt, mul), (95, 474));
    assert_eq!(
        graph
            .operations
            .iter()
            .filter(|op| matches!(op, Operation::Norm { .. }))
            .count(),
        6
    );
    eprintln!("unproved committed relation: polynomials={}, bytes={}, expressions={}, operations={}, NTT={ntt}, products={mul}, elapsed={elapsed:?}",
        graph.polynomials.len(), graph.bytes.len(), graph.expressions.len(), graph.operations.len());
    let mut counts = BTreeMap::new();
    for operation in &graph.operations {
        *counts.entry(operation_name(operation)).or_insert(0usize) += 1;
    }
    eprintln!("explicit unproved operation inventory: {counts:?}");
    let original_shape = shape(&graph);
    let changed_context = lower_unproved([29; 32], &[72; 32], &statement, &proof).unwrap();
    assert_eq!(shape(&changed_context), original_shape);
    assert!(!equality_hints_match(&changed_context));
    assert!(changed_context.has_unproved_obligations());
    let mut changed_proof = proof;
    changed_proof.alpha[0] ^= 1;
    let changed_alpha = lower_unproved([29; 32], &[71; 32], &statement, &changed_proof).unwrap();
    assert_eq!(shape(&changed_alpha), original_shape);
    assert!(!equality_hints_match(&changed_alpha));
    assert!(changed_alpha.has_unproved_obligations());
    drop(changed_context);
    drop(changed_alpha);
    let mut changed_statement = statement;
    changed_statement.ring[0][0].pk[0][0] = 0;
    changed_proof.f1[0][0] = 0;
    let changed_coefficients =
        lower_unproved([29; 32], &[71; 32], &changed_statement, &changed_proof).unwrap();
    assert_eq!(shape(&changed_coefficients), original_shape);
    assert!(!equality_hints_match(&changed_coefficients));
    assert!(changed_coefficients.has_unproved_obligations());
}
