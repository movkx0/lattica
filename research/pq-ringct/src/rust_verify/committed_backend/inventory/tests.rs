use super::*;
use p3_field::PrimeCharacteristicRing;

fn example() -> UnprovedRelationGraph {
    let mut backend = CommittedBackend::new([19; 32]);
    let a = backend.signed_node([1; D], 7, Source::ProofPolynomial { position: 0 });
    let b = backend.signed_node([2; D], 7, Source::ProofPolynomial { position: 1 });
    let fixed = backend.canonical_node([3; D], Q, Source::Fixed);
    let av = backend.signed_refs(a);
    let bv = backend.signed_refs(b);
    backend.equal_signed(&av, &bv).unwrap();
    backend.norm(&[av], 1).unwrap();
    let input = backend.import_bytes([4; 32], Source::Context);
    let output = backend.import_bytes([5; 32], Source::ProofAlpha);
    backend.equal_bytes(&input, &output).unwrap();
    assert_eq!(
        backend.graph.polynomial(fixed).commitment,
        commit_values(POLYNOMIAL_DOMAIN, Q, &[3; D])
    );
    backend.into_unproved_graph()
}

#[test]
fn inventory_is_owner_independent_and_does_not_discharge_false_relations() {
    let first = example();
    let second = example();
    assert_ne!(first.owner, second.owner);
    let a = inventory(&first);
    assert_eq!(a, inventory(&second));
    assert_eq!(a.counts().operations, 3);
    assert_eq!(
        a.counts().operation_kinds[OperationKind::EqualSigned as usize],
        1
    );
    assert_eq!(
        a.counts().operation_kinds[OperationKind::EqualBytes as usize],
        1
    );
    assert_eq!(a.counts().operation_kinds[OperationKind::Norm as usize], 1);
    // Both equality hints and the norm are false, yet inventory is defined.
    // This demonstrates why its fingerprint is never an acceptance proof.
    assert!(first.has_unproved_obligations());
    assert!(second.has_unproved_obligations());
}

#[test]
fn shape_and_witness_inventory_distinguish_sources_topology_and_all_root_roles() {
    let mut graph = example();
    let original = inventory(&graph);
    for index in 0..graph.polynomials.len() {
        for field in 0..4 {
            graph.polynomials[index].commitment[field] += Val::ONE;
            let changed = inventory(&graph);
            assert_ne!(changed.witness_sha3_256(), original.witness_sha3_256());
            assert_eq!(
                changed.shape_sha3_256() == original.shape_sha3_256(),
                !matches!(graph.polynomials[index].source, Source::Fixed),
            );
            graph.polynomials[index].commitment[field] -= Val::ONE;
        }
    }
    for index in 0..graph.bytes.len() {
        for field in 0..4 {
            graph.bytes[index].commitment[field] += Val::ONE;
            let changed = inventory(&graph);
            assert_ne!(changed.witness_sha3_256(), original.witness_sha3_256());
            assert_eq!(changed.shape_sha3_256(), original.shape_sha3_256());
            graph.bytes[index].commitment[field] -= Val::ONE;
        }
    }
    let source = graph.polynomials[0].source.clone();
    graph.polynomials[0].source = Source::StatementPolynomial { position: 0 };
    assert_ne!(
        inventory(&graph).shape_sha3_256(),
        original.shape_sha3_256()
    );
    graph.polynomials[0].source = source;
    graph.polynomials[0].expressions.swap(0, 1);
    assert_ne!(
        inventory(&graph).shape_sha3_256(),
        original.shape_sha3_256()
    );
    graph.polynomials[0].expressions.swap(0, 1);
    graph.operations.swap(0, 1);
    assert_ne!(
        inventory(&graph).shape_sha3_256(),
        original.shape_sha3_256()
    );
    graph.operations.swap(0, 1);
    let Operation::Norm { maximum, .. } = &mut graph.operations[1] else {
        unreachable!()
    };
    *maximum += 1;
    assert_ne!(
        inventory(&graph).shape_sha3_256(),
        original.shape_sha3_256()
    );
    let Operation::Norm { maximum, .. } = &mut graph.operations[1] else {
        unreachable!()
    };
    *maximum -= 1;
    assert_eq!(inventory(&graph), original);
    graph.operations.pop();
    assert_ne!(
        inventory(&graph).shape_sha3_256(),
        original.shape_sha3_256()
    );
}

#[test]
fn framing_keeps_full_integers_record_lengths_and_root_order() {
    let encode = |records: &[(u64, Vec<u64>, Vec<[Val; 4]>)]| {
        let mut encoder = Encoder::new();
        for (index, (kind, words, roots)) in records.iter().enumerate() {
            encoder.record(*kind, index, words, &[], roots);
        }
        <[u8; 32]>::from(encoder.witness.finalize())
    };
    let empty = vec![];
    assert_ne!(
        encode(&[(1, vec![u64::MAX], empty.clone())]),
        encode(&[(1, vec![u64::MAX - 0xffff_ffff_0000_0001], empty.clone())]),
    );
    assert_ne!(
        encode(&[(1, vec![2, 3], empty.clone())]),
        encode(&[(1, vec![2], empty.clone()), (1, vec![3], empty.clone())]),
    );
    let a = [Val::ONE; 4];
    let b = [Val::from_u32(2); 4];
    assert_ne!(
        encode(&[(1, vec![2], vec![a, b])]),
        encode(&[(1, vec![2], vec![b, a])])
    );
}

#[cfg(feature = "native-matrict")]
#[test]
fn complete_fixture_inventory_retains_every_relation_and_stable_shape() {
    let (statement, proof, _) = super::super::tests::fixture();
    let first = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    let a = inventory(&first);
    assert_eq!(a.counts().polynomials, 1770);
    assert_eq!(a.counts().bytes, 8);
    assert_eq!(a.counts().expressions, 505162);
    assert_eq!(a.counts().operations, 1311);
    assert_eq!(a.counts().operation_kinds.iter().sum::<usize>(), 1311);
    assert_eq!(a.counts().operation_kinds[OperationKind::Ntt as usize], 95);
    assert_eq!(a.counts().operation_kinds[OperationKind::Mul as usize], 474);
    assert!(first.has_unproved_obligations());
    drop(first);
    let second = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    assert_eq!(a, inventory(&second));
    drop(second);
    let changed = lower_unproved([29; 32], &[72; 32], &statement, &proof).unwrap();
    let b = inventory(&changed);
    assert_eq!(a.counts(), b.counts());
    assert_eq!(a.shape_sha3_256(), b.shape_sha3_256());
    assert_ne!(a.witness_sha3_256(), b.witness_sha3_256());
    assert!(changed.has_unproved_obligations());
    eprintln!("complete_graph_inventory_counts={:?}", a.counts());
    eprintln!("complete_graph_shape_sha3_256={:02x?}", a.shape_sha3_256());
}
