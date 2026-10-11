use super::*;
use p3_field::PrimeCharacteristicRing;

#[test]
fn bounded_fingerprint_preserves_shared_dag_and_constraint_order() {
    type B = SymbolicExpression<Val>;
    type E = SymbolicExpressionExt<Val, Challenge>;
    let x = B::Leaf(BaseLeaf::IsFirstRow);
    let y = B::Leaf(BaseLeaf::IsLastRow);
    let shared = x.clone() + y.clone();
    let product = shared.clone() * shared.clone();
    let base = vec![
        shared.clone(),
        product.clone(),
        -product,
        shared - y,
        B::Leaf(BaseLeaf::IsTransition),
        B::from(Val::NEG_ONE),
    ];
    let constant =
        Challenge::from_basis_coefficients_slice(&[Val::ONE, Val::TWO, Val::NEG_ONE]).unwrap();
    let ext = E::from(constant);
    let lift = E::from(base[0].clone());
    let extension = vec![
        ext.clone(),
        lift.clone(),
        ext.clone() + lift.clone(),
        ext.clone() - lift.clone(),
        ext.clone() * lift,
        -ext,
    ];
    let layout = ConstraintLayout {
        base_indices: vec![0, 2, 4, 5, 8, 11],
        ext_indices: vec![1, 3, 6, 7, 9, 10],
    };
    let expected = super::super::encode(&base, &extension, &layout);
    let actual = encode(&base, &extension, &layout, HOST_BYTES).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        actual.capacity(),
        allocation(base.len() + extension.len(), 12, HOST_BYTES).unwrap()
    );
    let mut reordered = layout;
    reordered.base_indices.swap(0, 1);
    assert_ne!(
        encode(&base, &extension, &reordered, HOST_BYTES).unwrap(),
        expected
    );
}

#[test]
fn bounded_fingerprint_rejects_quota_and_geometry_before_encoding() {
    let empty = ConstraintLayout {
        base_indices: vec![],
        ext_indices: vec![],
    };
    let fields = allocation(0, 0, HOST_BYTES).unwrap();
    let bytes = FIXED_BYTES + 2 * SLOTS * std::mem::size_of::<Option<(usize, u64)>>() + fields * 8;
    assert!(encode(&[], &[], &empty, bytes - 1)
        .unwrap_err()
        .contains("allowance"));
    assert_eq!(
        encode(&[], &[], &empty, bytes).unwrap(),
        [1, 0, 0, 0, 0, 0, 0]
    );
    assert!(allocation(MAX_NODES + 1, 0, HOST_BYTES).is_err());
    assert!(allocation(0, MAX_NODES + 1, HOST_BYTES).is_err());
    assert!(allocation(usize::MAX, usize::MAX, usize::MAX).is_err());
    assert!(allocation(MAX_NODES, MAX_NODES, HOST_BYTES).is_ok());
    let mut deep = SymbolicExpression::Leaf(BaseLeaf::IsFirstRow);
    for _ in 0..MAX_DEPTH + 1 {
        deep = -deep;
    }
    assert!(encode(&[deep], &[], &empty, HOST_BYTES)
        .unwrap_err()
        .contains("depth"));
    // Distinct roots are distinct nodes even when their values are identical.
    let roots = vec![SymbolicExpression::Leaf(BaseLeaf::IsFirstRow); MAX_NODES];
    let at_limit = encode(&roots, &[], &empty, HOST_BYTES).unwrap();
    assert_eq!(at_limit[1], MAX_NODES as u64);
    let mut beyond = roots;
    beyond[0] = -beyond[0].clone();
    assert!(encode(&beyond, &[], &empty, HOST_BYTES)
        .unwrap_err()
        .contains("node"));
}
