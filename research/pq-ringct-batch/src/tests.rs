//! Ordinary tests exercise only native public contracts. They do not compile
//! verifier circuits, register proving keys, or generate/verify STARK proofs.
use crate::{
    contract::{canonical_left_count, leaf_root, Spec},
    Plan, BATCH_MODE, CONTEXT, COUNT, FIRST, LEAF_DOMAIN, LEVEL, MODE, NODE_DOMAIN, PUBLIC_VALUES,
    ROOT, TOTAL,
};
use lattica_pq_ringct_research::recursive_aggregation::LeafStatement;
use lattica_prover_p3::block_v2::{commitment, machine::program::Val};
use p3_field::PrimeCharacteristicRing;

fn statements(plan: &Plan) -> Vec<LeafStatement> {
    (0..plan.total())
        .map(|i| LeafStatement {
            profile: plan.graph_profile(),
            context: plan.context(),
            digest: [u64::from(i), 101 + u64::from(i), 202, 303],
        })
        .collect()
}

/// Independent pair/carry reference: it never uses the recursive expected-root
/// routine, Spec metadata, canonical_left_count, or production root helpers.
fn pair_carry_reference(statements: &[LeafStatement]) -> [u64; 4] {
    struct Node {
        first: u64,
        count: u64,
        level: u64,
        root: [u64; 4],
    }
    let total = statements.len() as u64;
    assert!(total > 0);
    let mut layer: Vec<_> = statements
        .iter()
        .enumerate()
        .map(|(i, statement)| {
            let mut fields = vec![i as u64, total];
            fields.extend(statement.digest);
            Node {
                first: i as u64,
                count: 1,
                level: 0,
                root: commitment::hash_fields(LEAF_DOMAIN, &fields).unwrap(),
            }
        })
        .collect();
    while layer.len() > 1 {
        let mut input = layer.into_iter();
        let mut next = Vec::new();
        while let Some(left) = input.next() {
            if let Some(right) = input.next() {
                assert_eq!(left.first + left.count, right.first);
                let count = left.count + right.count;
                let level = 1 + left.level.max(right.level);
                let mut fields = vec![left.first, count, total, level, left.count, right.count];
                fields.extend(left.root);
                fields.extend(right.root);
                next.push(Node {
                    first: left.first,
                    count,
                    level,
                    root: commitment::hash_fields(NODE_DOMAIN, &fields).unwrap(),
                });
            } else {
                next.push(left);
            }
        }
        layer = next;
    }
    layer.pop().unwrap().root
}

#[test]
fn recursive_expected_root_matches_independent_odd_tail_schedule() {
    for total in 1..=33 {
        let plan = Plan::new([7; 32], [9; 32], total).unwrap();
        let originals = statements(&plan);
        assert_eq!(
            plan.expected_root(&originals).unwrap(),
            pair_carry_reference(&originals),
            "ordered batch of {total} relations"
        );
    }
}

#[test]
fn split_levels_and_intervals_cover_u32_boundaries_without_wrap() {
    let plan = Plan::new([7; 32], [9; 32], u32::MAX).unwrap();
    assert!(Plan::new([7; 32], [9; 32], 0).is_err());
    assert!(canonical_left_count(0).is_err());
    assert!(canonical_left_count(1).is_err());
    for (count, left, level) in [
        (2, 1, 1),
        (3, 2, 2),
        (4, 2, 2),
        (7, 4, 3),
        (8, 4, 3),
        (9, 8, 4),
        (1 << 31, 1 << 30, 31),
        (u32::MAX, 1 << 31, 32),
    ] {
        assert_eq!(canonical_left_count(count).unwrap(), left);
        assert_eq!(Spec::new(&plan, 0, count).unwrap().level(), level);
    }
    assert_eq!(Spec::new(&plan, 0, 1).unwrap().level(), 0);
    let last = Spec::new(&plan, u32::MAX - 1, 1).unwrap();
    assert_eq!(last.end().unwrap(), u32::MAX);
    assert_eq!(last.remaining().unwrap(), 0);
    assert!(!last.complete());
    assert!(Spec::new(&plan, u32::MAX, 1).is_err());
    assert!(Spec::new(&plan, u32::MAX - 1, 2).is_err());
    assert!(Spec::new(&plan, 0, 0).is_err());
    let small = Plan::new([7; 32], [9; 32], 10).unwrap();
    assert!(Spec::new(&small, 9, 2).is_err());
}

#[test]
fn merge_requires_canonical_adjacent_positions_and_same_registration() {
    let plan = Plan::new([7; 32], [9; 32], 7).unwrap();
    let left = Spec::new(&plan, 0, 4).unwrap();
    let right = Spec::new(&plan.clone(), 4, 3).unwrap();
    let root = Spec::merge(&left, &right).unwrap();
    assert!(root.complete());
    assert_eq!(root.level(), 3);
    for (a_first, a_count, b_first, b_count) in [
        (0, 3, 3, 4), // Noncanonical split.
        (0, 2, 3, 1), // Omitted position.
        (0, 2, 0, 2), // Duplicated positions.
        (0, 2, 1, 1), // Overlap.
        (2, 2, 0, 2), // Reordered positions.
    ] {
        let a = Spec::new(&plan, a_first, a_count).unwrap();
        let b = Spec::new(&plan, b_first, b_count).unwrap();
        assert!(Spec::merge(&a, &b).is_err());
    }
    let separate_plan = Plan::new([7; 32], [9; 32], 7).unwrap();
    let separate_right = Spec::new(&separate_plan, 4, 3).unwrap();
    assert!(Spec::merge(&left, &separate_right).is_err());
}

#[test]
fn original_contract_rejects_wrong_counts_profiles_contexts_and_digest_aliases() {
    let plan = Plan::new([7; 32], [9; 32], 3).unwrap();
    let originals = statements(&plan);
    assert!(plan.expected_root(&originals[..2]).is_err());
    let mut changed = originals.clone();
    changed.push(originals[0].clone());
    assert!(plan.expected_root(&changed).is_err());
    let mut changed = originals.clone();
    changed[1].profile[0] ^= 1;
    assert!(plan.expected_root(&changed).is_err());
    let mut changed = originals.clone();
    changed[1].context[0] ^= 1;
    assert!(plan.expected_root(&changed).is_err());
    for word in 0..4 {
        for noncanonical in [commitment::MODULUS, commitment::MODULUS + 1, u64::MAX] {
            let mut changed = originals.clone();
            changed[1].digest[word] = noncanonical;
            assert!(plan.expected_root(&changed).is_err());
        }
    }
    let mut canonical_boundary = originals.clone();
    canonical_boundary[1].digest = [commitment::MODULUS - 1; 4];
    assert!(plan.expected_root(&canonical_boundary).is_ok());
    for changed_plan in [
        Plan::new([8; 32], [9; 32], 3).unwrap(),
        Plan::new([7; 32], [8; 32], 3).unwrap(),
        Plan::new([7; 32], [9; 32], 4).unwrap(),
    ] {
        assert!(changed_plan.expected_root(&originals).is_err());
    }
}

#[test]
fn order_and_positions_are_bound_while_repeated_relations_remain_valid() {
    let plan = Plan::new([7; 32], [9; 32], 3).unwrap();
    let originals = statements(&plan);
    let expected = plan.expected_root(&originals).unwrap();
    let mut reordered = originals.clone();
    reordered.swap(0, 1);
    assert_ne!(plan.expected_root(&reordered).unwrap(), expected);
    let mut repeated = originals.clone();
    repeated[1] = originals[0].clone();
    let repeated_root = plan.expected_root(&repeated).unwrap();
    assert_ne!(repeated_root, expected);
    assert_eq!(repeated_root, pair_carry_reference(&repeated));
    let first = Spec::new(&plan, 0, 1).unwrap();
    let second = Spec::new(&plan, 1, 1).unwrap();
    assert_ne!(
        leaf_root(&first, originals[0].digest).unwrap(),
        leaf_root(&second, originals[0].digest).unwrap()
    );
    let other_total = Plan::new([7; 32], [9; 32], 4).unwrap();
    let changed = Spec::new(&other_total, 0, 1).unwrap();
    assert_ne!(
        leaf_root(&first, originals[0].digest).unwrap(),
        leaf_root(&changed, originals[0].digest).unwrap()
    );
}

#[test]
fn every_public_metadata_field_is_exact_and_partial_is_not_complete() {
    let plan = Plan::new([7; 32], [9; 32], 4).unwrap();
    let originals = statements(&plan);
    let public = plan.expected_public(&originals).unwrap();
    let complete = Spec::new(&plan, 0, 4).unwrap();
    assert_eq!(public.len(), PUBLIC_VALUES);
    assert_eq!(public[CONTEXT], Val::from_u32(0x0909_0909));
    assert_eq!(public[MODE], Val::from_u64(BATCH_MODE));
    assert_eq!(public[LEVEL], Val::from_u32(2));
    assert_eq!(public[FIRST], Val::ZERO);
    assert_eq!(public[COUNT], Val::from_u32(4));
    assert_eq!(public[TOTAL], Val::from_u32(4));
    assert!(complete.validate_public(&public).is_ok());
    for index in 0..ROOT {
        let mut changed = public;
        changed[index] += Val::ONE;
        assert!(complete.validate_public(&changed).is_err());
    }
    // Header admission intentionally does not authenticate a root: BatchKey's
    // actual verifier must authenticate proof.public, and verify_expected must
    // additionally compare it with complete original ordered coverage.
    let mut changed_root = public;
    changed_root[ROOT] += Val::ONE;
    assert!(complete.validate_public(&changed_root).is_ok());
    assert_ne!(changed_root, plan.expected_public(&originals).unwrap());
    let partial = Spec::new(&plan, 0, 2).unwrap();
    assert!(!partial.complete());
    assert!(partial
        .validate_public(&partial.public([0; 4]).unwrap())
        .is_ok());
    assert!(partial.validate_public(&public).is_err());
}
