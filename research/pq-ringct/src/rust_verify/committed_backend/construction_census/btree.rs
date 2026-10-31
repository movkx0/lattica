//! Existing census qualification tests for the shared pinned collection model.
//! See BTREE.md for source proof, pins and the accepted allocation audit.
use super::super::source_graph::collections::{Collections, Tree};
use super::*;

#[test]
fn fixed_inline_btree_types_have_finite_conservative_requested_bounds() {
    let c = Collections::fixed().unwrap();
    assert_eq!(c.constants.node_requested_bytes, 420);
    assert_eq!(c.canonical_maps.node_requested_bytes, 22_948);
    assert_eq!(c.signed_maps.node_requested_bytes, 22_860);
    assert_eq!(c.dependency_seen.node_requested_bytes, 244);
    assert_eq!(c.dependency_inputs.node_requested_bytes, 332);
    assert_eq!(c.constants.entries, 47_363);
    assert_eq!(c.canonical_maps.entries, 2_596);
    assert_eq!(c.signed_maps.entries, 178);
    assert_eq!(c.dependency_seen.entries, 1_165_932);
    assert_eq!(c.dependency_inputs.entries, 4_351);
    assert_eq!(
        c.partial_constructor_requested_bytes,
        c.backend_inline_bytes
            + c.memo_requested_bytes
            + c.dependency_tree_requested_bytes
            + c.dependency_todo_growth_requested_bytes
    );
    assert!(c.partial_constructor_requested_bytes < 512 << 20);
    assert!(!c.complete_constructor_bound && !c.workflow_dispatch_authority);
    assert_eq!(Tree::pinned::<usize, ()>(0).unwrap().requested_bytes, 0);
    assert!(Tree::pinned::<usize, ()>(usize::MAX).is_err());
    #[repr(align(16))]
    struct UnsupportedAlignment;
    assert!(Tree::pinned::<UnsupportedAlignment, ()>(1).is_err());
    eprintln!("genuine graph constructor collections (partial; not admission): {c:?}");
}

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "native-verification-allocation-audit"
))]
mod allocation_tests {
    use super::*;
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    use std::collections::BTreeSet;

    fn permutation(index: usize, count: usize, order: usize) -> usize {
        match order {
            0 => index,
            1 => count - 1 - index,
            _ if index % 2 == 0 => index / 2,
            _ => count - 1 - index / 2,
        }
    }

    fn audit_map<K: Copy + Ord, V: Copy>(
        entries: usize,
        key: impl Fn(usize) -> K,
        value: impl Fn(usize) -> V,
    ) {
        let bound = Tree::pinned::<K, V>(entries).unwrap();
        for order in 0..3 {
            observe_planner_allocations(bound.requested_bytes, || {
                let mut map = BTreeMap::new();
                for index in 0..entries {
                    let i = permutation(index, entries, order);
                    assert!(map.insert(key(i), value(i)).is_none());
                }
                // Replacing an existing key and reading all entries must not
                // allocate another tree, even after cascading root splits.
                for i in 0..entries {
                    assert!(map.insert(key(i), value(i)).is_some());
                }
                assert_eq!(map.len(), entries);
                assert_eq!(map.into_iter().count(), entries);
            });
        }
    }

    fn audit_set<K: Copy + Ord>(entries: usize, key: impl Fn(usize) -> K) {
        let bound = Tree::pinned::<K, ()>(entries).unwrap();
        for order in 0..3 {
            observe_planner_allocations(bound.requested_bytes, || {
                let mut set = BTreeSet::new();
                for index in 0..entries {
                    let i = permutation(index, entries, order);
                    assert!(set.insert(key(i)));
                }
                for i in 0..entries {
                    assert!(!set.insert(key(i)));
                }
                assert_eq!(set.len(), entries);
                // The last-key drop path differs from a completed IntoIter.
                drop(set);
            });
        }
    }

    #[test]
    #[ignore = "process-wide allocation observer; coordinator must serialize with stream disabled"]
    fn fixed_constructor_btrees_cover_splits_duplicates_iteration_and_drop() {
        let c = Ceilings::fixed();
        for count in [0, 1, 11, 12, 144, c.constant_calls] {
            audit_map(count, |i| (Q, i as u64), |i| i);
        }
        let id = |i| PolyId { owner: 1, index: i };
        audit_map(c.canonical_lookups, |i| (Q, [i; D]), id);
        audit_map(c.signed_lookups, |i| [i; D], id);
        audit_set(c.expressions, |i| i);
        audit_set(c.polynomials, id);
    }
}
