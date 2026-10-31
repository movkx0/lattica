use super::*;
use crate::graph_tree::tests::{fixture, singles};
const KINDS: [AuxiliaryGraphKind; 4] = [AuxiliaryGraphKind::SampleG, AuxiliaryGraphKind::ExpandAlpha,
    AuxiliaryGraphKind::HashAlpha, AuxiliaryGraphKind::HashX];
#[test]
fn auxiliary_leaf_requires_exact_ordered_registered_producer_coverage() {
    let (graph, _) = fixture();
    let mut tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    for kind in KINDS {
        let ordinal = tree.leaves().iter().position(|leaf| leaf.kind() == &LeafKind::Operations(kind.family())).unwrap();
        let operation = tree.leaves()[ordinal].operation_indices()[0];
        validate_leaf(&tree, &graph, kind, operation, ordinal).unwrap();
        let other = if kind == AuxiliaryGraphKind::HashX { AuxiliaryGraphKind::SampleG } else { AuxiliaryGraphKind::HashX };
        assert!(validate_leaf(&tree, &graph, other, operation, ordinal).is_err());
        Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
        assert!(validate_leaf(&tree, &graph, kind, operation, ordinal).is_err());
        Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
        let removed = Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.pop().unwrap();
        assert!(validate_leaf(&tree, &graph, kind, operation, ordinal).is_err());
        Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.push(removed);
        Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.push(operation);
        assert!(validate_leaf(&tree, &graph, kind, operation, ordinal).is_err());
        Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.pop();
        if !tree.leaves()[ordinal].polynomial_indices().is_empty() {
            let removed = Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.pop().unwrap();
            assert!(validate_leaf(&tree, &graph, kind, operation, ordinal).is_err());
            Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.push(removed);
        }
        validate_leaf(&tree, &graph, kind, operation, ordinal).unwrap();
    }
}
#[test]
fn auxiliary_requests_reject_equal_value_foreign_owners_and_boundary_changes() {
    let (graph, _) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    let foreign = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    for kind in KINDS {
        let leaf = tree.leaves().iter().find(|leaf| leaf.kind() == &LeafKind::Operations(kind.family())).unwrap();
        let operation = leaf.operation_indices()[0];
        for actual in crypto.requests().iter().filter(|r| r.operation_index() == operation) {
            let sub = actual.subrequest(); let descriptor = actual.descriptor();
            validate_request(&crypto, actual, operation, sub, descriptor).unwrap();
            let same = foreign.requests().iter().find(|r| r.operation_index() == operation && r.subrequest() == sub).unwrap();
            assert_eq!(same.descriptor(), descriptor);
            assert!(validate_request(&crypto, same, operation, sub, descriptor).is_err());
            assert!(validate_request(&crypto, actual, operation, sub + 1, descriptor).is_err());
            assert!(validate_request(&crypto, actual, operation + 1, sub, descriptor).is_err());
            let changed = match descriptor {
                RequestDescriptor::Aes(mut d) => { d.start_counter += 1; RequestDescriptor::Aes(d) },
                RequestDescriptor::Shake(mut d) => { d.output_len += 1; RequestDescriptor::Shake(d) },
            };
            assert!(validate_request(&crypto, actual, operation, sub, changed).is_err());
        }
    }
}
#[test]
fn auxiliary_expand_alpha_pins_both_aes_domain_counter_and_length_boundaries() {
    let (graph, _) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    let operation = tree.leaves().iter().find(|leaf| leaf.kind() == &LeafKind::Operations(OperationFamily::ExpandAlpha))
        .unwrap().operation_indices()[0];
    let uniform = crypto.requests().iter().find(|r| r.operation_index() == operation && r.subrequest() == 0).unwrap();
    let sparse = crypto.requests().iter().find(|r| r.operation_index() == operation && r.subrequest() == 1).unwrap();
    let u = RequestDescriptor::Aes(crate::aes_air::Descriptor { domain: 0x4368, start_counter: 0, output_len: 2572 });
    let s = RequestDescriptor::Aes(crate::aes_air::Descriptor { domain: 0x4368, start_counter: 161, output_len: 127 });
    validate_request(&crypto, uniform, operation, 0, u).unwrap();
    validate_request(&crypto, sparse, operation, 1, s).unwrap();
    assert!(validate_request(&crypto, sparse, operation, 0, u).is_err());
    assert!(validate_request(&crypto, uniform, operation, 1, s).is_err());
    for bad in [crate::aes_air::Descriptor { domain: 0, start_counter: 161, output_len: 127 },
        crate::aes_air::Descriptor { domain: 0x4368, start_counter: 160, output_len: 127 },
        crate::aes_air::Descriptor { domain: 0x4368, start_counter: 161, output_len: 137 }] {
        assert!(validate_request(&crypto, sparse, operation, 1, RequestDescriptor::Aes(bad)).is_err());
    }
}
