use super::*;
use crate::graph_tree::tests::{fixture, singles, context};
#[test]
fn fixed_leaf_bound_covers_unchanged_compiler_and_rejects_wrong_source_header() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let compiler = FixedSourceCompilePlan::new(&plan, &graph, &context).unwrap();
    let source = derive(&plan, &graph, &context, compiler.census(), [3; 32], [7; 32]).unwrap();
    let mut node = compiler.compile().unwrap();
    source.check_compiled(&node).unwrap();
    assert_eq!(node.witness.len(), source.maximum_inputs);
    assert_eq!(node.witness.capacity(), source.maximum_inputs);
    assert_eq!(shape::selection_hint_words(&node.program).unwrap(), 0);
    for index in [0, CONTEXT, CONTEXT + 7, STATEMENT, NODE_MANIFEST, FIRST, COUNT, TOTAL, LEVEL] {
        node.public[index] += Val::ONE;
        assert!(source.check_compiled(&node).is_err());
        node.public[index] -= Val::ONE;
    }
    source.check_compiled(&node).unwrap();
}
