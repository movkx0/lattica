//! Shared pinned-source BTree/dependency scratch model.
//! The initial source census and the test-only source-graph owner use one formula.
//! No whole-runtime or dispatch authority follows from this partial bound.
use super::super::*;
use super::bounds::{add, backing, mul, Ceilings};
use core::mem::{align_of, size_of};
type Error = &'static str;

#[derive(Clone, Copy, Debug)]
pub(in crate::rust_verify::committed_backend) struct Tree {
    pub(in crate::rust_verify::committed_backend) entries: usize,
    pub(in crate::rust_verify::committed_backend) node_requested_bytes: usize,
    pub(in crate::rust_verify::committed_backend) requested_bytes: usize,
}
impl Tree {
    pub(in crate::rust_verify::committed_backend) fn pinned<K, V>(
        entries: usize,
    ) -> Result<Self, Error> {
        // All five actual key/value pairs are inline Copy data with alignment
        // <=8. This is not a bound for arbitrary collection types or allocators.
        if size_of::<usize>() != 8 || align_of::<K>() > 8 || align_of::<V>() > 8 {
            return Err("BTree census requires the pinned 64-bit inline layouts");
        }
        // Leaf: pointer + u16 + u16 + [K;11] + [V;11]. Charge a full eight
        // padding bytes for each of five fields, then 12 child pointers and
        // another eight for the enclosing InternalNode's padding.
        let node_requested_bytes = add(156, mul(11, add(size_of::<K>(), size_of::<V>())?)?)?;
        // All insertions are distinct or replace an existing inline value.
        // Insertion-only trees never retire nodes before the final drain/drop.
        // Every allocated node is part of the completed nonempty tree, which
        // has at most one node per key. One extra node covers initialization
        // and insertion-in-progress conservatively. An empty tree allocates 0.
        let nodes = if entries == 0 { 0 } else { add(entries, 1)? };
        Ok(Self {
            entries,
            node_requested_bytes,
            requested_bytes: mul(nodes, node_requested_bytes)?,
        })
    }
}

#[derive(Debug)]
pub(in crate::rust_verify::committed_backend) struct Collections {
    pub(in crate::rust_verify::committed_backend) constants: Tree,
    pub(in crate::rust_verify::committed_backend) canonical_maps: Tree,
    pub(in crate::rust_verify::committed_backend) signed_maps: Tree,
    pub(in crate::rust_verify::committed_backend) dependency_seen: Tree,
    pub(in crate::rust_verify::committed_backend) dependency_inputs: Tree,
    pub(in crate::rust_verify::committed_backend) memo_requested_bytes: usize,
    pub(in crate::rust_verify::committed_backend) dependency_tree_requested_bytes: usize,
    pub(in crate::rust_verify::committed_backend) dependency_todo_growth_requested_bytes: usize,
    pub(in crate::rust_verify::committed_backend) backend_inline_bytes: usize,
    pub(in crate::rust_verify::committed_backend) partial_constructor_requested_bytes: usize,
    pub(in crate::rust_verify::committed_backend) complete_constructor_bound: bool,
    pub(in crate::rust_verify::committed_backend) workflow_dispatch_authority: bool,
}
impl Collections {
    pub(in crate::rust_verify::committed_backend) fn fixed() -> Result<Self, Error> {
        let c = Ceilings::fixed();
        let constants = Tree::pinned::<(u64, u64), usize>(c.constant_calls)?;
        let canonical_maps = Tree::pinned::<(u64, [usize; D]), PolyId>(c.canonical_lookups)?;
        let signed_maps = Tree::pinned::<[usize; D], PolyId>(c.signed_lookups)?;
        let dependency_seen = Tree::pinned::<usize, ()>(c.expressions)?;
        let dependency_inputs = Tree::pinned::<PolyId, ()>(c.polynomials)?;
        let memo_requested_bytes = add(
            add(constants.requested_bytes, canonical_maps.requested_bytes)?,
            signed_maps.requested_bytes,
        )?;
        let dependency_tree_requested_bytes = add(
            dependency_seen.requested_bytes,
            dependency_inputs.requested_bytes,
        )?;
        // One traversal at a time. Each unseen expression enqueues at most two
        // children; this bounds all pushes, not merely the final list length.
        let todo = add(D, mul(2, c.expressions)?)?;
        let dependency_todo_growth_requested_bytes = backing::<usize>(mul(3, todo)?)?;
        let backend_inline_bytes = size_of::<CommittedBackend<'static>>();
        let partial_constructor_requested_bytes = add(
            backend_inline_bytes,
            add(
                memo_requested_bytes,
                add(
                    dependency_tree_requested_bytes,
                    dependency_todo_growth_requested_bytes,
                )?,
            )?,
        )?;
        Ok(Self {
            constants,
            canonical_maps,
            signed_maps,
            dependency_seen,
            dependency_inputs,
            memo_requested_bytes,
            dependency_tree_requested_bytes,
            dependency_todo_growth_requested_bytes,
            backend_inline_bytes,
            partial_constructor_requested_bytes,
            complete_constructor_bound: false,
            workflow_dispatch_authority: false,
        })
    }
}
