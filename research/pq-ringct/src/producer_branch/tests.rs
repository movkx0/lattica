//! Contract/join probes and explicitly unproved branch geometry. Shape-only
//! templates never establish mutation security of a valid recursive proof.
use super::*;

mod cache;
mod contracts;
mod joins;

#[cfg(all(feature = "native-matrict", feature = "recursive-wide"))]
mod acceptance;
#[cfg(all(feature = "native-matrict", feature = "recursive-wide"))]
mod geometry;

fn fixture(descriptor: Descriptor) -> (Spec, graph_tree::GraphContext, [[Val; 4]; 2]) {
    (
        Spec {
            profile: [7; 32],
            operation: 624,
            descriptor,
        },
        graph_tree::GraphContext {
            context: [11; 32],
            statement: core::array::from_fn(|i| Val::from_usize(i + 17)),
            node_manifest: core::array::from_fn(|i| Val::from_usize(i + 23)),
        },
        [
            core::array::from_fn(|i| Val::from_usize(i + 31)),
            core::array::from_fn(|i| Val::from_usize(i + 41)),
        ],
    )
}

/// This deliberately small program tests header/cache plumbing only. It has
/// no sampler, transcript, request verifier, graph coverage or branch claim.
/// Any key it registers is the actual cap of this isolated probe, never a key
/// for a complete producer branch, and is never passed to a graph consumer.
fn header_only_probe(descriptor: Descriptor) -> CompiledNode {
    let (spec, context, roots) = fixture(descriptor);
    let public = header(&spec, &context, roots).unwrap();
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let wires = public_wires(&mut b, &spec).unwrap();
    let expected = ContextWires {
        profile: words(&spec.profile).map(|v| b.constant(v)),
        context: words(&context.context).map(|v| b.constant(v)),
        statement: context.statement.map(|v| b.constant(v)),
    };
    let manifest = context.node_manifest.map(|v| b.constant(v));
    bind_context(&mut b, &wires, &expected, &manifest);
    CompiledNode {
        spec,
        program: Arc::new(b.finish(None).unwrap()),
        public,
        witness: vec![],
    }
}
