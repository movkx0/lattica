//! Bindings exist only inside one admitted, immutable source-preparation scope.
//! These hints do not authorize proving or replace any source-byte equality check.
use super::{GraphContext, Plan};
use crate::{graph_crypto, recursive_aggregation::LeafStatement,
    rust_verify::committed_backend::{Source, UnprovedRelationGraph}};
use lattica_prover_p3::block_v2::{machine::program::Val, native_gpu::OperationContext};
use p3_field::PrimeCharacteristicRing;

pub(crate) struct PreparedStatement<'a, 'op, 'run> {
    statement: &'a [u8],
    context: [u8; 32],
    label: [u8; 32],
    digest: [Val; 4],
    operations: &'op OperationContext<'run>,
}
impl<'a, 'op, 'run> PreparedStatement<'a, 'op, 'run> {
    pub(crate) fn new(label: [u8; 32], context: [u8; 32], statement: &'a [u8],
        operations: &'op OperationContext<'run>) -> Result<Self, String> {
        if statement.len() != crate::native_packet::STATEMENT_BYTES {
            return Err("prepared statement length".into());
        }
        let leaf = LeafStatement::from_bytes_on_gpu(label, context, statement, operations)
            .map_err(|e| e.to_string())?;
        Ok(Self { statement, context, label, digest: leaf.digest.map(Val::from_u64), operations })
    }
    pub(crate) fn bind(self, tree: &'op Plan, graph: &'a UnprovedRelationGraph)
        -> Result<PreparedBindings<'a, 'op, 'run>, String> {
        self.bind_inner(tree, graph, None)
    }
    pub(crate) fn bind_structure(self, tree: &'op Plan,
        structure: &crate::rust_verify::committed_backend::source_binding::prepared::PreparedGraphStructure<'a>)
        -> Result<PreparedBindings<'a, 'op, 'run>, String> {
        if !std::sync::Arc::ptr_eq(&tree.0.shape, structure.shape()) {
            return Err("foreign prepared graph registration".into());
        }
        self.bind_inner(tree, structure.graph(), Some(structure))
    }
    fn bind_inner(self, tree: &'op Plan, graph: &'a UnprovedRelationGraph,
        structure: Option<&crate::rust_verify::committed_backend::source_binding::prepared::PreparedGraphStructure<'a>>)
        -> Result<PreparedBindings<'a, 'op, 'run>, String> {
        self.operations.admit_field_chunks(0)?;
        if tree.label() != self.label || graph.setup_seed().as_slice() != &self.statement[..32] {
            return Err("prepared graph label or setup mismatch".into());
        }
        for node in graph.bytes() {
            match node.source {
                Source::Context if node.values != self.context => return Err("prepared graph context mismatch".into()),
                Source::StatementSeed if node.values != graph.setup_seed() => return Err("prepared graph seed mismatch".into()),
                _ => {}
            }
        }
        let context = GraphContext { context: self.context, statement: self.digest,
            node_manifest: match structure {
                Some(structure) => structure.manifest(self.operations).map_err(|e| e.to_string())?,
                None => tree.node_manifest_hint_on_gpu(graph, self.operations).map_err(|e| e.to_string())?,
            } };
        Ok(PreparedBindings { statement: self, tree, graph, context })
    }
}

pub(crate) struct PreparedBindings<'a, 'op, 'run> {
    statement: PreparedStatement<'a, 'op, 'run>,
    tree: &'op Plan,
    graph: &'a UnprovedRelationGraph,
    context: GraphContext,
}
impl<'a, 'op, 'run> PreparedBindings<'a, 'op, 'run> {
    pub(crate) fn check(&self) -> Result<(), String> {
        // Includes the failed-scope check even when all hints are reused.
        self.operations().admit_field_chunks(0)
    }
    pub(crate) fn tree(&self) -> &'op Plan { self.tree }
    pub(crate) fn graph(&self) -> &'a UnprovedRelationGraph { self.graph }
    pub(crate) fn context(&self) -> &GraphContext { &self.context }
    pub(crate) fn statement(&self) -> &'a [u8] { self.statement.statement }
    pub(crate) fn operations(&self) -> &'op OperationContext<'run> { self.statement.operations }
    pub(crate) fn crypto(&self, policy: graph_crypto::Policy) -> Result<PreparedCrypto<'_, 'a, 'op, 'run>, String> {
        self.check()?;
        let plan = graph_crypto::Plan::new_prepared(self, policy).map_err(|e| e.to_string())?;
        Ok(PreparedCrypto { binding: self, plan })
    }
}

pub(crate) struct PreparedCrypto<'binding, 'graph, 'op, 'run> {
    binding: &'binding PreparedBindings<'graph, 'op, 'run>,
    plan: graph_crypto::Plan,
}
impl<'binding, 'graph, 'op, 'run> PreparedCrypto<'binding, 'graph, 'op, 'run> {
    pub(crate) fn prepare_endpoints(&mut self, batched: bool) -> Result<(), String> {
        self.binding.check()?;
        self.plan.prepare_endpoint_facts(self.binding.context(), self.binding.operations(), batched).map_err(|e| e.to_string())
    }
    pub(crate) fn binding(&self) -> &'binding PreparedBindings<'graph, 'op, 'run> { self.binding }
    pub(crate) fn plan(&self) -> &graph_crypto::Plan { &self.plan }
    pub(crate) fn into_plan(self) -> graph_crypto::Plan { self.plan }
}

#[cfg(test)]
mod tests;
