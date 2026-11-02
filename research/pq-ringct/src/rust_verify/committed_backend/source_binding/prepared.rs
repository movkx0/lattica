//! Exact registration and structural facts tied to one immutable graph borrow.
use super::*;
use std::sync::Arc;

pub(crate) struct PreparedGraphStructure<'graph> {
    graph: &'graph UnprovedRelationGraph,
    shape: Arc<RegisteredGraphShape>,
    counts: inventory::Counts,
    digest: [u8; 32],
}
pub(crate) const FRAME_BYTES: usize = 8
    * (core::mem::size_of::<PreparedGraphStructure<'static>>()
        + core::mem::size_of::<RegisteredGraphShape>()
        + inventory::PREPARED_FRAME_BYTES);

impl<'graph> PreparedGraphStructure<'graph> {
    pub(crate) fn new(graph: &'graph UnprovedRelationGraph) -> Result<Self> {
        let plan = SourcePlan::from_graph(graph)?;
        let (exact_shape, counts, label, digest) = inventory::prepared_shape(graph);
        crate::preparation_options::reuse_count(
            crate::preparation_options::ReuseCounter::PreparedStructures,
        );
        Ok(Self {
            graph,
            shape: Arc::new(RegisteredGraphShape {
                exact_shape,
                label,
                plan,
            }),
            counts,
            digest,
        })
    }
    pub(crate) fn graph(&self) -> &'graph UnprovedRelationGraph {
        self.graph
    }
    pub(crate) fn shape(&self) -> &Arc<RegisteredGraphShape> {
        &self.shape
    }
    pub(crate) fn counts(&self) -> &inventory::Counts {
        &self.counts
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[cfg(feature = "opencl")]
    pub(crate) fn manifest(
        &self,
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
    ) -> Result<[Val; 4]> {
        self.shape
            .bound_node_manifest_on_gpu(self.graph, operations)
    }
}
