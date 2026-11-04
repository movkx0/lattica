//! Exact registration and structural facts tied to one immutable graph borrow.
use super::*;
use std::sync::Arc;


#[derive(Clone, Copy, Default)]
pub(crate) struct RegistrationHashPlan { pub(crate) parallel: bool }
impl RegistrationHashPlan {
    pub(crate) const WORKER_BYTES: usize = (3 << 20) + 2 * 8192 + 4096;
    pub(crate) fn new(workers: usize, available: usize) -> Self {
        Self { parallel: crate::preparation_options::parallel_registration()
            && workers >= 2 && available >= Self::WORKER_BYTES }
    }
    pub(crate) fn scratch_bytes(self) -> usize { if self.parallel { Self::WORKER_BYTES } else { 0 } }
}

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

/// Only immutable graph data enters the CPU queue. The exact vector is moved
/// into the final shape after both hashes complete; it is never re-encoded or
/// copied, and no ledger/GPU owner is retained here.
pub(crate) struct EncodedGraphStructure<'graph> {
    graph: &'graph UnprovedRelationGraph,
    plan: SourcePlan,
    words: Vec<u64>,
    counts: inventory::Counts,
}
impl<'graph> EncodedGraphStructure<'graph> {
    pub(crate) fn encode(graph: &'graph UnprovedRelationGraph, capacity: usize) -> Result<Box<Self>> {
        let plan = SourcePlan::from_graph(graph)?;
        let (words, counts) = inventory::encode_registration(graph, capacity).map_err(error)?;
        Ok(Box::new(Self { graph, plan, words, counts }))
    }
    pub(crate) fn hash(&self, inventory: bool) -> Result<[u8; 32]> {
        inventory::hash_registration(&self.words, inventory).map_err(error)
    }
    pub(crate) fn finish(self, label: [u8; 32], digest: [u8; 32]) -> PreparedGraphStructure<'graph> {
        crate::preparation_options::reuse_count(crate::preparation_options::ReuseCounter::PreparedStructures);
        crate::preparation_options::pipeline_count(crate::preparation_options::PipelineCounter::ParallelRegistrations, 1);
        PreparedGraphStructure { graph: self.graph, shape: Arc::new(RegisteredGraphShape {
            exact_shape: self.words, label, plan: self.plan,
        }), counts: self.counts, digest }
    }
}

impl<'graph> PreparedGraphStructure<'graph> {
    pub(crate) fn new(graph: &'graph UnprovedRelationGraph) -> Result<Self> {
        Self::with_capacity(graph, None)
    }
    pub(crate) fn with_capacity(graph: &'graph UnprovedRelationGraph, capacity: Option<usize>) -> Result<Self> {
        Self::with_hash_plan(graph, capacity, RegistrationHashPlan::default())
    }
    pub(crate) fn with_hash_plan(graph: &'graph UnprovedRelationGraph, capacity: Option<usize>, hashing: RegistrationHashPlan) -> Result<Self> {
        let plan = SourcePlan::from_graph(graph)?;
        let (exact_shape, counts, label, digest) = inventory::prepared_shape_with_plan(graph, capacity, hashing.parallel)
            .map_err(error)?;
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
