//! Bounded, resumable production of a complete AES/SHAKE request proof.
//! A complete request still has to be verified inside its consuming graph leaf.
use super::*;
use crate::component_tree::{self, CompiledNode, Geometry, NodeKey, NodeProof};

#[derive(Clone, Debug)]
pub struct NodeProvingReport {
    pub stage: &'static str,
    pub first_unit: usize,
    pub units: usize,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub retained_lde_bytes: u64,
    pub cache_hit: bool,
    pub cache_identity: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct RequestProvingReport {
    pub native_children: usize,
    pub native_cache_hits: usize,
    pub outer_leaves: usize,
    pub outer_parents: usize,
    pub outer_cache_hits: usize,
    pub maximum_retained_lde_bytes: u64,
    pub nodes: Vec<NodeProvingReport>,
}

pub struct CompleteRequestProof {
    pub key: NodeKey,
    pub proof: NodeProof,
    pub report: RequestProvingReport,
}

pub struct RequestProver<'a> {
    native_cache: &'a ProofCache,
    outer_cache: &'a OuterProofCache,
    outer_memory_budget_bytes: u64,
    execution: Option<&'a crate::execution::ProvingContext>,
}

struct ActualNode {
    first: usize,
    units: usize,
    key: NodeKey,
    proof: NodeProof,
}

/// The occupied slots represent adjacent power-of-two batches of leaves.
/// Only compact keys/proofs survive; no prepared program is retained here.
struct CarryStack<T> {
    slots: Vec<Option<T>>,
}
impl<T> CarryStack<T> {
    fn new() -> Self {
        Self { slots: Vec::new() }
    }
    fn push(&mut self, mut value: T, mut merge: impl FnMut(T, T) -> Result<T>) -> Result<()> {
        let mut level = 0;
        loop {
            if level == self.slots.len() {
                self.slots.push(None);
            }
            match self.slots[level].take() {
                None => {
                    self.slots[level] = Some(value);
                    return Ok(());
                }
                Some(left) => {
                    value = merge(left, value)?;
                    level += 1;
                }
            }
        }
    }
    fn finish(self, mut merge: impl FnMut(T, T) -> Result<T>) -> Result<T> {
        let mut right = None;
        for left in self.slots.into_iter().flatten() {
            right = Some(match right {
                None => left,
                Some(right) => merge(left, right)?,
            });
        }
        right.ok_or_else(|| Error("empty complete crypto request".into()))
    }
}

fn admit(stage: &str, first: usize, units: usize, geometry: &Geometry, budget: u64) -> Result<()> {
    require(geometry.retained_lde_bytes <= budget, &format!(
        "crypto {stage} span [{first}, {}) exceeds outer retained-LDE admission before registration: active_rows={}, padded_rows={}, retained_bytes={}, budget_bytes={budget}; this is not a peak-memory bound",
        first.saturating_add(units), geometry.active_rows, geometry.padded_rows, geometry.retained_lde_bytes,
    ))
}

impl<'a> RequestProver<'a> {
    /// This budget gates actual retained-LDE geometry before registration.
    /// It does not bound peak RSS; callers still need process memory guards.
    pub fn new(
        native_cache: &'a ProofCache,
        outer_cache: &'a OuterProofCache,
        outer_memory_budget_bytes: u64,
    ) -> Result<Self> {
        require(
            outer_memory_budget_bytes != 0,
            "zero outer crypto memory budget",
        )?;
        Ok(Self {
            native_cache,
            outer_cache,
            outer_memory_budget_bytes,
            execution: None,
        })
    }

    pub fn new_with_context(
        native_cache: &'a ProofCache,
        outer_cache: &'a OuterProofCache,
        outer_memory_budget_bytes: u64,
        execution: &'a crate::execution::ProvingContext,
    ) -> Result<Self> {
        let mut prover = Self::new(
            native_cache,
            outer_cache,
            outer_memory_budget_bytes.min(execution.host_bytes()),
        )?;
        prover.execution = Some(execution);
        Ok(prover)
    }

    fn prove_node(
        &self,
        stage: &'static str,
        first: usize,
        units: usize,
        compiled: CompiledNode,
        report: &mut RequestProvingReport,
    ) -> Result<ActualNode> {
        let geometry = compiled.geometry().map_err(err)?;
        admit(
            stage,
            first,
            units,
            &geometry,
            self.outer_memory_budget_bytes,
        )?;
        let outcome = match self.execution {
            Some(execution) => compiled.prove_or_load_with_context(execution, self.outer_cache),
            None => compiled
                .prepare(self.outer_memory_budget_bytes)
                .and_then(|prepared| prepared.prove_or_load(self.outer_cache)),
        }
        .map_err(err)?;
        report.maximum_retained_lde_bytes = report
            .maximum_retained_lde_bytes
            .max(geometry.retained_lde_bytes);
        report.outer_cache_hits += usize::from(outcome.cache_hit);
        if stage == "parent" {
            report.outer_parents += 1;
        } else {
            report.outer_leaves += 1;
        }
        report.nodes.push(NodeProvingReport {
            stage,
            first_unit: first,
            units,
            active_rows: geometry.active_rows,
            padded_rows: geometry.padded_rows,
            retained_lde_bytes: geometry.retained_lde_bytes,
            cache_hit: outcome.cache_hit,
            cache_identity: outcome.identity,
        });
        Ok(ActualNode {
            first,
            units,
            key: outcome.key,
            proof: outcome.proof,
        })
    }

    fn merge(
        &self,
        left: ActualNode,
        right: ActualNode,
        report: &mut RequestProvingReport,
    ) -> Result<ActualNode> {
        require(
            left.first.checked_add(left.units) == Some(right.first),
            "nonadjacent crypto prover nodes",
        )?;
        let units = left
            .units
            .checked_add(right.units)
            .ok_or_else(|| Error("crypto prover span overflow".into()))?;
        if let Some(execution) = self.execution {
            execution.release_prepared().map_err(err)?;
        }
        let compiled =
            component_tree::compile_merge(&left.key, &right.key, [&left.proof, &right.proof])
                .map_err(err)?;
        // Compilation has consumed child values as witnesses; only the actual
        // registered verifier program and its witnesses remain during proving.
        let first = left.first;
        drop((left, right));
        self.prove_node("parent", first, units, compiled, report)
    }

    fn finish(
        &self,
        stack: CarryStack<ActualNode>,
        request: &Request,
        endpoints: &crate::component_tree::EndpointContext,
        mut report: RequestProvingReport,
    ) -> Result<CompleteRequestProof> {
        let node = stack.finish(|left, right| self.merge(left, right, &mut report))?;
        require(
            node.first == 0 && node.units == request.units(),
            "incomplete crypto prover coverage",
        )?;
        node.key
            .verify_request(&node.proof, endpoints)
            .map_err(err)?;
        Ok(CompleteRequestProof {
            key: node.key,
            proof: node.proof,
            report,
        })
    }

    pub fn prove_serial(
        &self,
        request: &Request,
        context: &graph_tree::GraphContext,
    ) -> Result<CompleteRequestProof> {
        let endpoints = request.endpoint_context_hint_with_context(context, self.execution)?;
        let mut report = RequestProvingReport::default();
        let mut stack = CarryStack::new();
        for (index, segment) in request.segments().iter().enumerate() {
            let native =
                self.native_cache
                    .load_or_prove_with_context(request, index, self.execution)?;
            report.native_children += 1;
            report.native_cache_hits += usize::from(native.cache_hit);
            let compiled = request.compile_segment_leaf_with_endpoints(
                index,
                &endpoints,
                &native.artifact,
                self.execution,
            )?;
            drop(native);
            let node = self.prove_node(
                "serial leaf",
                segment.first_unit,
                segment.units,
                compiled,
                &mut report,
            )?;
            stack.push(node, |left, right| self.merge(left, right, &mut report))?;
        }
        self.finish(stack, request, &endpoints, report)
    }

    pub fn prove_wide(
        &self,
        factory: &WideShakeFactory<'_>,
        context: &graph_tree::GraphContext,
    ) -> Result<CompleteRequestProof> {
        let endpoints = factory
            .request()
            .endpoint_context_hint_with_context(context, self.execution)?;
        let mut report = RequestProvingReport::default();
        let mut stack = CarryStack::new();
        for (index, segment) in factory.segments().iter().enumerate() {
            let native = self.native_cache.load_or_prove_wide_with_context(
                factory,
                index,
                self.execution,
            )?;
            report.native_children += 1;
            report.native_cache_hits += usize::from(native.cache_hit);
            let compiled = factory.compile_segment_leaf_with_endpoints(
                index,
                &endpoints,
                &native.artifact,
                self.execution,
            )?;
            drop(native);
            let node = self.prove_node(
                "wide leaf",
                segment.first_permutation,
                segment.permutations,
                compiled,
                &mut report,
            )?;
            stack.push(node, |left, right| self.merge(left, right, &mut report))?;
        }
        self.finish(stack, factory.request(), &endpoints, report)
    }

    /// One native whole-request AES proof and one actual complete outer leaf.
    /// The measured outer geometry must fit before registration or proving.
    pub fn prove_wide_aes(
        &self,
        factory: &WideAesFactory<'_>,
        context: &graph_tree::GraphContext,
    ) -> Result<CompleteRequestProof> {
        let endpoints = factory
            .request()
            .endpoint_context_hint_with_context(context, self.execution)?;
        let mut report = RequestProvingReport::default();
        let native = self
            .native_cache
            .load_or_prove_wide_aes_with_context(factory, self.execution)?;
        report.native_children = 1;
        report.native_cache_hits = usize::from(native.cache_hit);
        let compiled =
            factory.compile_leaf_with_endpoints(&endpoints, &native.artifact, self.execution)?;
        drop(native);
        let node = self.prove_node(
            "whole wide AES leaf",
            0,
            factory.request().units(),
            compiled,
            &mut report,
        )?;
        let mut stack = CarryStack::new();
        stack.push(node, |left, right| self.merge(left, right, &mut report))?;
        self.finish(stack, factory.request(), &endpoints, report)
    }
}

#[cfg(test)]
mod tests;
