//! Resumable real graph proving. Every node retains its actual registered
//! verifier key and proof; a cache hit never bypasses native verification.
use super::*;
pub use crate::outer_cache::ProofCache;

/// An actual proof and its registration-derived verifier key. The pipeline
/// still verifies every child when merging, and full graph acceptance remains
/// the explicit `verify_complete` predicate.
pub struct ProvenNode {
    key: NodeKey,
    proof: NodeProof,
    cache_hit: bool,
}
impl ProvenNode {
    pub fn key(&self) -> &NodeKey {
        &self.key
    }
    pub fn proof(&self) -> &NodeProof {
        &self.proof
    }
    pub fn cache_hit(&self) -> bool {
        self.cache_hit
    }
    pub fn into_parts(self) -> (NodeKey, NodeProof) {
        (self.key, self.proof)
    }
    pub fn verify_complete(&self, context: &GraphContext) -> Result<()> {
        self.key.verify_complete(&self.proof, context)
    }
}

pub struct GraphProver<'a> {
    plan: Plan,
    context: GraphContext,
    cache: &'a ProofCache,
    retained_memory_budget: u64,
    execution: Option<&'a crate::execution::ProvingContext>,
}
impl<'a> GraphProver<'a> {
    /// This budget controls the existing retained-LDE admission check. It is
    /// not a complete process-memory bound; callers must separately guard peak
    /// allocations and coordinate concurrent proving jobs.
    pub fn new(
        plan: &Plan,
        context: &GraphContext,
        cache: &'a ProofCache,
        retained_memory_budget: u64,
    ) -> Result<Self> {
        require(
            retained_memory_budget != 0,
            "zero graph proving memory budget",
        )?;
        Ok(Self {
            plan: plan.clone(),
            context: context.clone(),
            cache,
            retained_memory_budget,
            execution: None,
        })
    }

    pub fn new_with_context(
        plan: &Plan,
        context: &GraphContext,
        cache: &'a ProofCache,
        retained_memory_budget: u64,
        execution: &'a crate::execution::ProvingContext,
    ) -> Result<Self> {
        let mut prover = Self::new(
            plan,
            context,
            cache,
            retained_memory_budget.min(execution.host_bytes()),
        )?;
        prover.execution = Some(execution);
        Ok(prover)
    }

    fn registered_plan(&self, spec: &Spec) -> Result<()> {
        require(
            Arc::ptr_eq(&self.plan.0, &spec.plan),
            "graph prover received a different registered plan",
        )
    }

    fn verify_node(&self, node: &ProvenNode) -> Result<()> {
        self.registered_plan(&node.key.spec)?;
        require(
            node.proof.public == header(&node.key.spec, &self.context),
            "graph prover child context mismatch",
        )?;
        node.key.verify(&node.proof)
    }

    fn prove_node(&self, compiled: CompiledNode) -> Result<ProvenNode> {
        self.registered_plan(&compiled.spec)?;
        require(
            compiled.public == header(&compiled.spec, &self.context),
            "compiled graph node context mismatch",
        )?;
        // Even on a cache hit, the source cap comes from this actual trusted
        // compiled program's registration. No cap/key is loaded from storage.
        let (key, proof, cache_hit) =
            match self.execution {
                Some(execution) => {
                    require(compiled.geometry()?.retained_lde_bytes <= self.retained_memory_budget,
                    "graph node exceeds retained-LDE admission; this is not a peak-memory bound")?;
                    compiled.prove_or_load_with_context(execution, self.cache, &self.context)?
                }
                None => {
                    let prepared = compiled.prepare(self.retained_memory_budget)?;
                    prepared.prove_or_load(self.cache, &self.context)?
                }
            };
        Ok(ProvenNode {
            key,
            proof,
            cache_hit,
        })
    }

    pub fn prove_leaf(&self, compiled: CompiledNode) -> Result<ProvenNode> {
        require(compiled.spec.level == 0, "graph leaf is a recursive parent")?;
        self.prove_node(compiled)
    }

    /// Merge adjacent registered intervals pairwise. Odd tails are retained
    /// for the next round. Partial spans may be combined, but they cannot pass
    /// `verify_complete` until they cover the entire trusted schedule.
    pub fn aggregate_adjacent(&self, mut nodes: Vec<ProvenNode>) -> Result<ProvenNode> {
        require(!nodes.is_empty(), "empty graph aggregation")?;
        for node in &nodes {
            self.verify_node(node)?;
        }
        for pair in nodes.windows(2) {
            Spec::merge(&pair[0].key.spec, &pair[1].key.spec)?;
        }
        while nodes.len() > 1 {
            let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
            let mut children = nodes.into_iter();
            while let Some(left) = children.next() {
                let Some(right) = children.next() else {
                    next.push(left);
                    break;
                };
                if let Some(execution) = self.execution {
                    execution.release_prepared().map_err(err)?;
                }
                let compiled = compile_merge(&left.key, &right.key, [&left.proof, &right.proof])?;
                // The compiled program owns its witness, so child artifacts
                // can be released before the next registration/proving phase.
                drop(left);
                drop(right);
                next.push(self.prove_node(compiled)?);
            }
            nodes = next;
        }
        let result = nodes.pop().unwrap();
        self.verify_node(&result)?;
        Ok(result)
    }

    pub fn verify_complete(&self, node: &ProvenNode) -> Result<()> {
        self.registered_plan(&node.key.spec)?;
        node.key.verify_complete(&node.proof, &self.context)
    }
}

#[cfg(all(test, feature = "native-matrict"))]
mod tests;
