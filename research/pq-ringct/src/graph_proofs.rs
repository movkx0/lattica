//! Deterministic child-proof provisioning for a trusted committed relation.
//!
//! Planning and native proof caching do not discharge graph obligations. The
//! consuming source binding must still verify every child inside its circuit.
//! Crypto/equality obligations remain explicit singleton batches for another
//! producer; this module never invents artifacts for unsupported operations.
use crate::{
    affine_air::{AffineBatchProof, AffineKind},
    g_bound_air::join::GBoundArtifact,
    linear_map_air::{LinearMapDescriptor, LinearMapProof},
    ntt_air::NttBatchProof,
    permutation_air::{PermutationKind, PermutationProof},
    poly_air::MulBatchProof,
    rust_verify::committed_backend::{
        inventory, source_binding::RegisteredGraphShape, Operation, PolyId, PolynomialKind,
        PolynomialValues, Source, UnprovedRelationGraph,
    },
};
use lattica_prover_p3::block_v2::{machine::program::Val, profile};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, fmt};

mod cache;
mod factory;
#[cfg(feature = "opencl")]
mod preparation;
mod version;
pub use cache::{ArchivedReverification, CacheOutcome, ProofCache};
/// Shared compiled source identity for other typed child-proof caches.
pub(crate) fn compiled_source_fingerprint() -> [u8; 32] {
    version::source_fingerprint()
}
#[cfg(all(test, feature = "native-matrict"))]
mod geometry_tests;
#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod planned_geometry_tests;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn error(message: impl Into<String>) -> Error {
    Error(message.into())
}
fn component_error(e: crate::crypto_join::Error) -> Error {
    error(e.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentKind {
    Affine {
        kind: AffineKind,
        modulus: u64,
    },
    Ntt {
        modulus: u64,
    },
    Mul {
        modulus: u64,
    },
    GBound {
        bound: u32,
    },
    Permutation {
        kind: PermutationKind,
    },
    LinearMap {
        descriptor: LinearMapDescriptor,
    },
    /// Still required by the graph; must be produced/discharged elsewhere.
    External,
}

pub enum ComponentArtifact {
    Affine(AffineBatchProof),
    Ntt(NttBatchProof),
    Mul(MulBatchProof),
    GBound(GBoundArtifact),
    Permutation(PermutationProof),
    LinearMap(LinearMapProof),
}
impl ComponentArtifact {
    pub fn as_leaf_artifact(&self) -> crate::graph_tree::LeafArtifact<'_> {
        use crate::graph_tree::LeafArtifact;
        match self {
            Self::Affine(p) => LeafArtifact::Affine(p),
            Self::Ntt(p) => LeafArtifact::Ntt(p),
            Self::Mul(p) => LeafArtifact::Mul(p),
            Self::GBound(p) => LeafArtifact::GBound(p),
            Self::Permutation(p) => LeafArtifact::Permutation(p),
            Self::LinearMap(p) => LeafArtifact::LinearMap(p),
        }
    }
    pub fn public_values(&self) -> &[Val] {
        match self {
            Self::Affine(p) => &p.public_values,
            Self::Ntt(p) => &p.public_values,
            Self::Mul(p) => &p.public_values,
            Self::GBound(p) => &p.public_values,
            Self::Permutation(p) => &p.public_values,
            Self::LinearMap(p) => &p.public_values,
        }
    }
    fn proof(&self) -> &p3_uni_stark::Proof<profile::Config> {
        match self {
            Self::Affine(p) => &p.proof,
            Self::Ntt(p) => &p.proof,
            Self::Mul(p) => &p.proof,
            Self::GBound(p) => &p.proof,
            Self::Permutation(p) => &p.proof,
            Self::LinearMap(p) => &p.proof,
        }
    }
}

/// Preflight budgets, not an operating-system memory guard. The estimate is
/// deliberately explicit and remains a heuristic until each batch is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_batch_count: usize,
    /// Separate family ceilings permit empirical local limits to override an
    /// optimistic memory estimate. These are not performance certifications.
    pub max_ntt_batch_count: usize,
    pub max_mul_batch_count: usize,
    pub max_trace_cells: u64,
    /// Heuristic partition ceiling and hard admitted native GPU host allowance.
    pub max_estimated_prover_bytes: u64,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_batch_count: 8,
            max_ntt_batch_count: 32,
            // QHAT Mul32 exhausted the unchanged local8GiB guard. Mul16 is
            // the next candidate; passing its own guarded test remains vital.
            max_mul_batch_count: 16,
            max_trace_cells: 1 << 24,
            max_estimated_prover_bytes: 2 << 30,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceEstimate {
    pub width: usize,
    pub height: usize,
    pub public_values: usize,
    pub trace_bytes: u64,
    /// Two blowup-domain trace copies plus a fixed 256 MiB allowance. This is
    /// not a proven upper bound on allocator, quotient, FRI or FFT workspace.
    pub estimated_prover_bytes: u64,
}
impl ResourceLimits {
    fn accepts(&self, estimate: ResourceEstimate) -> bool {
        estimate.trace_bytes / 8 <= self.max_trace_cells
            && estimate.estimated_prover_bytes <= self.max_estimated_prover_bytes
    }
}

#[derive(Clone, Debug)]
pub struct PlannedBatch {
    indices: Vec<usize>,
    kind: ComponentKind,
    estimate: Option<ResourceEstimate>,
    // Immutable endpoints prepared once for this graph. Reusing these public
    // roots never reuses a private trace or a proof and grants no acceptance.
    expected_public: Option<Vec<Val>>,
}
impl PlannedBatch {
    pub fn operation_indices(&self) -> &[usize] {
        &self.indices
    }
    pub fn kind(&self) -> &ComponentKind {
        &self.kind
    }
    pub fn resource_estimate(&self) -> Option<ResourceEstimate> {
        self.estimate
    }
}

pub struct GraphProofPlan<'a> {
    graph: &'a UnprovedRelationGraph,
    batches: Vec<PlannedBatch>,
    shape_fingerprint: [u8; 32],
    source_fingerprint: [u8; 32],
    native_host_limit_bytes: u64,
    resource_limits: ResourceLimits,
}
impl<'a> GraphProofPlan<'a> {
    /// The caller must obtain `registered` from its trusted network/relation
    /// compiler. A caller-selected graph registration authenticates nothing.
    pub fn new(
        registered: &RegisteredGraphShape,
        graph: &'a UnprovedRelationGraph,
        limits: ResourceLimits,
    ) -> Result<Self> {
        let mut plan = Self::topology(registered, graph, limits)?;
        for index in 0..plan.batches.len() {
            if plan.batches[index].kind != ComponentKind::External {
                let public = plan.collect_expected_public_values(
                    &plan.batches[index],
                    |kind, modulus, count, roots| {
                        crate::affine_air::RegisteredAffineAir::new(kind, modulus, count)
                            .map_err(component_error)?
                            .air()
                            .bundle_roots(roots)
                            .map_err(|e| error(format!("affine root framing: {e:?}")))
                    },
                )?;
                plan.batches[index].expected_public = Some(public);
            }
        }
        Ok(plan)
    }

    pub fn new_with_context(
        registered: &RegisteredGraphShape,
        graph: &'a UnprovedRelationGraph,
        limits: ResourceLimits,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<Self> {
        if let Some(execution) = execution {
            if execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
                #[cfg(feature = "opencl")]
                {
                    let host = usize::try_from(
                        limits
                            .max_estimated_prover_bytes
                            .min(execution.host_bytes()),
                    )
                    .map_err(|e| error(e.to_string()))?;
                    let (plan, _) = execution
                        .with_witness_preparation(host, |operations| {
                            Self::new_with_operations(registered, graph, limits, operations)
                                .map_err(|e| e.to_string())
                        })
                        .map_err(error)?;
                    return Ok(plan);
                }
                #[cfg(not(feature = "opencl"))]
                return Err(error("GPU algebra endpoint preparation unavailable"));
            }
        }
        Self::new(registered, graph, limits)
    }

    fn topology(
        registered: &RegisteredGraphShape,
        graph: &'a UnprovedRelationGraph,
        limits: ResourceLimits,
    ) -> Result<Self> {
        if !registered.matches(graph) {
            return Err(error("unregistered graph shape"));
        }
        if [
            limits.max_batch_count,
            limits.max_ntt_batch_count,
            limits.max_mul_batch_count,
        ]
        .into_iter()
        .any(|count| count == 0 || count > 128)
        {
            return Err(error("batch count limit must be in 1..=128"));
        }
        let mut groups: BTreeMap<(u8, u64, u32), (ComponentKind, Vec<usize>)> = BTreeMap::new();
        let mut batches = Vec::new();
        for (index, operation) in graph.operations().iter().enumerate() {
            if matches!(operation, Operation::Norm { .. }) {
                continue;
            }
            let kind = classify(graph, index)?;
            let group = match kind {
                ComponentKind::Affine { kind, modulus } => {
                    Some((kind.code() as u8, modulus, kind.bound()))
                }
                ComponentKind::Ntt { modulus } => Some((4, modulus, 0)),
                ComponentKind::Mul { modulus } => Some((5, modulus, 0)),
                _ => None,
            };
            if let Some(group) = group {
                groups
                    .entry(group)
                    .or_insert_with(|| (kind.clone(), Vec::new()))
                    .1
                    .push(index);
            } else {
                let estimate = factory::estimate(&kind, 1)?;
                if estimate.is_some_and(|e| !limits.accepts(e)) {
                    return Err(error(format!(
                        "operation {index} exceeds resource preflight"
                    )));
                }
                batches.push(PlannedBatch {
                    indices: vec![index],
                    kind,
                    estimate,
                    expected_public: None,
                });
            }
        }
        for (_, (kind, indices)) in groups {
            let mut offset = 0;
            while offset < indices.len() {
                let family_maximum = match kind {
                    ComponentKind::Ntt { .. } => limits.max_ntt_batch_count,
                    ComponentKind::Mul { .. } => limits.max_mul_batch_count,
                    _ => limits.max_batch_count,
                };
                let maximum = limits
                    .max_batch_count
                    .min(family_maximum)
                    .min(indices.len() - offset);
                let mut count = 1usize << maximum.ilog2();
                let estimate = loop {
                    let estimate = factory::estimate(&kind, count)?.expect("batched algebra");
                    if limits.accepts(estimate) {
                        break estimate;
                    }
                    if count == 1 {
                        return Err(error(format!(
                            "operation {} exceeds resource preflight",
                            indices[offset]
                        )));
                    }
                    count /= 2;
                };
                batches.push(PlannedBatch {
                    indices: indices[offset..offset + count].to_vec(),
                    kind: kind.clone(),
                    estimate: Some(estimate),
                    expected_public: None,
                });
                offset += count;
            }
        }
        batches.sort_by_key(|batch| batch.indices[0]);
        let plan = Self {
            graph,
            batches,
            shape_fingerprint: inventory::inventory(graph).shape_sha3_256(),
            source_fingerprint: compiled_source_fingerprint(),
            native_host_limit_bytes: limits.max_estimated_prover_bytes,
            resource_limits: limits,
        };
        Ok(plan)
    }
    pub fn native_host_limit_bytes(&self) -> u64 {
        self.native_host_limit_bytes
    }
    /// Exact immutable partition limits used to construct this plan.
    pub fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }
    pub fn batches(&self) -> &[PlannedBatch] {
        &self.batches
    }
    /// Exact non-Norm partition for graph-tree registration. Norms belong to
    /// the private-proof source leaf, not an omitted operation proof.
    pub fn operation_batches(&self) -> Vec<Vec<usize>> {
        self.batches
            .iter()
            .map(|batch| batch.indices.clone())
            .collect()
    }
    pub fn source_fingerprint(&self) -> [u8; 32] {
        self.source_fingerprint
    }
    pub fn shape_fingerprint(&self) -> [u8; 32] {
        self.shape_fingerprint
    }
    fn batch(&self, index: usize) -> Result<&PlannedBatch> {
        self.batches.get(index).ok_or_else(|| error("batch index"))
    }
    /// Stable content key, not an authorization token. Every cache hit also
    /// checks the expected roots and verifies the actual child STARK.
    pub fn cache_key(&self, batch_index: usize) -> Result<[u8; 32]> {
        let batch = self.batch(batch_index)?;
        let public = self.expected_public_values(batch)?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/actual-child-cache/v1");
        hash.update(profile::CANDIDATE_PROFILE_ID);
        hash.update(self.source_fingerprint);
        hash.update(self.shape_fingerprint);
        hash.update((batch.indices.len() as u64).to_le_bytes());
        for &index in &batch.indices {
            hash.update((index as u64).to_le_bytes());
        }
        hash.update((public.len() as u64).to_le_bytes());
        for value in public {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        Ok(hash.finalize().into())
    }
    fn root(&self, id: PolyId, kind: PolynomialKind) -> Result<[Val; 4]> {
        let node = self.graph.polynomial(id);
        if node.kind != kind {
            return Err(error("operation input/output kind or bound"));
        }
        Ok(node.commitment)
    }
    fn output_root(&self, operation: usize, id: PolyId, kind: PolynomialKind) -> Result<[Val; 4]> {
        if self.graph.polynomial(id).source != (Source::Derived { operation }) {
            return Err(error("operation output producer"));
        }
        self.root(id, kind)
    }
    fn canonical(&self, id: PolyId) -> Result<[u64; 256]> {
        match &self.graph.polynomial(id).values {
            PolynomialValues::Canonical(values) => Ok(*values),
            _ => Err(error("canonical polynomial hint required")),
        }
    }
    fn signed(&self, id: PolyId) -> Result<[i64; 256]> {
        match &self.graph.polynomial(id).values {
            PolynomialValues::Signed(values) => Ok(*values),
            _ => Err(error("signed polynomial hint required")),
        }
    }
}

fn classify(graph: &UnprovedRelationGraph, index: usize) -> Result<ComponentKind> {
    Ok(match &graph.operations()[index] {
        Operation::Add { modulus, .. } => ComponentKind::Affine {
            kind: AffineKind::Add,
            modulus: *modulus,
        },
        Operation::Sub { modulus, .. } => ComponentKind::Affine {
            kind: AffineKind::Sub,
            modulus: *modulus,
        },
        Operation::SignedToCanonical { modulus, bound, .. } => ComponentKind::Affine {
            kind: AffineKind::SignedToCanonical { bound: *bound },
            modulus: *modulus,
        },
        Operation::Ntt { modulus, .. } => ComponentKind::Ntt { modulus: *modulus },
        Operation::Mul { modulus, .. } => ComponentKind::Mul { modulus: *modulus },
        Operation::GBound { bound, .. } => ComponentKind::GBound { bound: *bound },
        Operation::AutomorphismQ { .. }
        | Operation::CanonicalMap { .. }
        | Operation::SignedMap { .. } => {
            if let Ok((kind, _, _)) = crate::permutation_air::graph::graph_operation(graph, index) {
                ComponentKind::Permutation { kind }
            } else {
                let map = crate::linear_map_air::graph_operation(graph, index)
                    .map_err(|e| error(format!("unsupported graph map {index}: {e:?}")))?;
                ComponentKind::LinearMap {
                    descriptor: map.descriptor,
                }
            }
        }
        Operation::Norm { .. } => return Err(error("norm belongs to private-proof source")),
        Operation::EqualBytes { .. }
        | Operation::EqualSigned { .. }
        | Operation::ByteMap { .. }
        | Operation::ParametersPp { .. }
        | Operation::SampleG { .. }
        | Operation::ExpandAlpha { .. }
        | Operation::HashAlpha { .. }
        | Operation::HashX { .. } => ComponentKind::External,
    })
}
