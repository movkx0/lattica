use super::*;
use crate::{
    affine_air::AffineKind,
    rust_verify::committed_backend::{inventory, Operation, Source},
};
use sha3::{Digest, Sha3_256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationFamily {
    Affine { kind: AffineKind, modulus: u64 },
    Ntt { modulus: u64 },
    Mul { modulus: u64 },
    Permutation,
    LinearMap,
    GBound,
    Equality,
    ParametersPp,
    SampleG,
    ExpandAlpha,
    HashAlpha,
    HashX,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafKind {
    FixedSources,
    Statement,
    PrivateProof,
    Operations(OperationFamily),
}
#[derive(Clone, Debug)]
pub struct LeafPlan {
    pub(super) kind: LeafKind,
    pub(super) polynomials: Vec<usize>,
    pub(super) bytes: Vec<usize>,
    pub(super) operations: Vec<usize>,
}
impl LeafPlan {
    pub fn kind(&self) -> &LeafKind {
        &self.kind
    }
    pub fn operation_indices(&self) -> &[usize] {
        &self.operations
    }
    pub fn polynomial_indices(&self) -> &[usize] {
        &self.polynomials
    }
    pub fn byte_indices(&self) -> &[usize] {
        &self.bytes
    }
}
fn family(graph: &UnprovedRelationGraph, index: usize) -> Result<OperationFamily> {
    use OperationFamily as F;
    Ok(
        match graph
            .operations()
            .get(index)
            .ok_or_else(|| Error("graph operation index".into()))?
        {
            Operation::Add { modulus, .. } => F::Affine {
                kind: AffineKind::Add,
                modulus: *modulus,
            },
            Operation::Sub { modulus, .. } => F::Affine {
                kind: AffineKind::Sub,
                modulus: *modulus,
            },
            Operation::SignedToCanonical { bound, modulus, .. } => F::Affine {
                kind: AffineKind::SignedToCanonical { bound: *bound },
                modulus: *modulus,
            },
            Operation::Ntt { modulus, .. } => F::Ntt { modulus: *modulus },
            Operation::Mul { modulus, .. } => F::Mul { modulus: *modulus },
            Operation::AutomorphismQ { .. } => {
                crate::permutation_air::graph::graph_operation(graph, index).map_err(err)?;
                F::Permutation
            }
            Operation::CanonicalMap { .. } | Operation::SignedMap { .. } => {
                if crate::permutation_air::graph::graph_operation(graph, index).is_ok() {
                    F::Permutation
                } else {
                    crate::linear_map_air::graph_operation(graph, index).map_err(err)?;
                    F::LinearMap
                }
            }
            Operation::GBound { .. } => F::GBound,
            Operation::EqualBytes { .. } | Operation::EqualSigned { .. } => F::Equality,
            Operation::ParametersPp { .. } => F::ParametersPp,
            Operation::SampleG { .. } => F::SampleG,
            Operation::ExpandAlpha { .. } => F::ExpandAlpha,
            Operation::HashAlpha { .. } => F::HashAlpha,
            Operation::HashX { .. } => F::HashX,
            Operation::Norm { .. } => {
                return Err(Error(
                    "norms belong to the exact private-proof source leaf".into(),
                ))
            }
            Operation::ByteMap { .. } => {
                return Err(Error("unimplemented graph ByteMap predicate".into()))
            }
        },
    )
}
fn validate_batch(graph: &UnprovedRelationGraph, indices: &[usize]) -> Result<OperationFamily> {
    require(
        !indices.is_empty() && indices.windows(2).all(|v| v[0] < v[1]),
        "graph batch must be nonempty, unique and ordered",
    )?;
    let first = family(graph, indices[0])?;
    for &index in &indices[1..] {
        require(
            family(graph, index)? == first,
            "heterogeneous graph operation batch",
        )?;
    }
    match first {
        OperationFamily::Affine { kind, modulus } => {
            crate::affine_air::AffineAir::new(kind, modulus, indices.len()).map_err(err)?;
        }
        OperationFamily::Ntt { modulus } => {
            crate::ntt_air::NttAir::new(modulus, indices.len()).map_err(err)?;
        }
        OperationFamily::Mul { modulus } => {
            crate::poly_air::MulAir::new(modulus, indices.len()).map_err(err)?;
        }
        _ => require(
            indices.len() == 1,
            "this graph operation family requires singleton leaves",
        )?,
    }
    Ok(first)
}

/// A trusted, immutable full-profile schedule. Batches may contain noncontiguous
/// operation ordinals; their exact lists and order are part of registration.
/// Never register a caller-supplied reduced relation as the network profile.
#[derive(Clone)]
pub struct Plan(pub(super) Arc<PlanInner>);
impl Plan {
    pub fn from_trusted_graph(
        graph: &UnprovedRelationGraph,
        batches: Vec<Vec<usize>>,
    ) -> Result<Self> {
        let shape = RegisteredGraphShape::from_trusted_graph(graph).map_err(err)?;
        let inventory = inventory::inventory(graph);
        let counts = inventory.counts();
        require(
            counts.operations == FULL_OPERATIONS && counts.polynomials == 1770 && counts.bytes == 8,
            "graph is not the complete registered MatRiCT+ N10 profile",
        )?;
        require(
            counts.operation_kinds
                == [
                    6, 2, 409, 201, 2, 95, 95, 474, 6, 12, 2, 1, 0, 1, 2, 1, 1, 1,
                ],
            "graph operation family counts differ from full MatRiCT+ N10",
        )?;
        require(
            batches.windows(2).all(|p| p[0].first() < p[1].first()),
            "graph batches must be ordered by their first operation",
        )?;
        let mut leaves = vec![
            LeafPlan {
                kind: LeafKind::FixedSources,
                polynomials: vec![],
                bytes: vec![],
                operations: vec![],
            },
            LeafPlan {
                kind: LeafKind::Statement,
                polynomials: vec![],
                bytes: vec![],
                operations: vec![],
            },
            LeafPlan {
                kind: LeafKind::PrivateProof,
                polynomials: vec![],
                bytes: vec![],
                operations: vec![],
            },
        ];
        let mut owner = vec![None; FULL_OPERATIONS];
        for (index, operation) in graph.operations().iter().enumerate() {
            if matches!(operation, Operation::Norm { .. }) {
                owner[index] = Some(2);
                leaves[2].operations.push(index);
            }
        }
        for indices in batches {
            let family = validate_batch(graph, &indices)?;
            let leaf = leaves.len();
            for &index in &indices {
                require(
                    owner[index].replace(leaf).is_none(),
                    "duplicate graph operation or norm in batches",
                )?;
            }
            leaves.push(LeafPlan {
                kind: LeafKind::Operations(family),
                polynomials: vec![],
                bytes: vec![],
                operations: indices,
            });
        }
        require(
            owner.iter().all(Option::is_some),
            "missing graph operations in registered leaf schedule",
        )?;
        require(
            u32::try_from(leaves.len()).is_ok(),
            "graph leaf count overflow",
        )?;
        for (index, node) in graph.polynomials().iter().enumerate() {
            let leaf = match node.source {
                Source::Fixed => 0,
                Source::StatementPolynomial { .. } => 1,
                Source::ProofPolynomial { .. } => 2,
                Source::Derived { operation } => owner
                    .get(operation)
                    .copied()
                    .flatten()
                    .ok_or_else(|| Error("unregistered polynomial producer".into()))?,
                _ => return Err(Error("byte source in polynomial namespace".into())),
            };
            leaves[leaf].polynomials.push(index);
        }
        for (index, node) in graph.bytes().iter().enumerate() {
            let leaf = match node.source {
                Source::Context | Source::StatementSeed => {
                    for leaf in &mut leaves {
                        leaf.bytes.push(index);
                    }
                    continue;
                }
                Source::Fixed => 0,
                Source::StatementSerial { .. } => 1,
                Source::ProofAlpha => 2,
                Source::Derived { operation } => owner
                    .get(operation)
                    .copied()
                    .flatten()
                    .ok_or_else(|| Error("unregistered byte producer".into()))?,
                _ => return Err(Error("polynomial source in byte namespace".into())),
            };
            leaves[leaf].bytes.push(index);
        }
        // Frame every exact coverage set, not just a count or family label.
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/full-graph-tree/v1");
        hash.update(inventory.shape_sha3_256());
        hash.update((leaves.len() as u64).to_le_bytes());
        for (index, leaf) in leaves.iter().enumerate() {
            hash.update((index as u64).to_le_bytes());
            for indices in [&leaf.polynomials, &leaf.bytes, &leaf.operations] {
                hash.update((indices.len() as u64).to_le_bytes());
                for &index in indices {
                    hash.update((index as u64).to_le_bytes());
                }
            }
        }
        Ok(Self(Arc::new(PlanInner {
            shape,
            label: hash.finalize().into(),
            leaves,
        })))
    }
    pub fn leaves(&self) -> &[LeafPlan] {
        &self.0.leaves
    }
    pub fn label(&self) -> [u8; 32] {
        self.0.label
    }
    pub fn node_manifest_hint(&self, graph: &UnprovedRelationGraph) -> Result<[Val; 4]> {
        self.0.shape.node_manifest_hint(graph).map_err(err)
    }
    #[cfg(feature = "opencl")]
    pub fn node_manifest_hint_on_gpu(
        &self,
        graph: &UnprovedRelationGraph,
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
    ) -> Result<[Val; 4]> {
        self.0
            .shape
            .node_manifest_hint_on_gpu(graph, operations)
            .map_err(err)
    }
    pub(super) fn leaf_spec(&self, index: usize) -> Result<Spec> {
        require(index < self.0.leaves.len(), "graph leaf index")?;
        Ok(Spec {
            plan: self.0.clone(),
            first: index as u32,
            count: 1,
            level: 0,
        })
    }
}
