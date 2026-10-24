//! Complete registered MatRiCT graph coverage through actual recursive proofs.
//!
//! Intervals count entries in an immutable leaf schedule, not operation IDs.
//! A schedule entry may contain noncontiguous homogeneous operation IDs. The
//! registration checks an exact partition of all 1,311 operations and every
//! source/producer, including the six private-response norms. Each leaf emits
//! real verifiers in one SourceBinding scope and consumes an exact coverage
//! check before a compiled node can exist. Tree nodes verify actual children
//! under their registered preprocessing caps and join adjacent schedule spans.
//!
//! Compilation and trace evaluation are not accepted proofs. Memory admission
//! can reject leaves or parents, and no complete graph proof is claimed here.
use crate::rust_verify::committed_backend::{
    source_binding::RegisteredGraphShape, UnprovedRelationGraph,
};
use lattica_prover_p3::block_v2::machine::{
    program::{Val, Wire},
    ProgramBuilder,
};
use p3_field::PrimeCharacteristicRing;
use std::sync::Arc;

mod leaf;
mod plan;
mod tree;
pub use crate::component_tree::Geometry;
pub use leaf::{compile_group, compile_leaf, AesProof, LeafArtifact, ShakeProof};
pub use plan::{LeafKind, LeafPlan, OperationFamily, Plan};
pub use tree::{
    compile_merge, CompiledNode, GraphProver, NodeKey, NodeProof, PreparedNode, ProofCache, ProvenNode,
};

pub const CONTEXT: usize = 8;
pub const STATEMENT: usize = 16;
pub const NODE_MANIFEST: usize = 20;
const FIRST: usize = 24;
const COUNT: usize = 25;
const TOTAL: usize = 26;
const LEVEL: usize = 27;
pub const PUBLIC_VALUES: usize = 28;
pub const FULL_OPERATIONS: usize = 1311;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(value: impl std::fmt::Debug) -> Error {
    Error(format!("{value:?}"))
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}

struct PlanInner {
    shape: RegisteredGraphShape,
    label: [u8; 32],
    leaves: Vec<LeafPlan>,
}
#[derive(Clone)]
struct Spec {
    plan: Arc<PlanInner>,
    first: u32,
    count: u32,
    level: u32,
}
impl Spec {
    fn end(&self) -> u32 {
        self.first + self.count
    }
    fn merge(left: &Self, right: &Self) -> Result<Self> {
        require(
            Arc::ptr_eq(&left.plan, &right.plan),
            "different registered graph plans",
        )?;
        require(
            left.end() == right.first,
            "missing, duplicate, overlapping or reordered graph leaves",
        )?;
        let count = left
            .count
            .checked_add(right.count)
            .ok_or_else(|| Error("graph span overflow".into()))?;
        let end = left
            .first
            .checked_add(count)
            .ok_or_else(|| Error("graph span overflow".into()))?;
        require(
            count != 0 && end as usize <= left.plan.leaves.len(),
            "graph span outside registered plan",
        )?;
        Ok(Self {
            plan: left.plan.clone(),
            first: left.first,
            count,
            level: left
                .level
                .max(right.level)
                .checked_add(1)
                .ok_or_else(|| Error("graph level overflow".into()))?,
        })
    }
    fn complete(&self) -> bool {
        self.first == 0 && self.count as usize == self.plan.leaves.len()
    }
}

/// The manifest is an unproved root until all registered source and operation
/// leaves have been verified. It is shared by every leaf and parent proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphContext {
    pub context: [u8; 32],
    pub statement: [Val; 4],
    pub node_manifest: [Val; 4],
}
/// Expected wires belonging to the caller's current outer program. A block
/// coordinator must link the context/statement to that transaction's public
/// semantics and consistently bind its graph node manifest; these wires are
/// not a transferable verified receipt.
pub struct ContextWires {
    pub context: [Wire; 8],
    pub statement: [Wire; 4],
    pub node_manifest: [Wire; 4],
}
fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}
fn header(spec: &Spec, context: &GraphContext) -> Vec<Val> {
    let mut result = vec![Val::ZERO; PUBLIC_VALUES];
    result[..8].copy_from_slice(&words(&spec.plan.label));
    result[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&context.context));
    result[STATEMENT..STATEMENT + 4].copy_from_slice(&context.statement);
    result[NODE_MANIFEST..NODE_MANIFEST + 4].copy_from_slice(&context.node_manifest);
    result[FIRST] = Val::from_u32(spec.first);
    result[COUNT] = Val::from_u32(spec.count);
    result[TOTAL] = Val::from_usize(spec.plan.leaves.len());
    result[LEVEL] = Val::from_u32(spec.level);
    result
}
fn constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let fixed = b.constant(value);
    b.assert_equal(wire, fixed);
}
fn public_wires(b: &mut ProgramBuilder, spec: &Spec) -> Result<Vec<Wire>> {
    let public = (0..PUBLIC_VALUES)
        .map(|i| b.public(i).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    for (wire, value) in public[..8].iter().zip(words(&spec.plan.label)) {
        constant(b, *wire, value);
    }
    for &wire in &public[CONTEXT..CONTEXT + 8] {
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(b, wire, 32).map_err(err)?;
    }
    for (index, value) in [
        (FIRST, spec.first as usize),
        (COUNT, spec.count as usize),
        (TOTAL, spec.plan.leaves.len()),
        (LEVEL, spec.level as usize),
    ] {
        constant(b, public[index], Val::from_usize(value));
    }
    Ok(public)
}

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
pub(crate) mod composite_shape_tests;
