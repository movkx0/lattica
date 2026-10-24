//! Unproved, root-only lowering of the shared MatRiCT relation.
//!
//! Coefficient references are symbolic expressions, never unchecked modular
//! machine values. Native values and commitments are witness hints. Every source
//! needs its typed range/bundle proof and every recorded operation needs its
//! typed component proof. This module deliberately has no acceptance API and
//! cannot construct a verified leaf; unsupported operations remain obligations.
pub use super::constraints_ntt::SIGNED_POLYNOMIAL_DOMAIN;
use super::constraints_ntt::{commit_signed_values, commit_values, POLYNOMIAL_DOMAIN};
use super::{
    arithmetic, generic::*, primitives, Account, Proof, Statement, VerifyError, D, Q, QHAT,
};
use crate::shake_air::commit_bytes;
use lattica_prover_p3::block_v2::machine::program::Val;
#[cfg(feature = "opencl")]
use p3_field::PrimeCharacteristicRing;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

// A GPU failure can only produce temporary placeholders for the infallible
// Backend trait. The poisoned backend can never release a graph. The CPU
// expression is evaluated only for the explicitly selected legacy CPU backend.
macro_rules! witness_value {
    ($backend:expr, $device:ident => $gpu:expr, $cpu:expr, $failed:expr) => {{
        #[cfg(feature = "opencl")]
        {
            match $backend.on_device(|$device| $gpu) {
                Some(Ok(value)) => value,
                Some(Err(_)) => $failed,
                None => $cpu,
            }
        }
        #[cfg(not(feature = "opencl"))]
        {
            $cpu
        }
    }};
}

mod arena;
mod backend;
#[cfg(feature = "opencl")]
mod gpu;
#[cfg(feature = "opencl")]
pub use gpu::lower_unproved_on_gpu;
mod import;
pub mod inventory;
pub mod source_binding;
#[cfg(test)]
mod tests;

static NEXT_GRAPH: AtomicU64 = AtomicU64::new(1);
/// Framing for an opaque 32-byte value. Hash output, source and equality roles
/// still require typed predicates; sharing this digest does not assert SHAKE.
pub const BYTES32_DOMAIN: u64 = 0x4259_5445_5051_3332;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolyId {
    owner: u64,
    index: usize,
}
impl PolyId {
    pub fn index(self) -> usize {
        self.index
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BytesId {
    owner: u64,
    index: usize,
}
impl BytesId {
    pub fn index(self) -> usize {
        self.index
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ResidueRef {
    owner: u64,
    expr: usize,
    modulus: u64,
    value: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct SignedRef {
    owner: u64,
    expr: usize,
    bound: u32,
    value: i64,
}
#[derive(Clone, Copy, Debug)]
pub struct ByteRef {
    buffer: BytesId,
    index: usize,
    value: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolynomialKind {
    Canonical { modulus: u64 },
    Signed { bound: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    StatementPolynomial { position: usize },
    ProofPolynomial { position: usize },
    Context,
    StatementSeed,
    StatementSerial { position: usize },
    ProofAlpha,
    Fixed,
    Derived { operation: usize },
}
#[derive(Clone, Debug)]
pub enum PolynomialValues {
    Canonical([u64; D]),
    Signed([i64; D]),
}
#[derive(Clone, Debug)]
pub struct PolynomialNode {
    pub kind: PolynomialKind,
    pub source: Source,
    pub commitment: [Val; 4],
    pub values: PolynomialValues,
    expressions: [usize; D],
}
#[derive(Clone, Debug)]
pub struct BytesNode {
    pub source: Source,
    pub commitment: [Val; 4],
    pub values: [u8; 32],
}

/// Fixed expression topology. Input roots and coefficients are witness data;
/// operation kinds, indices, constants, moduli and bounds are trusted metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expression {
    CanonicalInput {
        polynomial: PolyId,
        index: usize,
    },
    SignedInput {
        polynomial: PolyId,
        index: usize,
    },
    CanonicalConstant {
        modulus: u64,
        value: u64,
    },
    Add {
        left: usize,
        right: usize,
        modulus: u64,
    },
    Sub {
        left: usize,
        right: usize,
        modulus: u64,
    },
    Scale {
        input: usize,
        factor: u64,
        modulus: u64,
    },
    SignedNeg {
        input: usize,
        bound: u32,
    },
    SignedSub {
        left: usize,
        right: usize,
        bound: u32,
    },
    ConvertCoefficient {
        input: usize,
        bound: u32,
        modulus: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranscriptPart {
    Bytes(BytesId),
    Polynomial(PolyId),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    CanonicalMap {
        modulus: u64,
        inputs: Vec<PolyId>,
        expressions: [usize; D],
        output: PolyId,
    },
    SignedMap {
        bound: u32,
        inputs: Vec<PolyId>,
        expressions: [usize; D],
        output: PolyId,
    },
    Add {
        modulus: u64,
        left: PolyId,
        right: PolyId,
        output: PolyId,
    },
    Sub {
        modulus: u64,
        left: PolyId,
        right: PolyId,
        output: PolyId,
    },
    AutomorphismQ {
        input: PolyId,
        output: PolyId,
    },
    SignedToCanonical {
        bound: u32,
        modulus: u64,
        input: PolyId,
        output: PolyId,
    },
    Ntt {
        modulus: u64,
        input: PolyId,
        output: PolyId,
    },
    Mul {
        modulus: u64,
        left: PolyId,
        right: PolyId,
        output: PolyId,
    },
    Norm {
        inputs: Vec<PolyId>,
        maximum: u64,
    },
    GBound {
        f: PolyId,
        x: PolyId,
        bound: u32,
    },
    EqualBytes {
        left: BytesId,
        right: BytesId,
    },
    EqualSigned {
        left: PolyId,
        right: PolyId,
    },
    ByteMap {
        inputs: [(BytesId, usize); 32],
        output: BytesId,
    },
    /// SHAKE of the exact fixed setup/domain/context encoding in primitives.
    ParametersPp {
        setup_seed: [u8; 32],
        context: BytesId,
        output: BytesId,
    },
    /// Full typed sampler obligation, including AES and bounded rejection.
    SampleG {
        seed: BytesId,
        output: [PolyId; 4],
    },
    ExpandAlpha {
        seed: BytesId,
        canonical: [PolyId; 2],
        signed: PolyId,
    },
    /// Exact native ordered LE-u32 transcript and SHAKE-256 digest.
    HashAlpha {
        parts: Vec<TranscriptPart>,
        output: BytesId,
    },
    /// Exact native transcript, SHAKE, and sparse-challenge decoding.
    HashX {
        parts: Vec<TranscriptPart>,
        output: PolyId,
    },
}

/// Immutable unproved graph. Source and operation inventories cannot be cleared
/// or marked accepted by a caller. A future coordinator must discharge all of
/// them through source-specific proofs, including composite transcript/samplers.
pub struct UnprovedRelationGraph {
    owner: u64,
    setup_seed: [u8; 32],
    polynomials: Vec<PolynomialNode>,
    bytes: Vec<BytesNode>,
    expressions: Vec<Expression>,
    operations: Vec<Operation>,
}
impl UnprovedRelationGraph {
    pub fn polynomials(&self) -> &[PolynomialNode] {
        &self.polynomials
    }
    pub fn bytes(&self) -> &[BytesNode] {
        &self.bytes
    }
    pub fn expressions(&self) -> &[Expression] {
        &self.expressions
    }
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
    pub fn setup_seed(&self) -> [u8; 32] {
        self.setup_seed
    }
    pub fn polynomial(&self, id: PolyId) -> &PolynomialNode {
        assert_eq!(id.owner, self.owner);
        &self.polynomials[id.index]
    }
    pub fn byte_string(&self, id: BytesId) -> &BytesNode {
        assert_eq!(id.owner, self.owner);
        &self.bytes[id.index]
    }
    /// Inventory only: `false` on an empty/fixed-only graph is not acceptance.
    pub fn has_unproved_obligations(&self) -> bool {
        !self.operations.is_empty()
            || self
                .polynomials
                .iter()
                .any(|node| !matches!(node.source, Source::Fixed | Source::Derived { .. }))
            || self
                .bytes
                .iter()
                .any(|node| !matches!(node.source, Source::Fixed | Source::Derived { .. }))
    }
}

pub struct CommittedBackend<'a> {
    graph: UnprovedRelationGraph,
    constants: BTreeMap<(u64, u64), usize>,
    canonical_maps: BTreeMap<(u64, [usize; D]), PolyId>,
    signed_maps: BTreeMap<[usize; D], PolyId>,
    #[cfg(feature = "opencl")]
    device: Option<&'a dyn gpu::GraphDevice>,
    #[cfg(not(feature = "opencl"))]
    _lifetime: std::marker::PhantomData<&'a ()>,
    failure: Option<String>,
}
impl CommittedBackend<'_> {
    pub fn new(setup_seed: [u8; 32]) -> Self {
        Self {
            graph: UnprovedRelationGraph {
                owner: NEXT_GRAPH.fetch_add(1, Ordering::Relaxed),
                setup_seed,
                polynomials: vec![],
                bytes: vec![],
                expressions: vec![],
                operations: vec![],
            },
            constants: BTreeMap::new(),
            canonical_maps: BTreeMap::new(),
            signed_maps: BTreeMap::new(),
            #[cfg(feature = "opencl")]
            device: None,
            #[cfg(not(feature = "opencl"))]
            _lifetime: std::marker::PhantomData,
            failure: None,
        }
    }
    pub fn into_unproved_graph(self) -> UnprovedRelationGraph {
        assert!(
            self.failure.is_none(),
            "failed GPU preparation cannot return a graph"
        );
        self.graph
    }
}

/// Lower the relation without allocating any per-coefficient machine wires.
/// Returning a graph is not native verification or proof acceptance. Invalid
/// equality/norm witnesses still create obligations that must fail when proved.
pub fn lower_unproved(
    setup_seed: [u8; 32],
    context: &[u8; 32],
    statement: &Statement,
    proof: &Proof,
) -> Result<UnprovedRelationGraph, VerifyError> {
    let mut backend = CommittedBackend::new(setup_seed);
    let context = backend.import_bytes(*context, Source::Context);
    let statement = backend.import_statement(statement);
    let proof = backend.import_proof(proof);
    verify_relation(&mut backend, &context, &statement, &proof)?;
    Ok(backend.into_unproved_graph())
}
