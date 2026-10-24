//! Actual typed source proofs bound to one complete, fixed graph inventory.
//!
//! This session proves sources and the six response-norm predicates already
//! proved by ProofAir. It does not accept a MatRiCT spend. All remaining graph
//! nodes/operations stay pending, and completion fails until they are proved.
use super::*;
use crate::{proof_air, statement_air};
use lattica_prover_p3::block_v2::{
    commitment,
    machine::{
        pq_bytes::{poseidon_commit_bytes, Byte},
        pq_modular::bounded_bits,
        program::{ScopedProgramBuilder, Wire},
        verifier::{CompileError, ProofInputs},
    },
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha3::{Digest, Sha3_256};

pub const NODE_MANIFEST_DOMAIN: u64 = 0x4d4154525f534731;
mod operations;
const VERSION: u64 = 1;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<CompileError> for Error {
    fn from(error: CompileError) -> Self {
        Self(error.to_string())
    }
}
type Result<T> = std::result::Result<T, Error>;
fn error(message: &str) -> Error {
    Error(message.into())
}

#[derive(Clone, Debug)]
struct SourcePlan {
    statement: [usize; statement_air::POLYNOMIALS],
    proof: [usize; proof_air::POLYNOMIALS],
    context: usize,
    seed: usize,
    serials: [usize; 2],
    alpha: usize,
    norms: [usize; 6],
    fixed_polynomials: Vec<(usize, [Val; 4])>,
    fixed_bytes: Vec<(usize, [Val; 4])>,
}
fn assign(slot: &mut Option<usize>, index: usize) -> Result<()> {
    if slot.replace(index).is_some() {
        return Err(error("duplicate source position"));
    }
    Ok(())
}
fn finish_slots<const N: usize>(slots: [Option<usize>; N]) -> Result<[usize; N]> {
    slots
        .into_iter()
        .map(|slot| slot.ok_or_else(|| error("missing source position")))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| error("source profile count"))
}
fn proof_kind(position: usize) -> PolynomialKind {
    let class = proof_air::class(position);
    match class {
        0 => PolynomialKind::Canonical { modulus: Q },
        1 => PolynomialKind::Canonical { modulus: QHAT },
        _ => PolynomialKind::Signed {
            bound: proof_air::OFFSETS[class],
        },
    }
}
impl SourcePlan {
    fn from_graph(graph: &UnprovedRelationGraph) -> Result<Self> {
        let mut statement = [None; statement_air::POLYNOMIALS];
        let mut proof = [None; proof_air::POLYNOMIALS];
        for (index, node) in graph.polynomials.iter().enumerate() {
            match node.source {
                Source::StatementPolynomial { position } => {
                    if node.kind != (PolynomialKind::Canonical { modulus: Q }) {
                        return Err(error("statement polynomial kind"));
                    }
                    assign(
                        statement
                            .get_mut(position)
                            .ok_or_else(|| error("statement position"))?,
                        index,
                    )?;
                }
                Source::ProofPolynomial { position } => {
                    let slot = proof
                        .get_mut(position)
                        .ok_or_else(|| error("proof position"))?;
                    if node.kind != proof_kind(position) {
                        return Err(error("proof polynomial kind/bound"));
                    }
                    assign(slot, index)?;
                }
                Source::Fixed | Source::Derived { .. } => {}
                Source::Context
                | Source::StatementSeed
                | Source::StatementSerial { .. }
                | Source::ProofAlpha => {
                    return Err(error("byte source in polynomial namespace"));
                }
            }
        }
        let statement = finish_slots(statement)?;
        let proof = finish_slots(proof)?;
        let (mut context, mut seed, mut alpha) = (None, None, None);
        let mut serials = [None; 2];
        for (index, node) in graph.bytes.iter().enumerate() {
            match node.source {
                Source::Context => assign(&mut context, index)?,
                Source::StatementSeed => assign(&mut seed, index)?,
                Source::ProofAlpha => assign(&mut alpha, index)?,
                Source::StatementSerial { position } => {
                    assign(
                        serials
                            .get_mut(position)
                            .ok_or_else(|| error("serial position"))?,
                        index,
                    )?;
                }
                Source::Fixed | Source::Derived { .. } => {}
                Source::StatementPolynomial { .. } | Source::ProofPolynomial { .. } => {
                    return Err(error("polynomial source in byte namespace"));
                }
            }
        }
        let mut norms = [None; 6];
        for (operation_index, operation) in graph.operations.iter().enumerate() {
            if let Operation::Norm { inputs, maximum } = operation {
                let group = proof_air::NORMS
                    .iter()
                    .position(|&(first, end, limit)| {
                        *maximum == proof_air::NORM_LIMITS[limit]
                            && inputs.len() == end - first
                            && inputs.iter().zip(&proof[first..end]).all(|(&id, &index)| {
                                graph.polynomial(id);
                                id.index() == index
                            })
                    })
                    .ok_or_else(|| error("norm is not one of the six exact source-proof groups"))?;
                assign(&mut norms[group], operation_index)?;
            }
        }
        Ok(Self {
            statement,
            proof,
            context: context.ok_or_else(|| error("missing context"))?,
            seed: seed.ok_or_else(|| error("missing seed"))?,
            serials: finish_slots(serials)?,
            alpha: alpha.ok_or_else(|| error("missing alpha"))?,
            norms: finish_slots(norms)?,
            fixed_polynomials: graph
                .polynomials
                .iter()
                .enumerate()
                .filter(|(_, node)| node.source == Source::Fixed)
                .map(|(index, node)| (index, node.commitment))
                .collect(),
            fixed_bytes: graph
                .bytes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.source == Source::Fixed)
                .map(|(index, node)| (index, node.commitment))
                .collect(),
        })
    }
}

/// Trusted compilation metadata, analogous to a source-registered AIR. Build
/// this from the shared relation compiler's trusted profile, never from an
/// untrusted proof header. Exact canonical shape words are retained and compared
/// before using a witness graph; a diagnostic digest alone cannot authorize it.
pub struct RegisteredGraphShape {
    exact_shape: Vec<u64>,
    label: [u8; 32],
    plan: SourcePlan,
}
impl RegisteredGraphShape {
    pub fn from_trusted_graph(graph: &UnprovedRelationGraph) -> Result<Self> {
        let plan = SourcePlan::from_graph(graph)?;
        let exact_shape = inventory::exact_shape(graph);
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/registered-graph-label/v1");
        for word in &exact_shape {
            hash.update(word.to_le_bytes());
        }
        Ok(Self {
            exact_shape,
            label: hash.finalize().into(),
            plan,
        })
    }
    pub fn matches(&self, graph: &UnprovedRelationGraph) -> bool {
        self.exact_shape == inventory::exact_shape(graph)
    }
    fn header(&self, graph: &UnprovedRelationGraph) -> Vec<u64> {
        let mut header = vec![VERSION];
        header.extend(
            self.label
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
        );
        header.extend([
            graph.polynomials.len() as u64,
            graph.bytes.len() as u64,
            graph.operations.len() as u64,
        ]);
        header
    }
    /// Native witness helper for the ordered node-root manifest. This hashes
    /// hints only and does not discharge any source or operation.
    pub fn node_manifest_hint(&self, graph: &UnprovedRelationGraph) -> Result<[Val; 4]> {
        if !self.matches(graph) {
            return Err(error("graph shape differs from trusted registration"));
        }
        let mut fields = self.header(graph);
        for (index, node) in graph.polynomials.iter().enumerate() {
            fields.extend([1, index as u64]);
            fields.extend(node.commitment.map(|v| v.as_canonical_u64()));
        }
        for (index, node) in graph.bytes.iter().enumerate() {
            fields.extend([2, index as u64]);
            fields.extend(node.commitment.map(|v| v.as_canonical_u64()));
        }
        commitment::hash_fields(NODE_MANIFEST_DOMAIN, &fields)
            .map(|root| root.map(Val::from_u64))
            .map_err(|e| Error(e.to_string()))
    }

    /// Compute the ordered node manifest on the admitted GPU. Exact graph
    /// shape comparison and framing remain ordinary control/serialization.
    #[cfg(feature = "opencl")]
    pub fn node_manifest_hint_on_gpu(
        &self,
        graph: &UnprovedRelationGraph,
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
    ) -> Result<[Val; 4]> {
        if !self.matches(graph) {
            return Err(error("graph shape differs from trusted registration"));
        }
        let count = graph
            .polynomials
            .len()
            .checked_add(graph.bytes.len())
            .and_then(|n| n.checked_mul(6))
            .and_then(|n| n.checked_add(12))
            .ok_or_else(|| error("node manifest framing overflow"))?;
        operations.admit_field_chunks(count).map_err(Error)?;
        let mut fields = self.header(graph);
        fields.reserve_exact(count - fields.len());
        for (index, node) in graph.polynomials.iter().enumerate() {
            fields.extend([1, index as u64]);
            fields.extend(node.commitment.map(|v| v.as_canonical_u64()));
        }
        for (index, node) in graph.bytes.iter().enumerate() {
            fields.extend([2, index as u64]);
            fields.extend(node.commitment.map(|v| v.as_canonical_u64()));
        }
        operations
            .commit_field_chunks([NODE_MANIFEST_DOMAIN, count as u64, 0, 0], &fields)
            .map(|root| root.map(Val::from_u64))
            .map_err(Error)
    }
}

fn bytes_from_words(b: &mut ScopedProgramBuilder<'_>, words: &[Wire; 8]) -> Result<[Byte; 32]> {
    let mut bytes = Vec::with_capacity(32);
    for &word in words {
        let bits = bounded_bits(b, word, 32).map_err(|e| Error(format!("{e:?}")))?;
        bytes.extend(
            bits.chunks_exact(8)
                .map(|bits| Byte::from_bits(b, bits.try_into().unwrap())),
        );
    }
    bytes.try_into().map_err(|_| error("byte bridge width"))
}
fn bind_words(b: &mut ScopedProgramBuilder<'_>, words: &[Wire; 8], root: [Wire; 4]) -> Result<()> {
    let bytes = bytes_from_words(b, words)?;
    let actual = poseidon_commit_bytes(b, BYTES32_DOMAIN, &bytes);
    for i in 0..4 {
        b.assert_equal(actual[i], root[i]);
    }
    Ok(())
}
fn native_words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}

/// Diagnostic counts, never an acceptance token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remaining {
    pub polynomial_nodes: usize,
    pub byte_nodes: usize,
    pub operations: usize,
}

/// One mutable circuit scope owns root witnesses and verification state. There
/// is no public constructor for a verified-source token, and no caller-supplied
/// host Boolean can clear a pending node or operation.
pub struct SourceBinding<'graph, 'builder, 'scope> {
    graph: &'graph UnprovedRelationGraph,
    plan: &'graph SourcePlan,
    builder: &'builder mut ScopedProgramBuilder<'scope>,
    inputs: &'builder mut ProofInputs,
    polynomial_roots: Vec<[Wire; 4]>,
    byte_roots: Vec<[Wire; 4]>,
    polynomial_bound: Vec<bool>,
    byte_bound: Vec<bool>,
    operation_bound: Vec<bool>,
    expected_statement: [Wire; 4],
    statement_verified: bool,
    proof_verified: bool,
    fixed_verified: bool,
}
impl<'graph, 'builder, 'scope> SourceBinding<'graph, 'builder, 'scope> {
    pub fn new(
        shape: &'graph RegisteredGraphShape,
        graph: &'graph UnprovedRelationGraph,
        builder: &'builder mut ScopedProgramBuilder<'scope>,
        inputs: &'builder mut ProofInputs,
        expected_context_words: [Wire; 8],
        expected_statement: [Wire; 4],
        expected_node_manifest: [Wire; 4],
    ) -> Result<Self> {
        if !shape.matches(graph) {
            return Err(error("graph shape differs from trusted registration"));
        }
        let mut polynomial_roots = Vec::with_capacity(graph.polynomials.len());
        for node in &graph.polynomials {
            polynomial_roots.push(inputs.bases(builder, &node.commitment)?.try_into().unwrap());
        }
        let mut byte_roots = Vec::with_capacity(graph.bytes.len());
        for node in &graph.bytes {
            byte_roots.push(inputs.bases(builder, &node.commitment)?.try_into().unwrap());
        }
        let mut fields: Vec<_> = shape
            .header(graph)
            .into_iter()
            .map(|v| builder.constant(Val::from_u64(v)))
            .collect();
        for (kind, roots) in [(1u64, &polynomial_roots), (2u64, &byte_roots)] {
            for (index, root) in roots.iter().enumerate() {
                fields.extend([
                    builder.constant(Val::from_u64(kind)),
                    builder.constant(Val::from_usize(index)),
                ]);
                fields.extend(root);
            }
        }
        let manifest = builder.hash_fields(NODE_MANIFEST_DOMAIN, &fields);
        for i in 0..4 {
            builder.assert_equal(manifest[i], expected_node_manifest[i]);
        }
        bind_words(
            builder,
            &expected_context_words,
            byte_roots[shape.plan.context],
        )?;
        let seed = graph.setup_seed.map(|byte| Byte::constant(builder, byte));
        let seed_root = poseidon_commit_bytes(builder, BYTES32_DOMAIN, &seed);
        for i in 0..4 {
            builder.assert_equal(seed_root[i], byte_roots[shape.plan.seed][i]);
        }
        let mut byte_bound = vec![false; graph.bytes.len()];
        byte_bound[shape.plan.context] = true;
        byte_bound[shape.plan.seed] = true;
        Ok(Self {
            graph,
            plan: &shape.plan,
            builder,
            inputs,
            polynomial_roots,
            byte_roots,
            polynomial_bound: vec![false; graph.polynomials.len()],
            byte_bound,
            operation_bound: vec![false; graph.operations.len()],
            expected_statement,
            statement_verified: false,
            proof_verified: false,
            fixed_verified: false,
        })
    }
    /// Pin fixed roots retained by trusted registration (network setup and
    /// literal constants), never roots supplied by the witness graph alone.
    /// These equalities do not cover any derived operation or private source.
    pub fn constrain_fixed_sources(&mut self) -> Result<()> {
        if self.fixed_verified {
            return Err(error("fixed sources already constrained"));
        }
        for &(index, values) in &self.plan.fixed_polynomials {
            for (wire, value) in self.polynomial_roots[index].into_iter().zip(values) {
                let expected = self.builder.constant(value);
                self.builder.assert_equal(wire, expected);
            }
            self.polynomial_bound[index] = true;
        }
        for &(index, values) in &self.plan.fixed_bytes {
            for (wire, value) in self.byte_roots[index].into_iter().zip(values) {
                let expected = self.builder.constant(value);
                self.builder.assert_equal(wire, expected);
            }
            self.byte_bound[index] = true;
        }
        self.fixed_verified = true;
        Ok(())
    }
    pub fn verify_statement(
        &mut self,
        artifact: &statement_air::bundle::StatementProof,
    ) -> Result<()> {
        if self.statement_verified {
            return Err(error("statement source already verified"));
        }
        let roots = self
            .plan
            .statement
            .map(|index| self.polynomial_roots[index]);
        let mut serial_words = Vec::with_capacity(16);
        for &index in &self.plan.serials {
            serial_words.extend(
                self.inputs
                    .bases(self.builder, &native_words(&self.graph.bytes[index].values))?,
            );
        }
        let serial_words: [Wire; 16] = serial_words.try_into().unwrap();
        statement_air::bundle::verify_bundle(
            self.builder,
            self.inputs,
            self.graph.setup_seed,
            self.expected_statement,
            &roots,
            &serial_words,
            artifact,
        )?;
        for (&index, words) in self.plan.serials.iter().zip(serial_words.chunks_exact(8)) {
            bind_words(
                self.builder,
                words.try_into().unwrap(),
                self.byte_roots[index],
            )?;
        }
        for index in self.plan.statement {
            self.polynomial_bound[index] = true;
        }
        for index in self.plan.serials {
            self.byte_bound[index] = true;
        }
        self.statement_verified = true;
        Ok(())
    }
    pub fn verify_private_proof(
        &mut self,
        artifact: &proof_air::join::ProofArtifact,
    ) -> Result<()> {
        if self.proof_verified {
            return Err(error("private proof source already verified"));
        }
        let roots = self.plan.proof.map(|index| self.polynomial_roots[index]);
        let alpha: [Wire; 8] = self
            .inputs
            .bases(
                self.builder,
                &native_words(&self.graph.bytes[self.plan.alpha].values),
            )?
            .try_into()
            .unwrap();
        proof_air::join::verify_bundle(self.builder, self.inputs, &roots, &alpha, artifact)?;
        bind_words(self.builder, &alpha, self.byte_roots[self.plan.alpha])?;
        for index in self.plan.proof {
            self.polynomial_bound[index] = true;
        }
        self.byte_bound[self.plan.alpha] = true;
        // These indices were matched to the exact ordered source roots and the
        // same limits/intervals used inside ProofAir, before emitting a verifier.
        for index in self.plan.norms {
            self.operation_bound[index] = true;
        }
        self.proof_verified = true;
        Ok(())
    }
    pub fn remaining(&self) -> Remaining {
        Remaining {
            polynomial_nodes: self.polynomial_bound.iter().filter(|&&v| !v).count(),
            byte_nodes: self.byte_bound.iter().filter(|&&v| !v).count(),
            operations: self.operation_bound.iter().filter(|&&v| !v).count(),
        }
    }
    /// A graph-tree leaf uses its fixed registered coverage plan here after
    /// emitting real verifiers in this session. This consumes the session and
    /// returns no transferable coverage token. Constructor-bound context/seed
    /// nodes must be included, and even one unexpected covered node rejects.
    pub(crate) fn require_exact_coverage(
        self,
        polynomial_indices: &[usize],
        byte_indices: &[usize],
        operation_indices: &[usize],
    ) -> Result<()> {
        for (expected, actual) in [
            (polynomial_indices, self.polynomial_bound.as_slice()),
            (byte_indices, self.byte_bound.as_slice()),
            (operation_indices, self.operation_bound.as_slice()),
        ] {
            if expected.windows(2).any(|pair| pair[0] >= pair[1])
                || expected.iter().any(|&index| index >= actual.len())
                || !expected.iter().copied().eq(actual
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &bound)| bound.then_some(index)))
            {
                return Err(error("leaf coverage differs from exact registered subset"));
            }
        }
        Ok(())
    }
    /// No current source-only fixture can pass this gate: its other algebraic,
    /// transcript and sampler predicates still require actual typed verifiers.
    pub fn require_complete(self) -> Result<()> {
        let pending = self.remaining();
        if pending
            != (Remaining {
                polynomial_nodes: 0,
                byte_nodes: 0,
                operations: 0,
            })
        {
            return Err(Error(format!(
                "unproved graph obligations remain: {pending:?}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
