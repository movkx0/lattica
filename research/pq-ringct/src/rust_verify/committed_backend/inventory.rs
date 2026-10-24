//! Canonical, **unproved** inventory of the complete committed relation graph.
//!
//! The fingerprints in this module are native diagnostics, not circuit public
//! values, accepted proofs, or substitutes for source/component verification.
//! Every source, scalar expression and operation is included. Process-local
//! owner IDs are checked when resolving references but never serialized.
use super::*;
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

const VERSION: u64 = 1;
const DOMAIN: &[u8] = b"lattica/matrict/unproved-relation-inventory";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum OperationKind {
    CanonicalMap,
    SignedMap,
    Add,
    Sub,
    AutomorphismQ,
    SignedToCanonical,
    Ntt,
    Mul,
    Norm,
    GBound,
    EqualBytes,
    EqualSigned,
    ByteMap,
    ParametersPp,
    SampleG,
    ExpandAlpha,
    HashAlpha,
    HashX,
}
impl OperationKind {
    pub const ALL: [Self; 18] = [
        Self::CanonicalMap,
        Self::SignedMap,
        Self::Add,
        Self::Sub,
        Self::AutomorphismQ,
        Self::SignedToCanonical,
        Self::Ntt,
        Self::Mul,
        Self::Norm,
        Self::GBound,
        Self::EqualBytes,
        Self::EqualSigned,
        Self::ByteMap,
        Self::ParametersPp,
        Self::SampleG,
        Self::ExpandAlpha,
        Self::HashAlpha,
        Self::HashX,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counts {
    pub polynomials: usize,
    pub bytes: usize,
    pub expressions: usize,
    pub operations: usize,
    pub operation_kinds: [usize; 18],
}

/// Native fingerprints of graph shape and all hinted roots. There is
/// intentionally no conversion to a verified graph or transaction leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnprovedInventory {
    counts: Counts,
    shape_sha3_256: [u8; 32],
    witness_sha3_256: [u8; 32],
}
impl UnprovedInventory {
    pub fn counts(&self) -> &Counts {
        &self.counts
    }
    /// Fixed topology, constants, setup seed and fixed-source commitments.
    pub fn shape_sha3_256(&self) -> [u8; 32] {
        self.shape_sha3_256
    }
    /// Complete topology plus every node and ordered operation operand root.
    pub fn witness_sha3_256(&self) -> [u8; 32] {
        self.witness_sha3_256
    }
}

struct Encoder {
    shape: Sha3_256,
    witness: Sha3_256,
    exact_shape: Option<Vec<u64>>,
}
impl Encoder {
    fn new() -> Self {
        let mut shape = Sha3_256::new();
        let mut witness = Sha3_256::new();
        for (hash, role) in [(&mut shape, 0u64), (&mut witness, 1u64)] {
            hash.update((DOMAIN.len() as u64).to_le_bytes());
            hash.update(DOMAIN);
            hash.update(VERSION.to_le_bytes());
            hash.update(role.to_le_bytes());
        }
        Self {
            shape,
            witness,
            exact_shape: None,
        }
    }
    fn word(&mut self, word: u64) {
        if let Some(words) = &mut self.exact_shape {
            words.push(word);
            return;
        }
        self.shape.update(word.to_le_bytes());
        self.witness.update(word.to_le_bytes());
    }
    /// All integers use full LE-u64 encodings, avoiding field-reduction
    /// aliases. Count framing distinguishes records and variable-length lists.
    fn record(
        &mut self,
        kind: u64,
        index: usize,
        words: &[u64],
        fixed: &[[Val; 4]],
        roots: &[[Val; 4]],
    ) {
        self.word(kind);
        self.word(index as u64);
        self.word(words.len() as u64);
        for &word in words {
            self.word(word);
        }
        self.word(fixed.len() as u64);
        for root in fixed {
            for field in root {
                self.word(field.as_canonical_u64());
            }
        }
        self.word(roots.len() as u64);
        if self.exact_shape.is_some() {
            return;
        }
        for root in roots {
            for field in root {
                self.witness.update(field.as_canonical_u64().to_le_bytes());
            }
        }
    }
}

fn source(source: &Source, words: &mut Vec<u64>) {
    match *source {
        Source::StatementPolynomial { position } => words.extend([1, position as u64]),
        Source::ProofPolynomial { position } => words.extend([2, position as u64]),
        Source::Context => words.push(3),
        Source::StatementSeed => words.push(4),
        Source::StatementSerial { position } => words.extend([5, position as u64]),
        Source::ProofAlpha => words.push(6),
        Source::Fixed => words.push(7),
        Source::Derived { operation } => words.extend([8, operation as u64]),
    }
}

fn expression(expression: &Expression) -> Vec<u64> {
    match *expression {
        Expression::CanonicalInput { polynomial, index } => {
            vec![1, polynomial.index() as u64, index as u64]
        }
        Expression::SignedInput { polynomial, index } => {
            vec![2, polynomial.index() as u64, index as u64]
        }
        Expression::CanonicalConstant { modulus, value } => vec![3, modulus, value],
        Expression::Add {
            left,
            right,
            modulus,
        } => vec![4, left as u64, right as u64, modulus],
        Expression::Sub {
            left,
            right,
            modulus,
        } => vec![5, left as u64, right as u64, modulus],
        Expression::Scale {
            input,
            factor,
            modulus,
        } => vec![6, input as u64, factor, modulus],
        Expression::SignedNeg { input, bound } => vec![7, input as u64, bound as u64],
        Expression::SignedSub { left, right, bound } => {
            vec![8, left as u64, right as u64, bound as u64]
        }
        Expression::ConvertCoefficient {
            input,
            bound,
            modulus,
        } => vec![9, input as u64, bound as u64, modulus],
    }
}

struct Record<'a> {
    graph: &'a UnprovedRelationGraph,
    words: Vec<u64>,
    roots: Vec<[Val; 4]>,
}
impl<'a> Record<'a> {
    fn new(graph: &'a UnprovedRelationGraph) -> Self {
        Self {
            graph,
            words: vec![],
            roots: vec![],
        }
    }
    fn polynomial(&mut self, id: PolyId) {
        self.words.push(id.index() as u64);
        self.roots.push(self.graph.polynomial(id).commitment);
    }
    fn polynomials(&mut self, ids: &[PolyId]) {
        self.words.push(ids.len() as u64);
        for &id in ids {
            self.polynomial(id);
        }
    }
    fn bytes(&mut self, id: BytesId) {
        self.words.push(id.index() as u64);
        self.roots.push(self.graph.byte_string(id).commitment);
    }
    fn transcript(&mut self, parts: &[TranscriptPart]) {
        self.words.push(parts.len() as u64);
        for part in parts {
            match *part {
                TranscriptPart::Bytes(id) => {
                    self.words.push(1);
                    self.bytes(id);
                }
                TranscriptPart::Polynomial(id) => {
                    self.words.push(2);
                    self.polynomial(id);
                }
            }
        }
    }
    fn operation(&mut self, operation: &Operation) -> OperationKind {
        match operation {
            Operation::CanonicalMap {
                modulus,
                inputs,
                expressions,
                output,
            } => {
                self.words.push(*modulus);
                self.polynomials(inputs);
                self.words.push(expressions.len() as u64);
                self.words
                    .extend(expressions.iter().map(|&index| index as u64));
                self.polynomial(*output);
                OperationKind::CanonicalMap
            }
            Operation::SignedMap {
                bound,
                inputs,
                expressions,
                output,
            } => {
                self.words.push(*bound as u64);
                self.polynomials(inputs);
                self.words.push(expressions.len() as u64);
                self.words
                    .extend(expressions.iter().map(|&index| index as u64));
                self.polynomial(*output);
                OperationKind::SignedMap
            }
            Operation::Add {
                modulus,
                left,
                right,
                output,
            } => {
                self.words.push(*modulus);
                for id in [left, right, output] {
                    self.polynomial(*id);
                }
                OperationKind::Add
            }
            Operation::Sub {
                modulus,
                left,
                right,
                output,
            } => {
                self.words.push(*modulus);
                for id in [left, right, output] {
                    self.polynomial(*id);
                }
                OperationKind::Sub
            }
            Operation::AutomorphismQ { input, output } => {
                self.polynomial(*input);
                self.polynomial(*output);
                OperationKind::AutomorphismQ
            }
            Operation::SignedToCanonical {
                bound,
                modulus,
                input,
                output,
            } => {
                self.words.extend([*bound as u64, *modulus]);
                self.polynomial(*input);
                self.polynomial(*output);
                OperationKind::SignedToCanonical
            }
            Operation::Ntt {
                modulus,
                input,
                output,
            } => {
                self.words.push(*modulus);
                self.polynomial(*input);
                self.polynomial(*output);
                OperationKind::Ntt
            }
            Operation::Mul {
                modulus,
                left,
                right,
                output,
            } => {
                self.words.push(*modulus);
                for id in [left, right, output] {
                    self.polynomial(*id);
                }
                OperationKind::Mul
            }
            Operation::Norm { inputs, maximum } => {
                self.words.push(*maximum);
                self.polynomials(inputs);
                OperationKind::Norm
            }
            Operation::GBound { f, x, bound } => {
                self.words.push(*bound as u64);
                self.polynomial(*f);
                self.polynomial(*x);
                OperationKind::GBound
            }
            Operation::EqualBytes { left, right } => {
                self.bytes(*left);
                self.bytes(*right);
                OperationKind::EqualBytes
            }
            Operation::EqualSigned { left, right } => {
                self.polynomial(*left);
                self.polynomial(*right);
                OperationKind::EqualSigned
            }
            Operation::ByteMap { inputs, output } => {
                self.words.push(inputs.len() as u64);
                for &(id, index) in inputs {
                    self.bytes(id);
                    self.words.push(index as u64);
                }
                self.bytes(*output);
                OperationKind::ByteMap
            }
            Operation::ParametersPp {
                setup_seed,
                context,
                output,
            } => {
                self.words.push(setup_seed.len() as u64);
                self.words
                    .extend(setup_seed.iter().map(|&byte| byte as u64));
                self.bytes(*context);
                self.bytes(*output);
                OperationKind::ParametersPp
            }
            Operation::SampleG { seed, output } => {
                self.bytes(*seed);
                self.polynomials(output);
                OperationKind::SampleG
            }
            Operation::ExpandAlpha {
                seed,
                canonical,
                signed,
            } => {
                self.bytes(*seed);
                self.polynomials(canonical);
                self.polynomial(*signed);
                OperationKind::ExpandAlpha
            }
            Operation::HashAlpha { parts, output } => {
                self.transcript(parts);
                self.bytes(*output);
                OperationKind::HashAlpha
            }
            Operation::HashX { parts, output } => {
                self.transcript(parts);
                self.polynomial(*output);
                OperationKind::HashX
            }
        }
    }
}

/// Stream an exhaustive canonical inventory. No native verification result is
/// accepted as an input, and no obligation is discharged by this function.
pub fn inventory(graph: &UnprovedRelationGraph) -> UnprovedInventory {
    let mut encoder = Encoder::new();
    let counts = encode_graph(graph, &mut encoder);
    UnprovedInventory {
        counts,
        shape_sha3_256: encoder.shape.finalize().into(),
        witness_sha3_256: encoder.witness.finalize().into(),
    }
}

/// Exact native shape comparison for a source-registered plan. The diagnostic
/// SHA3 fingerprints are deliberately not used as proof of shape equality.
pub(super) fn exact_shape(graph: &UnprovedRelationGraph) -> Vec<u64> {
    let mut encoder = Encoder::new();
    encoder.exact_shape = Some(vec![VERSION]);
    encode_graph(graph, &mut encoder);
    encoder.exact_shape.expect("shape collector")
}

fn encode_graph(graph: &UnprovedRelationGraph, encoder: &mut Encoder) -> Counts {
    // Intentionally exhaustive: adding a graph/node field must force this
    // inventory to be reviewed, even if it has no effect on today's fixture.
    let UnprovedRelationGraph {
        owner: _owner,
        setup_seed,
        polynomials,
        bytes,
        expressions,
        operations,
    } = graph;
    let mut counts = Counts {
        polynomials: polynomials.len(),
        bytes: bytes.len(),
        expressions: expressions.len(),
        operations: operations.len(),
        operation_kinds: [0; 18],
    };
    let mut header = vec![
        D as u64,
        POLYNOMIAL_DOMAIN,
        SIGNED_POLYNOMIAL_DOMAIN,
        BYTES32_DOMAIN,
        polynomials.len() as u64,
        bytes.len() as u64,
        expressions.len() as u64,
        operations.len() as u64,
        setup_seed.len() as u64,
    ];
    header.extend(setup_seed.iter().map(|&byte| byte as u64));
    encoder.record(1, 0, &header, &[], &[]);
    for (index, node) in polynomials.iter().enumerate() {
        let PolynomialNode {
            kind,
            source: origin,
            commitment,
            values: _values,
            expressions: coefficient_ids,
        } = node;
        let mut words = match *kind {
            PolynomialKind::Canonical { modulus } => vec![1, modulus],
            PolynomialKind::Signed { bound } => vec![2, bound as u64],
        };
        source(origin, &mut words);
        words.push(coefficient_ids.len() as u64);
        words.extend(coefficient_ids.iter().map(|&id| id as u64));
        let fixed = if matches!(origin, Source::Fixed) {
            std::slice::from_ref(commitment)
        } else {
            &[]
        };
        encoder.record(2, index, &words, fixed, std::slice::from_ref(commitment));
    }
    for (index, node) in bytes.iter().enumerate() {
        let BytesNode {
            source: origin,
            commitment,
            values: _values,
        } = node;
        let mut words = vec![];
        source(origin, &mut words);
        let fixed = if matches!(origin, Source::Fixed) {
            std::slice::from_ref(commitment)
        } else {
            &[]
        };
        encoder.record(3, index, &words, fixed, std::slice::from_ref(commitment));
    }
    for (index, item) in expressions.iter().enumerate() {
        // Validate namespace ownership without putting a process-local ID in
        // the protocol-shaped metadata. Other expression variants carry only
        // expression indices, and are exhaustively encoded above.
        if let Expression::CanonicalInput { polynomial, .. }
        | Expression::SignedInput { polynomial, .. } = item
        {
            graph.polynomial(*polynomial);
        }
        encoder.record(4, index, &expression(item), &[], &[]);
    }
    for (index, item) in operations.iter().enumerate() {
        let mut record = Record::new(graph);
        let kind = record.operation(item);
        counts.operation_kinds[kind as usize] += 1;
        record.words.insert(0, kind as u64 + 1);
        encoder.record(5, index, &record.words, &[], &record.roots);
    }
    counts
}

#[cfg(test)]
mod tests;
