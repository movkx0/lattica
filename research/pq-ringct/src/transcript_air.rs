//! Exact serialization of an ordered graph transcript into a SHAKE input root.
//!
//! Each part is a universal Bytes32 root or canonical Q/QHAT polynomial root.
//! The AIR serializes every coefficient as four little-endian bytes, proves the
//! source roots, and commits the complete byte stream. A second ordered bundle
//! includes every part's type, length, position, and root. SHAKE itself remains
//! a separate constrained component whose input root must be joined here.
use crate::{
    rust_verify::{
        committed_backend::{
            Operation, PolynomialKind, PolynomialValues, TranscriptPart, UnprovedRelationGraph,
            BYTES32_DOMAIN,
        },
        constraints_ntt::{commit_values, POLYNOMIAL_DOMAIN},
        D, Q, QHAT,
    },
    shake_air::{
        commit_bytes, round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH,
    },
    statement_air::bundle::absorb,
};
use lattica_prover_p3::block_v2::machine::pq_bytes::SHAKE_INPUT_DOMAIN;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;
mod constraints;
pub mod join;
#[cfg(test)]
mod tests;
mod witness;
pub use witness::TranscriptWitness;

pub const PUBLIC_VALUES: usize = 8;
pub const ROWS_PER_PART: usize = 128;
pub const BUNDLE_DOMAIN: u64 = 0x5452_414e_5350_5131;
const WORD: usize = 0;
const BITS: usize = WORD + 2;
const PREFIX: usize = BITS + 64;
const BUFFER: usize = PREFIX + 16;
const COUNTER: usize = BUFFER + 2;
const EVENTS: usize = COUNTER + 1;
const P_START: usize = 0;
const P_END: usize = 1;
const P_EVEN: usize = 2;
const P_BYTES: usize = 3;
const PERIODIC: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartKind {
    Bytes32,
    PolynomialQ,
    PolynomialQhat,
}
impl PartKind {
    fn index(self) -> usize {
        match self {
            Self::Bytes32 => 0,
            Self::PolynomialQ => 1,
            Self::PolynomialQhat => 2,
        }
    }
    pub fn byte_len(self) -> usize {
        if self == Self::Bytes32 {
            32
        } else {
            4 * D
        }
    }
    fn modulus(self) -> u64 {
        match self {
            Self::Bytes32 => 1 << 32,
            Self::PolynomialQ => Q,
            Self::PolynomialQhat => QHAT,
        }
    }
    fn initial(self) -> [Val; 4] {
        match self {
            Self::Bytes32 => [
                Val::from_u64(BYTES32_DOMAIN),
                Val::from_u32(32),
                Val::ZERO,
                Val::ZERO,
            ],
            _ => [
                Val::from_u64(POLYNOMIAL_DOMAIN),
                Val::from_u64(self.modulus()),
                Val::from_usize(D),
                Val::ZERO,
            ],
        }
    }
}
#[derive(Clone, Debug)]
pub enum PartValues {
    Bytes32([u8; 32]),
    Polynomial([u64; D]),
}
impl PartValues {
    pub fn root(&self, kind: PartKind) -> Result<[Val; 4], &'static str> {
        match (kind, self) {
            (PartKind::Bytes32, Self::Bytes32(bytes)) => Ok(commit_bytes(BYTES32_DOMAIN, bytes)),
            (PartKind::PolynomialQ | PartKind::PolynomialQhat, Self::Polynomial(values))
                if values.iter().all(|&v| v < kind.modulus()) =>
            {
                Ok(commit_values(POLYNOMIAL_DOMAIN, kind.modulus(), values))
            }
            _ => Err("transcript source kind/canonicality"),
        }
    }
    fn words(&self, kind: PartKind) -> Result<Vec<u32>, &'static str> {
        match (kind, self) {
            (PartKind::Bytes32, Self::Bytes32(bytes)) => Ok(bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect()),
            (PartKind::PolynomialQ | PartKind::PolynomialQhat, Self::Polynomial(values)) => values
                .iter()
                .map(|&v| u32::try_from(v).map_err(|_| "transcript u32 encoding"))
                .collect(),
            _ => Err("transcript source kind"),
        }
    }
}
#[derive(Clone, Debug)]
struct Event {
    at: usize,
    from: usize,
    to: usize,
}
#[derive(Clone, Debug)]
pub struct TranscriptAir {
    parts: Vec<PartKind>,
    bytes: usize,
    height: usize,
    events: Vec<Event>,
}
impl TranscriptAir {
    pub fn new(parts: Vec<PartKind>) -> Result<Self, &'static str> {
        if parts.is_empty() || parts.len() > 256 {
            return Err("transcript part count");
        }
        let height = parts.len().next_power_of_two() * ROWS_PER_PART;
        let mut events = Vec::new();
        for index in 0..parts.len() {
            let from = parts[index].index();
            let to = parts.get(index + 1).map(|k| k.index()).unwrap_or(3);
            if from != to {
                events.push(Event {
                    at: index,
                    from,
                    to,
                });
            }
        }
        let bytes = parts.iter().map(|k| k.byte_len()).sum();
        Ok(Self {
            parts,
            bytes,
            height,
            events,
        })
    }
    pub fn parts(&self) -> &[PartKind] {
        &self.parts
    }
    pub fn byte_len(&self) -> usize {
        self.bytes
    }
    pub fn height(&self) -> usize {
        self.height
    }
    fn inverse(&self) -> usize {
        EVENTS + self.events.len()
    }
    fn class(&self) -> usize {
        self.inverse() + self.events.len()
    }
    fn source_acc(&self) -> usize {
        self.class() + 4
    }
    fn byte_acc(&self) -> usize {
        self.source_acc() + 4
    }
    fn bundle_acc(&self) -> usize {
        self.byte_acc() + 4
    }
    fn source_poseidon(&self) -> usize {
        self.bundle_acc() + 4
    }
    fn byte_poseidon(&self) -> usize {
        self.source_poseidon() + POSEIDON_WIDTH
    }
    fn bundle_poseidon(&self) -> usize {
        self.byte_poseidon() + POSEIDON_WIDTH
    }
    pub fn width(&self) -> usize {
        self.bundle_poseidon() + POSEIDON_WIDTH
    }
    fn bundle_initial(&self) -> [Val; 4] {
        [
            Val::from_u64(BUNDLE_DOMAIN),
            Val::from_usize(self.parts.len()),
            Val::from_usize(self.bytes),
            Val::ONE,
        ]
    }
    fn byte_initial(&self) -> [Val; 4] {
        [
            Val::from_u64(SHAKE_INPUT_DOMAIN),
            Val::from_usize(self.bytes),
            Val::ZERO,
            Val::ZERO,
        ]
    }
    fn metadata(kind: PartKind, index: usize) -> [Val; 4] {
        [
            Val::from_usize(kind.index() + 1),
            Val::from_usize(kind.byte_len()),
            Val::from_usize(index),
            Val::ZERO,
        ]
    }
    pub fn bundle(&self, roots: &[[Val; 4]]) -> Result<[Val; 4], &'static str> {
        if roots.len() != self.parts.len() {
            return Err("transcript ordered root count");
        }
        let mut state = self.bundle_initial();
        for (index, (&kind, &root)) in self.parts.iter().zip(roots).enumerate() {
            let _ = absorb(&mut state, Self::metadata(kind, index));
            let _ = absorb(&mut state, root);
        }
        Ok(state)
    }
    pub fn serialize(&self, values: &[PartValues]) -> Result<Vec<u8>, &'static str> {
        if values.len() != self.parts.len() {
            return Err("transcript source count");
        }
        let mut bytes = Vec::with_capacity(self.bytes);
        for (&kind, part) in self.parts.iter().zip(values) {
            for word in part.words(kind)? {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        Ok(bytes)
    }
    pub fn from_graph_operation(
        graph: &UnprovedRelationGraph,
        operation: &Operation,
    ) -> Result<(Self, Vec<PartValues>, Vec<[Val; 4]>), &'static str> {
        let parts = match operation {
            Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => parts,
            _ => return Err("not a transcript operation"),
        };
        let mut kinds = Vec::with_capacity(parts.len());
        let mut values = Vec::with_capacity(parts.len());
        let mut roots = Vec::with_capacity(parts.len());
        for part in parts {
            match part {
                TranscriptPart::Bytes(id) => {
                    let node = graph.byte_string(*id);
                    kinds.push(PartKind::Bytes32);
                    values.push(PartValues::Bytes32(node.values));
                    roots.push(node.commitment);
                }
                TranscriptPart::Polynomial(id) => {
                    let node = graph.polynomial(*id);
                    let kind = match node.kind {
                        PolynomialKind::Canonical { modulus: Q } => PartKind::PolynomialQ,
                        PolynomialKind::Canonical { modulus: QHAT } => PartKind::PolynomialQhat,
                        _ => return Err("noncanonical transcript polynomial"),
                    };
                    let PolynomialValues::Canonical(value) = &node.values else {
                        return Err("transcript value kind");
                    };
                    kinds.push(kind);
                    values.push(PartValues::Polynomial(*value));
                    roots.push(node.commitment);
                }
            }
        }
        Ok((Self::new(kinds)?, values, roots))
    }
    fn schedule(&self) -> Vec<Vec<Val>> {
        let mut p = vec![Val::zero_vec(ROWS_PER_PART); PERIODIC];
        p[P_START][0] = Val::ONE;
        p[P_END][127] = Val::ONE;
        p[P_EVEN] = vec![Val::ONE, Val::ZERO];
        for i in 0..4 {
            p[P_BYTES][i] = Val::ONE;
        }
        p
    }
}
impl BaseAir<Val> for TranscriptAir {
    fn width(&self) -> usize {
        TranscriptAir::width(self)
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.schedule()
    }
}

#[cfg(feature = "opencl")]
mod gpu;
