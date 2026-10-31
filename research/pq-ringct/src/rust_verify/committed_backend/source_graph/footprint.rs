//! Allocation-free initial fixed-native source census. This exposes only the
//! maintained symbolic, memo, graph-vector and raw-adapter formulas. It cannot
//! construct a graph, issue a reservation or authorize GPU work.
use super::{
    bounds::{add, backing, mul, Ceilings},
    inputs::{self, FixedInputs},
    raw_adapters::RawAdapterPlan,
    symbolic::SymbolicScratch,
};
use crate::{
    native_packet::{PROOF_BYTES, STATEMENT_BYTES},
    rust_verify::{Proof, Statement},
};
use core::mem::size_of;
use super::super::{
    BytesNode, Expression, Operation, PolyId, PolynomialNode, TranscriptPart,
    UnprovedRelationGraph,
};

type Result<T> = core::result::Result<T, &'static str>;

/// Source-derived requested storage, not an allocator/RSS or complete runtime
/// bound. The enclosing plan must separately charge source-factory outputs,
/// reports/errors, compiler frames and backend/session storage. All fields are
/// private so no caller can make a smaller census from numeric assertions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InitialSourceFootprint {
    ceiling: Ceilings,
    decoded: usize,
    decode_temporary: usize,
    graph_retained: usize,
    graph_growth: usize,
    symbolic: SymbolicScratch,
    raw: RawAdapterPlan,
}

/// Success provenance owns the exact graph inspected by the capacity census.
/// The graph has no mutable, extracting or cloning accessor. Moving this owner
/// cannot detach the census from its graph or permit its vectors to grow.
/// This grants no reservation or cleanup authority.
pub(crate) struct CheckedInitialGraph {
    graph: UnprovedRelationGraph,
    initial_host_bytes: usize,
    retained_host_bytes: usize,
}

impl CheckedInitialGraph {
    pub(crate) fn graph(&self) -> &UnprovedRelationGraph { &self.graph }
    pub(crate) fn initial_host_bytes(&self) -> usize { self.initial_host_bytes }
    pub(crate) fn retained_host_bytes(&self) -> usize { self.retained_host_bytes }

    #[cfg(test)]
    pub(crate) fn retention_fixture() -> Self {
        InitialSourceFootprint::fixed().unwrap().check_graph(tests::graph()).unwrap()
    }
}

impl InitialSourceFootprint {
    pub(crate) fn fixed() -> Result<Self> {
        let ceiling = Ceilings::fixed();
        let graph_retained = add(
            ceiling.main_vector_bytes(2)?,
            ceiling.nested_vector_bytes(2)?,
        )?;
        let graph_peak = add(
            ceiling.main_vector_bytes(3)?,
            ceiling.nested_vector_bytes(3)?,
        )?;
        Ok(Self {
            ceiling,
            decoded: inputs::decoded_retained_bytes()?,
            decode_temporary: inputs::decode_temporary_bytes()?,
            graph_retained,
            graph_growth: graph_peak
                .checked_sub(graph_retained)
                .ok_or("initial graph source growth underflow")?,
            symbolic: SymbolicScratch::fixed()?,
            raw: RawAdapterPlan::fixed()?,
        })
    }

    /// Real spare capacity of the two existing owners, including Vec headers.
    /// A borrowed slice's length is deliberately not accepted as its owner's
    /// retained capacity. This remains an enclosing census, not retroactive
    /// ownership of packets which existed before workflow admission.
    pub(crate) fn encoded_owner_bytes(
        statement: &Vec<u8>,
        proof: &Vec<u8>,
    ) -> Result<usize> {
        if statement.len() != STATEMENT_BYTES || proof.len() != PROOF_BYTES {
            return Err("initial source requires exact fixed native packet lengths");
        }
        add(
            backing::<Vec<u8>>(2)?,
            add(statement.capacity(), proof.capacity())?,
        )
    }

    /// Actual decoded immutable input backing; exact n10 dimensions are checked
    /// before any source-plan derivation. Returned bytes include inline owners.
    pub(crate) fn decoded_owner_bytes(statement: &Statement, proof: &Proof) -> Result<usize> {
        FixedInputs::inspect(statement, proof)?.retained_bytes()
    }

    pub(crate) fn decoded_bytes(self) -> usize {
        self.decoded
    }

    pub(crate) fn decode_temporary_bytes(self) -> usize {
        self.decode_temporary
    }

    pub(crate) fn graph_retained_bytes(self) -> Result<usize> {
        add(
            self.graph_retained,
            size_of::<crate::rust_verify::committed_backend::UnprovedRelationGraph>(),
        )
    }

    pub(crate) fn graph_growth_bytes(self) -> usize {
        self.graph_growth
    }

    /// Postconstruction source-drift assertion against the preceding fixed
    /// bound. Consume the immutable graph so the successful capacity census
    /// cannot be detached or applied to another graph. The full preceding
    /// reservation remains required until actual source cleanup succeeds.
    pub(crate) fn check_graph(self, graph: UnprovedRelationGraph) -> Result<CheckedInitialGraph> {
        let lengths = [
            graph.polynomials.len(), graph.bytes.len(),
            graph.expressions.len(), graph.operations.len(),
        ];
        let capacities = [
            graph.polynomials.capacity(), graph.bytes.capacity(),
            graph.expressions.capacity(), graph.operations.capacity(),
        ];
        let maxima = [
            self.ceiling.polynomials, self.ceiling.bytes,
            self.ceiling.expressions, self.ceiling.operations,
        ];
        for ((length, capacity), maximum) in lengths.into_iter().zip(capacities).zip(maxima) {
            if length > maximum || capacity > mul(2, maximum)? {
                return Err("source graph vector exceeded preceding bound");
            }
        }
        let mut ids = 0;
        let mut parts = 0;
        let mut maps = [0usize; 2];
        let mut hashes = [0usize; 2];
        let mut norm_inputs = 0;
        for operation in &graph.operations {
            match operation {
                Operation::CanonicalMap { inputs, .. } | Operation::SignedMap { inputs, .. } => {
                    let kind = usize::from(matches!(operation, Operation::SignedMap { .. }));
                    maps[kind] = add(maps[kind], 1)?;
                    if inputs.len() > self.ceiling.polynomials
                        || inputs.capacity() > mul(2, self.ceiling.polynomials)?
                    {
                        return Err("source graph map exceeded preceding bound");
                    }
                    ids = add(ids, inputs.capacity())?;
                }
                Operation::Norm { inputs, .. } => {
                    norm_inputs = add(norm_inputs, inputs.len())?;
                    if inputs.capacity() > mul(2, inputs.len())? {
                        return Err("source graph norm exceeded preceding bound");
                    }
                    ids = add(ids, inputs.capacity())?;
                }
                Operation::HashAlpha { parts: transcript, .. }
                | Operation::HashX { parts: transcript, .. } => {
                    let kind = usize::from(matches!(operation, Operation::HashX { .. }));
                    hashes[kind] = add(hashes[kind], 1)?;
                    let maximum = if kind == 0 { self.ceiling.alpha_parts } else { self.ceiling.x_parts };
                    if transcript.len() != maximum || transcript.capacity() > mul(2, maximum)? {
                        return Err("source graph transcript exceeded preceding bound");
                    }
                    parts = add(parts, transcript.capacity())?;
                }
                Operation::Add { .. } | Operation::Sub { .. } | Operation::AutomorphismQ { .. }
                | Operation::SignedToCanonical { .. } | Operation::Ntt { .. } | Operation::Mul { .. }
                | Operation::GBound { .. } | Operation::EqualBytes { .. } | Operation::EqualSigned { .. }
                | Operation::ByteMap { .. } | Operation::ParametersPp { .. } | Operation::SampleG { .. }
                | Operation::ExpandAlpha { .. } => {}
            }
        }
        if maps[0] > self.ceiling.canonical_lookups
            || maps[1] > self.ceiling.signed_lookups
            || hashes != [1, 1]
            || norm_inputs != self.ceiling.norm_inputs
        {
            return Err("source graph nested inventory differs from fixed constructor");
        }
        let actual = [
            size_of::<UnprovedRelationGraph>(),
            backing::<PolynomialNode>(capacities[0])?,
            backing::<BytesNode>(capacities[1])?,
            backing::<Expression>(capacities[2])?,
            backing::<Operation>(capacities[3])?,
            backing::<PolyId>(ids)?,
            backing::<TranscriptPart>(parts)?,
        ].into_iter().try_fold(0usize, add)?;
        let initial_host_bytes = self.graph_retained_bytes()?;
        if actual > initial_host_bytes {
            return Err("source graph storage exceeded preceding bound");
        }
        Ok(CheckedInitialGraph { graph, initial_host_bytes, retained_host_bytes: actual })
    }

    pub(crate) fn symbolic_bytes(self) -> usize {
        self.symbolic.requested_bytes
    }

    pub(crate) fn raw_host_bytes(self) -> usize {
        self.raw.host_bytes
    }

    pub(crate) fn raw_device_bytes(self) -> usize {
        self.raw.device_bytes
    }

    pub(crate) fn raw_operation_host_bytes(self) -> usize {
        self.raw.operation_host_allowance
    }

    pub(crate) fn polynomials(self) -> usize {
        self.ceiling.polynomials
    }

    pub(crate) fn byte_nodes(self) -> usize {
        self.ceiling.bytes
    }

    pub(crate) fn expressions(self) -> usize {
        self.ceiling.expressions
    }

    pub(crate) fn operations(self) -> usize {
        self.ceiling.operations
    }

    pub(crate) fn canonical_maps(self) -> usize {
        self.ceiling.canonical_lookups
    }

    pub(crate) fn signed_maps(self) -> usize {
        self.ceiling.signed_lookups
    }

    pub(crate) fn norm_inputs(self) -> usize {
        self.ceiling.norm_inputs
    }

    pub(crate) fn alpha_parts(self) -> usize {
        self.ceiling.alpha_parts
    }

    pub(crate) fn x_parts(self) -> usize {
        self.ceiling.x_parts
    }
}

#[cfg(test)]
mod tests;
