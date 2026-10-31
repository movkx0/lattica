//! Test-only census of the genuine fixed-profile constructor's graph vectors.
//!
//! No graph is copied, constructed, admitted, or authenticated here. In
//! particular, inspecting an already allocated graph cannot acquire ownership
//! of that allocation. See construction_census/BOUNDS.md for the source census
//! and the separate, still-open constructor lifetime obligations.
use super::*;
use core::mem::size_of;

mod btree;
mod tests;

type Error = &'static str;

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or("graph census sum overflow")
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or("graph census product overflow")
}
fn backing<T>(capacity: usize) -> Result<usize, Error> {
    mul(capacity, size_of::<T>())
}

// The live raw boundary and graph owner use these same definitions.
use super::source_graph::{bounds::Ceilings, inputs::FixedInputs as FixedProfile};

#[derive(Debug)]
pub(super) struct GraphVectorCensus {
    lengths: [usize; 4],
    capacities: [usize; 4],
    nested_id_capacity: usize,
    nested_transcript_capacity: usize,
    observed_inline_and_backing_bytes: usize,
    retained_graph_vector_ceiling_bytes: usize,
    graph_vector_growth_coexistence_ceiling_bytes: usize,
    complete_constructor_bound: bool,
    owns_source_graph_allocation: bool,
    workflow_dispatch_authority: bool,
}

fn inspect_graph(
    _profile: &FixedProfile<'_>,
    graph: &UnprovedRelationGraph,
) -> Result<GraphVectorCensus, Error> {
    let c = Ceilings::fixed();
    let lengths = [
        graph.polynomials.len(),
        graph.bytes.len(),
        graph.expressions.len(),
        graph.operations.len(),
    ];
    let capacities = [
        graph.polynomials.capacity(),
        graph.bytes.capacity(),
        graph.expressions.capacity(),
        graph.operations.capacity(),
    ];
    let maxima = [c.polynomials, c.bytes, c.expressions, c.operations];
    for ((len, capacity), maximum) in lengths.into_iter().zip(capacities).zip(maxima) {
        if len > maximum || capacity > mul(2, maximum)? {
            return Err("genuine graph vector exceeds the source census");
        }
    }
    let mut nested_id_capacity = 0;
    let mut nested_transcript_capacity = 0;
    let mut maps = [0usize; 2];
    let mut hashes = [0usize; 2];
    let mut norm_inputs = 0;
    for operation in &graph.operations {
        match operation {
            Operation::CanonicalMap { inputs, .. } | Operation::SignedMap { inputs, .. } => {
                let kind = usize::from(matches!(operation, Operation::SignedMap { .. }));
                maps[kind] = add(maps[kind], 1)?;
                if inputs.len() > c.polynomials || inputs.capacity() > mul(2, c.polynomials)? {
                    return Err("genuine map input vector exceeds the source census");
                }
                nested_id_capacity = add(nested_id_capacity, inputs.capacity())?;
            }
            Operation::Norm { inputs, .. } => {
                norm_inputs = add(norm_inputs, inputs.len())?;
                // Every fixed norm has at least eight input polynomials.
                if inputs.capacity() > mul(2, inputs.len())? {
                    return Err("genuine norm input capacity exceeds the source census");
                }
                nested_id_capacity = add(nested_id_capacity, inputs.capacity())?;
            }
            Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => {
                let kind = usize::from(matches!(operation, Operation::HashX { .. }));
                hashes[kind] = add(hashes[kind], 1)?;
                let maximum = if kind == 0 { c.alpha_parts } else { c.x_parts };
                if parts.len() != maximum || parts.capacity() > mul(2, maximum)? {
                    return Err("genuine transcript vector differs from the fixed census");
                }
                nested_transcript_capacity = add(nested_transcript_capacity, parts.capacity())?;
            }
            _ => {}
        }
    }
    if maps[0] > c.canonical_lookups
        || maps[1] > c.signed_lookups
        || hashes != [1, 1]
        || norm_inputs != c.norm_inputs
    {
        return Err("genuine nested operation inventory differs from the fixed census");
    }
    let mut observed = size_of::<UnprovedRelationGraph>();
    for bytes in [
        backing::<PolynomialNode>(capacities[0])?,
        backing::<BytesNode>(capacities[1])?,
        backing::<Expression>(capacities[2])?,
        backing::<Operation>(capacities[3])?,
        backing::<PolyId>(nested_id_capacity)?,
        backing::<TranscriptPart>(nested_transcript_capacity)?,
    ] {
        observed = add(observed, bytes)?;
    }
    let retained = add(
        size_of::<UnprovedRelationGraph>(),
        add(c.main_vector_bytes(2)?, c.nested_vector_bytes(2)?)?,
    )?;
    let growth = add(
        size_of::<UnprovedRelationGraph>(),
        add(c.main_vector_bytes(3)?, c.nested_vector_bytes(3)?)?,
    )?;
    if observed > retained {
        return Err("genuine graph capacity census exceeds retained ceiling");
    }
    Ok(GraphVectorCensus {
        lengths,
        capacities,
        nested_id_capacity,
        nested_transcript_capacity,
        observed_inline_and_backing_bytes: observed,
        retained_graph_vector_ceiling_bytes: retained,
        graph_vector_growth_coexistence_ceiling_bytes: growth,
        complete_constructor_bound: false,
        owns_source_graph_allocation: false,
        workflow_dispatch_authority: false,
    })
}

/// Existing genuine fixture test only. This is an observation after allocation,
/// not an ownership constructor, preflight reservation, or measured peak.
pub(super) fn qualify_fixture(
    statement: &Statement,
    proof: &Proof,
    graph: &UnprovedRelationGraph,
) -> Result<(), Error> {
    let profile = FixedProfile::inspect(statement, proof)?;
    let census = inspect_graph(&profile, graph)?;
    let operation_count = |predicate: fn(&Operation) -> bool| {
        graph.operations.iter().filter(|op| predicate(op)).count()
    };
    if operation_count(|op| matches!(op, Operation::Add { .. })) != 409
        || operation_count(|op| matches!(op, Operation::Sub { .. })) != 201
        || operation_count(|op| matches!(op, Operation::Mul { .. })) != 474
        || operation_count(|op| matches!(op, Operation::Ntt { .. })) != 95
        || operation_count(|op| matches!(op, Operation::AutomorphismQ { .. })) != 2
    {
        return Err("genuine whole-polynomial operation counts changed");
    }
    eprintln!("genuine fixed-profile graph vectors (post-construction; not admission): {census:?}");
    Ok(())
}
