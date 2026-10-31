//! Source closure for the maintained N3/N4 pair/carry aggregation compiler.
//!
//! A plan borrows the exact immutable graph registrations and contexts. It owns
//! its original metadata reservation; source geometry is never inferred from a
//! generated proof. The enclosing workflow must close graph production and all
//! runtime owners before this source plan can participate in dispatch.
use super::{err, require, Error, Plan, Result, PUBLIC_VALUES};
use crate::{
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    graph_tree::{GraphContext, Plan as GraphPlan},
};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, MAX_WIRES},
    verifier::batch::shape::{self, OperationCounts, VerifierHeightEnvelope},
    Program, WIDTH,
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

pub(crate) const ROW_LIMIT: usize = 1 << 20;
const COMPILER_BYTES: usize = 2 << 30;
const AUXILIARY_BYTES: usize = 512 << 20;
const INPUT_LIMIT: usize = 1 << 20;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(|| Error("aggregate source size overflow".into()))
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or_else(|| Error("aggregate source size overflow".into()))
}

/// Borrowed registration identities, never an accepted graph proof.
pub(crate) struct GraphSource<'a> {
    pub(crate) plan: &'a GraphPlan,
    pub(crate) context: &'a GraphContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildSource {
    Graph(usize),
    Merge(usize),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MergeSource {
    ordinal: usize,
    first: usize,
    count: usize,
    children: [ChildSource; 2],
    operations: OperationCounts,
    active_rows: usize,
    padded_rows: usize,
    wires: usize,
    inputs: usize,
    hint_words: usize,
}
impl MergeSource {
    /// Numerical backend screening uses the maintained aggregate width and
    /// every possible child height. It grants no phase or proof authority.
    #[cfg(feature = "opencl")]
    pub(crate) fn outer_shape(&self) -> Result<lattica_prover_p3::block_v2::machine::OuterSourceShape> {
        lattica_prover_p3::block_v2::machine::OuterSourceShape::registered_graph_bounds(
            PUBLIC_VALUES, self.operations, self.wires, self.inputs, self.hint_words,
        ).map_err(err)
    }
    pub(crate) fn ordinal(&self) -> usize { self.ordinal }
    pub(crate) fn span(&self) -> (usize, usize) { (self.first, self.count) }
    pub(crate) fn children(&self) -> [ChildSource; 2] { self.children }
    pub(crate) fn rows(&self) -> (usize, usize) { (self.active_rows, self.padded_rows) }
    pub(crate) fn maximum_wires(&self) -> usize { self.wires }
    pub(crate) fn maximum_inputs(&self) -> usize { self.inputs }
    pub(crate) fn maximum_hint_words(&self) -> usize { self.hint_words }
    pub(crate) fn construction(&self) -> ConstructionLimits {
        ConstructionLimits {
            max_requested_program_bytes: COMPILER_BYTES,
            max_wires: self.wires,
            max_input_values: self.inputs,
        }
    }
    pub(crate) fn check_program(&self, program: &Program) -> Result<()> {
        let actual = OperationCounts::from_program(program);
        require(
            actual.scalar <= self.operations.scalar
                && actual.cubic <= self.operations.cubic
                && actual.poseidon <= self.operations.poseidon
                && program.active_rows() <= self.active_rows
                && program.height() <= self.padded_rows
                && program.wire_count() <= self.wires
                && program.witness_values() <= self.inputs
                && program.public_values() == PUBLIC_VALUES,
            "aggregate compiler exceeded its source closure",
        )
    }
}

/// No Clone: the metadata and its original claim have one lifetime.
pub(crate) struct FinalAggregationPlan<'a> {
    scope: &'a Plan,
    graphs: &'a [GraphSource<'a>],
    fingerprint: [u8; 32],
    merges: [Option<MergeSource>; 3],
    // Drop the source data before returning its original reservation.
    original: Reservation,
}

fn topology(total: usize) -> Result<[(usize, usize, [ChildSource; 2]); 3]> {
    use ChildSource::{Graph, Merge};
    require(matches!(total, 3 | 4), "aggregate workflow requires exactly N3 or N4")?;
    Ok(if total == 3 {
        [(0, 2, [Graph(0), Graph(1)]), (0, 3, [Merge(0), Graph(2)]),
         (0, 0, [Graph(0), Graph(0)])]
    } else {
        [(0, 2, [Graph(0), Graph(1)]), (2, 2, [Graph(2), Graph(3)]),
         (0, 4, [Merge(0), Merge(1)])]
    })
}

fn close_merge(
    ordinal: usize,
    first: usize,
    count: usize,
    children: [ChildSource; 2],
    graph: VerifierHeightEnvelope,
    aggregate: VerifierHeightEnvelope,
) -> Result<MergeSource> {
    let envelopes = children.map(|child| match child {
        ChildSource::Graph(_) => graph,
        ChildSource::Merge(_) => aggregate,
    });
    let graph_children = children.iter().filter(|c| matches!(c, ChildSource::Graph(_))).count();
    // Maintained tree.rs framing: header/interval, two child bindings, graph
    // leaf hashes, adjacency and final node hash. These are the same formulas
    // used by the complete graph row census: 136/8, 132/6, and 128/4.
    let overhead = OperationCounts { scalar: 128 + 4 * graph_children, cubic: 0,
        poseidon: 4 + 2 * graph_children };
    let operations = envelopes[0].operations.with_overhead(envelopes[1].operations)
        .and_then(|v| v.with_overhead(overhead)).map_err(err)?;
    let active_rows = operations.active_rows(PUBLIC_VALUES).map_err(err)?;
    let padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(err)?;
    // A scalar framing op has at most one output wire; a Poseidon op at most
    // WIDTH. Public wires and the additional graph digest/manifest inputs are
    // also charged, independently of any constant folding.
    let wires = add(add(envelopes[0].wire_upper_bound, envelopes[1].wire_upper_bound)?,
        add(PUBLIC_VALUES, add(overhead.scalar, mul(WIDTH, overhead.poseidon)?)?)?)?;
    let inputs = add(add(envelopes[0].input_values_upper_bound,
        envelopes[1].input_values_upper_bound)?, mul(8, graph_children)?)?;
    let hint_words = add(envelopes[0].selection_hint_words_upper_bound,
        envelopes[1].selection_hint_words_upper_bound)?;
    require(padded_rows <= ROW_LIMIT && wires <= MAX_WIRES && inputs <= INPUT_LIMIT,
        "N3/N4 aggregate source does not fit unchanged row/wire/input limits")?;
    Ok(MergeSource { ordinal, first, count, children, operations, active_rows,
        padded_rows, wires, inputs, hint_words })
}

impl<'a> FinalAggregationPlan<'a> {
    fn metadata_requirements() -> Result<Requirements> {
        // This type owns no Vec. Charge the complete fixed result plus source
        // descriptors and return/move capacity before any compiler is created.
        let bytes = [
            mul(4, core::mem::size_of::<Self>())?,
            mul(4, core::mem::size_of::<GraphSource<'_>>())?,
            mul(2, core::mem::size_of::<Sha3_256>())?,
            mul(2, core::mem::size_of::<VerifierHeightEnvelope>())?,
            core::mem::size_of::<[(usize, usize, [ChildSource; 2]); 3]>(),
            mul(2, core::mem::size_of::<[Option<MergeSource>; 3]>())?,
            core::mem::size_of::<ConstructionLimits>(),
            mul(4, core::mem::size_of::<Result<Self>>())?,
            // Bounded error text plus iterator/arithmetic/result call frames.
            1024,
            mul(128, core::mem::size_of::<usize>())?,
        ].into_iter().try_fold(0, add)?;
        Ok(Requirements::single(Category::RegisteredMetadata,
            Bytes { host: bytes as u64, device: 0 }))
    }
    pub(crate) fn planning_requirements() -> Result<Requirements> {
        Self::metadata_requirements()
    }
    pub(crate) fn planning_scratch_requirements() -> Result<Requirements> {
        Ok(Requirements::single(Category::PhaseScratch,
            Bytes { host: add(COMPILER_BYTES, AUXILIARY_BYTES)? as u64, device: 0 }))
    }
    pub(crate) fn derive_pre_reserved(
        scope: &'a Plan,
        graphs: &'a [GraphSource<'a>],
        original: Reservation,
        scratch: &Reservation,
        ledger: &Ledger,
    ) -> Result<Self> {
        require(original.belongs_to(ledger), "aggregate source belongs to another ledger")?;
        require(scratch.belongs_to(ledger), "aggregate source scratch belongs to another ledger")?;
        for (claim, wanted) in [
            (&original, Self::planning_requirements()?),
            (scratch, Self::planning_scratch_requirements()?),
        ] {
            for category in Category::ALL {
                let have = claim.requirements().get(category);
                let need = wanted.get(category);
                require(have.host >= need.host && have.device >= need.device,
                    "aggregate source planning was not fully pre-reserved")?;
            }
        }
        let total = scope.total() as usize;
        let topology = topology(total)?;
        require(graphs.len() == total, "aggregate source omitted or added a graph")?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/ordered-aggregate/source/n3n4/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(scope.batch_profile());
        hash.update(scope.context());
        hash.update(scope.total().to_le_bytes());
        for graph in graphs {
            require(graph.plan.label() == scope.graph_profile()
                && graph.context.context == scope.context(),
                "aggregate source profile or context mismatch")?;
            hash.update(graph.plan.label());
            for value in graph.context.statement.iter().chain(&graph.context.node_manifest) {
                hash.update(value.as_canonical_u64().to_le_bytes());
            }
        }
        let construction = ConstructionLimits { max_requested_program_bytes: COMPILER_BYTES,
            max_wires: MAX_WIRES, max_input_values: INPUT_LIMIT };
        let graph = shape::verifier_height_envelope(crate::graph_tree::PUBLIC_VALUES,
            ROW_LIMIT, construction, AUXILIARY_BYTES).map_err(err)?;
        let aggregate = shape::verifier_height_envelope(PUBLIC_VALUES,
            ROW_LIMIT, construction, AUXILIARY_BYTES).map_err(err)?;
        require(graph.heights_enumerated == 18 && aggregate.heights_enumerated == 18,
            "aggregate source height-domain drift")?;
        let mut merges = [None; 3];
        for (ordinal, &(first, count, children)) in topology.iter().take(total - 1).enumerate() {
            merges[ordinal] = Some(close_merge(ordinal, first, count, children, graph, aggregate)?);
        }
        let fingerprint = hash.finalize().into();
        // Source compiler/template allocations have been destroyed. The
        // coordinator still owns the borrowed scratch for the next planner;
        // this immutable result owns only its original metadata reservation.
        Ok(Self { scope, graphs, fingerprint, merges, original })
    }
    pub(crate) fn scope(&self) -> &Plan { self.scope }
    pub(crate) fn graphs(&self) -> &[GraphSource<'a>] { self.graphs }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] {
        crate::graph_proofs::compiled_source_fingerprint()
    }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.fingerprint }
    pub(crate) fn merge_count(&self) -> usize { self.scope.total() as usize - 1 }
    pub(crate) fn merge(&self, ordinal: usize) -> Option<&MergeSource> {
        self.merges.get(ordinal)?.as_ref()
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.original.belongs_to(ledger) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;

    #[test]
    fn n3_n4_source_topology_consumes_each_original_once() {
        for total in [3, 4] {
            let schedule = topology(total).unwrap();
            let mut graph_live = [true; 4];
            let mut merge_live = [false; 3];
            for (ordinal, &(first, count, children)) in schedule.iter().take(total - 1).enumerate() {
                let mut next = first;
                for child in children {
                    let (child_first, child_count) = match child {
                        ChildSource::Graph(index) => {
                            assert!(index < total && graph_live[index]);
                            graph_live[index] = false;
                            (index, 1)
                        }
                        ChildSource::Merge(index) => {
                            assert!(index < ordinal && merge_live[index]);
                            merge_live[index] = false;
                            (schedule[index].0, schedule[index].1)
                        }
                    };
                    assert_eq!(child_first, next);
                    next += child_count;
                }
                assert_eq!(next, first + count);
                merge_live[ordinal] = true;
            }
            assert!(graph_live[..total].iter().all(|live| !live));
            assert_eq!(merge_live.iter().filter(|live| **live).count(), 1);
            assert_eq!((schedule[total - 2].0, schedule[total - 2].1), (0, total));
        }
        for invalid in [0, 1, 2, 5, usize::MAX] {
            assert!(topology(invalid).is_err());
        }
    }

    #[test]
    fn source_refusal_preserves_borrowed_scratch_and_releases_metadata() {
        let ledger = Ledger::new(WorkerAllowance { host: 4 << 30, device: 0 });
        let other = Ledger::new(WorkerAllowance { host: 4 << 30, device: 0 });
        let scratch = ledger.admit_phase(FinalAggregationPlan::planning_scratch_requirements().unwrap()).unwrap();
        let before = ledger.snapshot();
        let scope = Plan::new([1; 32], [2; 32], 3).unwrap();
        // Both calls refuse before a shape compiler exists. The second uses
        // the original ledger but omits the required source graph identities.
        for wrong_ledger in [true, false] {
            let original = ledger.admit_phase(FinalAggregationPlan::planning_requirements().unwrap()).unwrap();
            assert!(FinalAggregationPlan::derive_pre_reserved(&scope, &[], original, &scratch,
                if wrong_ledger { &other } else { &ledger }).is_err());
            assert_eq!(ledger.snapshot().current, before.current);
            assert_eq!(other.snapshot().current, Bytes::ZERO);
        }
        drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
