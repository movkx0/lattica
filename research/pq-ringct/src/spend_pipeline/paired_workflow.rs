//! Complete selected-R4 row screening over immutable trusted requests.
//!
//! No proof, prepared backend state, admission permit or callback escapes.
//! This establishes row closure only for these borrowed descriptors. A fixture
//! screen cannot authorize a fresh transaction or account for runtime owners.
use super::{AesLayout, Budgets, CompositeLayout, TranscriptLayout};
use crate::{
    component_tree::native_shape::{
        self, framing,
        unchanged::{other_native_core_bound, OtherNativeDescriptor},
        NativeDescriptor,
    },
    graph_auxiliary::{AuxiliaryFactory, Kind as AuxiliaryKind, Role},
    graph_crypto::{self, Request, RequestDescriptor, ShakeWrapperLayout},
    graph_proofs::{ComponentKind, GraphProofPlan, ResourceLimits},
    graph_tree::{LeafKind, OperationFamily, Plan},
    rust_verify::committed_backend::UnprovedRelationGraph,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, MAX_WIRES},
    verifier::batch::shape::{self, OperationCounts},
};

const ROWS: usize = 1 << 20;
const META_LIMIT: usize = 4 << 20;
const AUXILIARY: usize = 512 << 20;
const REPORT_SCRATCH: usize = 16 << 10;
const SELECTED_ALGEBRA_LIMITS: ResourceLimits = ResourceLimits {
    max_batch_count: 64,
    max_ntt_batch_count: 32,
    max_mul_batch_count: 32,
    max_trace_cells: 1 << 27,
    max_estimated_prover_bytes: 24u64 << 30,
};

type Result<T> = core::result::Result<T, String>;
fn err(e: impl core::fmt::Display) -> String {
    e.to_string()
}
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn plus(a: OperationCounts, b: OperationCounts) -> Result<OperationCounts> {
    a.with_overhead(b).map_err(err)
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| "selected metadata overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b)
        .ok_or_else(|| "selected metadata overflow".into())
}
fn backing<T>(count: usize, copies: usize) -> Result<usize> {
    // Fixed source capacities never grow. Reserve a second capacity for
    // allocator rounding/temporary movement before constructing each Vec.
    mul(mul(count, copies)?, 2 * size_of::<T>())
}
fn construction() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}

#[derive(Clone, Copy, Debug)]
struct Node {
    first: usize,
    count: usize,
    height: usize,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct RowBound {
    pub stage: &'static str,
    pub ordinal: usize,
    pub first: usize,
    pub count: usize,
    pub active: usize,
    pub padded: usize,
}

pub(super) struct LayoutScreen {
    pub layout: ShakeWrapperLayout,
    pub nodes: Vec<RowBound>,
    pub graph_root: usize,
    pub n3: [RowBound; 2],
    pub n4: [RowBound; 3],
}

/// All owned plans are created together by the diagnostic harness from one
/// immutable graph. No public constructor accepts independently built plans.
/// Existing fixture/graph/plan setup is outside compiler-screen accounting;
/// these objects cannot grant source-generation or runtime memory admission.
struct SelectedR4Inputs<'g> {
    graph: &'g UnprovedRelationGraph,
    tree: Plan,
    algebra: GraphProofPlan<'g>,
    crypto: graph_crypto::Plan,
    auxiliary: AuxiliaryFactory,
    budgets: Budgets,
}

/// Retain the complete private owner and its exact Request slice throughout
/// this diagnostic. This is not a reusable shape certificate or dispatch token.
struct SelectedR4Screen<'a, 'g> {
    inputs: &'a SelectedR4Inputs<'g>,
    requests: &'a [Request],
    pub profile: [u8; 32],
    pub native_proofs: usize,
    pub metadata_reservation: usize,
    pub singleton: LayoutScreen,
    pub paired: LayoutScreen,
}
impl SelectedR4Screen<'_, '_> {
    fn is_for(&self, inputs: &SelectedR4Inputs<'_>) -> bool {
        core::ptr::eq(self.inputs, inputs) && core::ptr::eq(self.requests, inputs.crypto.requests())
    }
}

/// All four registered widths cover every configured power-of-two height.
/// These are source-derived independent maxima, never sampled child heights.
struct Descendants {
    component: OperationCounts,
    branch: OperationCounts,
    graph: OperationCounts,
    aggregate: OperationCounts,
}
impl Descendants {
    fn new() -> Result<Self> {
        let core = |width| -> Result<OperationCounts> {
            let envelope = shape::verifier_height_envelope(width, ROWS, construction(), AUXILIARY)
                .map_err(err)?;
            require(
                envelope.heights_enumerated == 18,
                "registered height domain drift",
            )?;
            Ok(envelope.operations)
        };
        Ok(Self {
            component: core(46)?,
            branch: core(38)?,
            graph: core(28)?,
            aggregate: core(25)?,
        })
    }
    fn component_merge(&self) -> Result<OperationCounts> {
        plus(
            plus(self.component, self.component)?,
            OperationCounts {
                scalar: 1419,
                ..Default::default()
            },
        )
    }
    fn graph_merge(&self) -> Result<OperationCounts> {
        plus(
            plus(self.graph, self.graph)?,
            OperationCounts {
                scalar: 1375,
                ..Default::default()
            },
        )
    }
}

fn row_bound(
    stage: &'static str,
    ordinal: usize,
    first: usize,
    count: usize,
    operations: OperationCounts,
    publics: usize,
) -> Result<RowBound> {
    let active = operations.active_rows(publics).map_err(err)?;
    let padded = operations.padded_rows(publics).map_err(err)?;
    if padded > ROWS {
        return Err(format!("selected R4 row admission refused before proving: stage={stage} ordinal={ordinal} span=[{first},+{count}) active_upper={active} padded_upper={padded} limit={ROWS}; no dispatch or fallback"));
    }
    Ok(RowBound {
        stage,
        ordinal,
        first,
        count,
        active,
        padded,
    })
}

fn record(
    nodes: &mut Vec<RowBound>,
    limit: usize,
    stage: &'static str,
    ordinal: usize,
    first: usize,
    count: usize,
    ops: OperationCounts,
    publics: usize,
) -> Result<Node> {
    require(nodes.len() < limit, "selected row metadata node capacity")?;
    let bound = row_bound(stage, ordinal, first, count, ops, publics)?;
    nodes.push(bound);
    Ok(Node {
        first,
        count,
        height: bound.padded,
    })
}

/// Allocation-free copy of RequestProver's binary carry topology. Spans are
/// exact native units, so odd segment tails cannot become invented pairs.
struct Carry([Option<Node>; usize::BITS as usize]);
impl Carry {
    fn push(
        &mut self,
        mut node: Node,
        mut merge: impl FnMut(Node, Node) -> Result<Node>,
    ) -> Result<()> {
        for slot in &mut self.0 {
            match slot.take() {
                Some(left) => node = merge(left, node)?,
                None => {
                    *slot = Some(node);
                    return Ok(());
                }
            }
        }
        Err("selected carry depth overflow".into())
    }
    fn finish(self, mut merge: impl FnMut(Node, Node) -> Result<Node>) -> Result<Node> {
        let mut right = None;
        for left in self.0.into_iter().flatten() {
            right = Some(match right {
                None => left,
                Some(right) => merge(left, right)?,
            });
        }
        right.ok_or_else(|| "empty selected request".into())
    }
}

fn joined(left: Node, right: Node) -> Result<(usize, usize)> {
    require(
        left.height <= ROWS && right.height <= ROWS,
        "unclosed child reached a parent",
    )?;
    require(
        left.first.checked_add(left.count) == Some(right.first),
        "nonadjacent selected row spans",
    )?;
    Ok((
        left.first,
        left.count
            .checked_add(right.count)
            .ok_or("selected span overflow")?,
    ))
}

struct NativeCores {
    crypto: Vec<Vec<OperationCounts>>,
    auxiliary: Vec<OperationCounts>,
    graph: Vec<Option<OperationCounts>>,
}

fn crypto_cores(crypto: &graph_crypto::Plan) -> Result<NativeCores> {
    let mut requests = Vec::with_capacity(crypto.requests().len());
    for request in crypto.requests() {
        let mut segments = Vec::with_capacity(request.segments().len());
        for segment in request.segments() {
            let descriptor = match request.descriptor() {
                RequestDescriptor::Shake(descriptor) => NativeDescriptor::Shake {
                    descriptor,
                    first: segment.first_unit,
                    count: segment.units,
                },
                RequestDescriptor::Aes(descriptor) => NativeDescriptor::Aes {
                    descriptor,
                    first: segment.first_unit,
                    count: segment.units,
                },
            };
            let g = descriptor.geometry().map_err(err)?;
            require(
                (g.width, g.height) == (segment.width, segment.height),
                "selected native geometry differs from Request",
            )?;
            let bound = native_shape::native_core_bound(descriptor, construction(), AUXILIARY)
                .map_err(err)?;
            segments.push(bound.counts.operations);
        }
        requests.push(segments);
    }
    Ok(NativeCores {
        crypto: requests,
        auxiliary: Vec::new(),
        graph: Vec::new(),
    })
}

fn remaining_native_cores(
    mut cores: NativeCores,
    tree: &Plan,
    algebra: &GraphProofPlan<'_>,
    graph: &UnprovedRelationGraph,
    auxiliary: &AuxiliaryFactory,
) -> Result<NativeCores> {
    let mut auxiliary_cores = Vec::with_capacity(auxiliary.requests().len());
    for request in auxiliary.requests() {
        let descriptor = match request.kind() {
            AuxiliaryKind::Transcript => NativeDescriptor::Transcript(
                request
                    .transcript_air()
                    .ok_or("missing selected transcript AIR")?
                    .parts(),
            ),
            AuxiliaryKind::Sparse(kind) => NativeDescriptor::Sparse(kind),
            AuxiliaryKind::Uniform(kind) => NativeDescriptor::Uniform(kind),
        };
        let g = descriptor.geometry().map_err(err)?;
        require(
            (g.width, g.height) == (request.geometry().width, request.geometry().height),
            "selected auxiliary geometry mismatch",
        )?;
        auxiliary_cores.push(
            native_shape::native_core_bound(descriptor, construction(), AUXILIARY)
                .map_err(err)?
                .counts
                .operations,
        );
    }
    let mut graph_cores = Vec::with_capacity(tree.leaves().len());
    for leaf in tree.leaves() {
        let descriptor = match leaf.kind() {
            LeafKind::Statement => Some(OtherNativeDescriptor::Statement {
                setup_seed: graph.setup_seed(),
            }),
            LeafKind::PrivateProof => Some(OtherNativeDescriptor::PrivateProof),
            LeafKind::Operations(
                OperationFamily::Affine { .. }
                | OperationFamily::Ntt { .. }
                | OperationFamily::Mul { .. }
                | OperationFamily::GBound
                | OperationFamily::Permutation
                | OperationFamily::LinearMap,
            ) => {
                let batch = algebra
                    .batches()
                    .iter()
                    .find(|b| b.operation_indices() == leaf.operation_indices())
                    .ok_or("missing selected exact algebra batch")?;
                require(
                    !matches!(batch.kind(), ComponentKind::External),
                    "external native algebra core",
                )?;
                Some(OtherNativeDescriptor::Algebra {
                    kind: batch.kind(),
                    count: batch.operation_indices().len(),
                })
            }
            _ => None,
        };
        graph_cores.push(
            descriptor
                .map(|d| {
                    other_native_core_bound(d, construction(), AUXILIARY)
                        .map(|b| b.counts.operations)
                        .map_err(err)
                })
                .transpose()?,
        );
    }
    cores.auxiliary = auxiliary_cores;
    cores.graph = graph_cores;
    Ok(cores)
}

fn close_requests(
    layout: ShakeWrapperLayout,
    crypto: &graph_crypto::Plan,
    cores: &NativeCores,
    descendants: &Descendants,
    nodes: &mut Vec<RowBound>,
    node_limit: usize,
) -> Result<Vec<Node>> {
    let merge_ops = descendants.component_merge()?;
    let mut roots = Vec::with_capacity(crypto.requests().len());
    for (request_index, request) in crypto.requests().iter().enumerate() {
        let mut carry = Carry([None; usize::BITS as usize]);
        let mut merge = |left, right, nodes: &mut Vec<RowBound>| -> Result<Node> {
            let (first, count) = joined(left, right)?;
            record(
                nodes,
                node_limit,
                "component-parent",
                request.operation_index(),
                first,
                count,
                merge_ops,
                46,
            )
        };
        let mut push = |first_segment: usize,
                        members: usize,
                        first: usize,
                        count: usize,
                        framing|
         -> Result<()> {
            let mut ops = framing;
            let end_segment = add(first_segment, members)?;
            for core in cores.crypto[request_index]
                .get(first_segment..end_segment)
                .ok_or("selected segment core range")?
            {
                ops = plus(ops, *core)?;
            }
            let node = record(
                nodes,
                node_limit,
                "component-wrapper",
                request.operation_index(),
                first,
                count,
                ops,
                46,
            )?;
            carry.push(node, |left, right| merge(left, right, nodes))
        };
        match request.descriptor() {
            RequestDescriptor::Shake(_) => {
                let schedule = request.shake_wrapper_schedule(layout).map_err(err)?;
                for span in schedule.groups() {
                    push(
                        span.first_segment,
                        span.segment_count,
                        span.first_unit,
                        span.units,
                        framing::shake_wrapper(span.segment_count).map_err(err)?,
                    )?;
                }
            }
            RequestDescriptor::Aes(_) => {
                for (index, segment) in request.segments().iter().enumerate() {
                    push(
                        index,
                        1,
                        segment.first_unit,
                        segment.units,
                        framing::AES_WRAPPER,
                    )?;
                }
            }
        }
        let root = carry.finish(|left, right| merge(left, right, nodes))?;
        require(
            root.first == 0 && root.count == request.units(),
            "selected complete request coverage",
        )?;
        roots.push(root);
    }
    Ok(roots)
}

#[allow(clippy::too_many_arguments)]
fn close_graph(
    tree: &Plan,
    algebra: &GraphProofPlan<'_>,
    graph: &UnprovedRelationGraph,
    crypto: &graph_crypto::Plan,
    auxiliary: &AuxiliaryFactory,
    cores: &NativeCores,
    requests: &[Node],
    descendants: &Descendants,
    nodes: &mut Vec<RowBound>,
    node_limit: usize,
) -> Result<Node> {
    let common = plus(
        framing::GRAPH_HEADER,
        framing::source_binding_initialization(graph.polynomials().len(), graph.bytes().len())
            .map_err(err)?,
    )?;
    let mut request_uses = vec![false; crypto.requests().len()];
    let mut auxiliary_uses = vec![false; auxiliary.requests().len()];
    let mut request = |operation, subrequest| -> Result<OperationCounts> {
        let index = crypto
            .requests()
            .iter()
            .position(|r| r.operation_index() == operation && r.subrequest() == subrequest)
            .ok_or("missing selected request consumer")?;
        require(!request_uses[index], "selected request consumed twice")?;
        request_uses[index] = true;
        require(
            requests[index].height <= ROWS
                && requests[index].count == crypto.requests()[index].units(),
            "unclosed request consumer",
        )?;
        Ok(descendants.component)
    };
    let mut aux = |operation, role| -> Result<(OperationCounts, usize)> {
        let index = auxiliary
            .requests()
            .iter()
            .position(|r| r.operation_index() == operation && r.role() == role)
            .ok_or("missing selected auxiliary consumer")?;
        require(!auxiliary_uses[index], "selected auxiliary consumed twice")?;
        auxiliary_uses[index] = true;
        let parts = auxiliary.requests()[index]
            .transcript_air()
            .map(|a| a.parts().len())
            .unwrap_or(0);
        Ok((cores.auxiliary[index], parts))
    };
    let mut leaves = Vec::with_capacity(tree.leaves().len());
    for (ordinal, leaf) in tree.leaves().iter().enumerate() {
        let operation = leaf.operation_indices().first().copied().unwrap_or(0);
        let mut ops = common;
        let core =
            || cores.graph[ordinal].ok_or_else(|| "missing closed native graph core".to_string());
        let extra = match leaf.kind() {
            LeafKind::FixedSources => framing::fixed_sources(add(
                leaf.polynomial_indices().len(),
                leaf.byte_indices().len(),
            )?)
            .map_err(err)?,
            LeafKind::Statement => plus(core()?, framing::STATEMENT_SOURCE)?,
            LeafKind::PrivateProof => plus(core()?, framing::PRIVATE_SOURCE)?,
            LeafKind::Operations(family) => match family {
                OperationFamily::Equality => framing::EQUALITY,
                OperationFamily::Affine { kind, .. } => plus(
                    core()?,
                    framing::affine_join(leaf.operation_indices().len(), kind.is_conversion())
                        .map_err(err)?,
                )?,
                OperationFamily::Ntt { .. }
                | OperationFamily::Mul { .. }
                | OperationFamily::GBound
                | OperationFamily::Permutation
                | OperationFamily::LinearMap => {
                    let batch = algebra
                        .batches()
                        .iter()
                        .find(|b| b.operation_indices() == leaf.operation_indices())
                        .ok_or("missing selected graph algebra geometry")?;
                    let d = OtherNativeDescriptor::Algebra {
                        kind: batch.kind(),
                        count: batch.operation_indices().len(),
                    };
                    plus(
                        core()?,
                        framing::native_root_join(d.geometry().map_err(err)?.public_values)
                            .map_err(err)?,
                    )?
                }
                OperationFamily::ParametersPp => plus(
                    request(operation, 0)?,
                    framing::parameters_pp_consumer().map_err(err)?,
                )?,
                OperationFamily::SampleG => plus(
                    plus(
                        request(operation, 0)?,
                        aux(operation, Role::SampleGUniform)?.0,
                    )?,
                    framing::sample_g_consumer().map_err(err)?,
                )?,
                OperationFamily::ExpandAlpha => {
                    for (subrequest, role, stage) in [
                        (0, Role::AlphaUniform, "alpha-uniform-producer"),
                        (1, Role::AlphaSparse, "alpha-sparse-producer"),
                    ] {
                        let branch_ops = plus(
                            plus(request(operation, subrequest)?, aux(operation, role)?.0)?,
                            framing::ALPHA_PRODUCER,
                        )?;
                        record(nodes, node_limit, stage, operation, 0, 1, branch_ops, 38)?;
                    }
                    plus(
                        plus(descendants.branch, descendants.branch)?,
                        framing::expand_alpha_branch_consumer().map_err(err)?,
                    )?
                }
                OperationFamily::HashAlpha => {
                    let (native, parts) = aux(operation, Role::HashAlphaTranscript)?;
                    plus(
                        plus(request(operation, 0)?, native)?,
                        framing::hash_alpha_consumer(parts).map_err(err)?,
                    )?
                }
                OperationFamily::HashX => {
                    let (native, parts) = aux(operation, Role::HashXTranscript)?;
                    let producer = plus(
                        plus(request(operation, 0)?, native)?,
                        framing::HASH_X_PRODUCER,
                    )?;
                    record(
                        nodes,
                        node_limit,
                        "hash-x-producer",
                        operation,
                        0,
                        1,
                        producer,
                        38,
                    )?;
                    plus(
                        plus(descendants.branch, aux(operation, Role::HashXSparse)?.0)?,
                        framing::hash_x_branch_consumer(parts).map_err(err)?,
                    )?
                }
            },
        };
        ops = plus(ops, extra)?;
        leaves.push(record(
            nodes,
            node_limit,
            "graph-leaf",
            ordinal,
            ordinal,
            1,
            ops,
            28,
        )?);
    }
    require(
        request_uses.into_iter().all(|used| used),
        "selected omitted crypto request",
    )?;
    require(
        auxiliary_uses.into_iter().all(|used| used),
        "selected omitted auxiliary request",
    )?;
    let merge_ops = descendants.graph_merge()?;
    // GraphProver::aggregate_adjacent pairs left-to-right, carrying odd tails.
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut current = leaves.into_iter();
        while let Some(left) = current.next() {
            next.push(match current.next() {
                None => left,
                Some(right) => {
                    let (first, count) = joined(left, right)?;
                    record(
                        nodes,
                        node_limit,
                        "graph-parent",
                        0,
                        first,
                        count,
                        merge_ops,
                        28,
                    )?
                }
            });
        }
        leaves = next;
    }
    let root = leaves.pop().ok_or("empty selected graph")?;
    require(
        root.first == 0 && root.count == tree.leaves().len(),
        "selected complete graph coverage",
    )?;
    Ok(root)
}

fn final_aggregation(
    descendants: &Descendants,
    graph: Node,
) -> Result<([RowBound; 2], [RowBound; 3])> {
    require(graph.height <= ROWS, "unclosed graph reached aggregate")?;
    let merge = |stage, left, right, scalar, poseidon, first, count| {
        row_bound(
            stage,
            0,
            first,
            count,
            plus(
                plus(left, right)?,
                OperationCounts {
                    scalar,
                    cubic: 0,
                    poseidon,
                },
            )?,
            25,
        )
    };
    let first = merge(
        "aggregate-graph-graph",
        descendants.graph,
        descendants.graph,
        136,
        8,
        0,
        2,
    )?;
    let n3 = merge(
        "aggregate-batch-graph",
        descendants.aggregate,
        descendants.graph,
        132,
        6,
        0,
        3,
    )?;
    let second = merge(
        "aggregate-graph-graph",
        descendants.graph,
        descendants.graph,
        136,
        8,
        2,
        2,
    )?;
    let n4 = merge(
        "aggregate-batch-batch",
        descendants.aggregate,
        descendants.aggregate,
        128,
        4,
        0,
        4,
    )?;
    Ok(([first, n3], [first, second, n4]))
}

fn screen_selected_r4<'a, 'g>(
    inputs: &'a SelectedR4Inputs<'g>,
    max_rows: usize,
) -> Result<SelectedR4Screen<'a, 'g>> {
    let tree = &inputs.tree;
    let graph = inputs.graph;
    let algebra = &inputs.algebra;
    let crypto = &inputs.crypto;
    let auxiliary = &inputs.auxiliary;
    let budgets = inputs.budgets;
    require(
        max_rows == ROWS,
        "selected R4 requires unchanged1048576 row ceiling",
    )?;
    require(
        budgets.native_bytes == 24u64 << 30
            && budgets.outer_bytes == 32u64 << 30
            && budgets.cache_entry_bytes == 64 << 20
            && budgets.transcripts == TranscriptLayout::Serial
            && budgets.aes == AesLayout::Serial
            && budgets.composites == CompositeLayout::Branches,
        "selected R4 pipeline profile mismatch",
    )?;
    require(
        algebra.resource_limits() == SELECTED_ALGEBRA_LIMITS
            && algebra.native_host_limit_bytes() == 24u64 << 30,
        "selected R4 algebra profile mismatch",
    )?;
    for policy in [budgets.crypto_policy, crypto.policy()] {
        require(
            policy.maximum_aes_blocks == 64
                && policy.maximum_shake_permutations == 32
                && policy.child_memory_budget_bytes == 24u64 << 30
                && policy.admission == graph_crypto::Admission::Estimated,
            "selected R4 crypto profile mismatch",
        )?;
    }
    // The private fixture constructor derives all owned plans from one graph.
    // This result retains that complete owner, never independently mixed plans.
    // Exact schedule equality, not merely matching leaf counts or sample rows.
    let mut batches = algebra.batches().iter();
    for leaf in tree
        .leaves()
        .iter()
        .filter(|l| matches!(l.kind(), LeafKind::Operations(_)))
    {
        require(
            batches
                .next()
                .is_some_and(|b| b.operation_indices() == leaf.operation_indices()),
            "selected graph/algebra schedule mismatch",
        )?;
    }
    require(batches.next().is_none(), "selected omitted algebra batch")?;
    let native_crypto = crypto.requests().iter().try_fold(0usize, |n, r| {
        n.checked_add(r.segments().len())
            .ok_or("selected native count overflow")
    })?;
    let algebra_native = algebra
        .batches()
        .iter()
        .filter(|b| !matches!(b.kind(), ComponentKind::External))
        .count();
    let native_proofs = [native_crypto, auxiliary.requests().len(), algebra_native, 2]
        .into_iter()
        .try_fold(0, add)?;
    let branches = tree
        .leaves()
        .iter()
        .map(|leaf| match leaf.kind() {
            LeafKind::Operations(OperationFamily::ExpandAlpha) => 2,
            LeafKind::Operations(OperationFamily::HashX) => 1,
            _ => 0,
        })
        .try_fold(0, add)?;
    let node_limit = native_crypto
        .checked_mul(2)
        .and_then(|n| n.checked_add(tree.leaves().len().checked_mul(2)?))
        .and_then(|n| n.checked_add(branches))
        .ok_or("selected node count overflow")?;
    // All planner-owned Vec backings are admitted before any core compilation
    // or allocation. BOUNDS.md derives each count and its simultaneous owners.
    // Diagnostic fixture/graph/plan setup is owned by the enclosing harness.
    let q = crypto.requests().len();
    let a = auxiliary.requests().len();
    let l = tree.leaves().len();
    let metadata_reservation = [
        backing::<RowBound>(node_limit, 2)?, // Both layout report vectors.
        backing::<Vec<OperationCounts>>(q, 1)?, // Crypto matrix outer headers.
        backing::<OperationCounts>(native_crypto, 1)?, // All segment cores.
        backing::<OperationCounts>(a, 1)?,   // Auxiliary cores.
        backing::<Option<OperationCounts>>(l, 1)?, // Exact graph core slots.
        backing::<Node>(q, 2)?,              // Both layout request-root vectors.
        backing::<Node>(l, 2)?,              // Current/next graph generations, sequential layouts.
        backing::<bool>(add(q, a)?, 1)?,     // Exact complete-consumption flags.
        size_of::<SelectedR4Screen<'_, '_>>(),
        size_of::<NativeCores>(),
        size_of::<Descendants>(),
        16 << 10, // Carry, Vec headers, closure and scalar stack scratch.
    ]
    .into_iter()
    .try_fold(0, add)?;
    require(
        metadata_reservation <= META_LIMIT,
        "selected row metadata allowance",
    )?;
    let descendants = Descendants::new()?;
    let cores = crypto_cores(crypto)?;
    // Screen every initial wrapper and carry ancestor first. A row refusal
    // here avoids compiling any unchanged source/algebra consumer core.
    let mut singleton_nodes = Vec::with_capacity(node_limit);
    let singleton_requests = close_requests(
        ShakeWrapperLayout::Singleton,
        crypto,
        &cores,
        &descendants,
        &mut singleton_nodes,
        node_limit,
    )?;
    let mut paired_nodes = Vec::with_capacity(node_limit);
    let paired_requests = close_requests(
        ShakeWrapperLayout::PairedV1,
        crypto,
        &cores,
        &descendants,
        &mut paired_nodes,
        node_limit,
    )?;
    let cores = remaining_native_cores(cores, tree, algebra, graph, auxiliary)?;
    let layout = |layout, mut nodes: Vec<RowBound>, requests: Vec<Node>| -> Result<LayoutScreen> {
        let graph_root = close_graph(
            tree,
            algebra,
            graph,
            crypto,
            auxiliary,
            &cores,
            &requests,
            &descendants,
            &mut nodes,
            node_limit,
        )?;
        let (n3, n4) = final_aggregation(&descendants, graph_root)?;
        Ok(LayoutScreen {
            layout,
            nodes,
            graph_root: graph_root.height,
            n3,
            n4,
        })
    };
    Ok(SelectedR4Screen {
        inputs,
        requests: crypto.requests(),
        profile: tree.label(),
        native_proofs,
        metadata_reservation,
        singleton: layout(
            ShakeWrapperLayout::Singleton,
            singleton_nodes,
            singleton_requests,
        )?,
        paired: layout(ShakeWrapperLayout::PairedV1, paired_nodes, paired_requests)?,
    })
}

#[cfg(all(test, feature = "native-matrict"))]
mod tests;
