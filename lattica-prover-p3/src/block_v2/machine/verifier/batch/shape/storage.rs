//! Allocation-free storage admission for the closed planner, pinned to release
//! x86_64 / Rust 1.96 / p3 0.6.1. Requested capacities are not allocator/RSS bounds.
use super::{
    CompileError, ConstructionLimits, RegisteredChildShape, MAX_CHILDREN, MAX_PUBLIC_VALUES,
    MAX_WIRES,
};
use crate::block_v2::{
    machine::{
        program::{Program, Row, Val, Wire, LANES, PUBLICS_PER_ROW},
        symbolic, MachineAir, WIDTH,
    },
    profile::{self, Challenge, Config},
};
use core::mem::size_of;
use p3_air::{AirBuilder, ExtensionBuilder};
use p3_batch_stark::BatchProof;
use p3_field::BasedVectorSpace;
use p3_symmetric::MerkleCap;

type Proof = BatchProof<Config>;
type Digest = [Val; 4];
type Cap = MerkleCap<Val, Digest>;

pub(super) fn add(a: usize, b: usize) -> Result<usize, CompileError> {
    a.checked_add(b).ok_or(CompileError::ResourceAdmission(
        "registered shape size overflow",
    ))
}
fn mul(a: usize, b: usize) -> Result<usize, CompileError> {
    a.checked_mul(b).ok_or(CompileError::ResourceAdmission(
        "registered shape size overflow",
    ))
}
fn exact<T>(count: usize) -> Result<usize, CompileError> {
    mul(count, size_of::<T>())
}
fn capacity(n: usize) -> Result<usize, CompileError> {
    if n == 0 {
        Ok(0)
    } else {
        Ok(mul(n, 2)?.max(4))
    }
}
fn array<T>(n: usize) -> Result<usize, CompileError> {
    exact::<T>(capacity(n)?)
}
// Never invoke the selector: use inaccessible upstream nested element layouts
// without allocating a template just to discover its dimensions.
fn element_size<T>(_: for<'a> fn(&'a Proof) -> &'a Vec<T>) -> usize {
    size_of::<T>()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanningStorage {
    pub symbolic_workspace_bytes: usize,
    pub symbolic_retained_bytes: usize,
    pub template_retained_bytes: usize,
    pub template_construction_bytes: usize,
    pub input_backing_bytes: usize,
    pub returned_wire_bytes: usize,
    pub helper_bytes: usize,
    pub auxiliary_peak_bytes: usize,
    pub total_requested_bytes: usize,
}

impl PlanningStorage {
    /// Makes no allocation on success or error. All children are checked before
    /// any template or compiler is constructed, including later child shapes.
    pub fn for_children(
        outer_public_values: usize,
        children: &[RegisteredChildShape],
        construction: ConstructionLimits,
    ) -> Result<Self, CompileError> {
        if children.is_empty() || children.len() > MAX_CHILDREN {
            return Err(CompileError::Shape("registered shape child count"));
        }
        if outer_public_values > MAX_PUBLIC_VALUES
            || construction.max_requested_program_bytes == 0
            || construction.max_wires > MAX_WIRES
            || outer_public_values > construction.max_wires
            || construction.max_input_values > construction.max_wires - outer_public_values
        {
            return Err(CompileError::Shape(
                "registered shape construction geometry",
            ));
        }
        for &child in children {
            child.validate()?;
        }
        if !(cfg!(all(not(debug_assertions), target_arch = "x86_64"))
            && size_of::<Val>() == 8
            && size_of::<usize>() == 8
            && <Challenge as BasedVectorSpace<Val>>::DIMENSION == 3
            && matches!(LANES, 8 | 23)
            && WIDTH == 94
            && profile::LOG_BLOWUP == 4
            && profile::CAP_HEIGHT == 6
            && profile::NUM_QUERIES == 128
            && profile::NUM_RANDOM_CODEWORDS == 4)
        {
            return Err(CompileError::Unsupported(
                "registered shape storage profile",
            ));
        }
        let mut template_retained_bytes = 0;
        for &child in children {
            template_retained_bytes = template_retained_bytes.max(template_bytes(child)?);
        }
        // template::batch_from_geometry uses exact-length nested iterators and
        // vec![value; n]. A doubled allowed retained capacity covers each final
        // allocation; a second whole footprint covers old/new growth and the
        // one cloned row/column used to initialize nested vectors. No template
        // clones or multiple child templates coexist. widths[5] is separate.
        let widths = add(array::<Vec<usize>>(5)?, array::<usize>(32 + 4)?)?;
        let template_construction_bytes = add(mul(2, template_retained_bytes)?, widths)?;
        let limits = symbolic::verifier::Limits::default();
        let symbolic_workspace_bytes = limits.workspace();
        // Packed lookups and normalized final constraints coexist while
        // lowering. Normalization owns both graph nodes and root capacities.
        let symbolic_retained_bytes = add(limits.retained, symbolic::UNI_RETAINED_HOST_BYTES)?;
        let input_backing_bytes = mul(2, exact::<Val>(construction.max_input_values)?)?;
        let returned_wire_bytes = exact::<Wire>(construction.max_input_values)?;
        let helper_bytes = helpers()?;
        let auxiliary_peak_bytes = [
            symbolic_workspace_bytes,
            symbolic_retained_bytes,
            template_construction_bytes,
            input_backing_bytes,
            returned_wire_bytes,
            helper_bytes,
        ]
        .into_iter()
        .try_fold(0, add)?;
        let total_requested_bytes = add(
            construction.max_requested_program_bytes,
            auxiliary_peak_bytes,
        )?;
        Ok(Self {
            symbolic_workspace_bytes,
            symbolic_retained_bytes,
            template_retained_bytes,
            template_construction_bytes,
            input_backing_bytes,
            returned_wire_bytes,
            helper_bytes,
            auxiliary_peak_bytes,
            total_requested_bytes,
        })
    }
}

fn roots(log: usize) -> usize {
    1 << log.min(profile::CAP_HEIGHT)
}
fn path(log: usize) -> usize {
    log.saturating_sub(profile::CAP_HEIGHT)
}

fn template_bytes(child: RegisteredChildShape) -> Result<usize, CompileError> {
    let degree = child.height.ilog2() as usize + 1;
    let log_lde = degree + profile::LOG_BLOWUP;
    let q = 1 << (profile::LOG_BLOWUP + 1);
    // Source bounds, not maximum dimensions observed in sample compilations.
    let main = WIDTH;
    let pre = 200;
    let perm = 3 * (4 * LANES + child.public_values + 1);
    let mut bytes = mul(4, array::<Digest>(roots(log_lde))?)?;
    bytes = add(bytes, array::<usize>(1)?)?;
    bytes = add(
        bytes,
        mul(capacity(1)?, element_size(|p| &p.lookup_terminals))?,
    )?;
    bytes = add(
        bytes,
        mul(capacity(1)?, element_size(|p| &p.opened_values.instances))?,
    )?;
    for width in [main, pre, 3, perm, perm] {
        bytes = add(bytes, array::<Challenge>(width)?)?;
    }
    bytes = add(bytes, array::<Vec<Challenge>>(q)?)?;
    bytes = add(bytes, mul(q, array::<Challenge>(3)?)?)?;
    // Hiding extension openings: five rounds, quotient has q matrices, only
    // permutation has two points, preprocessing has no hiding suffix.
    bytes = add(bytes, array::<Vec<Vec<Vec<Challenge>>>>(5)?)?;
    for (matrices, points, suffix) in [(1, 1, 4), (1, 1, 4), (q, 1, 4), (1, 1, 0), (1, 2, 4)] {
        bytes = add(bytes, array::<Vec<Vec<Challenge>>>(matrices)?)?;
        let one = add(
            array::<Vec<Challenge>>(points)?,
            mul(points, array::<Challenge>(suffix)?)?,
        )?;
        bytes = add(bytes, mul(matrices, one)?)?;
    }
    bytes = add(bytes, array::<Cap>(degree)?)?;
    for r in 0..degree {
        bytes = add(bytes, array::<Digest>(roots(log_lde - r - 1))?)?;
    }
    bytes = add(bytes, array::<Val>(degree)?)?;
    bytes = add(bytes, array::<Challenge>(1)?)?;
    bytes = add(
        bytes,
        mul(
            capacity(profile::NUM_QUERIES)?,
            element_size(|p| &p.opening_proof.1.query_proofs),
        )?,
    )?;
    let mut query = mul(
        capacity(5)?,
        element_size(|p| &p.opening_proof.1.query_proofs[0].input_proof),
    )?;
    for (matrices, width, suffix) in [
        (1, 3, 4),
        (1, main, 4),
        (q, 3, 4),
        (1, pre, 0),
        (1, perm, 4),
    ] {
        query = add(query, array::<Vec<Val>>(matrices)?)?;
        query = add(query, mul(matrices, array::<Val>(width + suffix)?)?)?;
        query = add(query, array::<Vec<Val>>(matrices)?)?;
        query = add(query, mul(matrices, array::<Val>(4)?)?)?;
        query = add(query, array::<Digest>(path(log_lde))?)?;
    }
    query = add(
        query,
        mul(
            capacity(degree)?,
            element_size(|p| &p.opening_proof.1.query_proofs[0].commit_phase_openings),
        )?,
    )?;
    for r in 0..degree {
        query = add(query, array::<Challenge>(1)?)?;
        query = add(query, array::<Vec<Val>>(1)?)?;
        query = add(query, array::<Val>(4)?)?;
        query = add(query, array::<Digest>(path(log_lde - r - 1))?)?;
    }
    add(bytes, mul(profile::NUM_QUERIES, query)?)
}

fn helpers() -> Result<usize, CompileError> {
    type B = symbolic::Builder;
    type E = <B as ExtensionBuilder>::ExprEF;
    // MachineAir emits 4*LANES+publics width-two interactions. LogUp resolves
    // one fraction at a time: 2n element expressions, n multiplicities, n
    // denominator terms, prefix[n+1], suffix[n+1], and n Vec headers. Factor
    // four covers vector capacity and growth overlap; Arc children are already
    // charged by the bounded recorder. The AIR itself uses stack arrays and
    // shared (not cloned-backing) symbolic windows, and has no periodic table.
    let n = 4 * LANES + MAX_PUBLIC_VALUES;
    let mut bytes = exact::<E>(4 * (6 * n + 2))?;
    bytes = add(bytes, exact::<Vec<E>>(4 * n)?)?;
    // Shape inspection/lookup-name comparisons and source lookup degree loops.
    bytes = add(bytes, exact::<usize>(4 * n)?)?;
    bytes = add(bytes, exact::<u8>(4 * n * 64)?)?;
    // Empty shape: exact public reference/defined/row buffers and Arc<Program>.
    // No trace-height-sized allocation occurs. Include complete inline owners.
    bytes = add(bytes, exact::<u32>(MAX_PUBLIC_VALUES)?)?;
    bytes = add(bytes, exact::<bool>(MAX_PUBLIC_VALUES)?)?;
    bytes = add(
        bytes,
        exact::<Row>(MAX_PUBLIC_VALUES.div_ceil(PUBLICS_PER_ROW))?,
    )?;
    bytes = add(
        bytes,
        size_of::<Program>()
            + 4 * size_of::<usize>()
            + size_of::<MachineAir>()
            + size_of::<Proof>(),
    )?;
    // Quotient Vec headers, transcript buffers, bit sampling, fixed helper
    // vectors. All large scratch/memo/hint backing is inside ConstructionLimits;
    // all ProofInputs return payload is counted cumulatively above.
    bytes = add(bytes, exact::<Vec<[Wire; 3]>>(4 * 32)?)?;
    bytes = add(bytes, exact::<Wire>(4 * (4 + 8 + 64))?)?;
    // One CPU folding permutation set (4x8 initial/final and 22 internal),
    // conservatively four sets including constructors and scalar helpers.
    bytes = add(bytes, exact::<Val>(4 * (4 * 8 + 4 * 8 + 22))?)?;
    bytes = add(bytes, exact::<Vec<Val>>(4 * 3)?)?;
    // Keep the trait-associated base-expression layout part of the derivation
    // even when a future helper resolves a base buffer before extension lift.
    add(bytes, exact::<<B as AirBuilder>::Expr>(4 * 2 * n)?)
}
