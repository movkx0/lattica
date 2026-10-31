use super::*;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SourceReport {
    pub children: usize,
    pub scalar_operations_upper_bound: usize,
    pub cubic_operations_upper_bound: usize,
    pub poseidon_operations_upper_bound: usize,
    pub active_rows_upper_bound: usize,
    pub padded_rows_upper_bound: usize,
    pub wires_upper_bound: usize,
    pub input_values_upper_bound: usize,
    pub construction_reserved_bytes: usize,
    pub source_closed_before_setup: bool,
}
pub(super) struct Bound {
    pub report: SourceReport,
    shapes: [RegisteredChildShape; MAX_CHILDREN],
    operations: OperationCounts,
    storage: PlanningStorage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub descriptor: artifact::ProofDescriptor,
    pub retained_program_bytes: usize,
    pub construction_peak_bytes: usize,
}
impl Identity {
    pub fn from(compiled: &Compiled) -> Result<Self, Failure> {
        Ok(Self { descriptor: descriptor(&compiled.program, compiled.manifest, [0; 4]),
            retained_program_bytes: compiled.program.retained_host_bytes()
                .map_err(|_| Failure::new("compiler", "program capacity"))?,
            construction_peak_bytes: compiled.program.construction_host_bytes() })
    }
}
pub(super) fn descriptor(program: &Program, manifest: [u8; 32], id: [u64; 4]) -> artifact::ProofDescriptor {
    artifact::ProofDescriptor { active_rows: program.active_rows() as u64,
        padded_rows: program.height() as u64, wires: program.wire_count() as u64,
        witness_values: program.witness_values() as u64,
        canonical_manifest_digest: manifest, registered_program_id: id }
}
pub(super) fn shape(compiled: &Compiled) -> Result<RegisteredChildShape, Failure> {
    let height = compiled.program.height();
    if compiled.program.public_values() != PUBLICS || !(8..=MAX_ROWS).contains(&height)
        || !height.is_power_of_two() || compiled.program.witness_values() != compiled.inputs.0.len() {
        return Err(Failure::new("compiler", "registered geometry"));
    }
    let roots = 1 << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    if roots != ROOTS { return Err(Failure::new("compiler", "registered cap geometry")); }
    Ok(RegisteredChildShape { public_values: PUBLICS, height, preprocessing_cap_roots: roots })
}

fn complete(program: Program, inputs: Vec<Val>, public: [Val; PUBLICS], maximum_inputs: usize,
    budget: &bounds::Budget) -> Result<Compiled, Failure> {
    // The planner sees the full fixed input capacity before any dispatch. This
    // bounds genuine-vs-synthetic Vec growth; all actual inputs stay secret.
    let mut inputs = SecretInputs(inputs);
    budget.admit(sum(&[PROGRAM_BYTES, 2 * maximum_inputs * size_of::<Val>()])?)?;
    if inputs.0.len() != program.witness_values() || inputs.0.capacity() > maximum_inputs {
        return Err(Failure::new("compiler", "input capacity"));
    }
    inputs.0.try_reserve_exact(maximum_inputs - inputs.0.len())
        .map_err(|_| Failure::new("compiler", "bounded input reserve"))?;
    if inputs.0.capacity() != maximum_inputs { return Err(Failure::new("compiler", "input reserve drift")); }
    let manifest = proving::canonical_manifest_digest(&program)
        .map_err(|_| Failure::new("compiler", "canonical manifest"))?;
    let compiled = Compiled { program: Arc::new(program), inputs, public, manifest };
    shape(&compiled)?;
    if compiled.program.retained_host_bytes().map_err(|_| Failure::new("compiler", "program capacity"))? > PROGRAM_BYTES {
        return Err(Failure::new("compiler", "program allowance"));
    }
    Ok(compiled)
}

fn from_relation(relation: CompiledRelation, statement: &Statement, budget: &bounds::Budget) -> Result<Compiled, Failure> {
    let CompiledRelation { program, witness, public, summary } = relation;
    let witness = SecretInputs(witness);
    if summary.deferred_crypto_obligations != 0 || summary.representation != REPRESENTATION.name()
        || summary.active_rows != program.active_rows() || summary.padded_rows != program.height()
        || summary.wires != program.wire_count() || summary.witness_values != program.witness_values()
        || public != artifact::statement_binding(statement) {
        return Err(Failure::new("compiler", "whole relation conformance"));
    }
    let mut witness = witness;
    complete(program, std::mem::take(&mut witness.0), public, CAPACITY.limits().input_limit, budget)
}
pub(super) fn genuine_leaf(statement: &Statement, witness: &Witness, context: Context,
    budget: &bounds::Budget) -> Result<Compiled, Failure> {
    let allowance = budget.compiler()?;
    let relation = attempt("leaf_compilation", || {
        super::super::compile_with_representation_diagnostics(statement, witness, context,
            CAPACITY, REPRESENTATION, allowance)
            .map_err(|_| Failure::new("leaf_compilation", "bounded full relation compiler"))
    })?;
    from_relation(relation, statement, budget)
}
pub(super) fn expected_leaf(statement: &Statement, context: Context,
    budget: &bounds::Budget) -> Result<Compiled, Failure> {
    let allowance = budget.compiler()?;
    let relation = verification::reconstruction::compile_in_partition(statement, context,
        CAPACITY, REPRESENTATION, allowance)
        .map_err(|_| Failure::new("public_reconstruction", "bounded expected relation"))?;
    from_relation(relation, statement, budget)
}

pub(super) fn preflight(shapes: &[RegisteredChildShape], budget: &bounds::Budget) -> Result<Bound, Failure> {
    if !matches!(shapes.len(), 3 | 4) { return Err(Failure::new("source", "exact N3/N4")); }
    let storage = PlanningStorage::for_children(PUBLICS, shapes, construction())
        .map_err(|_| Failure::new("source", "planning storage"))?;
    budget.admit(storage.total_requested_bytes)?;
    let source_storage = fixed_batch::Storage::new(shapes, construction())
        .map_err(|_| Failure::new("source", "reconstruction storage"))?;
    budget.admit(source_storage.required_bytes())?;
    let core = attempt("source_geometry", || {
        shape::verifier_core_bound(PUBLICS, shapes, construction(), storage.auxiliary_peak_bytes)
            .map_err(|_| Failure::new("source_geometry", "bounded verifier core"))
    })?;
    if core.storage != storage { return Err(Failure::new("source", "planner storage drift")); }
    let operations = core.operations.with_overhead(fixed_batch::binding_overhead(shapes.len())
        .map_err(|_| Failure::new("source", "binding source"))?)
        .map_err(|_| Failure::new("source", "operation bound"))?;
    let active = operations.active_rows(PUBLICS).map_err(|_| Failure::new("source", "active rows"))?;
    let padded = operations.padded_rows(PUBLICS).map_err(|_| Failure::new("source", "padded rows"))?;
    let wires = core.wire_upper_bound.checked_add(PUBLICS * (shapes.len() + 1))
        .ok_or_else(|| Failure::new("source", "wire overflow"))?;
    if padded > MAX_ROWS || wires > MAX_WIRES || core.input_values_upper_bound > MAX_INPUTS {
        return Err(Failure::new("source", "fixed flat aggregate does not close"));
    }
    let mut saved = [shapes[0]; MAX_CHILDREN];
    saved[..shapes.len()].copy_from_slice(shapes);
    Ok(Bound { shapes: saved, operations, storage, report: SourceReport {
        children: shapes.len(), scalar_operations_upper_bound: operations.scalar,
        cubic_operations_upper_bound: operations.cubic, poseidon_operations_upper_bound: operations.poseidon,
        active_rows_upper_bound: active, padded_rows_upper_bound: padded, wires_upper_bound: wires,
        input_values_upper_bound: core.input_values_upper_bound,
        construction_reserved_bytes: source_storage.required_bytes(), source_closed_before_setup: true,
    } })
}

fn conform(program: &Program, bound: &Bound) -> Result<(), Failure> {
    let counts = OperationCounts::from_program(program);
    if counts.scalar > bound.operations.scalar || counts.cubic > bound.operations.cubic
        || counts.poseidon > bound.operations.poseidon || program.wire_count() > bound.report.wires_upper_bound
        || program.witness_values() > bound.report.input_values_upper_bound
        || program.active_rows() > bound.report.active_rows_upper_bound
        || program.height() > bound.report.padded_rows_upper_bound {
        return Err(Failure::new("aggregate_compilation", "source bound conformance"));
    }
    Ok(())
}
fn sources<'a>(expected: &ExpectedBatch, sources: &'a [PublicSource], bound: &Bound)
    -> Result<[fixed_batch::Child<'a>; MAX_CHILDREN], Failure> {
    let n = expected.selection.transactions();
    if sources.len() != n || bound.report.children != n { return Err(Failure::new("source", "source coverage")); }
    let mut children = [fixed_batch::Child { shape: sources[0].shape,
        preprocessing_cap: &sources[0].cap, public: sources[0].public }; MAX_CHILDREN];
    for (index, source) in sources.iter().enumerate() {
        if source.shape != bound.shapes[index] || source.public != artifact::statement_binding(&expected.statements[index]) {
            return Err(Failure::new("source", "expected child identity"));
        }
        children[index] = fixed_batch::Child { shape: source.shape, preprocessing_cap: &source.cap, public: source.public };
    }
    Ok(children)
}

pub(super) fn expected_aggregate(expected: &ExpectedBatch, source: &[PublicSource], bound: &Bound,
    budget: &bounds::Budget) -> Result<Compiled, Failure> {
    budget.admit(bound.report.construction_reserved_bytes)?;
    let children = sources(expected, source, bound)?;
    let program = attempt("aggregate_reconstruction", || {
        fixed_batch::reconstruct(expected.public, &children[..source.len()], construction(),
            bound.report.construction_reserved_bytes)
            .map_err(|_| Failure::new("aggregate_reconstruction", "bounded public source"))
    })?;
    conform(&program, bound)?;
    budget.admit(sum(&[PROGRAM_BYTES, 2 * MAX_INPUTS * size_of::<Val>()])?)?;
    let mut synthetic = Vec::new();
    synthetic.try_reserve_exact(MAX_INPUTS).map_err(|_| Failure::new("source", "synthetic input allocation"))?;
    if synthetic.capacity() != MAX_INPUTS || program.witness_values() > MAX_INPUTS {
        return Err(Failure::new("source", "synthetic input capacity"));
    }
    synthetic.resize(program.witness_values(), Val::ZERO);
    complete(program, synthetic, expected.public, MAX_INPUTS, budget)
}

pub(super) fn genuine_aggregate(expected: &ExpectedBatch, source: &[PublicSource], proof: &[OwnedProof],
    bound: &Bound, budget: &bounds::Budget) -> Result<Compiled, Failure> {
    budget.admit(bound.report.construction_reserved_bytes)?;
    let children = sources(expected, source, bound)?;
    if proof.len() != source.len() || proof.iter().zip(source).any(|(p,s)| p.descriptor != s.descriptor) {
        return Err(Failure::new("aggregate_compilation", "verified child coverage"));
    }
    let (program, mut inputs) = attempt("aggregate_compilation", || {
        let mut builder = ProgramBuilder::new_with_construction_limits(PUBLICS, construction())
            .map_err(|_| Failure::new("aggregate_compilation", "builder admission"))?;
        for (index, value) in expected.public.into_iter().enumerate() {
            let public = builder.public(index).map_err(|_| Failure::new("aggregate_compilation", "public wire"))?;
            let expected = builder.constant(value);
            builder.assert_equal(public, expected);
        }
        let mut inputs = ProofInputs::default();
        for (child, proof) in children[..proof.len()].iter().zip(proof) {
            let public = inputs.bases(&mut builder, &child.public)
                .map_err(|_| Failure::new("aggregate_compilation", "child public inputs"))?;
            for (&wire, value) in public.iter().zip(child.public) {
                let expected = builder.constant(value);
                builder.assert_equal(wire, expected);
            }
            let placeholder = builder.public(0).map_err(|_| Failure::new("aggregate_compilation", "cap placeholder"))?;
            let mut cap = [[placeholder; 4]; ROOTS];
            for (destination, digest) in cap.iter_mut().zip(child.preprocessing_cap) {
                *destination = digest.map(|word| builder.constant(word));
            }
            let empty = ProgramBuilder::new(PUBLICS).and_then(|b| b.finish(Some(child.shape.height)))
                .map_err(|_| Failure::new("aggregate_compilation", "child AIR"))?;
            let air = MachineAir::new(empty);
            batch::verify_with_bounded_cpu_symbolic(&mut builder, &mut inputs, &air,
                &public, &cap, &proof.proof)
                .map_err(|_| Failure::new("aggregate_compilation", "complete child verifier"))?;
        }
        let program = builder.finish(None).map_err(|_| Failure::new("aggregate_compilation", "program finalization"))?;
        Ok((program, inputs))
    })?;
    conform(&program, bound)?;
    let compiled = complete(program, std::mem::take(&mut inputs.values), expected.public, MAX_INPUTS, budget)?;
    budget.evaluation()?;
    attempt("aggregate_constraints", || compiled.program.check_host_constraints(&compiled.public, &compiled.inputs.0)
        .map_err(|_| Failure::new("aggregate_constraints", "genuine full verifier rejected")))?;
    Ok(compiled)
}
