use super::*;
use std::path::Path;

/// Only independent reconstruction plus numerical verification can create this
/// owner. It retains the actual bounded final proof, available for transport.
pub struct VerifiedAggregate { artifact: AggregateArtifact }
impl VerifiedAggregate {
    pub fn artifact(&self) -> &AggregateArtifact { &self.artifact }
    pub fn into_artifact(self) -> AggregateArtifact { self.artifact }
}
pub struct Outcome {
    pub aggregate: VerifiedAggregate,
    pub report: Report,
}

fn slots<T>(count: usize) -> Result<Vec<T>, Failure> {
    if count > MAX_CHILDREN { return Err(Failure::new("ownership", "fixed slot count")); }
    let mut owners = Vec::new();
    owners.try_reserve_exact(count).map_err(|_| Failure::new("ownership", "bounded owner allocation"))?;
    if owners.capacity() != count { return Err(Failure::new("ownership", "owner capacity")); }
    Ok(owners)
}
fn initial_shapes() -> [RegisteredChildShape; MAX_CHILDREN] {
    [RegisteredChildShape { public_values: PUBLICS, height: 8, preprocessing_cap_roots: ROOTS }; MAX_CHILDREN]
}

fn genuine_preflight(input: &BatchInput, budget: &bounds::Budget, report: &mut Report)
    -> Result<([Option<compiler::Identity>; MAX_CHILDREN], compiler::Bound), Failure> {
    let started = Instant::now();
    let mut identities = [None; MAX_CHILDREN];
    let mut shapes = initial_shapes();
    // One full compiler owner exists at a time. Retaining all private witnesses
    // permits exact pre-dispatch planning without retaining N whole programs.
    for (index, (statement, witness)) in input.expected.statements.iter().zip(&input.witnesses).enumerate() {
        budget.compiler()?;
        crate::ring::check_relation(statement, witness, input.expected.context)
            .map_err(|_| Failure::new("batch", "native differential relation"))?;
        let compiled = compiler::genuine_leaf(statement, witness, input.expected.context, budget)?;
        budget.evaluation()?;
        attempt("leaf_constraints", || compiled.program.check_host_constraints(&compiled.public, &compiled.inputs.0)
            .map_err(|_| Failure::new("leaf_constraints", "complete native relation rejected")))?;
        shapes[index] = compiler::shape(&compiled)?;
        identities[index] = Some(compiler::Identity::from(&compiled)?);
        runtime::preflight(&compiled, budget)?;
        drop(compiled);
    }
    report.compilation_ns += started.elapsed().as_nanos();
    let source_started = Instant::now();
    let bound = compiler::preflight(&shapes[..input.expected.selection.transactions()], budget)?;
    report.source_planning_ns += source_started.elapsed().as_nanos();
    report.source = Some(bound.report);
    Ok((identities, bound))
}

fn expected_preflight(expected: &ExpectedBatch, budget: &bounds::Budget, report: &mut Report)
    -> Result<([Option<compiler::Identity>; MAX_CHILDREN], compiler::Bound), Failure> {
    let started = Instant::now();
    let mut identities = [None; MAX_CHILDREN];
    let mut shapes = initial_shapes();
    for (index, statement) in expected.statements.iter().enumerate() {
        let compiled = compiler::expected_leaf(statement, expected.context, budget)?;
        shapes[index] = compiler::shape(&compiled)?;
        identities[index] = Some(compiler::Identity::from(&compiled)?);
        runtime::preflight(&compiled, budget)?;
        drop(compiled);
    }
    report.compilation_ns += started.elapsed().as_nanos();
    let started = Instant::now();
    let bound = compiler::preflight(&shapes[..expected.selection.transactions()], budget)?;
    report.source_planning_ns += started.elapsed().as_nanos();
    Ok((identities, bound))
}

fn reconstruct_sources(expected: &ExpectedBatch, identities: &[Option<compiler::Identity>; MAX_CHILDREN],
    budget: &bounds::Budget, report: &mut Report, phase: &'static str) -> Result<Vec<PublicSource>, Failure> {
    let mut sources = slots(expected.selection.transactions())?;
    for (index, statement) in expected.statements.iter().enumerate() {
        let started = Instant::now();
        let compiled = compiler::expected_leaf(statement, expected.context, budget)?;
        if Some(compiler::Identity::from(&compiled)?) != identities[index] {
            return Err(Failure::new("public_reconstruction", "independent full program mismatch"));
        }
        report.compilation_ns += started.elapsed().as_nanos();
        let (source, observation) = runtime::setup(compiled, budget, phase, Some(index))?;
        report.push(observation)?;
        sources.push(source);
    }
    Ok(sources)
}

fn independent(mut artifact: AggregateArtifact, expected: &ExpectedBatch, budget: &bounds::Budget,
    report: &mut Report) -> Result<VerifiedAggregate, Failure> {
    artifact.check_expected(expected).map_err(|_| Failure::new("final_verification", "expected batch envelope"))?;
    // Rebuild every source from the independent expected statements. No caller
    // key, producer program, retained cap or prior report is accepted here.
    let (identities, bound) = expected_preflight(expected, budget, report)?;
    let sources = reconstruct_sources(expected, &identities, budget, report, "final_independent_child_source")?;
    let started = Instant::now();
    let compiled = compiler::expected_aggregate(expected, &sources, &bound, budget)?;
    report.compilation_ns += started.elapsed().as_nanos();
    let claimed_id = artifact.descriptor().registered_program_id;
    artifact.check_descriptor(compiler::descriptor(&compiled.program, compiled.manifest, claimed_id))
        .map_err(|_| Failure::new("final_verification", "reconstructed root manifest and geometry"))?;
    // The bound Program now contains all authenticated child caps and expected
    // constants. No old key owner need overlap independent root registration.
    drop(sources);
    let (source, phase) = runtime::setup(compiled, budget, "final_independent_root_source", None)?;
    report.push(phase)?;
    artifact.check_descriptor(source.descriptor)
        .map_err(|_| Failure::new("final_verification", "independent root registration identity"))?;
    report.envelope_rejections += artifact.probe_envelopes(expected, source.descriptor)
        .map_err(|_| Failure::new("final_verification", "forged envelope accepted"))?;
    runtime::verify_and_probe(&source.verifier, artifact.proof_mut(), expected.public, report)?;
    report.independent_final_cpu_acceptances += 1;
    drop(source);
    Ok(VerifiedAggregate { artifact })
}

/// Verify a bounded aggregate against separately supplied expected statements.
/// This creates fresh public-only setups, retires them, then verifies on CPU.
/// No proof generation is claimed by this entry point.
pub fn verify_independently(artifact: AggregateArtifact, expected: ExpectedBatch) -> Result<Outcome, Failure> {
    let started = Instant::now();
    runtime::request()?;
    let budget = bounds::Budget::new(&expected, 0)?;
    let mut report = Report::new(expected.selection)?;
    report.scope = "independent direct-ring N3/N4 aggregate verification";
    report.proof_generation = "external artifact; no proving";
    report.storage = Some(budget.report);
    let attempted = independent(artifact, &expected, &budget, &mut report);
    drop(expected);
    drop(budget);
    report.owned_workflow_ns = started.elapsed().as_nanos();
    match attempted {
        Ok(aggregate) => Ok(Outcome { aggregate, report }),
        Err(mut failure) => { failure.progress = Some(report); Err(failure) }
    }
}

/// Create N whole direct-ring proofs and one genuine recursive aggregate;
/// independently verify the children, round-trip the root through a new disk
/// artifact, reconstruct all final keys independently, and return the verified
/// owned artifact. Every selected configuration is admitted before child0.
pub fn prove_complete(input: BatchInput, artifact_path: &Path) -> Result<Outcome, Failure> {
    let started = Instant::now();
    runtime::request()?;
    let budget = bounds::Budget::new(&input.expected, input.witnesses.capacity())?;
    let mut report = Report::new(input.expected.selection)?;
    report.storage = Some(budget.report);
    let attempted = prove_inner(input, artifact_path, &budget, &mut report);
    drop(budget);
    report.owned_workflow_ns = started.elapsed().as_nanos();
    match attempted {
        Ok(aggregate) => Ok(Outcome { aggregate, report }),
        Err(mut failure) => { failure.progress = Some(report); Err(failure) }
    }
}

fn prove_inner(input: BatchInput, artifact_path: &Path, budget: &bounds::Budget,
    report: &mut Report) -> Result<VerifiedAggregate, Failure> {
    let (identities, bound) = genuine_preflight(&input, budget, report)?;
    budget.admit(artifact::aggregate::required_host_bytes()
        .map_err(|_| Failure::new("preflight", "artifact source storage"))?)?;
    // Validate fresh destination/access before any source setup or proof. The
    // original file owner survives until the bounded final write/read roundtrip.
    let destination = artifact::aggregate::prepare_destination(artifact_path, budget.active())
        .map_err(|_| Failure::new("preflight", "fresh bounded artifact destination"))?;
    let sources = reconstruct_sources(&input.expected, &identities, budget, report, "expected_child_source")?;
    let compilation_started = Instant::now();
    let expected_root = compiler::expected_aggregate(&input.expected, &sources, &bound, budget)?;
    let root_identity = compiler::Identity::from(&expected_root)?;
    // Full source, GPU proving, independent registration, CPU and codec plans
    // are now closed before the first native child proof can be dispatched.
    runtime::preflight(&expected_root, budget)?;
    drop(expected_root);
    report.compilation_ns += compilation_started.elapsed().as_nanos();
    let BatchInput { expected, witnesses } = input;
    let mut proofs = slots(expected.selection.transactions())?;
    for (index, witness) in witnesses.into_iter().enumerate() {
        let started = Instant::now();
        let compiled = compiler::genuine_leaf(&expected.statements[index], &witness, expected.context, budget)?;
        drop(witness);
        report.compilation_ns += started.elapsed().as_nanos();
        let identity = identities[index].ok_or_else(|| Failure::new("proving", "missing preflight identity"))?;
        let (mut proof, phase) = runtime::prove(compiled, identity, Some(&sources[index]), budget,
            "fresh_whole_transaction_proof", Some(index))?;
        report.push(phase)?;
        report.fresh_whole_transaction_proofs += 1;
        runtime::verify_and_probe(&sources[index].verifier, &mut proof.proof, sources[index].public, report)?;
        report.independent_child_cpu_acceptances += 1;
        report.public_setup_reused_for_child_cpu_checks += 1;
        proofs.push(proof);
    }
    let started = Instant::now();
    let compiled = compiler::genuine_aggregate(&expected, &sources, &proofs, &bound, budget)?;
    if compiler::Identity::from(&compiled)? != root_identity {
        return Err(Failure::new("aggregate_compilation", "actual proof source reconstruction mismatch"));
    }
    report.compilation_ns += started.elapsed().as_nanos();
    drop(proofs);
    drop(sources);
    let (root, phase) = runtime::prove(compiled, root_identity, None, budget, "fresh_fixed_aggregate_proof", None)?;
    report.push(phase)?;
    report.fresh_recursive_aggregate_proofs += 1;
    let artifact = AggregateArtifact::from_proof(&expected, root.descriptor, root.proof, budget.active())
        .map_err(|_| Failure::new("aggregate_artifact", "bounded final owner"))?;
    let (artifact, roundtrip) = artifact.disk_roundtrip(destination, budget.active())
        .map_err(|_| Failure::new("aggregate_artifact", "bounded final disk roundtrip"))?;
    report.artifact_roundtrip = Some(roundtrip);
    independent(artifact, &expected, budget, report)
}
