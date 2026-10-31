//! Reservations derived from the maintained bounded final compiler and real
//! registered-machine verifier. Observing an allocated output never admits it.
use super::*;
use lattica_prover_p3::{
    block_v2::profile,
    proving::{operation_storage::RawPreparationReportStorage, Report, Request},
};

const COMPILER_BYTES: usize = 2 << 30;
const AUXILIARY_BYTES: usize = 512 << 20;
const INPUT_VALUES: usize = 1 << 20;
const MAX_CHILD_CAP_ROOTS: usize = 1 << profile::CAP_HEIGHT;

pub(super) fn cap_roots(rows: usize) -> OwnedResult<usize> {
    if !(8..=ROW_LIMIT).contains(&rows) || !rows.is_power_of_two() {
        return Err(FinalFailure::Source);
    }
    Ok(1usize << (rows.ilog2() as usize + 1 + profile::LOG_BLOWUP)
        .min(profile::CAP_HEIGHT))
}

/// Child numerical verification may run before or during compilation. Enumerate
/// every permitted height for BOTH actual public widths. The original child
/// proofs/keys remain separately charged; no 64 MiB allowance substitutes for
/// this independent metadata/scratch lifecycle census.
pub(super) fn child_verifier() -> OwnedResult<Requirements> {
    let mut maximum = 0;
    for public in [crate::graph_tree::PUBLIC_VALUES, PUBLIC_VALUES] {
        for log in 3..=20 {
            let rows = 1usize << log;
            let cap = cap_roots(rows)?;
            let next = RegisteredVerifier::host_reservation_bytes(public, rows, cap, cap)
                .map_err(|_| FinalFailure::Source)?;
            maximum = maximum.max(next);
        }
    }
    requirement(Category::IndependentVerifier, maximum)
}

pub(super) fn forwarding_frames() -> OwnedResult<usize> {
    [
        bytes::<FinalCompileOperation<'static, 'static, 'static>>(8)?,
        bytes::<FinalOuterOperation<'static, 'static>>(8)?,
        // Complete-driver constructor refusals retain the original inputs;
        // charge both actual tuple and complete success/refusal Result shells.
        bytes::<(FinalFailure, [FinalChild<'static, 'static>; 2])>(8)?,
        bytes::<core::result::Result<FinalCompileOperation<'static, 'static, 'static>,
            (FinalFailure, [FinalChild<'static, 'static>; 2])>>(8)?,
        bytes::<(FinalFailure, Retained<FinalCompiled<'static>>)>(8)?,
        bytes::<core::result::Result<FinalOuterOperation<'static, 'static>,
            (FinalFailure, Retained<FinalCompiled<'static>>)>>(8)?,
        bytes::<OwnedResult<PhaseBinding>>(8)?,
        bytes::<FinalVerifyOperation<'static, 'static, 'static>>(8)?,
        bytes::<FinalCompiled<'static>>(8)?, bytes::<FinalNode<'static>>(8)?,
        bytes::<FinalVerification<'static, 'static>>(8)?,
        bytes::<[FinalChild<'static, 'static>; 2]>(8)?,
        bytes::<[Option<GraphChild<'static>>; 2]>(8)?,
        bytes::<[ChildRef<'static>; 2]>(8)?,
        bytes::<CompiledNode>(8)?, bytes::<BatchKey>(8)?, bytes::<BatchProof>(8)?,
        bytes::<RawProof<Config>>(8)?, bytes::<RegisteredProgram>(8)?,
        bytes::<RegisteredVerifier>(8)?, bytes::<Report>(8)?, bytes::<Request>(8)?,
        bytes::<FinalReport>(8)?, bytes::<Requirements>(16)?,
        bytes::<OwnedResult<FinalNode<'static>>>(8)?,
        bytes::<OwnedResult<FinalCompiled<'static>>>(8)?,
        bytes::<OwnedResult<FinalVerification<'static, 'static>>>(8)?,
        bytes::<String>(8)?, bytes::<[usize; 32]>(8)?,
        crate::execution::workflow_resources::final_report_transport_host_bytes(),
        qualification::planning_frames()?,
    ].into_iter().try_fold(64 << 10, add)
}

pub(super) fn failure() -> OwnedResult<Requirements> {
    requirement(Category::Report,
        add(bytes::<crate::execution::workflow_resources::PhaseFailure<FinalFailure>>(8)?,
            bytes::<FinalFailure>(16)?)?)
}

pub(super) fn compiler_output(merge: &MergeSource) -> OwnedResult<Requirements> {
    if merge.maximum_inputs() > INPUT_VALUES { return Err(FinalFailure::Source); }
    // ConstructionLimits accounts Program and all nested requested capacity.
    // ProofInputs grows geometrically; at most twice its source input ceiling.
    // There are exactly two optional fixed recursive-witness targets.
    let input = [
        bytes::<Val>(mul(2, merge.maximum_inputs())?)?,
        bytes::<RecursiveWitnessTarget>(4)?,
    ].into_iter().try_fold(0, add)?;
    let program = [
        COMPILER_BYTES,
        bytes::<std::sync::atomic::AtomicUsize>(2)?,
        core::mem::align_of::<Program>(),
        bytes::<Retained<FinalCompiled<'static>>>(8)?,
    ].into_iter().try_fold(0, add)?;
    combine(&[requirement(Category::SymbolicCompiler, program)?,
        requirement(Category::CompilerInputs, input)?])
}

pub(super) fn check_compiler(merge: &MergeSource, node: &CompiledNode) -> OwnedResult<()> {
    merge.check_program(&node.program).map_err(|_| FinalFailure::Source)?;
    if node.witness.len() != node.program.witness_values()
        || node.witness.capacity() > mul(2, merge.maximum_inputs())?
        || node.recursive_witness_targets.len() > 2
        || node.recursive_witness_targets.capacity() > 4
    { return Err(FinalFailure::Capacity); }
    Ok(())
}

/// gpu_merge_root hashes graph leaves of six words and one node of 6+4+4
/// words. Mirror native_gpu::operations_hash::field_chunk_staging_bytes.
pub(super) fn preparation_backend() -> Bytes {
    Bytes { host: (14 + 9) * 8, device: 8 << 30 }
}
pub(super) fn compiler_scratch(merge: &MergeSource) -> OwnedResult<Requirements> {
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
        PlanningStorage, RegisteredChildShape,
    };
    let shapes = merge.children().map(|child| RegisteredChildShape {
        public_values: match child {
            ChildSource::Graph(_) => crate::graph_tree::PUBLIC_VALUES,
            ChildSource::Merge(_) => PUBLIC_VALUES,
        },
        height: ROW_LIMIT,
        preprocessing_cap_roots: MAX_CHILD_CAP_ROOTS,
    });
    let storage = PlanningStorage::for_children(PUBLIC_VALUES, &shapes, merge.construction())
        .map_err(|_| FinalFailure::Source)?;
    if storage.auxiliary_peak_bytes > AUXILIARY_BYTES
        || storage.input_backing_bytes > bytes::<Val>(mul(2, merge.maximum_inputs())?)?
    { return Err(FinalFailure::Capacity); }
    let raw_report = RawPreparationReportStorage::new().map_err(|_| FinalFailure::Source)?;
    let prefix_words = add(mul(mul(4, MAX_CHILD_CAP_ROOTS)?, 4)?, 6)?;
    let local = [
        // Complete compiler/template temporary owner, not unused output credit.
        AUXILIARY_BYTES,
        bytes::<Val>(mul(2, prefix_words)?)?,
        bytes::<u64>(2 * 2 * 6 + 2 * 14)?,
        bytes::<Vec<Val>>(8)?, bytes::<Vec<u64>>(8)?,
        bytes::<[LeafStatement; 4]>(4)?,
        forwarding_frames()?,
    ].into_iter().try_fold(0, add)?;
    combine(&[
        requirement(Category::PhaseScratch, local)?,
        requirement(Category::Report, raw_report.required_host_bytes)?,
        child_verifier()?,
        crate::execution::workflow_resources::final_compile_issuer_requirements()
            .map_err(|_| FinalFailure::Source)?,
    ])
}

pub(super) fn outer_output(merge: &MergeSource)
    -> OwnedResult<(Requirements, Requirements)>
{
    let f = merge.outer_shape().and_then(|shape| shape.output_footprint().map_err(err))
        .map_err(|_| FinalFailure::Source)?;
    if f.public_values != PUBLIC_VALUES as u64 || !f.producer_backing_bound_complete {
        return Err(FinalFailure::Source);
    }
    let inline = bytes::<Retained<FinalNode<'static>>>(8)?;
    let proof = add(usize::try_from(f.proof_backing_ceiling_host_bytes)
        .map_err(|_| FinalFailure::Overflow)?, inline)?;
    let key = [
        usize::try_from(f.verifier_metadata_retained_host_bytes).map_err(|_| FinalFailure::Overflow)?,
        usize::try_from(f.copied_key_cap_host_bytes).map_err(|_| FinalFailure::Overflow)?,
        bytes::<std::sync::atomic::AtomicUsize>(2)?,
        core::mem::align_of::<RegisteredVerifier>(), inline,
    ].into_iter().try_fold(0, add)?;
    Ok((combine(&[requirement(Category::RecursiveProof, proof)?,
        requirement(Category::RegisteredMetadata, key)?])?,
        requirement(Category::IndependentVerifier,
            usize::try_from(f.verifier_lifecycle_peak_host_bytes).map_err(|_| FinalFailure::Overflow)?)?))
}

pub(super) fn outer_scratch(merge: &MergeSource) -> OwnedResult<Requirements> {
    let (_, verifier) = outer_output(merge)?;
    combine(&[
        verifier,
        requirement(Category::PhaseScratch, add(forwarding_frames()?,
            usize::try_from(crate::execution::workflow_resources::final_outer_forwarding_host_bytes()
                .map_err(|_| FinalFailure::Source)?).map_err(|_| FinalFailure::Overflow)?)?)?,
        requirement(Category::Report, usize::try_from(crate::execution::outer_report::required_host_bytes()
            .map_err(|_| FinalFailure::Source)?).map_err(|_| FinalFailure::Overflow)?)?,
        PreissuedFinalOuter::planning_scratch_requirement()?,
    ])
}

pub(super) fn verification_output() -> OwnedResult<Requirements> {
    requirement(Category::Report, bytes::<Retained<FinalVerification<'static, 'static>>>(8)?)
}
pub(super) fn verification_scratch(merge: &MergeSource) -> OwnedResult<Requirements> {
    let (_, verifier) = outer_output(merge)?;
    // expected_public recurses at most three levels for N3/N4. Each frame owns
    // at most a doubled 14-word field vector; charge all seven possible nodes.
    combine(&[verifier, qualification::requirements(merge)?, requirement(Category::PhaseScratch,
        add(forwarding_frames()?, bytes::<u64>(7 * 2 * 14)?)?)?,
        crate::execution::workflow_resources::final_verify_issuer_requirements()
            .map_err(|_| FinalFailure::Source)?])
}

pub(super) fn check_node(node: &FinalNode<'_>, plan: &FinalPhasePlan<'_>,
    ordinal: usize) -> OwnedResult<()>
{
    let source = plan.source;
    if !core::ptr::eq(node.source, source) || node.merge != ordinal {
        return Err(FinalFailure::Authority);
    }
    let merge = source.merge(ordinal).ok_or(FinalFailure::Order)?;
    let key = &node.node.key;
    if !key.spec.plan.same_scope(source.scope())
        || (key.spec.first as usize, key.spec.count as usize) != merge.span()
        || key.height > merge.rows().1
    { return Err(FinalFailure::Coverage); }
    let roots = cap_roots(key.height)?;
    if key.cap.len() != roots || key.cap.capacity() > roots {
        return Err(FinalFailure::Capacity);
    }
    let output = plan.phase_facts(2 * ordinal + 1).ok_or(FinalFailure::Order)?.output;
    let proof_limit = usize::try_from(output.get(Category::RecursiveProof).host)
        .map_err(|_| FinalFailure::Overflow)?;
    let backing = lattica_prover_p3::block_v2::machine::backend::retained_proof_capacity_bytes(
        &node.node.proof.proof, proof_limit).map_err(|_| FinalFailure::Capacity)?;
    if add(backing, size_of::<FinalNode<'_>>())? > proof_limit {
        return Err(FinalFailure::Capacity);
    }
    let key_bytes = [bytes::<[Val; 4]>(key.cap.capacity())?, key.verifier.cached_metadata_bytes(),
        bytes::<std::sync::atomic::AtomicUsize>(2)?, core::mem::align_of::<RegisteredVerifier>(),
        size_of::<FinalNode<'_>>()].into_iter().try_fold(0, add)?;
    if key_bytes as u64 > output.get(Category::RegisteredMetadata).host {
        return Err(FinalFailure::Capacity);
    }
    Ok(())
}
