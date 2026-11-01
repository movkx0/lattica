//! Source-only original metadata and transient constructor requirements.
//! Blueprint queries reuse the prepared owner's admitted graph analysis.
//! Bootstrap frames cover first initialization and pure numerical queries.
use super::*;
use crate::graph_tree::owned_parent::*;
use lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind;

pub(super) fn source_native<'a_member>(member: &'a_member SourceRetained<PreparedWorkflowSources<'a_member>>,
    kind: GraphSourceKind) -> Result<ProducerRequirements> {
    use crate::{graph_tree::native_sources::NativeSourceBlueprint,
        spend_pipeline::full_workflow::{source_native::SourceNativeOperationPlan,
            source_native_compile::SourceNativeCompilePlan}};
    let p = member.get();
    let blueprint = NativeSourceBlueprint::new_for_prepared(p, kind)
        .map_err(|_| ClosureError::Source)?;
    Ok(ProducerRequirements { original: sum(
        SourceNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        SourceNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        NativeLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?,
        construction: SourceNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)? })
}

pub(super) fn affine<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_affine::AffineSource,
        graph_tree::affine_sources::AffineLeafBlueprint,
        spend_pipeline::full_workflow::{affine_native::AffineNativeOperationPlan,
            affine_native_compile::AffineNativeCompilePlan}};
    let source = AffineSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = AffineLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = AffineNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    Ok(ProducerRequirements { original: sum(
        AffineNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        AffineNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        AffineLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}

pub(super) fn ntt<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_ntt::NttSource,
        graph_tree::ntt_sources::NttLeafBlueprint,
        spend_pipeline::full_workflow::{ntt_native::NttNativeOperationPlan,
            ntt_native_compile::NttNativeCompilePlan}};
    let source = NttSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = NttLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = NttNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    let construction = maximum(construction,
        NttNativeOperationPlan::verification_planning_requirements(source.kind()).map_err(|_| ClosureError::Resource)?);
    Ok(ProducerRequirements { original: sum(
        NttNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        NttNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        NttLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}

pub(super) fn mul<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_mul::MulSource,
        graph_tree::mul_sources::MulLeafBlueprint,
        spend_pipeline::full_workflow::{mul_native::MulNativeOperationPlan,
            mul_native_compile::MulNativeCompilePlan}};
    let source = MulSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = MulLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = MulNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    let construction = maximum(construction,
        MulNativeOperationPlan::verification_planning_requirements(source.kind()).map_err(|_| ClosureError::Resource)?);
    Ok(ProducerRequirements { original: sum(
        MulNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        MulNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        MulLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}

pub(super) fn g_bound<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_g_bound::GBoundSource,
        graph_tree::g_bound_sources::GBoundLeafBlueprint,
        spend_pipeline::full_workflow::{g_bound_native::GBoundNativeOperationPlan,
            g_bound_native_compile::GBoundNativeCompilePlan}};
    let source = GBoundSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = GBoundLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = GBoundNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    Ok(ProducerRequirements { original: sum(
        GBoundNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        GBoundNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        GBoundLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}

pub(super) fn permutation<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_permutation::PermutationSource,
        graph_tree::permutation_sources::PermutationLeafBlueprint,
        spend_pipeline::full_workflow::{permutation_native::PermutationNativeOperationPlan,
            permutation_native_compile::PermutationNativeCompilePlan}};
    let source = PermutationSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = PermutationLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = PermutationNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    let construction = maximum(construction,
        PermutationNativeOperationPlan::verification_planning_requirements(source.kind()).map_err(|_| ClosureError::Resource)?);
    Ok(ProducerRequirements { original: sum(
        PermutationNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        PermutationNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        PermutationLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}

pub(super) fn linear_map<'a>(member: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize)
    -> Result<ProducerRequirements> {
    use crate::{graph_proofs::owned_linear_map::LinearMapSource,
        graph_tree::linear_map_sources::LinearMapLeafBlueprint,
        spend_pipeline::full_workflow::{linear_map_native::LinearMapNativeOperationPlan,
            linear_map_native_compile::LinearMapNativeCompilePlan}};
    let source = LinearMapSource::from_original(member, ordinal).map_err(|_| ClosureError::Source)?;
    let p = member.get();
    let blueprint = LinearMapLeafBlueprint::new(p.plan(), p.graph(), p.context(), source)
        .map_err(|_| ClosureError::Source)?;
    let construction = LinearMapNativeCompilePlan::planning_requirements(&blueprint).map_err(|_| ClosureError::Resource)?;
    let construction = maximum(construction,
        LinearMapNativeOperationPlan::verification_planning_requirements(source.kind()).map_err(|_| ClosureError::Resource)?);
    Ok(ProducerRequirements { original: sum(
        LinearMapNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?, sum(
        LinearMapNativeCompilePlan::metadata_requirements().map_err(|_| ClosureError::Resource)?,
        LinearMapLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?)?, construction })
}
