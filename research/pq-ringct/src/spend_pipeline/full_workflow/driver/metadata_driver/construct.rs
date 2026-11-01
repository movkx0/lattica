use super::*;

/// All dependent owners remain in these scopes until the concrete continuation
/// completes workflow retirement and case completion.
pub(crate) fn run<const N: usize>(
    planning: WorkflowPlanning<'_>, metadata: &SourceMetadataPlanningPlan<'_>,
    startup: &CaseOwnerSlot<'_, core::result::Result<FreshPlanningContext<'_>, FreshGenerationError>>,
    batch: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>, case: &CaseRetirementState,
    native_cache: &ProofCache, outer_cache: &OuterProofCache,
    stage: &mut DriverStage,
) -> Result<CompletedCaseSummary> {
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Native);
    stage.layer("construct");
    let mut planning = PlanningGuard::new(planning);
    planning.get()?.validate_metadata_driver(metadata, case)?;
    if !matches!(N, 3 | 4) || metadata.members().len() != N {
        return Err(WorkflowError::Identity);
    }
    *stage = DriverStage::Call("metadata_source_native_plans");
    let source_native_plans_result = planning.get()?.metadata_source_native_plans(metadata, case);
    let source_native_plans = table(&source_native_plans_result)?;
    *stage = DriverStage::Call("metadata_uniform_native_plans");
    let uniform_native_plans_result = planning.get()?.metadata_uniform_native_plans(metadata, case);
    let uniform_native_plans = table(&uniform_native_plans_result)?;
    *stage = DriverStage::Call("metadata_sparse_native_plans");
    let sparse_native_plans_result = planning.get()?.metadata_sparse_native_plans(metadata, case);
    let sparse_native_plans = table(&sparse_native_plans_result)?;
    *stage = DriverStage::Call("metadata_transcript_native_plans");
    let transcript_native_plans_result = planning.get()?.metadata_transcript_native_plans(metadata, case);
    let transcript_native_plans = table(&transcript_native_plans_result)?;
    *stage = DriverStage::Call("metadata_affine_native_plans");
    let affine_native_plans_result = planning.get()?.metadata_affine_native_plans(metadata, case);
    let affine_native_plans = table(&affine_native_plans_result)?;
    *stage = DriverStage::Call("metadata_ntt_native_plans");
    let ntt_native_plans_result = planning.get()?.metadata_ntt_native_plans(metadata, case);
    let ntt_native_plans = table(&ntt_native_plans_result)?;
    *stage = DriverStage::Call("metadata_mul_native_plans");
    let mul_native_plans_result = planning.get()?.metadata_mul_native_plans(metadata, case);
    let mul_native_plans = table(&mul_native_plans_result)?;
    *stage = DriverStage::Call("metadata_g_bound_native_plans");
    let g_bound_native_plans_result = planning.get()?.metadata_g_bound_native_plans(metadata, case);
    let g_bound_native_plans = table(&g_bound_native_plans_result)?;
    *stage = DriverStage::Call("metadata_permutation_native_plans");
    let permutation_native_plans_result = planning.get()?.metadata_permutation_native_plans(metadata, case);
    let permutation_native_plans = table(&permutation_native_plans_result)?;
    *stage = DriverStage::Call("metadata_linear_map_native_plans");
    let linear_map_native_plans_result = planning.get()?.metadata_linear_map_native_plans(metadata, case);
    let linear_map_native_plans = table(&linear_map_native_plans_result)?;
    let native_plans = NativePlanTables {
        source: source_native_plans,
        uniform: uniform_native_plans,
        sparse: sparse_native_plans,
        transcript: transcript_native_plans,
        affine: affine_native_plans,
        ntt: ntt_native_plans,
        mul: mul_native_plans,
        g_bound: g_bound_native_plans,
        permutation: permutation_native_plans,
        linear_map: linear_map_native_plans,
    };
    native_layers::fill_native_layer(planning.get()?, metadata, case, native_plans, stage)?;

    *stage = DriverStage::Call("metadata_source_blueprints");

    let source_blueprints_result = planning.get()?.metadata_source_blueprints(metadata, case);
    let source_blueprints = table(&source_blueprints_result)?;
    *stage = DriverStage::Call("metadata_affine_blueprints");
    let affine_blueprints_result = planning.get()?.metadata_affine_blueprints(metadata, case);
    let affine_blueprints = table(&affine_blueprints_result)?;
    *stage = DriverStage::Call("metadata_ntt_blueprints");
    let ntt_blueprints_result = planning.get()?.metadata_ntt_blueprints(metadata, case);
    let ntt_blueprints = table(&ntt_blueprints_result)?;
    *stage = DriverStage::Call("metadata_mul_blueprints");
    let mul_blueprints_result = planning.get()?.metadata_mul_blueprints(metadata, case);
    let mul_blueprints = table(&mul_blueprints_result)?;
    *stage = DriverStage::Call("metadata_g_bound_blueprints");
    let g_bound_blueprints_result = planning.get()?.metadata_g_bound_blueprints(metadata, case);
    let g_bound_blueprints = table(&g_bound_blueprints_result)?;
    *stage = DriverStage::Call("metadata_permutation_blueprints");
    let permutation_blueprints_result = planning.get()?.metadata_permutation_blueprints(metadata, case);
    let permutation_blueprints = table(&permutation_blueprints_result)?;
    *stage = DriverStage::Call("metadata_linear_map_blueprints");
    let linear_map_blueprints_result = planning.get()?.metadata_linear_map_blueprints(metadata, case);
    let linear_map_blueprints = table(&linear_map_blueprints_result)?;
    let blueprints = BlueprintTables {
        source: source_blueprints,
        affine: affine_blueprints,
        ntt: ntt_blueprints,
        mul: mul_blueprints,
        g_bound: g_bound_blueprints,
        permutation: permutation_blueprints,
        linear_map: linear_map_blueprints,
    };
    native_layers::fill_blueprint_layer(planning.get()?, metadata, case, native_plans, blueprints, stage)?;

    *stage = DriverStage::Call("metadata_source_compiler_plans");

    let source_compiler_plans_result = planning.get()?.metadata_source_compiler_plans(metadata, case);
    let source_compiler_plans = table(&source_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_affine_compiler_plans");
    let affine_compiler_plans_result = planning.get()?.metadata_affine_compiler_plans(metadata, case);
    let affine_compiler_plans = table(&affine_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_ntt_compiler_plans");
    let ntt_compiler_plans_result = planning.get()?.metadata_ntt_compiler_plans(metadata, case);
    let ntt_compiler_plans = table(&ntt_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_mul_compiler_plans");
    let mul_compiler_plans_result = planning.get()?.metadata_mul_compiler_plans(metadata, case);
    let mul_compiler_plans = table(&mul_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_g_bound_compiler_plans");
    let g_bound_compiler_plans_result = planning.get()?.metadata_g_bound_compiler_plans(metadata, case);
    let g_bound_compiler_plans = table(&g_bound_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_permutation_compiler_plans");
    let permutation_compiler_plans_result = planning.get()?.metadata_permutation_compiler_plans(metadata, case);
    let permutation_compiler_plans = table(&permutation_compiler_plans_result)?;
    *stage = DriverStage::Call("metadata_linear_map_compiler_plans");
    let linear_map_compiler_plans_result = planning.get()?.metadata_linear_map_compiler_plans(metadata, case);
    let linear_map_compiler_plans = table(&linear_map_compiler_plans_result)?;
    let compiler_inputs = NativeCompilerInputs {
        source_native: source_native_plans,
        source_blueprint: source_blueprints,
        affine_native: affine_native_plans,
        affine_blueprint: affine_blueprints,
        ntt_native: ntt_native_plans,
        ntt_blueprint: ntt_blueprints,
        mul_native: mul_native_plans,
        mul_blueprint: mul_blueprints,
        g_bound_native: g_bound_native_plans,
        g_bound_blueprint: g_bound_blueprints,
        permutation_native: permutation_native_plans,
        permutation_blueprint: permutation_blueprints,
        linear_map_native: linear_map_native_plans,
        linear_map_blueprint: linear_map_blueprints,
    };
    let compilers = CompilerPlanTables {
        source: source_compiler_plans,
        affine: affine_compiler_plans,
        ntt: ntt_compiler_plans,
        mul: mul_compiler_plans,
        g_bound: g_bound_compiler_plans,
        permutation: permutation_compiler_plans,
        linear_map: linear_map_compiler_plans,
    };
    native_layers::fill_compiler_views(planning.get()?, metadata, case, compiler_inputs, compilers, stage)?;

    *stage = DriverStage::Call("metadata_source_outer_plans");

    let source_outer_plans_result = planning.get()?.metadata_source_outer_plans(metadata, case);
    let source_outer_plans = table(&source_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_affine_outer_plans");
    let affine_outer_plans_result = planning.get()?.metadata_affine_outer_plans(metadata, case);
    let affine_outer_plans = table(&affine_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_ntt_outer_plans");
    let ntt_outer_plans_result = planning.get()?.metadata_ntt_outer_plans(metadata, case);
    let ntt_outer_plans = table(&ntt_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_mul_outer_plans");
    let mul_outer_plans_result = planning.get()?.metadata_mul_outer_plans(metadata, case);
    let mul_outer_plans = table(&mul_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_g_bound_outer_plans");
    let g_bound_outer_plans_result = planning.get()?.metadata_g_bound_outer_plans(metadata, case);
    let g_bound_outer_plans = table(&g_bound_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_permutation_outer_plans");
    let permutation_outer_plans_result = planning.get()?.metadata_permutation_outer_plans(metadata, case);
    let permutation_outer_plans = table(&permutation_outer_plans_result)?;
    *stage = DriverStage::Call("metadata_linear_map_outer_plans");
    let linear_map_outer_plans_result = planning.get()?.metadata_linear_map_outer_plans(metadata, case);
    let linear_map_outer_plans = table(&linear_map_outer_plans_result)?;
    let outer_plans = OuterPlanTables {
        source: source_outer_plans,
        affine: affine_outer_plans,
        ntt: ntt_outer_plans,
        mul: mul_outer_plans,
        g_bound: g_bound_outer_plans,
        permutation: permutation_outer_plans,
        linear_map: linear_map_outer_plans,
    };
    native_layers::fill_outer_layer(planning.get()?, metadata, case, compilers, outer_cache, outer_plans, stage)?;

    // These source data borrows may shorten to the native compiler lifetime.
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Graph);
    *stage = DriverStage::Call("metadata_fixed_plans");
    let fixed_plans_result = planning.get()?.metadata_fixed_plans(metadata, case);
    let fixed_plans = table(&fixed_plans_result)?;
    graph_layers::fill_fixed_sources(planning.get()?, metadata, case, fixed_plans, stage)?;
    *stage = DriverStage::Call("metadata_fixed_outer_plans");
    let fixed_outer_plans_result = planning.get()?.metadata_fixed_outer_plans(metadata, case);
    let fixed_outer_plans = table(&fixed_outer_plans_result)?;
    graph_layers::fill_fixed_outer(planning.get()?, metadata, case, fixed_plans, outer_cache, fixed_outer_plans, stage)?;

    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Crypto);
    *stage = DriverStage::Call("metadata_shake_plans");

    let shake_plans_result = planning.get()?.metadata_shake_plans(metadata, case);
    let shake_plans = table(&shake_plans_result)?;
    *stage = DriverStage::Call("metadata_aes_plans");
    let aes_plans_result = planning.get()?.metadata_aes_plans(metadata, case);
    let aes_plans = table(&aes_plans_result)?;
    crypto::fill(planning.get()?, metadata, case, shake_plans, aes_plans, stage)?;

    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Graph);
    *stage = DriverStage::Call("metadata_parameters_plans");

    let parameters_plans_result = planning.get()?.metadata_parameters_plans(metadata, case);
    let parameters_plans = table(&parameters_plans_result)?;
    *stage = DriverStage::Call("metadata_auxiliary_plans");
    let auxiliary_plans_result = planning.get()?.metadata_auxiliary_plans(metadata, case);
    let auxiliary_plans = table(&auxiliary_plans_result)?;
    *stage = DriverStage::Call("metadata_equality_plans");
    let equality_plans_result = planning.get()?.metadata_equality_plans(metadata, case);
    let equality_plans = table(&equality_plans_result)?;
    let direct_dependencies = DirectDependencies {
        shake: shake_plans,
        aes: aes_plans,
        uniform: uniform_native_plans,
        sparse: sparse_native_plans,
        transcript: transcript_native_plans,
    };
    let direct_plans = DirectPlanTables {
        parameters: parameters_plans,
        auxiliary: auxiliary_plans,
        equality: equality_plans,
    };
    graph_layers::fill_direct_leaves(planning.get()?, metadata, case, direct_dependencies, outer_cache, direct_plans, stage)?;

    // Every execution/result/preissue table is also a separate original owner.
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Native);
    *stage = DriverStage::Call("metadata_source_native_outputs");
    let source_native_outputs_result = planning.get()?.metadata_source_native_outputs(metadata, case);
    let source_native_outputs = table(&source_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_source_native_preissues");
    let source_native_preissues_result = planning.get()?.metadata_source_native_preissues(metadata, case);
    let source_native_preissues = table(&source_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_uniform_native_outputs");
    let uniform_native_outputs_result = planning.get()?.metadata_uniform_native_outputs(metadata, case);
    let uniform_native_outputs = table(&uniform_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_uniform_native_preissues");
    let uniform_native_preissues_result = planning.get()?.metadata_uniform_native_preissues(metadata, case);
    let uniform_native_preissues = table(&uniform_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_sparse_native_outputs");
    let sparse_native_outputs_result = planning.get()?.metadata_sparse_native_outputs(metadata, case);
    let sparse_native_outputs = table(&sparse_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_sparse_native_preissues");
    let sparse_native_preissues_result = planning.get()?.metadata_sparse_native_preissues(metadata, case);
    let sparse_native_preissues = table(&sparse_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_transcript_native_outputs");
    let transcript_native_outputs_result = planning.get()?.metadata_transcript_native_outputs(metadata, case);
    let transcript_native_outputs = table(&transcript_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_transcript_native_preissues");
    let transcript_native_preissues_result = planning.get()?.metadata_transcript_native_preissues(metadata, case);
    let transcript_native_preissues = table(&transcript_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_affine_native_outputs");
    let affine_native_outputs_result = planning.get()?.metadata_affine_native_outputs(metadata, case);
    let affine_native_outputs = table(&affine_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_affine_native_preissues");
    let affine_native_preissues_result = planning.get()?.metadata_affine_native_preissues(metadata, case);
    let affine_native_preissues = table(&affine_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_ntt_native_outputs");
    let ntt_native_outputs_result = planning.get()?.metadata_ntt_native_outputs(metadata, case);
    let ntt_native_outputs = table(&ntt_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_ntt_native_preissues");
    let ntt_native_preissues_result = planning.get()?.metadata_ntt_native_preissues(metadata, case);
    let ntt_native_preissues = table(&ntt_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_mul_native_outputs");
    let mul_native_outputs_result = planning.get()?.metadata_mul_native_outputs(metadata, case);
    let mul_native_outputs = table(&mul_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_mul_native_preissues");
    let mul_native_preissues_result = planning.get()?.metadata_mul_native_preissues(metadata, case);
    let mul_native_preissues = table(&mul_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_g_bound_native_outputs");
    let g_bound_native_outputs_result = planning.get()?.metadata_g_bound_native_outputs(metadata, case);
    let g_bound_native_outputs = table(&g_bound_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_g_bound_native_preissues");
    let g_bound_native_preissues_result = planning.get()?.metadata_g_bound_native_preissues(metadata, case);
    let g_bound_native_preissues = table(&g_bound_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_permutation_native_outputs");
    let permutation_native_outputs_result = planning.get()?.metadata_permutation_native_outputs(metadata, case);
    let permutation_native_outputs = table(&permutation_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_permutation_native_preissues");
    let permutation_native_preissues_result = planning.get()?.metadata_permutation_native_preissues(metadata, case);
    let permutation_native_preissues = table(&permutation_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_linear_map_native_outputs");
    let linear_map_native_outputs_result = planning.get()?.metadata_linear_map_native_outputs(metadata, case);
    let linear_map_native_outputs = table(&linear_map_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_linear_map_native_preissues");
    let linear_map_native_preissues_result = planning.get()?.metadata_linear_map_native_preissues(metadata, case);
    let linear_map_native_preissues = table(&linear_map_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_source_compiled_outputs");
    let source_compiled_outputs_result = planning.get()?.metadata_source_compiled_outputs(metadata, case);
    let source_compiled_outputs = table(&source_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_source_outer_outputs");
    let source_outer_outputs_result = planning.get()?.metadata_source_outer_outputs(metadata, case);
    let source_outer_outputs = table(&source_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_source_outer_preissues");
    let source_outer_preissues_result = planning.get()?.metadata_source_outer_preissues(metadata, case);
    let source_outer_preissues = table(&source_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_affine_compiled_outputs");
    let affine_compiled_outputs_result = planning.get()?.metadata_affine_compiled_outputs(metadata, case);
    let affine_compiled_outputs = table(&affine_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_affine_outer_outputs");
    let affine_outer_outputs_result = planning.get()?.metadata_affine_outer_outputs(metadata, case);
    let affine_outer_outputs = table(&affine_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_affine_outer_preissues");
    let affine_outer_preissues_result = planning.get()?.metadata_affine_outer_preissues(metadata, case);
    let affine_outer_preissues = table(&affine_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_ntt_compiled_outputs");
    let ntt_compiled_outputs_result = planning.get()?.metadata_ntt_compiled_outputs(metadata, case);
    let ntt_compiled_outputs = table(&ntt_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_ntt_outer_outputs");
    let ntt_outer_outputs_result = planning.get()?.metadata_ntt_outer_outputs(metadata, case);
    let ntt_outer_outputs = table(&ntt_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_ntt_outer_preissues");
    let ntt_outer_preissues_result = planning.get()?.metadata_ntt_outer_preissues(metadata, case);
    let ntt_outer_preissues = table(&ntt_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_mul_compiled_outputs");
    let mul_compiled_outputs_result = planning.get()?.metadata_mul_compiled_outputs(metadata, case);
    let mul_compiled_outputs = table(&mul_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_mul_outer_outputs");
    let mul_outer_outputs_result = planning.get()?.metadata_mul_outer_outputs(metadata, case);
    let mul_outer_outputs = table(&mul_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_mul_outer_preissues");
    let mul_outer_preissues_result = planning.get()?.metadata_mul_outer_preissues(metadata, case);
    let mul_outer_preissues = table(&mul_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_g_bound_compiled_outputs");
    let g_bound_compiled_outputs_result = planning.get()?.metadata_g_bound_compiled_outputs(metadata, case);
    let g_bound_compiled_outputs = table(&g_bound_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_g_bound_outer_outputs");
    let g_bound_outer_outputs_result = planning.get()?.metadata_g_bound_outer_outputs(metadata, case);
    let g_bound_outer_outputs = table(&g_bound_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_g_bound_outer_preissues");
    let g_bound_outer_preissues_result = planning.get()?.metadata_g_bound_outer_preissues(metadata, case);
    let g_bound_outer_preissues = table(&g_bound_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_permutation_compiled_outputs");
    let permutation_compiled_outputs_result = planning.get()?.metadata_permutation_compiled_outputs(metadata, case);
    let permutation_compiled_outputs = table(&permutation_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_permutation_outer_outputs");
    let permutation_outer_outputs_result = planning.get()?.metadata_permutation_outer_outputs(metadata, case);
    let permutation_outer_outputs = table(&permutation_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_permutation_outer_preissues");
    let permutation_outer_preissues_result = planning.get()?.metadata_permutation_outer_preissues(metadata, case);
    let permutation_outer_preissues = table(&permutation_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_linear_map_compiled_outputs");
    let linear_map_compiled_outputs_result = planning.get()?.metadata_linear_map_compiled_outputs(metadata, case);
    let linear_map_compiled_outputs = table(&linear_map_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_linear_map_outer_outputs");
    let linear_map_outer_outputs_result = planning.get()?.metadata_linear_map_outer_outputs(metadata, case);
    let linear_map_outer_outputs = table(&linear_map_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_linear_map_outer_preissues");
    let linear_map_outer_preissues_result = planning.get()?.metadata_linear_map_outer_preissues(metadata, case);
    let linear_map_outer_preissues = table(&linear_map_outer_preissues_result)?;
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Graph);
    *stage = DriverStage::Call("metadata_fixed_compiled_outputs");
    let fixed_compiled_outputs_result = planning.get()?.metadata_fixed_compiled_outputs(metadata, case);
    let fixed_compiled_outputs = table(&fixed_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_fixed_outer_outputs");
    let fixed_outer_outputs_result = planning.get()?.metadata_fixed_outer_outputs(metadata, case);
    let fixed_outer_outputs = table(&fixed_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_fixed_outer_preissues");
    let fixed_outer_preissues_result = planning.get()?.metadata_fixed_outer_preissues(metadata, case);
    let fixed_outer_preissues = table(&fixed_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_parameters_compiled_outputs");
    let parameters_compiled_outputs_result = planning.get()?.metadata_parameters_compiled_outputs(metadata, case);
    let parameters_compiled_outputs = table(&parameters_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_parameters_outer_outputs");
    let parameters_outer_outputs_result = planning.get()?.metadata_parameters_outer_outputs(metadata, case);
    let parameters_outer_outputs = table(&parameters_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_parameters_preissues");
    let parameters_preissues_result = planning.get()?.metadata_parameters_preissues(metadata, case);
    let parameters_preissues = table(&parameters_preissues_result)?;
    *stage = DriverStage::Call("metadata_auxiliary_compiled_outputs");
    let auxiliary_compiled_outputs_result = planning.get()?.metadata_auxiliary_compiled_outputs(metadata, case);
    let auxiliary_compiled_outputs = table(&auxiliary_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_auxiliary_outer_outputs");
    let auxiliary_outer_outputs_result = planning.get()?.metadata_auxiliary_outer_outputs(metadata, case);
    let auxiliary_outer_outputs = table(&auxiliary_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_auxiliary_preissues");
    let auxiliary_preissues_result = planning.get()?.metadata_auxiliary_preissues(metadata, case);
    let auxiliary_preissues = table(&auxiliary_preissues_result)?;
    *stage = DriverStage::Call("metadata_equality_compiled_outputs");
    let equality_compiled_outputs_result = planning.get()?.metadata_equality_compiled_outputs(metadata, case);
    let equality_compiled_outputs = table(&equality_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_equality_outer_outputs");
    let equality_outer_outputs_result = planning.get()?.metadata_equality_outer_outputs(metadata, case);
    let equality_outer_outputs = table(&equality_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_equality_preissues");
    let equality_preissues_result = planning.get()?.metadata_equality_preissues(metadata, case);
    let equality_preissues = table(&equality_preissues_result)?;
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Crypto);
    *stage = DriverStage::Call("metadata_shake_endpoint_outputs");
    let shake_endpoint_outputs_result = planning.get()?.metadata_shake_endpoint_outputs(metadata, case);
    let shake_endpoint_outputs = table(&shake_endpoint_outputs_result)?;
    *stage = DriverStage::Call("metadata_shake_native_outputs");
    let shake_native_outputs_result = planning.get()?.metadata_shake_native_outputs(metadata, case);
    let shake_native_outputs = table(&shake_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_shake_compiled_outputs");
    let shake_compiled_outputs_result = planning.get()?.metadata_shake_compiled_outputs(metadata, case);
    let shake_compiled_outputs = table(&shake_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_shake_outer_outputs");
    let shake_outer_outputs_result = planning.get()?.metadata_shake_outer_outputs(metadata, case);
    let shake_outer_outputs = table(&shake_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_shake_native_preissues");
    let shake_native_preissues_result = planning.get()?.metadata_shake_native_preissues(metadata, case);
    let shake_native_preissues = table(&shake_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_shake_outer_preissues");
    let shake_outer_preissues_result = planning.get()?.metadata_shake_outer_preissues(metadata, case);
    let shake_outer_preissues = table(&shake_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_shake_request_outputs");
    let shake_request_outputs_result = planning.get()?.metadata_shake_request_outputs(metadata, case);
    let shake_request_outputs = table(&shake_request_outputs_result)?;
    *stage = DriverStage::Call("metadata_shake_reports");
    let shake_reports_result = planning.get()?.metadata_shake_reports(metadata, case);
    let shake_reports = table(&shake_reports_result)?;
    *stage = DriverStage::Call("metadata_aes_endpoint_outputs");
    let aes_endpoint_outputs_result = planning.get()?.metadata_aes_endpoint_outputs(metadata, case);
    let aes_endpoint_outputs = table(&aes_endpoint_outputs_result)?;
    *stage = DriverStage::Call("metadata_aes_native_outputs");
    let aes_native_outputs_result = planning.get()?.metadata_aes_native_outputs(metadata, case);
    let aes_native_outputs = table(&aes_native_outputs_result)?;
    *stage = DriverStage::Call("metadata_aes_compiled_outputs");
    let aes_compiled_outputs_result = planning.get()?.metadata_aes_compiled_outputs(metadata, case);
    let aes_compiled_outputs = table(&aes_compiled_outputs_result)?;
    *stage = DriverStage::Call("metadata_aes_outer_outputs");
    let aes_outer_outputs_result = planning.get()?.metadata_aes_outer_outputs(metadata, case);
    let aes_outer_outputs = table(&aes_outer_outputs_result)?;
    *stage = DriverStage::Call("metadata_aes_native_preissues");
    let aes_native_preissues_result = planning.get()?.metadata_aes_native_preissues(metadata, case);
    let aes_native_preissues = table(&aes_native_preissues_result)?;
    *stage = DriverStage::Call("metadata_aes_outer_preissues");
    let aes_outer_preissues_result = planning.get()?.metadata_aes_outer_preissues(metadata, case);
    let aes_outer_preissues = table(&aes_outer_preissues_result)?;
    *stage = DriverStage::Call("metadata_aes_request_outputs");
    let aes_request_outputs_result = planning.get()?.metadata_aes_request_outputs(metadata, case);
    let aes_request_outputs = table(&aes_request_outputs_result)?;
    *stage = DriverStage::Call("metadata_aes_reports");
    let aes_reports_result = planning.get()?.metadata_aes_reports(metadata, case);
    let aes_reports = table(&aes_reports_result)?;
    let native_outputs = NativeOutputs {
        source: source_native_outputs,
        uniform: uniform_native_outputs,
        sparse: sparse_native_outputs,
        transcript: transcript_native_outputs,
        affine: affine_native_outputs,
        ntt: ntt_native_outputs,
        mul: mul_native_outputs,
        g_bound: g_bound_native_outputs,
        permutation: permutation_native_outputs,
        linear_map: linear_map_native_outputs,
    };
    let native_packets = NativePackets {
        source: source_native_preissues,
        uniform: uniform_native_preissues,
        sparse: sparse_native_preissues,
        transcript: transcript_native_preissues,
        affine: affine_native_preissues,
        ntt: ntt_native_preissues,
        mul: mul_native_preissues,
        g_bound: g_bound_native_preissues,
        permutation: permutation_native_preissues,
        linear_map: linear_map_native_preissues,
    };
    let compiled_outputs = CompiledOutputs {
        source: source_compiled_outputs,
        affine: affine_compiled_outputs,
        ntt: ntt_compiled_outputs,
        mul: mul_compiled_outputs,
        g_bound: g_bound_compiled_outputs,
        permutation: permutation_compiled_outputs,
        linear_map: linear_map_compiled_outputs,
    };
    let outer_outputs = OuterOutputs {
        source: source_outer_outputs,
        affine: affine_outer_outputs,
        ntt: ntt_outer_outputs,
        mul: mul_outer_outputs,
        g_bound: g_bound_outer_outputs,
        permutation: permutation_outer_outputs,
        linear_map: linear_map_outer_outputs,
    };
    let outer_packets = OuterPackets {
        source: source_outer_preissues,
        affine: affine_outer_preissues,
        ntt: ntt_outer_preissues,
        mul: mul_outer_preissues,
        g_bound: g_bound_outer_preissues,
        permutation: permutation_outer_preissues,
        linear_map: linear_map_outer_preissues,
    };
    let native_runtime = NativeRuntime {
        plans: native_plans,
        compilers: compilers,
        outer_plans: outer_plans,
        native: native_outputs,
        native_packets: native_packets,
        compiled: compiled_outputs,
        outer: outer_outputs,
        outer_packets: outer_packets,
    };
    let shake_runtime = ShakeRuntime {
        plans: shake_plans,
        endpoints: shake_endpoint_outputs,
        native: shake_native_outputs,
        compiled: shake_compiled_outputs,
        outer: shake_outer_outputs,
        native_packets: shake_native_preissues,
        outer_packets: shake_outer_preissues,
        requests: shake_request_outputs,
        reports: shake_reports,
    };
    let aes_runtime = AesRuntime {
        plans: aes_plans,
        endpoints: aes_endpoint_outputs,
        native: aes_native_outputs,
        compiled: aes_compiled_outputs,
        outer: aes_outer_outputs,
        native_packets: aes_native_preissues,
        outer_packets: aes_outer_preissues,
        requests: aes_request_outputs,
        reports: aes_reports,
    };
    let fixed_runtime = FixedRuntime {
        compilers: fixed_plans,
        plans: fixed_outer_plans,
        compiled: fixed_compiled_outputs,
        outer: fixed_outer_outputs,
        packets: fixed_outer_preissues,
    };
    let parameters_runtime = ParametersRuntime {
        plans: parameters_plans,
        compiled: parameters_compiled_outputs,
        outer: parameters_outer_outputs,
        packets: parameters_preissues,
    };
    let auxiliary_runtime = AuxiliaryRuntime {
        plans: auxiliary_plans,
        compiled: auxiliary_compiled_outputs,
        outer: auxiliary_outer_outputs,
        packets: auxiliary_preissues,
    };
    let equality_runtime = EqualityRuntime {
        plans: equality_plans,
        compiled: equality_compiled_outputs,
        outer: equality_outer_outputs,
        packets: equality_preissues,
    };
    let direct_inputs = DirectInputs {
        shake: shake_request_outputs,
        aes: aes_request_outputs,
        uniform: uniform_native_outputs,
        sparse: sparse_native_outputs,
        transcript: transcript_native_outputs,
    };
    let parameters_dispatch = ParametersDispatch {
        runtime: &parameters_runtime,
        inputs: &direct_inputs,
    };
    let auxiliary_dispatch = AuxiliaryDispatch {
        runtime: &auxiliary_runtime,
        inputs: &direct_inputs,
    };
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Graph);
    let runtimes = OrdinaryRuntimes {
        native: &native_runtime,
        shake: &shake_runtime,
        aes: &aes_runtime,
        fixed: &fixed_runtime,
        parameters: &parameters_dispatch,
        auxiliary: &auxiliary_dispatch,
        equality: &equality_runtime,
    };
    let producer_tables = LeafPlanTables {
        fixed: fixed_plans,
        fixed_outer: fixed_outer_plans,
        source_native: source_native_plans,
        source_blueprint: source_blueprints,
        source_compiler: source_compiler_plans,
        source_outer: source_outer_plans,
        uniform: uniform_native_plans,
        sparse: sparse_native_plans,
        transcript: transcript_native_plans,
        affine: affine_native_plans,
        affine_blueprint: affine_blueprints,
        affine_compiler: affine_compiler_plans,
        affine_outer: affine_outer_plans,
        ntt: ntt_native_plans,
        ntt_blueprint: ntt_blueprints,
        ntt_compiler: ntt_compiler_plans,
        ntt_outer: ntt_outer_plans,
        mul: mul_native_plans,
        mul_blueprint: mul_blueprints,
        mul_compiler: mul_compiler_plans,
        mul_outer: mul_outer_plans,
        g_bound: g_bound_native_plans,
        g_bound_blueprint: g_bound_blueprints,
        g_bound_compiler: g_bound_compiler_plans,
        g_bound_outer: g_bound_outer_plans,
        permutation: permutation_native_plans,
        permutation_blueprint: permutation_blueprints,
        permutation_compiler: permutation_compiler_plans,
        permutation_outer: permutation_outer_plans,
        linear_map: linear_map_native_plans,
        linear_map_blueprint: linear_map_blueprints,
        linear_map_compiler: linear_map_compiler_plans,
        linear_map_outer: linear_map_outer_plans,
        parameters: parameters_plans,
        auxiliary: auxiliary_plans,
        equality: equality_plans,
        shake: shake_plans,
        aes: aes_plans,
    };
    let leaf_children = LeafViews {
        fixed: fixed_outer_plans,
        source: source_outer_plans,
        affine: affine_outer_plans,
        ntt: ntt_outer_plans,
        mul: mul_outer_plans,
        g_bound: g_bound_outer_plans,
        permutation: permutation_outer_plans,
        linear_map: linear_map_outer_plans,
        parameters: parameters_plans,
        auxiliary: auxiliary_plans,
        equality: equality_plans,
    };
    let graphs = GraphOutputs {
        fixed: fixed_outer_outputs,
        source: source_outer_outputs,
        affine: affine_outer_outputs,
        ntt: ntt_outer_outputs,
        mul: mul_outer_outputs,
        g_bound: g_bound_outer_outputs,
        permutation: permutation_outer_outputs,
        linear_map: linear_map_outer_outputs,
        parameters: parameters_outer_outputs,
        auxiliary: auxiliary_outer_outputs,
        equality: equality_outer_outputs,
        parents: [None; 32],
    };
    // All ordinary owners and descriptors above outlive every recursive frame.
    parents::run(planning.into_inner()?, metadata, startup, batch, case,
        native_cache, outer_cache, producer_tables, leaf_children, runtimes,
        [None; 32], [None; 32], [None; 32], graphs, 0, stage)
}
