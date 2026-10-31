//! Fixed/direct leaves, source-native wrappers, and scoped graph-parent levels.
use super::{CaseOwnerTable, RuntimeTable, Original, Outcome, PhaseFailure, Retained,
    RetainedOriginal, WorkflowError, OuterOwnedError};
use crate::{
    graph_tree::{fixed_sources::FixedSourceFailure,
        native_sources::{NativeSourceBlueprint, NativeSourceFailure, OwnedCompiledSource},
        owned_parent::{GraphParentPlan, GraphParentFailure, OwnedGraphCompiled, OwnedGraphNode,
            FixedLeafOuterPlan, NativeLeafOuterPlan, ParametersPpGraphPlan,
            AuxiliaryGraphPlan, EqualityGraphPlan, PreissuedFixedLeafOuter,
            PreissuedNativeLeafOuter, PreissuedParametersPpOuter, PreissuedAuxiliaryOuter,
            PreissuedEqualityOuter, PreissuedGraphParentOuter}},
    spend_pipeline::full_workflow::{SourceOperationPlan, CompiledFixedSources,
        source_native_compile::{SourceNativeCompilePlan, SourceNativeCompileFailure}},
};

pub(crate) type FixedPlanResult<'a> = Outcome<SourceOperationPlan<'a>, FixedSourceFailure>;
pub(crate) type FixedPlanTable<'case, 'a> = CaseOwnerTable<'case, FixedPlanResult<'a>>;
pub(crate) type FixedOuterPlanResult<'source, 'a> = Outcome<FixedLeafOuterPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type FixedOuterPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, FixedOuterPlanResult<'source, 'a>>;
pub(crate) type FixedCompiledResult<'a> = Outcome<Retained<CompiledFixedSources<'a>>, PhaseFailure<FixedSourceFailure>>;
pub(crate) type FixedCompiledOutputs<'case, 'a> = RuntimeTable<'case, FixedCompiledResult<'a>>;
pub(crate) type FixedOuterPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedFixedLeafOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type FixedOuterPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, FixedOuterPreissueResult<'plan, 'source, 'a>>;

pub(crate) type SourceBlueprintResult<'a, 'graph> = Outcome<NativeSourceBlueprint<'a, 'graph>, NativeSourceFailure>;
pub(crate) type SourceBlueprintTable<'case, 'a, 'graph> = CaseOwnerTable<'case, SourceBlueprintResult<'a, 'graph>>;
pub(crate) type SourceCompilerPlanResult<'a> = Outcome<SourceNativeCompilePlan<'a>, (SourceNativeCompileFailure, Original)>;
pub(crate) type SourceCompilerPlanTable<'case, 'a> = CaseOwnerTable<'case, SourceCompilerPlanResult<'a>>;
pub(crate) type SourceOuterPlanResult<'source, 'a> = Outcome<NativeLeafOuterPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type SourceOuterPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, SourceOuterPlanResult<'source, 'a>>;
pub(crate) type SourceCompiledResult<'a> = Outcome<RetainedOriginal<OwnedCompiledSource<'a, 'a, 'a>>, PhaseFailure<SourceNativeCompileFailure>>;
pub(crate) type SourceCompiledOutputs<'case, 'a> = RuntimeTable<'case, SourceCompiledResult<'a>>;
pub(crate) type SourceOuterPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedNativeLeafOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type SourceOuterPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, SourceOuterPreissueResult<'plan, 'source, 'a>>;

pub(crate) type ParametersPlanResult<'source, 'a> = Outcome<ParametersPpGraphPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type ParametersPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, ParametersPlanResult<'source, 'a>>;
pub(crate) type ParametersPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedParametersPpOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type ParametersPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, ParametersPreissueResult<'plan, 'source, 'a>>;
pub(crate) type AuxiliaryPlanResult<'source, 'a> = Outcome<AuxiliaryGraphPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type AuxiliaryPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, AuxiliaryPlanResult<'source, 'a>>;
pub(crate) type AuxiliaryPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedAuxiliaryOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type AuxiliaryPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, AuxiliaryPreissueResult<'plan, 'source, 'a>>;
pub(crate) type EqualityPlanResult<'source, 'a> = Outcome<EqualityGraphPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type EqualityPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, EqualityPlanResult<'source, 'a>>;
pub(crate) type EqualityPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedEqualityOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type EqualityPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, EqualityPreissueResult<'plan, 'source, 'a>>;

pub(crate) type GraphCompiledResult<'a> = Outcome<Retained<OwnedGraphCompiled<'a>>, PhaseFailure<GraphParentFailure>>;
pub(crate) type ParametersCompiledOutputs<'case, 'a> = RuntimeTable<'case, GraphCompiledResult<'a>>;
pub(crate) type AuxiliaryCompiledOutputs<'case, 'a> = RuntimeTable<'case, GraphCompiledResult<'a>>;
pub(crate) type EqualityCompiledOutputs<'case, 'a> = RuntimeTable<'case, GraphCompiledResult<'a>>;
pub(crate) type GraphOuterResult<'a> = Outcome<Retained<OwnedGraphNode<'a>>, PhaseFailure<OuterOwnedError>>;
pub(crate) type FixedOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type SourceOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type AffineOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type NttOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type MulOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type GBoundOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type PermutationOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type LinearMapOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type ParametersOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type AuxiliaryOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type EqualityOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;

// Each tree level owns a separate table before the next level borrows it.
// A recursively scoped driver may carry odd nodes by immutable child source.
pub(crate) type ParentPlanResult<'source, 'a> = Outcome<GraphParentPlan<'source, 'a>, GraphParentFailure>;
pub(crate) type ParentPlanTable<'case, 'source, 'a> = CaseOwnerTable<'case, ParentPlanResult<'source, 'a>>;
pub(crate) type ParentCompiledOutputs<'case, 'a> = RuntimeTable<'case, GraphCompiledResult<'a>>;
pub(crate) type ParentOuterOutputs<'case, 'a> = RuntimeTable<'case, GraphOuterResult<'a>>;
pub(crate) type ParentPreissueResult<'plan, 'source, 'a> = Outcome<PreissuedGraphParentOuter<'plan, 'source, 'a>, WorkflowError>;
pub(crate) type ParentPreissues<'case, 'plan, 'source, 'a> = RuntimeTable<'case, ParentPreissueResult<'plan, 'source, 'a>>;
