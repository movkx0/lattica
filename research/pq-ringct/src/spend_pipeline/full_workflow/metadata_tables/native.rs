//! Concrete table items match the named producer/constructor return types.
//! Declare owning dependency layers separately; no table is self-referential.
use super::{CaseOwnerTable, RuntimeTable, Original, Outcome, PhaseFailure, RetainedNative, WorkflowError};
use crate::spend_pipeline::full_workflow::source_native::{SourceNativeOperationPlan, SourceNativeOperationFailure, OwnedSourceNativeOutput};
use crate::execution::workflow_resources::PreissuedSourceNative;
pub(crate) type SourcePlanResult<'a> = Outcome<SourceNativeOperationPlan<'a>, (SourceNativeOperationFailure, Original)>;
pub(crate) type SourcePlanTable<'case, 'a> = CaseOwnerTable<'case, SourcePlanResult<'a>>;
pub(crate) type SourceNativeResult<'a> = Outcome<RetainedNative<OwnedSourceNativeOutput<'a>>, PhaseFailure<SourceNativeOperationFailure>>;
pub(crate) type SourceNativeOutputs<'case, 'a> = RuntimeTable<'case, SourceNativeResult<'a>>;
pub(crate) type SourceNativePreissueResult<'plan, 'a> = Outcome<PreissuedSourceNative<'plan, 'a>, WorkflowError>;
pub(crate) type SourceNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, SourceNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::uniform_native::{UniformNativeOperationPlan, UniformNativeOperationFailure, OwnedUniformOutput};
use crate::execution::workflow_resources::PreissuedUniformNative;
pub(crate) type UniformPlanResult<'a> = Outcome<UniformNativeOperationPlan<'a>, (UniformNativeOperationFailure, Original)>;
pub(crate) type UniformPlanTable<'case, 'a> = CaseOwnerTable<'case, UniformPlanResult<'a>>;
pub(crate) type UniformNativeResult<'a> = Outcome<RetainedNative<OwnedUniformOutput<'a>>, PhaseFailure<UniformNativeOperationFailure>>;
pub(crate) type UniformNativeOutputs<'case, 'a> = RuntimeTable<'case, UniformNativeResult<'a>>;
pub(crate) type UniformNativePreissueResult<'plan, 'a> = Outcome<PreissuedUniformNative<'plan, 'a>, WorkflowError>;
pub(crate) type UniformNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, UniformNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::sparse_native::{SparseNativeOperationPlan, SparseNativeOperationFailure, OwnedSparseOutput};
use crate::execution::workflow_resources::PreissuedSparseNative;
pub(crate) type SparsePlanResult<'a> = Outcome<SparseNativeOperationPlan<'a>, (SparseNativeOperationFailure, Original)>;
pub(crate) type SparsePlanTable<'case, 'a> = CaseOwnerTable<'case, SparsePlanResult<'a>>;
pub(crate) type SparseNativeResult<'a> = Outcome<RetainedNative<OwnedSparseOutput<'a>>, PhaseFailure<SparseNativeOperationFailure>>;
pub(crate) type SparseNativeOutputs<'case, 'a> = RuntimeTable<'case, SparseNativeResult<'a>>;
pub(crate) type SparseNativePreissueResult<'plan, 'a> = Outcome<PreissuedSparseNative<'plan, 'a>, WorkflowError>;
pub(crate) type SparseNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, SparseNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::transcript_native::{TranscriptNativeOperationPlan, TranscriptNativeOperationFailure, OwnedTranscriptOutput};
use crate::execution::workflow_resources::PreissuedTranscriptNative;
pub(crate) type TranscriptPlanResult<'a> = Outcome<TranscriptNativeOperationPlan<'a>, (TranscriptNativeOperationFailure, Original)>;
pub(crate) type TranscriptPlanTable<'case, 'a> = CaseOwnerTable<'case, TranscriptPlanResult<'a>>;
pub(crate) type TranscriptNativeResult<'a> = Outcome<RetainedNative<OwnedTranscriptOutput<'a>>, PhaseFailure<TranscriptNativeOperationFailure>>;
pub(crate) type TranscriptNativeOutputs<'case, 'a> = RuntimeTable<'case, TranscriptNativeResult<'a>>;
pub(crate) type TranscriptNativePreissueResult<'plan, 'a> = Outcome<PreissuedTranscriptNative<'plan, 'a>, WorkflowError>;
pub(crate) type TranscriptNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, TranscriptNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::affine_native::{AffineNativeOperationPlan, AffineNativeOperationFailure, OwnedAffineOutput};
use crate::execution::workflow_resources::PreissuedAffineNative;
pub(crate) type AffinePlanResult<'a> = Outcome<AffineNativeOperationPlan<'a>, (AffineNativeOperationFailure, Original)>;
pub(crate) type AffinePlanTable<'case, 'a> = CaseOwnerTable<'case, AffinePlanResult<'a>>;
pub(crate) type AffineNativeResult<'a> = Outcome<RetainedNative<OwnedAffineOutput<'a>>, PhaseFailure<AffineNativeOperationFailure>>;
pub(crate) type AffineNativeOutputs<'case, 'a> = RuntimeTable<'case, AffineNativeResult<'a>>;
pub(crate) type AffineNativePreissueResult<'plan, 'a> = Outcome<PreissuedAffineNative<'plan, 'a>, WorkflowError>;
pub(crate) type AffineNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, AffineNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::ntt_native::{NttNativeOperationPlan, NttNativeOperationFailure, OwnedNttOutput};
use crate::execution::workflow_resources::PreissuedNttNative;
pub(crate) type NttPlanResult<'a> = Outcome<NttNativeOperationPlan<'a>, (NttNativeOperationFailure, Original)>;
pub(crate) type NttPlanTable<'case, 'a> = CaseOwnerTable<'case, NttPlanResult<'a>>;
pub(crate) type NttNativeResult<'a> = Outcome<RetainedNative<OwnedNttOutput<'a>>, PhaseFailure<NttNativeOperationFailure>>;
pub(crate) type NttNativeOutputs<'case, 'a> = RuntimeTable<'case, NttNativeResult<'a>>;
pub(crate) type NttNativePreissueResult<'plan, 'a> = Outcome<PreissuedNttNative<'plan, 'a>, WorkflowError>;
pub(crate) type NttNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, NttNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::mul_native::{MulNativeOperationPlan, MulNativeOperationFailure, OwnedMulOutput};
use crate::execution::workflow_resources::PreissuedMulNative;
pub(crate) type MulPlanResult<'a> = Outcome<MulNativeOperationPlan<'a>, (MulNativeOperationFailure, Original)>;
pub(crate) type MulPlanTable<'case, 'a> = CaseOwnerTable<'case, MulPlanResult<'a>>;
pub(crate) type MulNativeResult<'a> = Outcome<RetainedNative<OwnedMulOutput<'a>>, PhaseFailure<MulNativeOperationFailure>>;
pub(crate) type MulNativeOutputs<'case, 'a> = RuntimeTable<'case, MulNativeResult<'a>>;
pub(crate) type MulNativePreissueResult<'plan, 'a> = Outcome<PreissuedMulNative<'plan, 'a>, WorkflowError>;
pub(crate) type MulNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, MulNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::g_bound_native::{GBoundNativeOperationPlan, GBoundNativeOperationFailure, OwnedGBoundOutput};
use crate::execution::workflow_resources::PreissuedGBoundNative;
pub(crate) type GBoundPlanResult<'a> = Outcome<GBoundNativeOperationPlan<'a>, (GBoundNativeOperationFailure, Original)>;
pub(crate) type GBoundPlanTable<'case, 'a> = CaseOwnerTable<'case, GBoundPlanResult<'a>>;
pub(crate) type GBoundNativeResult<'a> = Outcome<RetainedNative<OwnedGBoundOutput<'a>>, PhaseFailure<GBoundNativeOperationFailure>>;
pub(crate) type GBoundNativeOutputs<'case, 'a> = RuntimeTable<'case, GBoundNativeResult<'a>>;
pub(crate) type GBoundNativePreissueResult<'plan, 'a> = Outcome<PreissuedGBoundNative<'plan, 'a>, WorkflowError>;
pub(crate) type GBoundNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, GBoundNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::permutation_native::{PermutationNativeOperationPlan, PermutationNativeOperationFailure, OwnedPermutationOutput};
use crate::execution::workflow_resources::PreissuedPermutationNative;
pub(crate) type PermutationPlanResult<'a> = Outcome<PermutationNativeOperationPlan<'a>, (PermutationNativeOperationFailure, Original)>;
pub(crate) type PermutationPlanTable<'case, 'a> = CaseOwnerTable<'case, PermutationPlanResult<'a>>;
pub(crate) type PermutationNativeResult<'a> = Outcome<RetainedNative<OwnedPermutationOutput<'a>>, PhaseFailure<PermutationNativeOperationFailure>>;
pub(crate) type PermutationNativeOutputs<'case, 'a> = RuntimeTable<'case, PermutationNativeResult<'a>>;
pub(crate) type PermutationNativePreissueResult<'plan, 'a> = Outcome<PreissuedPermutationNative<'plan, 'a>, WorkflowError>;
pub(crate) type PermutationNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, PermutationNativePreissueResult<'plan, 'a>>;

use crate::spend_pipeline::full_workflow::linear_map_native::{LinearMapNativeOperationPlan, LinearMapNativeOperationFailure, OwnedLinearMapOutput};
use crate::execution::workflow_resources::PreissuedLinearMapNative;
pub(crate) type LinearMapPlanResult<'a> = Outcome<LinearMapNativeOperationPlan<'a>, (LinearMapNativeOperationFailure, Original)>;
pub(crate) type LinearMapPlanTable<'case, 'a> = CaseOwnerTable<'case, LinearMapPlanResult<'a>>;
pub(crate) type LinearMapNativeResult<'a> = Outcome<RetainedNative<OwnedLinearMapOutput<'a>>, PhaseFailure<LinearMapNativeOperationFailure>>;
pub(crate) type LinearMapNativeOutputs<'case, 'a> = RuntimeTable<'case, LinearMapNativeResult<'a>>;
pub(crate) type LinearMapNativePreissueResult<'plan, 'a> = Outcome<PreissuedLinearMapNative<'plan, 'a>, WorkflowError>;
pub(crate) type LinearMapNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, LinearMapNativePreissueResult<'plan, 'a>>;
