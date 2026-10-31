//! Final aggregation retains exact original plan/output/preissue Result owners.
use super::{CaseOwnerTable, RuntimeTable, Outcome, PhaseFailure, Retained,
    WorkflowError, OuterOwnedError};
use crate::ordered_aggregation::{Error as AggregateSourceError, source::FinalAggregationPlan,
    owned_final::{FinalPhasePlan, FinalFailure, FinalCompiled, FinalNode, FinalVerification,
        PreissuedFinalOuter}};

pub(crate) type FinalSourceResult<'a> = Outcome<FinalAggregationPlan<'a>, AggregateSourceError>;
pub(crate) type FinalSourceTable<'case, 'a> = CaseOwnerTable<'case, FinalSourceResult<'a>>;
pub(crate) type FinalPlanResult<'a> = Outcome<FinalPhasePlan<'a>, FinalFailure>;
pub(crate) type FinalPlanTable<'case, 'a> = CaseOwnerTable<'case, FinalPlanResult<'a>>;
pub(crate) type FinalCompiledResult<'a> = Outcome<Retained<FinalCompiled<'a>>, PhaseFailure<FinalFailure>>;
pub(crate) type FinalCompiledOutputs<'case, 'a> = RuntimeTable<'case, FinalCompiledResult<'a>>;
pub(crate) type FinalOuterResult<'a> = Outcome<Retained<FinalNode<'a>>, PhaseFailure<OuterOwnedError>>;
pub(crate) type FinalOuterOutputs<'case, 'a> = RuntimeTable<'case, FinalOuterResult<'a>>;
pub(crate) type FinalVerifyResult<'root, 'a> = Outcome<Retained<FinalVerification<'root, 'a>>, PhaseFailure<FinalFailure>>;
pub(crate) type FinalVerifyOutputs<'case, 'root, 'a> = RuntimeTable<'case, FinalVerifyResult<'root, 'a>>;
pub(crate) type FinalPreissueResult<'plan, 'a> = Outcome<PreissuedFinalOuter<'plan, 'a>, WorkflowError>;
pub(crate) type FinalPreissues<'case, 'plan, 'a> = RuntimeTable<'case, FinalPreissueResult<'plan, 'a>>;

/// The final root stays at a stable address for the complete verification receipt.
pub(crate) type FinalRootTable<'case, 'a> = CaseOwnerTable<'case, FinalOuterResult<'a>>;
pub(crate) type FinalDriverFailureTable<'case> = CaseOwnerTable<'case, std::cell::RefCell<Option<FinalFailure>>>;
