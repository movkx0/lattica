//! SHAKE/AES have separate concrete owning tables at every request/step layer.
use super::{CaseOwnerTable, RuntimeTable, Outcome, PhaseFailure, Retained,
    RetainedNative, WorkflowError, OuterOwnedError};
use crate::{execution::workflow_resources::{PreissuedAesNative, PreissuedPairedNative},
    graph_crypto::{PairedRequestPlan, OwnedAesRequestPlan, PairedFailure,
        PairedNativeOutput, OwnedAesNativeOutput, PairedEndpoints, OwnedAesEndpoints,
        PairedCompiled, PairedNode, PreissuedPairedOuter, PreissuedAesOuter,
        PairedRequestOutput, OwnedAesRequestOutput, PairedExecuteError, OwnedAesExecuteError}};

pub(crate) type ShakePlanResult<'a> = Outcome<PairedRequestPlan<'a>, PairedFailure>;
pub(crate) type ShakePlanTable<'case, 'a> = CaseOwnerTable<'case, ShakePlanResult<'a>>;
pub(crate) type AesPlanResult<'a> = Outcome<OwnedAesRequestPlan<'a>, PairedFailure>;
pub(crate) type AesPlanTable<'case, 'a> = CaseOwnerTable<'case, AesPlanResult<'a>>;
pub(crate) type ShakeNativeResult<'a> = Outcome<RetainedNative<PairedNativeOutput<'a>>, PhaseFailure<PairedFailure>>;
pub(crate) type ShakeNativeOutputs<'case, 'a> = RuntimeTable<'case, ShakeNativeResult<'a>>;
pub(crate) type AesNativeResult<'a> = Outcome<RetainedNative<OwnedAesNativeOutput<'a>>, PhaseFailure<PairedFailure>>;
pub(crate) type AesNativeOutputs<'case, 'a> = RuntimeTable<'case, AesNativeResult<'a>>;
pub(crate) type ShakeEndpointResult<'a> = Outcome<Retained<PairedEndpoints<'a>>, PhaseFailure<PairedFailure>>;
pub(crate) type ShakeEndpointOutputs<'case, 'a> = RuntimeTable<'case, ShakeEndpointResult<'a>>;
pub(crate) type AesEndpointResult<'a> = Outcome<Retained<OwnedAesEndpoints<'a>>, PhaseFailure<PairedFailure>>;
pub(crate) type AesEndpointOutputs<'case, 'a> = RuntimeTable<'case, AesEndpointResult<'a>>;
pub(crate) type ComponentCompiledResult<'a> = Outcome<Retained<PairedCompiled<'a>>, PhaseFailure<PairedFailure>>;
pub(crate) type ShakeCompiledOutputs<'case, 'a> = RuntimeTable<'case, ComponentCompiledResult<'a>>;
pub(crate) type AesCompiledOutputs<'case, 'a> = RuntimeTable<'case, ComponentCompiledResult<'a>>;
pub(crate) type ComponentOuterResult<'a> = Outcome<Retained<PairedNode<'a>>, PhaseFailure<OuterOwnedError>>;
pub(crate) type ShakeOuterOutputs<'case, 'a> = RuntimeTable<'case, ComponentOuterResult<'a>>;
pub(crate) type AesOuterOutputs<'case, 'a> = RuntimeTable<'case, ComponentOuterResult<'a>>;
pub(crate) type ShakeNativePreissueResult<'plan, 'a> = Outcome<PreissuedPairedNative<'plan, 'a>, WorkflowError>;
pub(crate) type ShakeNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, ShakeNativePreissueResult<'plan, 'a>>;
pub(crate) type AesNativePreissueResult<'plan, 'a> = Outcome<PreissuedAesNative<'plan, 'a>, WorkflowError>;
pub(crate) type AesNativePreissues<'case, 'plan, 'a> = RuntimeTable<'case, AesNativePreissueResult<'plan, 'a>>;
pub(crate) type ShakeOuterPreissueResult<'plan, 'a> = Outcome<PreissuedPairedOuter<'plan, 'a>, WorkflowError>;
pub(crate) type ShakeOuterPreissues<'case, 'plan, 'a> = RuntimeTable<'case, ShakeOuterPreissueResult<'plan, 'a>>;
pub(crate) type AesOuterPreissueResult<'plan, 'a> = Outcome<PreissuedAesOuter<'plan, 'a>, WorkflowError>;
pub(crate) type AesOuterPreissues<'case, 'plan, 'a> = RuntimeTable<'case, AesOuterPreissueResult<'plan, 'a>>;
pub(crate) type ShakeRequestResult<'a> = Outcome<PairedRequestOutput<'a>, PairedExecuteError>;
pub(crate) type ShakeRequestOutputs<'case, 'a> = RuntimeTable<'case, ShakeRequestResult<'a>>;
pub(crate) type AesRequestResult<'a> = Outcome<OwnedAesRequestOutput<'a>, OwnedAesExecuteError>;
pub(crate) type AesRequestOutputs<'case, 'a> = RuntimeTable<'case, AesRequestResult<'a>>;

// Per-request fixed counters are populated from observed phase results.
pub(crate) type ShakeReportTable<'case> = CaseOwnerTable<'case, std::cell::RefCell<crate::graph_crypto::PairedRequestReport>>;
pub(crate) type AesReportTable<'case> = CaseOwnerTable<'case, std::cell::RefCell<crate::graph_crypto::OwnedAesRequestReport>>;
