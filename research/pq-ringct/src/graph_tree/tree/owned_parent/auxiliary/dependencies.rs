//! Ordered typed producer dependencies, derivable before the first proof.
use super::*;
use crate::graph_crypto::{OwnedAesStepKind, RequestStepKind};

pub(crate) struct AuxiliaryDependencies {
    pub(crate) bindings: [Option<PhaseBinding>; 6],
    pub(crate) count: usize,
    pub(crate) consume: usize,
}
fn aes(plan: &OwnedAesRequestPlan<'_>) -> OwnedResult<[PhaseBinding; 2]> {
    if plan.ordered_steps().first().map(|s| s.kind) != Some(OwnedAesStepKind::Endpoints) {
        return Err(GraphParentFailure::Order);
    }
    let mut roots = plan.ordered_steps().iter().enumerate().filter(|(_, step)|
        step.kind == (OwnedAesStepKind::Outer { node: plan.root_id() }));
    let root = roots.next().ok_or(GraphParentFailure::Order)?.0;
    if roots.next().is_some() { return Err(GraphParentFailure::Order); }
    Ok([PhaseBinding::for_aes(plan, root).map_err(|_| GraphParentFailure::Authority)?,
        PhaseBinding::for_aes(plan, 0).map_err(|_| GraphParentFailure::Authority)?])
}
fn shake(plan: &PairedRequestPlan<'_>) -> OwnedResult<[PhaseBinding; 2]> {
    if plan.ordered_steps().first().map(|s| s.kind) != Some(RequestStepKind::Endpoints) {
        return Err(GraphParentFailure::Order);
    }
    let mut roots = plan.ordered_steps().iter().enumerate().filter(|(_, step)|
        step.kind == (RequestStepKind::Outer { node: plan.root_id() }));
    let root = roots.next().ok_or(GraphParentFailure::Order)?.0;
    if roots.next().is_some() { return Err(GraphParentFailure::Order); }
    Ok([PhaseBinding::for_paired(plan, root).map_err(|_| GraphParentFailure::Authority)?,
        PhaseBinding::for_paired(plan, 0).map_err(|_| GraphParentFailure::Authority)?])
}
impl AuxiliaryGraphPlan<'_, '_> {
    pub(crate) fn dependencies(&self, ordinal: usize) -> OwnedResult<AuxiliaryDependencies> {
        let mut bindings = [None; 6];
        let count = match ordinal {
            0 => {
                use AuxiliaryGraphSources as S;
                match self.sources {
                    S::SampleG { aes: a, uniform } => {
                        let [root, endpoints] = aes(a)?;
                        bindings[..3].copy_from_slice(&[Some(root), Some(endpoints),
                            Some(PhaseBinding::for_uniform_native(uniform, 0).map_err(|_| GraphParentFailure::Authority)?)]);
                    }
                    S::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse } => {
                        let [ar, ae] = aes(uniform_aes)?; let [br, be] = aes(sparse_aes)?;
                        bindings = [Some(ar), Some(ae),
                            Some(PhaseBinding::for_uniform_native(uniform, 0).map_err(|_| GraphParentFailure::Authority)?),
                            Some(br), Some(be),
                            Some(PhaseBinding::for_sparse_native(sparse, 0).map_err(|_| GraphParentFailure::Authority)?)];
                    }
                    S::HashAlpha { shake: s, transcript } => {
                        let [root, endpoints] = shake(s)?;
                        bindings[..3].copy_from_slice(&[Some(root), Some(endpoints),
                            Some(PhaseBinding::for_transcript_native(transcript, 0).map_err(|_| GraphParentFailure::Authority)?)]);
                    }
                    S::HashX { shake: s, transcript, sparse } => {
                        let [root, endpoints] = shake(s)?;
                        bindings[..4].copy_from_slice(&[Some(root), Some(endpoints),
                            Some(PhaseBinding::for_transcript_native(transcript, 0).map_err(|_| GraphParentFailure::Authority)?),
                            Some(PhaseBinding::for_sparse_native(sparse, 0).map_err(|_| GraphParentFailure::Authority)?)]);
                    }
                }
                self.kind().input_count()
            }
            1 => { bindings[0] = Some(self.binding(0)?); 1 }
            _ => return Err(GraphParentFailure::Order),
        };
        if bindings[..count].iter().enumerate().any(|(i, binding)| binding.is_none() || bindings[..i].contains(binding))
            || bindings[count..].iter().any(Option::is_some) { return Err(GraphParentFailure::Order); }
        Ok(AuxiliaryDependencies { bindings, count, consume: count })
    }
}
