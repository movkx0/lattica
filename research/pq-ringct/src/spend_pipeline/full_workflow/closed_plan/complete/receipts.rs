//! Immutable diagnostic descriptions of already authenticated complete steps.
//! These copied identities are never accepted as ownership or phase authority.
use super::*;
use crate::execution::workflow_resources::{VerificationBinding, PhaseFacts};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct DispatchVerificationIdentity {
    pub(crate) closed_ordinal: usize,
    pub(crate) expected_steps: usize,
    pub(crate) transactions: usize,
    pub(crate) route: ProducerRoute,
    pub(crate) binding: VerificationBinding,
    pub(crate) workflow_source_fingerprint: [u8; 32],
    pub(crate) member: Option<usize>,
    pub(crate) member_first: usize,
    pub(crate) member_count: usize,
    pub(crate) source_kind: &'static str,
    pub(crate) source_ordinal: Option<usize>,
}

fn native_family(family: NativeFamily) -> ProducerFamily {
    match family {
        NativeFamily::Source => ProducerFamily::Source,
        NativeFamily::Uniform => ProducerFamily::Uniform,
        NativeFamily::Sparse => ProducerFamily::Sparse,
        NativeFamily::Transcript => ProducerFamily::Transcript,
        NativeFamily::Affine => ProducerFamily::Affine,
        NativeFamily::Ntt => ProducerFamily::Ntt,
        NativeFamily::Mul => ProducerFamily::Mul,
        NativeFamily::GBound => ProducerFamily::GBound,
        NativeFamily::Permutation => ProducerFamily::Permutation,
        NativeFamily::LinearMap => ProducerFamily::LinearMap,
    }
}

fn leaf_family(family: LeafFamily) -> ProducerFamily {
    match family {
        LeafFamily::Source => ProducerFamily::Source,
        LeafFamily::Affine => ProducerFamily::Affine,
        LeafFamily::Ntt => ProducerFamily::Ntt,
        LeafFamily::Mul => ProducerFamily::Mul,
        LeafFamily::GBound => ProducerFamily::GBound,
        LeafFamily::Permutation => ProducerFamily::Permutation,
        LeafFamily::LinearMap => ProducerFamily::LinearMap,
    }
}

fn family_source_kind(family: ProducerFamily) -> &'static str {
    match family {
        ProducerFamily::Source => "source-kind-index",
        ProducerFamily::Fixed => "fixed-source",
        ProducerFamily::Uniform | ProducerFamily::Sparse | ProducerFamily::Transcript => "auxiliary-request",
        ProducerFamily::Affine | ProducerFamily::Ntt | ProducerFamily::Mul | ProducerFamily::GBound
            | ProducerFamily::Permutation | ProducerFamily::LinearMap => "algebra-batch",
        ProducerFamily::Parameters | ProducerFamily::Auxiliary | ProducerFamily::Equality => "graph-leaf",
        ProducerFamily::Shake | ProducerFamily::Aes => "crypto-request",
    }
}

impl ValidatedCompleteInventory<'_, '_> {
    pub(crate) fn verification_identity(&self, metadata: &SourceMetadataPlanningPlan<'_>, ordinal: usize)
        -> Result<DispatchVerificationIdentity>
    {
        if !self.matches_metadata(metadata) || self.plan.steps().len() != self.plan.dispatch().len()
            || self.plan.steps().len() != metadata.counts().steps()
        { return Err(ClosureError::Identity); }
        let dispatch = self.plan.dispatch().get(ordinal).ok_or(ClosureError::Order)?;
        let binding = self.plan.steps().get(ordinal).ok_or(ClosureError::Order)?.binding;
        let route = dispatch.producer();
        let dense = match route {
            ProducerRoute::Native { family, ordinal } => Some((native_family(family), ordinal)),
            ProducerRoute::Leaf { family, ordinal, .. } => Some((leaf_family(family), ordinal)),
            ProducerRoute::Fixed { ordinal, .. } => Some((ProducerFamily::Fixed, ordinal)),
            ProducerRoute::Direct { family, ordinal, .. } => Some((match family {
                DirectFamily::Parameters => ProducerFamily::Parameters,
                DirectFamily::Auxiliary => ProducerFamily::Auxiliary,
                DirectFamily::Equality => ProducerFamily::Equality,
            }, ordinal)),
            ProducerRoute::Crypto { family, request, .. } => Some((match family {
                CryptoFamily::Shake => ProducerFamily::Shake, CryptoFamily::Aes => ProducerFamily::Aes,
            }, request)),
            ProducerRoute::Parent { .. } | ProducerRoute::Final { .. } => None,
        };
        let (member, first, count, source_kind, source_ordinal) = if let Some((family, position)) = dense {
            let (member, source) = metadata.verification_source_position(family, position)?;
            (Some(member), member, 1, family_source_kind(family), Some(source))
        } else {
            match route {
                ProducerRoute::Parent { level, ordinal: parent, .. } => {
                    // A GraphRecord retains the outer binding. Compile uses
                    // its exact paired outer route; matching its own compile
                    // binding here would fail or invent a member label.
                    let expected = ProducerRoute::Parent { level, ordinal: parent, phase: GraphPhase::Outer };
                    let mut outer = None;
                    for (index, step) in self.plan.dispatch().iter().enumerate() {
                        if step.producer() == expected {
                            if outer.is_some() { return Err(ClosureError::Identity); }
                            outer = Some(self.plan.steps().get(index).ok_or(ClosureError::Order)?.binding);
                        }
                    }
                    let outer = outer.ok_or(ClosureError::Coverage)?;
                    let mut member = None;
                    for record in &self.plan.schedule.graph_nodes {
                        if record.child.binding() == outer {
                            if member.is_some() { return Err(ClosureError::Identity); }
                            member = Some(record.member);
                        }
                    }
                    let member = member.ok_or(ClosureError::Coverage)?;
                    (Some(member), member, 1, "parent-route", None)
                }
                ProducerRoute::Final { output, .. } => {
                    let merge = match output {
                        FinalOutput::Compiled(merge) | FinalOutput::Outer(merge) => Some(merge),
                        FinalOutput::Verified => None,
                    };
                    let (first, count) = match merge {
                        Some(merge) => self.plan.schedule.final_source.merge(merge)
                            .ok_or(ClosureError::Coverage)?.span(),
                        None => (0, metadata.members().len()),
                    };
                    (None, first, count, "ordered-merge", merge)
                }
                _ => return Err(ClosureError::Order),
            }
        };
        if count == 0 || add(first, count)? > metadata.members().len()
            || binding.facts().compiled_source_fingerprint != metadata.compiled_source_fingerprint()
        { return Err(ClosureError::Identity); }
        Ok(DispatchVerificationIdentity {
            closed_ordinal: ordinal, expected_steps: self.plan.steps().len(),
            transactions: metadata.members().len(), route, binding: binding.verification_binding(),
            workflow_source_fingerprint: self.plan.source_fingerprint(),
            member, member_first: first, member_count: count, source_kind, source_ordinal,
        })
    }
}

/// Additive fixed lookup/return frames; execution's retained census applies x8.
pub(crate) fn verification_identity_frame_bytes() -> Result<usize> {
    [SourceMetadataPlanningPlan::verification_position_frame_bytes()?,
        size_of::<DispatchVerificationIdentity>(), size_of::<Result<DispatchVerificationIdentity>>(),
        size_of::<VerificationBinding>(), size_of::<PhaseBinding>(), size_of::<PhaseFacts>(),
        size_of::<[Option<PhaseBinding>; 4]>(), size_of::<[ProducerRoute; 4]>(),
        size_of::<[ProducerFamily; 4]>(), size_of::<[usize; 24]>(),
        size_of::<[Option<usize>; 8]>(), size_of::<[&'static str; 8]>(),
        size_of::<[&GraphRecord<'_>; 8]>(), size_of::<[&(); 16]>(),
        size_of::<core::iter::Enumerate<core::slice::Iter<'static, StepDispatch>>>(),
        size_of::<core::slice::Iter<'static, GraphRecord<'static>>>()]
        .into_iter().try_fold(0usize, add)
}
