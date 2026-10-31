//! Immutable routing accompanies the same validated phase/slot traversal.
//! It is never execution authority; runtime still checks the concrete binding.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum NativeFamily { Source, Uniform, Sparse, Transcript, Affine, Ntt, Mul, GBound, Permutation, LinearMap }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum LeafFamily { Source, Affine, Ntt, Mul, GBound, Permutation, LinearMap }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum DirectFamily { Parameters, Auxiliary, Equality }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum CryptoFamily { Shake, Aes }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum CryptoOutput { Endpoint(usize), Native(usize), Compiled(usize), Outer(usize) }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum GraphPhase { Compile, Outer }
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum FinalOutput { Compiled(usize), Outer(usize), Verified }

/// Every ordinal names an exact table in CompleteProducerTables and the
/// matching concrete runtime table from metadata_tables. Crypto output indices
/// include preceding request prefixes; parent ordinals are local to a level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum ProducerRoute {
    Fixed { ordinal: usize, phase: GraphPhase },
    Native { family: NativeFamily, ordinal: usize },
    Leaf { family: LeafFamily, ordinal: usize, phase: GraphPhase },
    Direct { family: DirectFamily, ordinal: usize, phase: GraphPhase },
    Crypto { family: CryptoFamily, request: usize, step: usize, output: CryptoOutput },
    Parent { level: usize, ordinal: usize, phase: GraphPhase },
    Final { step: usize, output: FinalOutput },
}

#[derive(Clone, Copy)]
pub(crate) struct StepDispatch {
    producer: ProducerRoute,
    inputs: [Option<ProducerRoute>; MAX_PHASE_INPUTS],
    input_count: usize,
    consume_count: usize,
}
impl StepDispatch {
    pub(crate) fn producer(&self) -> ProducerRoute { self.producer }
    pub(crate) fn inputs(&self) -> &[Option<ProducerRoute>] { &self.inputs[..self.input_count] }
    pub(crate) fn consume_count(&self) -> usize { self.consume_count }
}

#[derive(Clone, Copy)]
pub(in crate::spend_pipeline::full_workflow::closed_plan) struct CryptoRoute {
    pub(in crate::spend_pipeline::full_workflow::closed_plan) family: CryptoFamily,
    pub(in crate::spend_pipeline::full_workflow::closed_plan) request: usize,
    pub(in crate::spend_pipeline::full_workflow::closed_plan) native_offset: usize,
    pub(in crate::spend_pipeline::full_workflow::closed_plan) recursive_offset: usize,
}
impl CryptoRoute {
    pub(in crate::spend_pipeline::full_workflow::closed_plan) fn step(self, plan: CryptoRequestPlan<'_>, ordinal: usize) -> Result<ProducerRoute> {
        let output = match plan {
            CryptoRequestPlan::Shake(plan) => match plan.ordered_steps().get(ordinal).ok_or(ClosureError::Order)?.kind {
                RequestStepKind::Endpoints => CryptoOutput::Endpoint(self.request),
                RequestStepKind::Native { index } => CryptoOutput::Native(add(self.native_offset, index)?),
                RequestStepKind::Group { node } | RequestStepKind::Merge { node, .. } =>
                    CryptoOutput::Compiled(add(self.recursive_offset, node)?),
                RequestStepKind::Outer { node } => CryptoOutput::Outer(add(self.recursive_offset, node)?),
            },
            CryptoRequestPlan::Aes(plan) => match plan.ordered_steps().get(ordinal).ok_or(ClosureError::Order)?.kind {
                OwnedAesStepKind::Endpoints => CryptoOutput::Endpoint(self.request),
                OwnedAesStepKind::Native { index } => CryptoOutput::Native(add(self.native_offset, index)?),
                OwnedAesStepKind::Compile { node } | OwnedAesStepKind::Merge { node, .. } =>
                    CryptoOutput::Compiled(add(self.recursive_offset, node)?),
                OwnedAesStepKind::Outer { node } => CryptoOutput::Outer(add(self.recursive_offset, node)?),
            },
        };
        Ok(ProducerRoute::Crypto { family: self.family, request: self.request, step: ordinal, output })
    }
}

impl SupportedSchedule<'_> {
    pub(in crate::spend_pipeline::full_workflow::closed_plan) fn slot_for_binding(&self, binding: PhaseBinding) -> Result<SlotId> {
        let step = self.steps.iter().find(|step| step.binding == binding).ok_or(ClosureError::Order)?;
        let current = self.steps.iter().rev().find(|next| next.output == step.output).ok_or(ClosureError::Order)?;
        if current.binding != binding || !self.live.get(step.output.index()).copied().unwrap_or(false) {
            return Err(ClosureError::Order);
        }
        Ok(step.output)
    }

    pub(in crate::spend_pipeline::full_workflow::closed_plan) fn record_routed(&mut self, binding: PhaseBinding, inputs: &[SlotId], consumed: usize,
        backend: Bytes, producer: ProducerRoute) -> Result<SlotId>
    {
        if self.dispatch.len() != self.steps.len() || inputs.len() > MAX_PHASE_INPUTS
            || self.dispatch.iter().any(|entry| entry.producer == producer)
        { return Err(ClosureError::Order); }
        let mut routes = [None; MAX_PHASE_INPUTS];
        for (position, slot) in inputs.iter().enumerate() {
            let index = self.steps.iter().rposition(|step| step.output == *slot).ok_or(ClosureError::Order)?;
            if !self.live.get(slot.index()).copied().unwrap_or(false) { return Err(ClosureError::Order); }
            routes[position] = Some(self.dispatch.get(index).ok_or(ClosureError::Order)?.producer);
        }
        let output = self.record(binding, inputs, consumed, backend)?;
        push(&mut self.dispatch, StepDispatch { producer, inputs: routes, input_count: inputs.len(), consume_count: consumed })?;
        Ok(output)
    }

    pub(in crate::spend_pipeline::full_workflow::closed_plan) fn record_dependencies(&mut self, binding: PhaseBinding,
        bindings: &[Option<PhaseBinding>], count: usize, consume: usize, backend: Bytes,
        route: ProducerRoute) -> Result<SlotId>
    {
        if count > MAX_PHASE_INPUTS || count > bindings.len() || consume > count
            || bindings[count..].iter().any(Option::is_some) { return Err(ClosureError::Order); }
        let mut inputs = [SlotId::new(0); MAX_PHASE_INPUTS];
        for (index, input) in bindings[..count].iter().enumerate() {
            inputs[index] = self.slot_for_binding(input.ok_or(ClosureError::Order)?)?;
        }
        self.record_routed(binding, &inputs[..count], consume, backend, route)
    }
}
