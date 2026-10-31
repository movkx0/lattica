use super::*;
pub(crate) struct AuxiliaryRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) plans: &'plans AuxiliaryPlanTable<'case, 'source, 'graph>,
    pub(crate) compiled: &'tables AuxiliaryCompiledOutputs<'case, 'graph>,
    pub(crate) outer: &'tables AuxiliaryOuterOutputs<'case, 'graph>,
    pub(crate) packets: &'tables AuxiliaryPreissues<'case, 'plans, 'source, 'graph>,
}
impl<'tables, 'case, 'plans, 'source, 'graph> AuxiliaryRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    fn plan(&self, ordinal: usize) -> Result<&'plans AuxiliaryGraphPlan<'source, 'graph>> { plan(self.plans, ordinal) }
    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let count = metadata.counts().family(ProducerFamily::Auxiliary);
        original_table(self.plans, case, count)?;
        for ordinal in 0..count { self.plan(ordinal)?; }
        uninitialized_table(self.compiled, case, count)?;
        uninitialized_table(self.outer, case, count)?;
        uninitialized_table(self.packets, case, count)?;
        initialize_table(self.compiled)?;
        initialize_table(self.outer)?;
        initialize_table(self.packets)?;
        guard.planning.validate_metadata_driver(metadata, case)?;
        guard.completed = true; Ok(())
    }
    /// Recheck this exact descriptor on every entry. Whole schedule edge replay
    /// belongs to preflight; current owners are rechecked before each move.
    fn validate_tables(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState) -> Result<()>
    {
        let count = inventory.producer_counts().family(ProducerFamily::Auxiliary);
        original_table(self.plans, case, count)?;
        original_table(self.compiled, case, count)?;
        original_table(self.outer, case, count)?;
        original_table(self.packets, case, count)?;
        Ok(())
    }
    pub(crate) fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case)?;
        let mut counts = [0usize; 2];
        for (closed_ordinal, (dispatch, step)) in inventory.closed_plan().dispatch().iter().zip(inventory.closed_plan().steps()).enumerate() {
            let ProducerRoute::Direct { family: DirectFamily::Auxiliary, ordinal, phase } = dispatch.producer()
                else { continue; };
            let index = match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 };
            if ordinal != counts[index] { return Err(WorkflowError::Sequence); }
            same_binding(self.plan(ordinal)?.binding(index).map_err(|_| WorkflowError::Source)?, step.binding)?;
            let dependencies = self.plan(ordinal)?.dependencies(index).map_err(|_| WorkflowError::Source)?;
            expected_edges(inventory, closed_ordinal, dispatch, &dependencies.bindings,
                dependencies.count, dependencies.consume)?;
            increment(&mut counts[index])?;
        }
        if counts[0] != counts[1] { return Err(WorkflowError::Sequence); }
        original_table(self.plans, case, counts[0])?;
        empty_table(self.compiled, case, counts[0])?;
        empty_table(self.outer, case, counts[0])?;
        empty_table(self.packets, case, counts[0])?;
        guard.completed = true; Ok(())
    }
    pub(crate) fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case)?;
        let dispatch = inventory.closed_plan().dispatch().get(closed_ordinal).ok_or(WorkflowError::Sequence)?;
        let (ordinal, phase) = direct_route(dispatch, DirectFamily::Auxiliary)?;
        if phase != GraphPhase::Outer { return Err(WorkflowError::Sequence); }
        let mut target = write(cell(self.packets, ordinal)?)?;
        empty(&target)?;
        *target = Some(guard.workflow.preissue_auxiliary_outer(self.plan(ordinal)?));
        ready(&target)?;
        guard.completed = true; Ok(())
    }
    pub(crate) fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize, inputs: &DirectInputs<'_, 'case, 'graph>) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        let dispatch = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        self.validate_tables(inventory, case)?;
        inputs.validate_inventory(inventory, case)?;
        let (ordinal, phase) = direct_route(&dispatch, DirectFamily::Auxiliary)?;
        let plan = self.plan(ordinal)?;
        let binding = plan.binding(match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 })
            .map_err(|_| WorkflowError::Source)?;
        match phase {
            GraphPhase::Compile => {
                self.compile(guard.workflow, inventory, case, closed_ordinal, &dispatch, inputs, ordinal, plan, binding)?;
            }
            GraphPhase::Outer => {
                shape(&dispatch, 1, 1)?;
                require_input(&dispatch, 0, ProducerRoute::Direct { family: DirectFamily::Auxiliary, ordinal, phase: GraphPhase::Compile })?;
                let mut compiled = write(cell(self.compiled, ordinal)?)?;
                let mut packet = write(cell(self.packets, ordinal)?)?;
                let mut target = write(cell(self.outer, ordinal)?)?;
                empty(&target)?;
                same_binding(ready(&compiled)?.binding(), plan.binding(0).map_err(|_| WorkflowError::Source)?)?;
                check_owner(ready(&compiled)?, inventory, closed_ordinal, 0)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take_ready(&mut packet)?;
                let owner = match take_ready(&mut compiled) {
                    Ok(owner) => owner,
                    Err(error) => { *packet = Some(Ok(packet_owner)); return Err(error); }
                };
                let operation = match plan.outer_operation_retaining(owner) {
                    Ok(operation) => operation,
                    Err((_error, owner)) => {
                        *compiled = Some(Ok(owner)); *packet = Some(Ok(packet_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.prove_owned_auxiliary_outer(operation, packet_owner));
                ready(&target)?;
            }
        }
        guard.completed = true; Ok(())
    }
}

use crate::graph_crypto::{PairedRequestPlan, OwnedAesRequestPlan, RequestStepKind, OwnedAesStepKind};
use crate::execution::workflow_resources::SlotId;
use crate::spend_pipeline::full_workflow::{uniform_native::UniformNativeOperationPlan,
    sparse_native::SparseNativeOperationPlan, transcript_native::TranscriptNativeOperationPlan};

pub(crate) struct DirectInputs<'tables, 'case, 'graph> {
    pub(crate) shake: &'tables ShakeRequestOutputs<'case, 'graph>,
    pub(crate) aes: &'tables AesRequestOutputs<'case, 'graph>,
    pub(crate) uniform: &'tables UniformNativeOutputs<'case, 'graph>,
    pub(crate) sparse: &'tables SparseNativeOutputs<'case, 'graph>,
    pub(crate) transcript: &'tables TranscriptNativeOutputs<'case, 'graph>,
}
impl<'tables, 'case, 'graph> DirectInputs<'tables, 'case, 'graph> {
    pub(crate) fn validate(&self, metadata: &SourceMetadataPlanningPlan<'_>,
        case: &CaseRetirementState) -> Result<()>
    { self.validate_counts(metadata.counts(), case) }
    pub(crate) fn validate_inventory(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState) -> Result<()>
    { self.validate_counts(inventory.producer_counts(), case) }
    fn validate_counts(&self, counts: ProducerCounts, case: &CaseRetirementState) -> Result<()>
    {
        original_table(self.shake, case, counts.family(ProducerFamily::Shake))?;
        original_table(self.aes, case, counts.family(ProducerFamily::Aes))?;
        original_table(self.uniform, case, counts.family(ProducerFamily::Uniform))?;
        original_table(self.sparse, case, counts.family(ProducerFamily::Sparse))?;
        original_table(self.transcript, case, counts.family(ProducerFamily::Transcript))?;
        Ok(())
    }
    pub(super) fn request_slots(root: (PhaseBinding, SlotId), endpoints: (PhaseBinding, SlotId),
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize, start: usize) -> Result<()>
    {
        if root != input_edge(inventory, closed_ordinal, start)?
            || endpoints != input_edge(inventory, closed_ordinal, start.checked_add(1).ok_or(WorkflowError::Overflow)?)?
        { return Err(WorkflowError::Identity); }
        Ok(())
    }
    fn request_route(dispatch: &StepDispatch, start: usize, family: CryptoFamily)
        -> Result<(usize, usize)>
    {
        let ProducerRoute::Crypto { family: actual, request, step, output: CryptoOutput::Outer(_) } = input(dispatch, start)?
            else { return Err(WorkflowError::Identity); };
        if actual != family { return Err(WorkflowError::Identity); }
        require_input(dispatch, start.checked_add(1).ok_or(WorkflowError::Overflow)?,
            ProducerRoute::Crypto { family, request, step: 0, output: CryptoOutput::Endpoint(request) })?;
        Ok((request, step))
    }
    pub(super) fn shake_route(dispatch: &StepDispatch, start: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &PairedRequestPlan<'_>) -> Result<usize>
    {
        let (request, step) = Self::request_route(dispatch, start, CryptoFamily::Shake)?;
        if plan.ordered_steps().get(step).map(|s| s.kind)
            != Some(RequestStepKind::Outer { node: plan.root_id() })
        { return Err(WorkflowError::Identity); }
        same_binding(input_edge(inventory, closed_ordinal, start)?.0, PhaseBinding::for_paired(plan, step)?)?;
        same_binding(input_edge(inventory, closed_ordinal, start + 1)?.0, PhaseBinding::for_paired(plan, 0)?)?;
        Ok(request)
    }
    fn aes_route(dispatch: &StepDispatch, start: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &OwnedAesRequestPlan<'_>) -> Result<usize>
    {
        let (request, step) = Self::request_route(dispatch, start, CryptoFamily::Aes)?;
        if plan.ordered_steps().get(step).map(|s| s.kind)
            != Some(OwnedAesStepKind::Outer { node: plan.root_id() })
        { return Err(WorkflowError::Identity); }
        same_binding(input_edge(inventory, closed_ordinal, start)?.0, PhaseBinding::for_aes(plan, step)?)?;
        same_binding(input_edge(inventory, closed_ordinal, start + 1)?.0, PhaseBinding::for_aes(plan, 0)?)?;
        Ok(request)
    }
    pub(super) fn shake_request(&self, dispatch: &StepDispatch, start: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &PairedRequestPlan<'_>, case: &CaseRetirementState)
        -> Result<&'tables RefCell<Option<ShakeRequestResult<'graph>>>>
    {
        if !self.shake.belongs_to_case(case) { return Err(WorkflowError::Identity); }
        cell(self.shake, Self::shake_route(dispatch, start, inventory, closed_ordinal, plan)?)
    }
    fn aes_request(&self, dispatch: &StepDispatch, start: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &OwnedAesRequestPlan<'_>, case: &CaseRetirementState)
        -> Result<&'tables RefCell<Option<AesRequestResult<'graph>>>>
    {
        if !self.aes.belongs_to_case(case) { return Err(WorkflowError::Identity); }
        cell(self.aes, Self::aes_route(dispatch, start, inventory, closed_ordinal, plan)?)
    }
    fn uniform_input(&self, dispatch: &StepDispatch, index: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &UniformNativeOperationPlan<'_>, case: &CaseRetirementState)
        -> Result<&'tables RefCell<Option<UniformNativeResult<'graph>>>>
    {
        let ProducerRoute::Native { family: NativeFamily::Uniform, ordinal } = input(dispatch, index)?
            else { return Err(WorkflowError::Identity); };
        if !self.uniform.belongs_to_case(case) { return Err(WorkflowError::Identity); }
        let expected = input_edge(inventory, closed_ordinal, index)?;
        same_binding(expected.0, PhaseBinding::for_uniform_native(plan, 0)?)?;
        let target = cell(self.uniform, ordinal)?;
        let borrowed = target.try_borrow().map_err(|_| WorkflowError::SlotBusy)?;
        let owner = ready(&borrowed)?;
        same_binding(owner.binding(), expected.0)?;
        if owner.slot_id() != expected.1 { return Err(WorkflowError::Identity); }
        drop(borrowed); Ok(target)
    }
    fn sparse_input(&self, dispatch: &StepDispatch, index: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &SparseNativeOperationPlan<'_>, case: &CaseRetirementState)
        -> Result<&'tables RefCell<Option<SparseNativeResult<'graph>>>>
    {
        let ProducerRoute::Native { family: NativeFamily::Sparse, ordinal } = input(dispatch, index)?
            else { return Err(WorkflowError::Identity); };
        if !self.sparse.belongs_to_case(case) { return Err(WorkflowError::Identity); }
        let expected = input_edge(inventory, closed_ordinal, index)?;
        same_binding(expected.0, PhaseBinding::for_sparse_native(plan, 0)?)?;
        let target = cell(self.sparse, ordinal)?;
        let borrowed = target.try_borrow().map_err(|_| WorkflowError::SlotBusy)?;
        let owner = ready(&borrowed)?;
        same_binding(owner.binding(), expected.0)?;
        if owner.slot_id() != expected.1 { return Err(WorkflowError::Identity); }
        drop(borrowed); Ok(target)
    }
    fn transcript_input(&self, dispatch: &StepDispatch, index: usize,
        inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
        plan: &TranscriptNativeOperationPlan<'_>, case: &CaseRetirementState)
        -> Result<&'tables RefCell<Option<TranscriptNativeResult<'graph>>>>
    {
        let ProducerRoute::Native { family: NativeFamily::Transcript, ordinal } = input(dispatch, index)?
            else { return Err(WorkflowError::Identity); };
        if !self.transcript.belongs_to_case(case) { return Err(WorkflowError::Identity); }
        let expected = input_edge(inventory, closed_ordinal, index)?;
        same_binding(expected.0, PhaseBinding::for_transcript_native(plan, 0)?)?;
        let target = cell(self.transcript, ordinal)?;
        let borrowed = target.try_borrow().map_err(|_| WorkflowError::SlotBusy)?;
        let owner = ready(&borrowed)?;
        same_binding(owner.binding(), expected.0)?;
        if owner.slot_id() != expected.1 { return Err(WorkflowError::Identity); }
        drop(borrowed); Ok(target)
    }
}
impl<'tables, 'case, 'plans, 'source, 'graph> AuxiliaryRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    fn compile(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState, closed_ordinal: usize,
        dispatch: &StepDispatch, inputs: &DirectInputs<'_, 'case, 'graph>, ordinal: usize,
        plan: &AuxiliaryGraphPlan<'source, 'graph>, binding: PhaseBinding) -> Result<()>
    {
        let dependencies = plan.dependencies(0).map_err(|_| WorkflowError::Source)?;
        expected_edges(inventory, closed_ordinal, dispatch, &dependencies.bindings,
            dependencies.count, dependencies.consume)?;
        let mut target = write(cell(self.compiled, ordinal)?)?;
        empty(&target)?;
        match plan.sources() {
            AuxiliaryGraphSources::SampleG { aes, uniform } => {
                let mut aes = write(inputs.aes_request(dispatch, 0, inventory, closed_ordinal, aes, case)?)?;
                let mut uniform = write(inputs.uniform_input(dispatch, 2, inventory, closed_ordinal, uniform, case)?)?;
                let value = ready(&aes)?;
                DirectInputs::request_slots((value.root_binding(), value.root_slot()),
                    (value.endpoint_binding(), value.endpoint_slot()), inventory, closed_ordinal, 0)?;
                ready(&uniform)?;
                let phase = workflow.next_phase(binding)?;
                let aes_owner = take_ready(&mut aes)?;
                let uniform_owner = match take_ready(&mut uniform) {
                    Ok(owner) => owner,
                    Err(error) => { *aes = Some(Ok(aes_owner)); return Err(error); }
                };
                let operation = match plan.sample_g_operation_retaining(aes_owner, uniform_owner) {
                    Ok(operation) => operation,
                    Err((_error, aes_owner, uniform_owner)) => {
                        *aes = Some(Ok(aes_owner)); *uniform = Some(Ok(uniform_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_owned_auxiliary(operation));
                ready(&target)?;
            }
            AuxiliaryGraphSources::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse } => {
                let mut uniform_aes = write(inputs.aes_request(dispatch, 0, inventory, closed_ordinal, uniform_aes, case)?)?;
                let mut uniform = write(inputs.uniform_input(dispatch, 2, inventory, closed_ordinal, uniform, case)?)?;
                let mut sparse_aes = write(inputs.aes_request(dispatch, 3, inventory, closed_ordinal, sparse_aes, case)?)?;
                let mut sparse = write(inputs.sparse_input(dispatch, 5, inventory, closed_ordinal, sparse, case)?)?;
                let value = ready(&uniform_aes)?;
                DirectInputs::request_slots((value.root_binding(), value.root_slot()),
                    (value.endpoint_binding(), value.endpoint_slot()), inventory, closed_ordinal, 0)?;
                ready(&uniform)?;
                let value = ready(&sparse_aes)?;
                DirectInputs::request_slots((value.root_binding(), value.root_slot()),
                    (value.endpoint_binding(), value.endpoint_slot()), inventory, closed_ordinal, 3)?;
                ready(&sparse)?;
                let phase = workflow.next_phase(binding)?;
                let uniform_aes_owner = take_ready(&mut uniform_aes)?;
                let uniform_owner = match take_ready(&mut uniform) {
                    Ok(owner) => owner,
                    Err(error) => { *uniform_aes = Some(Ok(uniform_aes_owner)); return Err(error); }
                };
                let sparse_aes_owner = match take_ready(&mut sparse_aes) {
                    Ok(owner) => owner,
                    Err(error) => { *uniform_aes = Some(Ok(uniform_aes_owner)); *uniform = Some(Ok(uniform_owner)); return Err(error); }
                };
                let sparse_owner = match take_ready(&mut sparse) {
                    Ok(owner) => owner,
                    Err(error) => { *uniform_aes = Some(Ok(uniform_aes_owner)); *uniform = Some(Ok(uniform_owner)); *sparse_aes = Some(Ok(sparse_aes_owner)); return Err(error); }
                };
                let operation = match plan.expand_alpha_operation_retaining(uniform_aes_owner, uniform_owner, sparse_aes_owner, sparse_owner) {
                    Ok(operation) => operation,
                    Err((_error, uniform_aes_owner, uniform_owner, sparse_aes_owner, sparse_owner)) => {
                        *uniform_aes = Some(Ok(uniform_aes_owner)); *uniform = Some(Ok(uniform_owner)); *sparse_aes = Some(Ok(sparse_aes_owner)); *sparse = Some(Ok(sparse_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_owned_auxiliary(operation));
                ready(&target)?;
            }
            AuxiliaryGraphSources::HashAlpha { shake, transcript } => {
                let mut shake = write(inputs.shake_request(dispatch, 0, inventory, closed_ordinal, shake, case)?)?;
                let mut transcript = write(inputs.transcript_input(dispatch, 2, inventory, closed_ordinal, transcript, case)?)?;
                let value = ready(&shake)?;
                DirectInputs::request_slots((value.root_binding(), value.root_slot()),
                    (value.endpoint_binding(), value.endpoint_slot()), inventory, closed_ordinal, 0)?;
                ready(&transcript)?;
                let phase = workflow.next_phase(binding)?;
                let shake_owner = take_ready(&mut shake)?;
                let transcript_owner = match take_ready(&mut transcript) {
                    Ok(owner) => owner,
                    Err(error) => { *shake = Some(Ok(shake_owner)); return Err(error); }
                };
                let operation = match plan.hash_alpha_operation_retaining(shake_owner, transcript_owner) {
                    Ok(operation) => operation,
                    Err((_error, shake_owner, transcript_owner)) => {
                        *shake = Some(Ok(shake_owner)); *transcript = Some(Ok(transcript_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_owned_auxiliary(operation));
                ready(&target)?;
            }
            AuxiliaryGraphSources::HashX { shake, transcript, sparse } => {
                let mut shake = write(inputs.shake_request(dispatch, 0, inventory, closed_ordinal, shake, case)?)?;
                let mut transcript = write(inputs.transcript_input(dispatch, 2, inventory, closed_ordinal, transcript, case)?)?;
                let mut sparse = write(inputs.sparse_input(dispatch, 3, inventory, closed_ordinal, sparse, case)?)?;
                let value = ready(&shake)?;
                DirectInputs::request_slots((value.root_binding(), value.root_slot()),
                    (value.endpoint_binding(), value.endpoint_slot()), inventory, closed_ordinal, 0)?;
                ready(&transcript)?;
                ready(&sparse)?;
                let phase = workflow.next_phase(binding)?;
                let shake_owner = take_ready(&mut shake)?;
                let transcript_owner = match take_ready(&mut transcript) {
                    Ok(owner) => owner,
                    Err(error) => { *shake = Some(Ok(shake_owner)); return Err(error); }
                };
                let sparse_owner = match take_ready(&mut sparse) {
                    Ok(owner) => owner,
                    Err(error) => { *shake = Some(Ok(shake_owner)); *transcript = Some(Ok(transcript_owner)); return Err(error); }
                };
                let operation = match plan.hash_x_operation_retaining(shake_owner, transcript_owner, sparse_owner) {
                    Ok(operation) => operation,
                    Err((_error, shake_owner, transcript_owner, sparse_owner)) => {
                        *shake = Some(Ok(shake_owner)); *transcript = Some(Ok(transcript_owner)); *sparse = Some(Ok(sparse_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_owned_auxiliary(operation));
                ready(&target)?;
            }
        }
        Ok(())
    }
}
