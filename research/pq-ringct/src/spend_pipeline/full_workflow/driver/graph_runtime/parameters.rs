use super::*;
pub(crate) struct ParametersRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) plans: &'plans ParametersPlanTable<'case, 'source, 'graph>,
    pub(crate) compiled: &'tables ParametersCompiledOutputs<'case, 'graph>,
    pub(crate) outer: &'tables ParametersOuterOutputs<'case, 'graph>,
    pub(crate) packets: &'tables ParametersPreissues<'case, 'plans, 'source, 'graph>,
}
impl<'tables, 'case, 'plans, 'source, 'graph> ParametersRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    fn plan(&self, ordinal: usize) -> Result<&'plans ParametersPpGraphPlan<'source, 'graph>> { plan(self.plans, ordinal) }
    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let count = metadata.counts().family(ProducerFamily::Parameters);
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
        let count = inventory.producer_counts().family(ProducerFamily::Parameters);
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
            let ProducerRoute::Direct { family: DirectFamily::Parameters, ordinal, phase } = dispatch.producer()
                else { continue; };
            let index = match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 };
            if ordinal != counts[index] { return Err(WorkflowError::Sequence); }
            same_binding(self.plan(ordinal)?.binding(index).map_err(|_| WorkflowError::Source)?, step.binding)?;
            match phase {
                GraphPhase::Compile => {
                    shape(dispatch, 2, 2)?;
                    DirectInputs::shake_route(dispatch, 0, inventory, closed_ordinal, self.plan(ordinal)?.request_plan())?;
                }
                GraphPhase::Outer => expected_edges(inventory, closed_ordinal, dispatch,
                    &[Some(self.plan(ordinal)?.binding(0).map_err(|_| WorkflowError::Source)?)], 1, 1)?,
            }
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
        let (ordinal, phase) = direct_route(dispatch, DirectFamily::Parameters)?;
        if phase != GraphPhase::Outer { return Err(WorkflowError::Sequence); }
        let mut target = write(cell(self.packets, ordinal)?)?;
        empty(&target)?;
        *target = Some(guard.workflow.preissue_parameters_pp_outer(self.plan(ordinal)?));
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
        let (ordinal, phase) = direct_route(&dispatch, DirectFamily::Parameters)?;
        let plan = self.plan(ordinal)?;
        let binding = plan.binding(match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 })
            .map_err(|_| WorkflowError::Source)?;
        match phase {
            GraphPhase::Compile => {
                shape(&dispatch, 2, 2)?;
                let request = inputs.shake_request(&dispatch, 0, inventory, closed_ordinal, plan.request_plan(), case)?;
                let mut request = write(request)?;
                let mut target = write(cell(self.compiled, ordinal)?)?;
                empty(&target)?;
                let request_owner = ready(&request)?;
                DirectInputs::request_slots((request_owner.root_binding(), request_owner.root_slot()),
                    (request_owner.endpoint_binding(), request_owner.endpoint_slot()),
                    inventory, closed_ordinal, 0)?;
                let phase = guard.workflow.next_phase(binding)?;
                let operation = match plan.compile_operation_retaining(take_ready(&mut request)?) {
                    Ok(operation) => operation,
                    Err((_error, owner)) => { *request = Some(Ok(owner)); return Err(WorkflowError::Source); }
                };
                *target = Some(phase.compile_owned_parameters_pp(operation));
                ready(&target)?;
            }
            GraphPhase::Outer => {
                shape(&dispatch, 1, 1)?;
                require_input(&dispatch, 0, ProducerRoute::Direct { family: DirectFamily::Parameters, ordinal, phase: GraphPhase::Compile })?;
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
                *target = Some(phase.prove_owned_parameters_pp_outer(operation, packet_owner));
                ready(&target)?;
            }
        }
        guard.completed = true; Ok(())
    }
}
