use super::*;
/// One real parent level. Earlier output levels remain separately owned.
pub(crate) struct ParentRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) level: usize,
    pub(crate) plans: &'plans ParentPlanTable<'case, 'source, 'graph>,
    pub(crate) compiled: &'tables ParentCompiledOutputs<'case, 'graph>,
    pub(crate) outer: &'tables ParentOuterOutputs<'case, 'graph>,
    pub(crate) packets: &'tables ParentPreissues<'case, 'plans, 'source, 'graph>,
}
impl<'tables, 'case, 'plans, 'source, 'graph> ParentRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    fn plan(&self, ordinal: usize) -> Result<&'plans GraphParentPlan<'source, 'graph>> { plan(self.plans, ordinal) }
    /// Identity observation for root's fixed descriptor alias audit only.
    pub(crate) fn compiled_table_identity(&self) -> *const () {
        self.compiled as *const ParentCompiledOutputs<'case, 'graph> as *const ()
    }
    /// Fixed read-only identities for the global output/packet alias audit.
    /// Plans and inputs are intentionally absent; no owner is extracted.
    pub(crate) fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.compiled as *const ParentCompiledOutputs<'case, 'graph> as *const ()),
            1 => Some(self.outer as *const ParentOuterOutputs<'case, 'graph> as *const ()),
            2 => Some(self.packets as *const ParentPreissues<'case, 'plans, 'source, 'graph> as *const ()),
            _ => None,
        }
    }
    fn route(&self, dispatch: &StepDispatch) -> Result<(usize, GraphPhase)> {
        match dispatch.producer() {
            ProducerRoute::Parent { level, ordinal, phase } if level == self.level && level < 32 => Ok((ordinal, phase)),
            _ => Err(WorkflowError::Identity),
        }
    }
    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let count = metadata.counts().parent_level(self.level).filter(|count| *count > 0)
            .ok_or(WorkflowError::Identity)?;
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
        let count = inventory.producer_counts().parent_level(self.level).filter(|count| *count > 0).ok_or(WorkflowError::Identity)?;
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
        if self.level >= 32 { return Err(WorkflowError::Identity); }
        let mut counts = [0usize; 2];
        for (closed_ordinal, (dispatch, step)) in inventory.closed_plan().dispatch().iter().zip(inventory.closed_plan().steps()).enumerate() {
            let ProducerRoute::Parent { level, ordinal, phase } = dispatch.producer() else { continue; };
            if level != self.level { continue; }
            let index = match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 };
            if ordinal != counts[index] { return Err(WorkflowError::Sequence); }
            let plan = self.plan(ordinal)?;
            same_binding(plan.binding(index).map_err(|_| WorkflowError::Source)?, step.binding)?;
            match phase {
                GraphPhase::Compile => {
                    let children = plan.child_sources();
                    expected_edges(inventory, closed_ordinal, dispatch,
                        &[Some(children[0].binding()), Some(children[1].binding())], 2, 2)?;
                    graph_route(input(dispatch, 0)?, self.level)?;
                    graph_route(input(dispatch, 1)?, self.level)?;
                }
                GraphPhase::Outer => expected_edges(inventory, closed_ordinal, dispatch,
                    &[Some(plan.binding(0).map_err(|_| WorkflowError::Source)?)], 1, 1)?,
            }
            increment(&mut counts[index])?;
        }
        if counts[0] == 0 || counts[0] != counts[1] { return Err(WorkflowError::Sequence); }
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
        let (ordinal, phase) = self.route(dispatch)?;
        if phase != GraphPhase::Outer { return Err(WorkflowError::Sequence); }
        let mut target = write(cell(self.packets, ordinal)?)?;
        empty(&target)?;
        *target = Some(guard.workflow.preissue_graph_parent_outer(self.plan(ordinal)?));
        ready(&target)?;
        guard.completed = true; Ok(())
    }
    pub(crate) fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize, graphs: &GraphOutputs<'_, '_, 'graph>) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        let dispatch = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        self.validate_tables(inventory, case)?;
        graphs.validate_inventory(inventory, case)?;
        let (ordinal, phase) = self.route(&dispatch)?;
        let plan = self.plan(ordinal)?;
        let binding = plan.binding(match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 })
            .map_err(|_| WorkflowError::Source)?;
        match phase {
            GraphPhase::Compile => {
                shape(&dispatch, 2, 2)?;
                let left_route = input(&dispatch, 0)?;
                let right_route = input(&dispatch, 1)?;
                graph_route(left_route, self.level)?;
                graph_route(right_route, self.level)?;
                let mut left = write(graphs.cell(left_route)?)?;
                let mut right = write(graphs.cell(right_route)?)?;
                let mut target = write(cell(self.compiled, ordinal)?)?;
                empty(&target)?;
                let children = plan.child_sources();
                same_binding(ready(&left)?.binding(), children[0].binding())?;
                same_binding(ready(&right)?.binding(), children[1].binding())?;
                check_owner(ready(&left)?, inventory, closed_ordinal, 0)?;
                check_owner(ready(&right)?, inventory, closed_ordinal, 1)?;
                let phase = guard.workflow.next_phase(binding)?;
                let left_owner = take_ready(&mut left)?;
                let right_owner = match take_ready(&mut right) {
                    Ok(owner) => owner,
                    Err(error) => { *left = Some(Ok(left_owner)); return Err(error); }
                };
                let operation = match plan.compile_operation_retaining([left_owner, right_owner]) {
                    Ok(operation) => operation,
                    Err((_error, [left_owner, right_owner])) => {
                        *left = Some(Ok(left_owner)); *right = Some(Ok(right_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_graph_parent(operation));
                ready(&target)?;
            }
            GraphPhase::Outer => {
                shape(&dispatch, 1, 1)?;
                require_input(&dispatch, 0, ProducerRoute::Parent { level: self.level, ordinal, phase: GraphPhase::Compile })?;
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
                *target = Some(phase.prove_owned_graph_parent_outer(operation, packet_owner));
                ready(&target)?;
            }
        }
        guard.completed = true; Ok(())
    }
}
// An odd carried tail may come from any earlier level, including the original
// leaf. No copied tree node or new owner is introduced for the carry.
fn graph_route(route: ProducerRoute, current_level: usize) -> Result<()> {
    match route {
        ProducerRoute::Fixed { phase: GraphPhase::Outer, .. }
        | ProducerRoute::Leaf { phase: GraphPhase::Outer, .. }
        | ProducerRoute::Direct { phase: GraphPhase::Outer, .. } => Ok(()),
        ProducerRoute::Parent { level, phase: GraphPhase::Outer, .. } if level < current_level => Ok(()),
        _ => Err(WorkflowError::Identity),
    }
}

mod sealed { pub trait ParentRuntimeSealed {} }
/// A borrowed projection only. Each implementation retains its actual typed
/// level tables and independent plan/source lifetimes; there is no owning union.
pub(crate) trait ParentRuntimeDriver<'graph>: sealed::ParentRuntimeSealed {
    fn level(&self) -> usize;
    fn compiled_table_identity(&self) -> *const ();
    fn storage_table(&self, index: usize) -> Option<*const ()>;
    fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>;
    fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>;
    fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>;
    fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize, graphs: &GraphOutputs<'_, '_, 'graph>) -> Result<()>;
}
pub(crate) type ParentRuntimes<'runtime, 'graph> =
    [Option<&'runtime dyn ParentRuntimeDriver<'graph>>; 32];
impl sealed::ParentRuntimeSealed for ParentRuntime<'_, '_, '_, '_, '_> {}
impl<'graph> ParentRuntimeDriver<'graph> for ParentRuntime<'_, '_, '_, '_, 'graph> {
    fn level(&self) -> usize { self.level }
    fn compiled_table_identity(&self) -> *const () { ParentRuntime::compiled_table_identity(self) }
    fn storage_table(&self, index: usize) -> Option<*const ()> { ParentRuntime::storage_table(self, index) }
    fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    { ParentRuntime::initialize(self, planning, metadata, case) }
    fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>
    { ParentRuntime::preflight(self, workflow, inventory, case) }
    fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    { ParentRuntime::preissue(self, workflow, inventory, case, closed_ordinal) }
    fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize, graphs: &GraphOutputs<'_, '_, 'graph>) -> Result<()>
    { ParentRuntime::execute_step(self, workflow, inventory, case, closed_ordinal, graphs) }
}
