//! Final merge execution keeps the actual final root in an immutable case slot.
//! A verification receipt can therefore borrow its original owner until cleanup.
use super::super::{closed_plan::{FinalOutput, ProducerRoute, StepDispatch, ValidatedCompleteInventory},
    fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState},
    metadata_planning::SourceMetadataPlanningPlan, metadata_tables::{final_aggregation::*, graph::GraphOuterResult}};
use super::{graph_runtime::GraphOutputs, runtime_inputs::{input_edge, check_owner}};
use crate::{execution::workflow_resources::{PhaseBinding, WorkflowAdmission, WorkflowPlanning, WorkflowError},
    ordered_aggregation::{source::ChildSource, owned_final::{FinalChild, FinalFailure, FinalPhasePlan, FinalStepKind}}};
use std::cell::{RefCell, RefMut};
type Result<T> = core::result::Result<T, WorkflowError>;

pub(crate) struct FinalRuntime<'tables, 'root, 'case, 'plans, 'graph, 'source> {
    pub(crate) plans: &'plans FinalPlanTable<'case, 'source>,
    pub(crate) compiled: &'tables FinalCompiledOutputs<'case, 'source>,
    pub(crate) outer: &'tables FinalOuterOutputs<'case, 'source>,
    pub(crate) root: &'root FinalRootTable<'case, 'source>,
    pub(crate) verified: &'tables FinalVerifyOutputs<'case, 'root, 'source>,
    pub(crate) packets: &'tables FinalPreissues<'case, 'plans, 'source>,
    pub(crate) failure: &'tables FinalDriverFailureTable<'case>,
    pub(crate) graphs: GraphOutputs<'tables, 'case, 'graph>,
}
struct InitGuard<'a, 'context> { planning: &'a mut WorkflowPlanning<'context>, complete: bool }
impl Drop for InitGuard<'_, '_> {
    fn drop(&mut self) { if !self.complete { self.planning.poison_metadata_driver(); } }
}
struct Guard<'a, 'plan, 'context> { workflow: &'a mut WorkflowAdmission<'plan, 'context>, complete: bool }
impl Drop for Guard<'_, '_, '_> {
    fn drop(&mut self) { if !self.complete { self.workflow.poison_driver(); } }
}
fn slot<'a, 'case, T>(table: &'a CaseOwnerTable<'case, T>, i: usize) -> Result<&'a CaseOwnerSlot<'case, T>> {
    table.slots().get(i).ok_or(WorkflowError::Slot)
}
fn value<'a, T>(slot: &'a CaseOwnerSlot<'_, T>) -> Result<&'a T> {
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)
}
fn cell<'a, T>(table: &'a CaseOwnerTable<'_, RefCell<Option<T>>>, i: usize) -> Result<&'a RefCell<Option<T>>> {
    value(slot(table, i)?)
}
fn ready<T, E>(v: &Option<core::result::Result<T, E>>) -> Result<&T> {
    v.as_ref().ok_or(WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Poisoned)
}
fn take<T, E>(v: &mut Option<core::result::Result<T, E>>) -> Result<T> {
    match v.take() { Some(Ok(v)) => Ok(v), Some(Err(e)) => { *v = Some(Err(e)); Err(WorkflowError::Poisoned) }, None => Err(WorkflowError::Empty) }
}
fn empty<T>(v: &Option<T>) -> Result<()> { if v.is_some() { Err(WorkflowError::SlotBusy) } else { Ok(()) } }
fn write<T>(cell: &RefCell<Option<T>>) -> Result<RefMut<'_, Option<T>>> { cell.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy) }
fn table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState, count: usize, initialized: bool) -> Result<()> {
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(|slot| slot.is_initialized() != initialized) { return Err(WorkflowError::Identity); }
    Ok(())
}
fn initialize<T>(table: &CaseOwnerTable<'_, RefCell<Option<T>>>) -> Result<()> {
    for slot in table.slots() { slot.install(RefCell::new(None)).map_err(|_| WorkflowError::Sequence)?; }
    Ok(())
}
fn empty_table<T>(t: &CaseOwnerTable<'_, RefCell<Option<T>>>, case: &CaseRetirementState, count: usize) -> Result<()> {
    table(t, case, count, true)?;
    for slot in t.slots() { empty(&*write(value(slot)?)?)?; }
    Ok(())
}
fn route(d: &StepDispatch) -> Result<(usize, FinalOutput)> {
    match d.producer() { ProducerRoute::Final { step, output } => Ok((step, output)), _ => Err(WorkflowError::Identity) }
}
fn same(a: PhaseBinding, b: PhaseBinding) -> Result<()> { if a == b { Ok(()) } else { Err(WorkflowError::Identity) } }
fn shape(d: &StepDispatch, count: usize, consumed: usize) -> Result<()> {
    if d.inputs().len() == count && d.consume_count() == consumed { Ok(()) } else { Err(WorkflowError::Sequence) }
}

/// Borrowed guards only; the existing FinalChild is the sole owning input enum.
enum ChildBorrow<'a, 'graph, 'source> {
    Graph { index: usize, value: RefMut<'a, Option<GraphOuterResult<'graph>>> },
    Merge(RefMut<'a, Option<FinalOuterResult<'source>>>),
}
impl<'graph, 'source> ChildBorrow<'_, 'graph, 'source> {
    fn check(&self, inventory: &ValidatedCompleteInventory<'_, '_>, before: usize, input: usize) -> Result<()> {
        match self { Self::Graph { value, .. } => check_owner(ready(value)?, inventory, before, input), Self::Merge(value) => check_owner(ready(value)?, inventory, before, input) }
    }
    fn take(&mut self) -> Result<FinalChild<'graph, 'source>> {
        match self { Self::Graph { index, value } => Ok(FinalChild::Graph { index: *index, owner: take(value)? }), Self::Merge(value) => Ok(FinalChild::Merge(take(value)?)) }
    }
    fn restore(&mut self, owner: FinalChild<'graph, 'source>) -> Result<()> {
        match (self, owner) {
            (Self::Graph { index, value }, FinalChild::Graph { index: actual, owner }) if *index == actual && value.is_none() => { **value = Some(Ok(owner)); Ok(()) },
            (Self::Merge(value), FinalChild::Merge(owner)) if value.is_none() => { **value = Some(Ok(owner)); Ok(()) },
            (_, owner) => { core::mem::forget(owner); Err(WorkflowError::Poisoned) }
        }
    }
}
impl<'tables, 'root, 'case, 'plans, 'graph, 'source> FinalRuntime<'tables, 'root, 'case, 'plans, 'graph, 'source> {
    fn plan(&self) -> Result<&'plans FinalPhasePlan<'source>> { value(slot(self.plans, 0)?)?.as_ref().map_err(|_| WorkflowError::Source) }

    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        let mut guard = InitGuard { planning, complete: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        table(self.plans, case, 1, true)?;
        let merges = self.plan()?.source().merge_count();
        if metadata.members().len().checked_sub(1) != Some(merges) { return Err(WorkflowError::Sequence); }
        table(self.compiled, case, merges, false)?; table(self.outer, case, merges, false)?;
        table(self.root, case, 1, false)?; table(self.verified, case, 1, false)?;
        table(self.packets, case, merges, false)?; table(self.failure, case, 1, false)?;
        if core::ptr::eq(self.outer as *const _ as *const (), self.root as *const _ as *const ()) { return Err(WorkflowError::Identity); }
        initialize(self.compiled)?; initialize(self.outer)?; initialize(self.verified)?;
        initialize(self.packets)?; initialize(self.failure)?;
        guard.planning.validate_metadata_driver(metadata, case)?;
        guard.complete = true; Ok(())
    }

    fn validate_tables(&self, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        table(self.plans, case, 1, true)?;
        let merges = self.plan()?.source().merge_count();
        if metadata.members().len().checked_sub(1) != Some(merges) { return Err(WorkflowError::Identity); }
        table(self.compiled, case, merges, true)?; table(self.outer, case, merges, true)?;
        table(self.verified, case, 1, true)?; table(self.packets, case, merges, true)?;
        table(self.failure, case, 1, true)?;
        if !self.root.belongs_to_case(case) || self.root.slots().len() != 1 { return Err(WorkflowError::Identity); }
        self.graphs.validate(metadata, case)
    }

    pub(crate) fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        let mut guard = Guard { workflow, complete: false };
        guard.workflow.validate_driver(inventory, case)?;
        if !inventory.matches_metadata(metadata) { return Err(WorkflowError::Identity); }
        self.graphs.validate(metadata, case)?;
        table(self.plans, case, 1, true)?;
        let plan = self.plan()?; let merges = plan.source().merge_count();
        if !plan.fresh_only() || !matches!(merges, 2 | 3) { return Err(WorkflowError::Policy); }
        empty_table(self.compiled, case, merges)?; empty_table(self.outer, case, merges)?;
        table(self.root, case, 1, false)?; empty_table(self.verified, case, 1)?;
        empty_table(self.packets, case, merges)?; empty_table(self.failure, case, 1)?;
        let mut count = 0usize;
        for (closed_ordinal, (d, step)) in inventory.closed_plan().dispatch().iter().zip(inventory.closed_plan().steps()).enumerate() {
            if !matches!(d.producer(), ProducerRoute::Final { .. }) { continue; }
            let (ordinal, output) = route(d)?;
            if ordinal != count { return Err(WorkflowError::Sequence); }
            same(PhaseBinding::for_final(plan, ordinal)?, step.binding)?;
            let deps = plan.dependencies(ordinal).map_err(|_| WorkflowError::Source)?;
            shape(d, deps.count, deps.consume)?;
            for position in 0..deps.count {
                same(input_edge(inventory, closed_ordinal, position)?.0, deps.bindings[position].ok_or(WorkflowError::Sequence)?)?;
            }
            match (plan.step_kind(ordinal), output) {
                (Some(FinalStepKind::Compile(i)), FinalOutput::Compiled(j)) if i == j => {
                    let children = plan.source().merge(i).ok_or(WorkflowError::Source)?.children();
                    for (position, child) in children.into_iter().enumerate() {
                        let route = d.inputs()[position].ok_or(WorkflowError::Sequence)?;
                        match child {
                            ChildSource::Graph(index) => { self.graphs.cell(route)?; same(deps.bindings[position].ok_or(WorkflowError::Sequence)?, plan.graph_binding(index).map_err(|_| WorkflowError::Source)?)?; },
                            ChildSource::Merge(index) if index < i => match route {
                                ProducerRoute::Final { step, output: FinalOutput::Outer(j) } if j == index && step == 2 * index + 1 => (),
                                _ => return Err(WorkflowError::Identity),
                            },
                            _ => return Err(WorkflowError::Sequence),
                        }
                    }
                },
                (Some(FinalStepKind::Outer(i)), FinalOutput::Outer(j)) if i == j => {
                    if d.inputs()[0] != Some(ProducerRoute::Final { step: 2 * i, output: FinalOutput::Compiled(i) }) { return Err(WorkflowError::Identity); }
                },
                (Some(FinalStepKind::Verify), FinalOutput::Verified) => {
                    if d.inputs()[0] != Some(ProducerRoute::Final { step: 2 * merges - 1, output: FinalOutput::Outer(merges - 1) }) { return Err(WorkflowError::Identity); }
                },
                _ => return Err(WorkflowError::Sequence),
            }
            count = count.checked_add(1).ok_or(WorkflowError::Overflow)?;
        }
        if count != plan.step_count() { return Err(WorkflowError::Sequence); }
        guard.complete = true; Ok(())
    }

    pub(crate) fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, closed_ordinal: usize) -> Result<()> {
        let mut guard = Guard { workflow, complete: false };
        guard.workflow.validate_driver(inventory, case)?;
        if !inventory.matches_metadata(metadata) { return Err(WorkflowError::Identity); }
        self.validate_tables(metadata, case)?;
        let d = inventory.closed_plan().dispatch().get(closed_ordinal).ok_or(WorkflowError::Sequence)?;
        let (ordinal, FinalOutput::Outer(index)) = route(d)? else { return Err(WorkflowError::Sequence); };
        let plan = self.plan()?;
        if plan.step_kind(ordinal) != Some(FinalStepKind::Outer(index)) { return Err(WorkflowError::Identity); }
        let mut target = write(cell(self.packets, index)?)?; empty(&target)?;
        *target = Some(guard.workflow.preissue_final_outer(plan, ordinal)); ready(&target)?;
        guard.complete = true; Ok(())
    }

    fn child(&self, route: ProducerRoute, child: ChildSource) -> Result<ChildBorrow<'tables, 'graph, 'source>> {
        match child {
            ChildSource::Graph(index) => Ok(ChildBorrow::Graph { index, value: write(self.graphs.cell(route)?)? }),
            ChildSource::Merge(index) => match route {
                ProducerRoute::Final { step, output: FinalOutput::Outer(actual) } if actual == index && step == 2 * index + 1 => Ok(ChildBorrow::Merge(write(cell(self.outer, index)?)?)),
                _ => Err(WorkflowError::Identity),
            },
        }
    }

    pub(crate) fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, closed_ordinal: usize) -> Result<()> {
        let mut guard = Guard { workflow, complete: false };
        let d = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        if !inventory.matches_metadata(metadata) { return Err(WorkflowError::Identity); }
        self.validate_tables(metadata, case)?;
        let (ordinal, output) = route(&d)?; let plan = self.plan()?;
        if !plan.fresh_only() { return Err(WorkflowError::Policy); }
        let binding = PhaseBinding::for_final(plan, ordinal)?;
        let mut failure = write(cell(self.failure, 0)?)?; empty(&failure)?;
        match (plan.step_kind(ordinal), output) {
            (Some(FinalStepKind::Compile(i)), FinalOutput::Compiled(j)) if i == j => {
                shape(&d, 2, 2)?;
                let mut target = write(cell(self.compiled, i)?)?; empty(&target)?;
                let children = plan.source().merge(i).ok_or(WorkflowError::Source)?.children();
                let mut left = self.child(d.inputs()[0].ok_or(WorkflowError::Sequence)?, children[0])?;
                let mut right = self.child(d.inputs()[1].ok_or(WorkflowError::Sequence)?, children[1])?;
                left.check(inventory, closed_ordinal, 0)?; right.check(inventory, closed_ordinal, 1)?;
                let phase = guard.workflow.next_phase(binding)?;
                let a = left.take()?; let b = match right.take() { Ok(b) => b, Err(e) => { left.restore(a)?; return Err(e); } };
                let operation = match plan.compile_operation_retaining(ordinal, [a, b]) {
                    Ok(operation) => operation,
                    Err((e, [a, b])) => { let l = left.restore(a); let r = right.restore(b); *failure = Some(e); l?; r?; return Err(WorkflowError::Source); }
                };
                *target = Some(phase.compile_final(operation)); ready(&target)?;
            },
            (Some(FinalStepKind::Outer(i)), FinalOutput::Outer(j)) if i == j => {
                shape(&d, 1, 1)?;
                if d.inputs()[0] != Some(ProducerRoute::Final { step: 2 * i, output: FinalOutput::Compiled(i) }) { return Err(WorkflowError::Identity); }
                let is_root = i + 1 == plan.source().merge_count();
                let root_target = slot(self.root, 0)?;
                if is_root && root_target.is_initialized() { return Err(WorkflowError::SlotBusy); }
                let mut target = write(cell(self.outer, i)?)?; empty(&target)?;
                let mut compiled = write(cell(self.compiled, i)?)?;
                let mut packet = write(cell(self.packets, i)?)?;
                same(ready(&compiled)?.binding(), PhaseBinding::for_final(plan, 2 * i)?)?;
                check_owner(ready(&compiled)?, inventory, closed_ordinal, 0)?;
                same(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take(&mut packet)?;
                let compiled_owner = match take(&mut compiled) { Ok(c) => c, Err(e) => { *packet = Some(Ok(packet_owner)); return Err(e); } };
                let operation = match plan.outer_operation_retaining(ordinal, compiled_owner) {
                    Ok(operation) => operation,
                    Err((e, owner)) => { *compiled = Some(Ok(owner)); *packet = Some(Ok(packet_owner)); *failure = Some(e); return Err(WorkflowError::Source); }
                };
                if is_root {
                    root_target.install(phase.prove_owned_final_outer(operation, packet_owner)).map_err(|_| WorkflowError::Sequence)?;
                    value(root_target)?.as_ref().map_err(|_| WorkflowError::Poisoned)?;
                } else { *target = Some(phase.prove_owned_final_outer(operation, packet_owner)); ready(&target)?; }
            },
            (Some(FinalStepKind::Verify), FinalOutput::Verified) => {
                shape(&d, 1, 0)?;
                let last = plan.source().merge_count() - 1;
                if d.inputs()[0] != Some(ProducerRoute::Final { step: 2 * last + 1, output: FinalOutput::Outer(last) }) { return Err(WorkflowError::Identity); }
                let mut target = write(cell(self.verified, 0)?)?; empty(&target)?;
                let root: &'root _ = value(slot(self.root, 0)?)?.as_ref().map_err(|_| WorkflowError::Poisoned)?;
                same(root.binding(), PhaseBinding::for_final(plan, 2 * last + 1)?)?;
                check_owner(root, inventory, closed_ordinal, 0)?;
                let operation = match plan.verify_operation(ordinal, root) { Ok(op) => op, Err(e) => { *failure = Some(e); return Err(WorkflowError::Source); } };
                let phase = guard.workflow.next_phase(binding)?;
                *target = Some(phase.verify_final(operation)); ready(&target)?;
            },
            _ => return Err(WorkflowError::Sequence),
        }
        guard.complete = true; Ok(())
    }
}

pub(crate) fn retained_requirements() -> Result<crate::execution::retained_resources::Requirements> {
    use crate::execution::retained_resources::{Bytes, Category, Requirements};
    use core::mem::size_of;
    macro_rules! shells { ($($ty:ty),+ $(,)?) => { [$(size_of::<$ty>(), size_of::<Option<$ty>>(),
        size_of::<RefMut<'static, Option<$ty>>>(), size_of::<Result<RefMut<'static, Option<$ty>>>>(), size_of::<Result<&'static $ty>>(),)+] }; }
    let shells = shells!(FinalCompiledResult<'static>, FinalOuterResult<'static>, FinalVerifyResult<'static, 'static>,
        FinalPreissueResult<'static, 'static>, GraphOuterResult<'static>, FinalFailure);
    let host = shells.into_iter().chain([
        size_of::<FinalRuntime<'static, 'static, 'static, 'static, 'static, 'static>>(),
        size_of::<Guard<'static, 'static, 'static>>(), size_of::<InitGuard<'static, 'static>>(),
        size_of::<ChildBorrow<'static, 'static, 'static>>(), size_of::<Result<ChildBorrow<'static, 'static, 'static>>>(),
        size_of::<FinalChild<'static, 'static>>(), size_of::<Result<FinalChild<'static, 'static>>>(),
        size_of::<[FinalChild<'static, 'static>; 2]>(), size_of::<[ChildSource; 2]>(),
        size_of::<Result<()>>(), size_of::<StepDispatch>(), size_of::<Result<(usize, FinalOutput)>>(),
        size_of::<Result<PhaseBinding>>(), size_of::<[usize; 8]>(),
    ]).try_fold(0usize, |a, b| a.checked_add(b.checked_mul(8).ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow))?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes { host: u64::try_from(host).map_err(|_| WorkflowError::Overflow)?, device: 0 }))
}
