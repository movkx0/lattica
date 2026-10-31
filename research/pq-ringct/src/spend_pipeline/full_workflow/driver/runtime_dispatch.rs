//! Sealed borrowed dispatch over concrete family runtimes. No proof owner or
//! arbitrary producer callback is erased; actual tables stay in their scopes.
use super::{crypto_runtime::{ShakeRuntime, AesRuntime}, native_runtime::NativeRuntime,
    graph_runtime::{FixedRuntime, ParametersRuntime, AuxiliaryRuntime, EqualityRuntime,
        DirectInputs, GraphOutputs, ParentRuntimeDriver}, final_runtime::FinalRuntime};
use super::metadata_driver::{DriverStage, RuntimeAction, runtime_stage_frame_bytes};
use super::super::{closed_plan::{ValidatedCompleteInventory, ProducerRoute, CryptoFamily,
    DirectFamily, CryptoOutput, GraphPhase, FinalOutput}, metadata_planning::SourceMetadataPlanningPlan,
    fresh_generation::case_lifetime::CaseRetirementState};
use crate::{execution::workflow_resources::{WorkflowPlanning, WorkflowAdmission, WorkflowError},
    graph_crypto::{ProofCache, OuterProofCache}, ordered_aggregation::owned_final::FinalReport};
type Result<T> = core::result::Result<T, WorkflowError>;
mod sealed { pub trait Runtime {} }
struct DispatchGuard<'a, 'plan, 'context> { workflow: &'a mut WorkflowAdmission<'plan, 'context>, complete: bool }
impl Drop for DispatchGuard<'_, '_, '_> {
    fn drop(&mut self) { if !self.complete { self.workflow.poison_driver(); } }
}
struct InitializationGuard<'a, 'context> { planning: &'a mut WorkflowPlanning<'context>, complete: bool }
impl Drop for InitializationGuard<'_, '_> {
    fn drop(&mut self) { if !self.complete { self.planning.poison_metadata_driver(); } }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeFamily { Native, Shake, Aes, Fixed, Parameters, Auxiliary, Equality, Final }
pub(crate) trait StepRuntime: sealed::Runtime {
    fn family(&self) -> RuntimeFamily;
    fn input_table(&self, _index: usize) -> Option<*const ()> { None }
    fn storage_table(&self, index: usize) -> Option<*const ()>;
    fn initialize(&self, planning: &mut WorkflowPlanning<'_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>;
    fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>;
    fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, ordinal: usize) -> Result<()>;
    fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>, inventory: &ValidatedCompleteInventory<'_, '_>, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, ordinal: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()>;
}
pub(crate) trait FinalStepRuntime: StepRuntime { fn final_report(&self) -> Result<FinalReport>; }

impl sealed::Runtime for NativeRuntime<'_, '_, '_, '_, '_, '_> {}
impl<'t, 'c, 'p, 's, 'native: 'a, 'a> StepRuntime for NativeRuntime<'t, 'c, 'p, 's, 'native, 'a> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Native }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.native.source as *const _ as *const ()),
            1 => Some(self.native.uniform as *const _ as *const ()),
            2 => Some(self.native.sparse as *const _ as *const ()),
            3 => Some(self.native.transcript as *const _ as *const ()),
            4 => Some(self.native.affine as *const _ as *const ()),
            5 => Some(self.native.ntt as *const _ as *const ()),
            6 => Some(self.native.mul as *const _ as *const ()),
            7 => Some(self.native.g_bound as *const _ as *const ()),
            8 => Some(self.native.permutation as *const _ as *const ()),
            9 => Some(self.native.linear_map as *const _ as *const ()),
            10 => Some(self.native_packets.source as *const _ as *const ()),
            11 => Some(self.native_packets.uniform as *const _ as *const ()),
            12 => Some(self.native_packets.sparse as *const _ as *const ()),
            13 => Some(self.native_packets.transcript as *const _ as *const ()),
            14 => Some(self.native_packets.affine as *const _ as *const ()),
            15 => Some(self.native_packets.ntt as *const _ as *const ()),
            16 => Some(self.native_packets.mul as *const _ as *const ()),
            17 => Some(self.native_packets.g_bound as *const _ as *const ()),
            18 => Some(self.native_packets.permutation as *const _ as *const ()),
            19 => Some(self.native_packets.linear_map as *const _ as *const ()),
            20 => Some(self.compiled.source as *const _ as *const ()),
            21 => Some(self.compiled.affine as *const _ as *const ()),
            22 => Some(self.compiled.ntt as *const _ as *const ()),
            23 => Some(self.compiled.mul as *const _ as *const ()),
            24 => Some(self.compiled.g_bound as *const _ as *const ()),
            25 => Some(self.compiled.permutation as *const _ as *const ()),
            26 => Some(self.compiled.linear_map as *const _ as *const ()),
            27 => Some(self.outer.source as *const _ as *const ()),
            28 => Some(self.outer.affine as *const _ as *const ()),
            29 => Some(self.outer.ntt as *const _ as *const ()),
            30 => Some(self.outer.mul as *const _ as *const ()),
            31 => Some(self.outer.g_bound as *const _ as *const ()),
            32 => Some(self.outer.permutation as *const _ as *const ()),
            33 => Some(self.outer.linear_map as *const _ as *const ()),
            34 => Some(self.outer_packets.source as *const _ as *const ()),
            35 => Some(self.outer_packets.affine as *const _ as *const ()),
            36 => Some(self.outer_packets.ntt as *const _ as *const ()),
            37 => Some(self.outer_packets.mul as *const _ as *const ()),
            38 => Some(self.outer_packets.g_bound as *const _ as *const ()),
            39 => Some(self.outer_packets.permutation as *const _ as *const ()),
            40 => Some(self.outer_packets.linear_map as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { NativeRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { NativeRuntime::preflight(self, w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { NativeRuntime::preissue(self, w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { NativeRuntime::execute(self, w, i, c, n) }
}
impl sealed::Runtime for ShakeRuntime<'_, '_, '_, '_> {}
impl StepRuntime for ShakeRuntime<'_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Shake }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.endpoints as *const _ as *const ()),
            1 => Some(self.native as *const _ as *const ()),
            2 => Some(self.compiled as *const _ as *const ()),
            3 => Some(self.outer as *const _ as *const ()),
            4 => Some(self.native_packets as *const _ as *const ()),
            5 => Some(self.outer_packets as *const _ as *const ()),
            6 => Some(self.requests as *const _ as *const ()),
            7 => Some(self.reports as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { ShakeRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { ShakeRuntime::preflight(self, w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { ShakeRuntime::preissue(self, w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { ShakeRuntime::execute_step(self, w, i, c, n, native, outer) }
}
impl sealed::Runtime for AesRuntime<'_, '_, '_, '_> {}
impl StepRuntime for AesRuntime<'_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Aes }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.endpoints as *const _ as *const ()),
            1 => Some(self.native as *const _ as *const ()),
            2 => Some(self.compiled as *const _ as *const ()),
            3 => Some(self.outer as *const _ as *const ()),
            4 => Some(self.native_packets as *const _ as *const ()),
            5 => Some(self.outer_packets as *const _ as *const ()),
            6 => Some(self.requests as *const _ as *const ()),
            7 => Some(self.reports as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { AesRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { AesRuntime::preflight(self, w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { AesRuntime::preissue(self, w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { AesRuntime::execute_step(self, w, i, c, n, native, outer) }
}
impl sealed::Runtime for FixedRuntime<'_, '_, '_, '_, '_> {}
impl StepRuntime for FixedRuntime<'_, '_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Fixed }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.compiled as *const _ as *const ()),
            1 => Some(self.outer as *const _ as *const ()),
            2 => Some(self.packets as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { FixedRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { FixedRuntime::preflight(self, w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { FixedRuntime::preissue(self, w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { FixedRuntime::execute_step(self, w, i, c, n) }
}
impl sealed::Runtime for EqualityRuntime<'_, '_, '_, '_, '_> {}
impl StepRuntime for EqualityRuntime<'_, '_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Equality }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.compiled as *const _ as *const ()),
            1 => Some(self.outer as *const _ as *const ()),
            2 => Some(self.packets as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { EqualityRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { EqualityRuntime::preflight(self, w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { EqualityRuntime::preissue(self, w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { EqualityRuntime::execute_step(self, w, i, c, n) }
}
impl sealed::Runtime for FinalRuntime<'_, '_, '_, '_, '_, '_> {}
impl StepRuntime for FinalRuntime<'_, '_, '_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Final }
    fn input_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.graphs.fixed as *const _ as *const ()),
            1 => Some(self.graphs.source as *const _ as *const ()),
            2 => Some(self.graphs.affine as *const _ as *const ()),
            3 => Some(self.graphs.ntt as *const _ as *const ()),
            4 => Some(self.graphs.mul as *const _ as *const ()),
            5 => Some(self.graphs.g_bound as *const _ as *const ()),
            6 => Some(self.graphs.permutation as *const _ as *const ()),
            7 => Some(self.graphs.linear_map as *const _ as *const ()),
            8 => Some(self.graphs.parameters as *const _ as *const ()),
            9 => Some(self.graphs.auxiliary as *const _ as *const ()),
            10 => Some(self.graphs.equality as *const _ as *const ()),
            11..=42 => self.graphs.parents[index - 11].map(|table| table as *const _ as *const ()),
            _ => None,
        }
    }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.compiled as *const _ as *const ()),
            1 => Some(self.outer as *const _ as *const ()),
            2 => Some(self.root as *const _ as *const ()),
            3 => Some(self.verified as *const _ as *const ()),
            4 => Some(self.packets as *const _ as *const ()),
            5 => Some(self.failure as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { FinalRuntime::initialize(self, p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { FinalRuntime::preflight(self, w, i, m, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { FinalRuntime::preissue(self, w, i, m, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, native: &ProofCache, outer: &OuterProofCache) -> Result<()> { FinalRuntime::execute_step(self, w, i, m, c, n) }
}
pub(crate) struct ParametersDispatch<'run, 'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) runtime: &'run ParametersRuntime<'tables, 'case, 'plans, 'source, 'graph>,
    pub(crate) inputs: &'run DirectInputs<'tables, 'case, 'graph>,
}
impl sealed::Runtime for ParametersDispatch<'_, '_, '_, '_, '_, '_> {}
impl StepRuntime for ParametersDispatch<'_, '_, '_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Parameters }
    fn input_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.inputs.shake as *const _ as *const ()),
            1 => Some(self.inputs.aes as *const _ as *const ()),
            2 => Some(self.inputs.uniform as *const _ as *const ()),
            3 => Some(self.inputs.sparse as *const _ as *const ()),
            4 => Some(self.inputs.transcript as *const _ as *const ()),
            _ => None,
        }
    }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.runtime.compiled as *const _ as *const ()),
            1 => Some(self.runtime.outer as *const _ as *const ()),
            2 => Some(self.runtime.packets as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { self.runtime.initialize(p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { self.inputs.validate_inventory(i, c).map_err(|e| { w.poison_driver(); e })?; self.runtime.preflight(w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { self.runtime.preissue(w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, _native: &ProofCache, _outer: &OuterProofCache) -> Result<()> { self.runtime.execute_step(w, i, c, n, self.inputs) }
}
pub(crate) struct AuxiliaryDispatch<'run, 'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) runtime: &'run AuxiliaryRuntime<'tables, 'case, 'plans, 'source, 'graph>,
    pub(crate) inputs: &'run DirectInputs<'tables, 'case, 'graph>,
}
impl sealed::Runtime for AuxiliaryDispatch<'_, '_, '_, '_, '_, '_> {}
impl StepRuntime for AuxiliaryDispatch<'_, '_, '_, '_, '_, '_> {
    fn family(&self) -> RuntimeFamily { RuntimeFamily::Auxiliary }
    fn input_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.inputs.shake as *const _ as *const ()),
            1 => Some(self.inputs.aes as *const _ as *const ()),
            2 => Some(self.inputs.uniform as *const _ as *const ()),
            3 => Some(self.inputs.sparse as *const _ as *const ()),
            4 => Some(self.inputs.transcript as *const _ as *const ()),
            _ => None,
        }
    }
    fn storage_table(&self, index: usize) -> Option<*const ()> {
        match index {
            0 => Some(self.runtime.compiled as *const _ as *const ()),
            1 => Some(self.runtime.outer as *const _ as *const ()),
            2 => Some(self.runtime.packets as *const _ as *const ()),
            _ => None,
        }
    }
    fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { self.runtime.initialize(p, m, c) }
    fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> { self.inputs.validate_inventory(i, c).map_err(|e| { w.poison_driver(); e })?; self.runtime.preflight(w, i, c) }
    fn preissue(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize) -> Result<()> { self.runtime.preissue(w, i, c, n) }
    fn execute_step(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, _m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, n: usize, _native: &ProofCache, _outer: &OuterProofCache) -> Result<()> { self.runtime.execute_step(w, i, c, n, self.inputs) }
}
impl FinalStepRuntime for FinalRuntime<'_, '_, '_, '_, '_, '_> {
    fn final_report(&self) -> Result<FinalReport> {
        let slot = self.verified.slots().first().ok_or(WorkflowError::Slot)?;
        if !slot.is_initialized() { return Err(WorkflowError::Empty); }
        let borrowed = slot.get().map_err(|_| WorkflowError::Empty)?.try_borrow().map_err(|_| WorkflowError::SlotBusy)?;
        let verified = borrowed.as_ref().ok_or(WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Poisoned)?;
        Ok(verified.get().report())
    }
}

pub(crate) struct RuntimeSet<'run, 'case, 'graph> {
    pub(crate) native: &'run dyn StepRuntime,
    pub(crate) shake: &'run dyn StepRuntime,
    pub(crate) aes: &'run dyn StepRuntime,
    pub(crate) fixed: &'run dyn StepRuntime,
    pub(crate) parameters: &'run dyn StepRuntime,
    pub(crate) auxiliary: &'run dyn StepRuntime,
    pub(crate) equality: &'run dyn StepRuntime,
    pub(crate) parents: [Option<&'run dyn ParentRuntimeDriver<'graph>>; 32],
    pub(crate) graphs: GraphOutputs<'run, 'case, 'graph>,
    pub(crate) final_runtime: &'run dyn FinalStepRuntime,
}
impl RuntimeSet<'_, '_, '_> {
    /// All borrowed reader projections name the same actual producer tables.
    /// Counts and equal empty geometry cannot substitute another table.
    fn validate_wiring(&self) -> Result<()> {
        let families = [RuntimeFamily::Native, RuntimeFamily::Shake, RuntimeFamily::Aes, RuntimeFamily::Fixed,
            RuntimeFamily::Parameters, RuntimeFamily::Auxiliary, RuntimeFamily::Equality, RuntimeFamily::Final];
        for (runtime, family) in self.ordinary().into_iter().zip(families) {
            if runtime.family() != family { return Err(WorkflowError::Identity); }
        }
        let actual = [Some(self.graphs.fixed as *const _ as *const ()),Some(self.graphs.source as *const _ as *const ()),Some(self.graphs.affine as *const _ as *const ()),Some(self.graphs.ntt as *const _ as *const ()),Some(self.graphs.mul as *const _ as *const ()),Some(self.graphs.g_bound as *const _ as *const ()),Some(self.graphs.permutation as *const _ as *const ()),Some(self.graphs.linear_map as *const _ as *const ()),Some(self.graphs.parameters as *const _ as *const ()),Some(self.graphs.auxiliary as *const _ as *const ()),Some(self.graphs.equality as *const _ as *const ())];
        let expected = [self.fixed.storage_table(1), self.native.storage_table(27), self.native.storage_table(28),
            self.native.storage_table(29), self.native.storage_table(30), self.native.storage_table(31),
            self.native.storage_table(32), self.native.storage_table(33), self.parameters.storage_table(1),
            self.auxiliary.storage_table(1), self.equality.storage_table(1)];
        for (index, (actual, expected)) in actual.into_iter().zip(expected).enumerate() {
            if actual != expected || actual != self.final_runtime.input_table(index) { return Err(WorkflowError::Identity); }
        }
        for level in 0..32 {
            let actual = self.graphs.parents[level].map(|table| table as *const _ as *const ());
            let expected = self.parents[level].and_then(|runtime| runtime.storage_table(1));
            if actual != expected || actual != self.final_runtime.input_table(11 + level) { return Err(WorkflowError::Identity); }
        }
        let inputs = [self.shake.storage_table(6), self.aes.storage_table(6), self.native.storage_table(1),
            self.native.storage_table(2), self.native.storage_table(3)];
        for (index, expected) in inputs.into_iter().enumerate() {
            if expected.is_none() || self.parameters.input_table(index) != expected || self.auxiliary.input_table(index) != expected { return Err(WorkflowError::Identity); }
        }
        self.distinct_storage()
    }

    fn distinct_storage(&self) -> Result<()> {
        let mut seen = [core::ptr::null::<()>(); 192];
        let mut used = 0usize;
        for runtime in self.ordinary() {
            for index in 0..=192 {
                let Some(identity) = runtime.storage_table(index) else { break; };
                if identity.is_null() || used == seen.len() || seen[..used].contains(&identity) { return Err(WorkflowError::Identity); }
                seen[used] = identity; used += 1;
            }
        }
        for runtime in self.parents.iter().flatten() {
            for index in 0..=3 {
                let Some(identity) = runtime.storage_table(index) else { break; };
                if index == 3 || identity.is_null() || used == seen.len() || seen[..used].contains(&identity) { return Err(WorkflowError::Identity); }
                seen[used] = identity; used += 1;
            }
        }
        Ok(())
    }

    fn ordinary(&self) -> [&dyn StepRuntime; 8] {
        [self.native, self.shake, self.aes, self.fixed, self.parameters, self.auxiliary, self.equality, self.final_runtime]
    }
    fn family(&self, route: ProducerRoute) -> Result<&dyn StepRuntime> {
        Ok(match route {
            ProducerRoute::Native { .. } | ProducerRoute::Leaf { .. } => self.native,
            ProducerRoute::Crypto { family: CryptoFamily::Shake, .. } => self.shake,
            ProducerRoute::Crypto { family: CryptoFamily::Aes, .. } => self.aes,
            ProducerRoute::Fixed { .. } => self.fixed,
            ProducerRoute::Direct { family: DirectFamily::Parameters, .. } => self.parameters,
            ProducerRoute::Direct { family: DirectFamily::Auxiliary, .. } => self.auxiliary,
            ProducerRoute::Direct { family: DirectFamily::Equality, .. } => self.equality,
            ProducerRoute::Final { .. } => self.final_runtime,
            ProducerRoute::Parent { .. } => return Err(WorkflowError::Sequence),
        })
    }
    pub(crate) fn initialize(&self, p: &mut WorkflowPlanning<'_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState) -> Result<()> {
        let mut guard = InitializationGuard { planning: p, complete: false };
        let p = &mut *guard.planning;
        self.validate_wiring()?;
        for runtime in self.ordinary() { runtime.initialize(p, m, c)?; }
        for (level, runtime) in self.parents.iter().enumerate() {
            if runtime.is_some() != m.counts().parent_level(level).is_some_and(|n| n != 0) { p.poison_metadata_driver(); return Err(WorkflowError::Identity); }
            if let Some(runtime) = runtime { if runtime.level() != level { p.poison_metadata_driver(); return Err(WorkflowError::Identity); } runtime.initialize(p, m, c)?; }
        }
        guard.complete = true;
        Ok(())
    }
    pub(crate) fn preflight(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, stage: &mut DriverStage) -> Result<()> {
        let mut guard = DispatchGuard { workflow: w, complete: false };
        let w = &mut *guard.workflow;
        stage.runtime(RuntimeAction::PreflightDriver);
        w.validate_driver(i, c)?;
        stage.runtime(RuntimeAction::PreflightWiring);
        self.validate_wiring()?;
        stage.runtime(RuntimeAction::PreflightMetadata);
        if !i.matches_metadata(m) { w.poison_driver(); return Err(WorkflowError::Identity); }
        for runtime in self.ordinary() {
            stage.runtime_family(RuntimeAction::PreflightFamily, runtime.family());
            runtime.preflight(w, i, m, c)?;
        }
        for (level, runtime) in self.parents.iter().enumerate() {
            stage.runtime_parent(RuntimeAction::PreflightParent, level);
            if runtime.is_some() != i.producer_counts().parent_level(level).is_some_and(|n| n != 0) { w.poison_driver(); return Err(WorkflowError::Identity); }
            if let Some(runtime) = runtime { if runtime.level() != level { w.poison_driver(); return Err(WorkflowError::Identity); } runtime.preflight(w, i, c)?; }
        }
        stage.runtime(RuntimeAction::PreflightGraphs);
        self.graphs.validate(m, c)?;
        stage.runtime(RuntimeAction::VerificationInventory);
        w.emit_verification_inventory(i, m, c)?;
        guard.complete = true;
        Ok(())
    }
    pub(crate) fn preissue_all(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, stage: &mut DriverStage) -> Result<()> {
        let mut guard = DispatchGuard { workflow: w, complete: false };
        let w = &mut *guard.workflow;
        stage.runtime(RuntimeAction::PreissueWiring);
        self.validate_wiring()?;
        for (n, step) in i.closed_plan().dispatch().iter().enumerate() {
            let route = step.producer();
            let needs_packet = matches!(route, ProducerRoute::Native { .. }
                | ProducerRoute::Crypto { output: CryptoOutput::Native(_) | CryptoOutput::Outer(_), .. }
                | ProducerRoute::Fixed { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Leaf { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Direct { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Parent { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Final { output: FinalOutput::Outer(_), .. });
            if !needs_packet { continue; }
            stage.runtime_step(RuntimeAction::PreissueStep, n, route);
            if let ProducerRoute::Parent { level, .. } = route {
                self.parents.get(level).copied().flatten().ok_or(WorkflowError::Sequence)?.preissue(w, i, c, n)?;
            } else { self.family(route)?.preissue(w, i, m, c, n)?; }
        }
        guard.complete = true;
        Ok(())
    }
    pub(crate) fn execute_all(&self, w: &mut WorkflowAdmission<'_, '_>, i: &ValidatedCompleteInventory<'_, '_>, m: &SourceMetadataPlanningPlan<'_>, c: &CaseRetirementState, native: &ProofCache, outer: &OuterProofCache, stage: &mut DriverStage) -> Result<()> {
        let mut guard = DispatchGuard { workflow: w, complete: false };
        let w = &mut *guard.workflow;
        stage.runtime(RuntimeAction::ExecuteWiring);
        self.validate_wiring()?;
        for (n, step) in i.closed_plan().dispatch().iter().enumerate() {
            let route = step.producer();
            stage.runtime_step(RuntimeAction::VerificationAttempt, n, route);
            w.emit_verification_attempt(i, m, c, n)?;
            stage.runtime_step(RuntimeAction::ExecuteStep, n, route);
            if let ProducerRoute::Parent { level, .. } = route {
                self.parents.get(level).copied().flatten().ok_or(WorkflowError::Sequence)?.execute_step(w, i, c, n, &self.graphs)?;
            } else { self.family(route)?.execute_step(w, i, m, c, n, native, outer)?; }
            stage.runtime_step(RuntimeAction::VerificationComplete, n, route);
            w.emit_verification_complete(i, m, c, n)?;
        }
        guard.complete = true;
        Ok(())
    }
}

pub(crate) fn retained_requirements() -> Result<crate::execution::retained_resources::Requirements> {
    use core::mem::size_of;
    use crate::execution::retained_resources::{Requirements, Category, Bytes};
    let host = [runtime_stage_frame_bytes(),
        size_of::<DispatchGuard<'static, 'static, 'static>>(), size_of::<InitializationGuard<'static, 'static>>(),
        size_of::<RuntimeSet<'static, 'static, 'static>>(),
        size_of::<ParametersDispatch<'static, 'static, 'static, 'static, 'static, 'static>>(),
        size_of::<AuxiliaryDispatch<'static, 'static, 'static, 'static, 'static, 'static>>(),
        size_of::<[*const (); 192]>(), size_of::<[Option<*const ()>; 11]>(),
        size_of::<[Option<*const ()>; 5]>(), size_of::<[RuntimeFamily; 8]>(), size_of::<Option<*const ()>>(),
        size_of::<[&dyn StepRuntime; 8]>(), size_of::<Result<&dyn StepRuntime>>(),
        size_of::<Result<()>>(), size_of::<Result<FinalReport>>(), size_of::<ProducerRoute>(),
        size_of::<[usize; 8]>(), size_of::<super::super::metadata_planning::ProducerCounts>(),
    ].into_iter().try_fold(0usize, |a, b| a.checked_add(b)).and_then(|n| n.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes { host: u64::try_from(host).map_err(|_| WorkflowError::Overflow)?, device: 0 }))
}
