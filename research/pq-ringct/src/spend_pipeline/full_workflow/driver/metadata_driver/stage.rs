//! Bounded diagnostic position, never ownership, admission, or dispatch authority.
//! Labels are compile-time source names; no witness-derived text is retained.
use super::ProducerFamily;
use super::super::runtime_dispatch::RuntimeFamily;
use crate::spend_pipeline::full_workflow::closed_plan::ProducerRoute;
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverAction { Validate, Locate, Inputs, Derive, Install, PrepareEndpoints, Finish }

/// Fixed source positions only. This value grants no phase or owner authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeAction {
    ReadBatch, ReadStartup, ReadComplete, ValidateInventory, ValidateMembers,
    SealMetadata, SealCase, CloseAdmission,
    PreflightDriver, PreflightWiring, PreflightMetadata, PreflightFamily,
    PreflightParent, PreflightGraphs,
    PreissueWiring, PreissueStep, ExecuteWiring, ExecuteStep,
    VerificationInventory, VerificationAttempt, VerificationComplete,
    FinalReport, WorkflowSnapshot, SourcePreparationSnapshot,
    FinishWorkflow, ConfirmCleanup, CompleteCase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverStage {
    Readiness,
    Call(&'static str),
    Layer {
        operation: &'static str,
        action: DriverAction,
        family: Option<ProducerFamily>,
        member: Option<usize>,
        source: Option<usize>,
        destination: Option<usize>,
        level: Option<usize>,
    },
    Runtime {
        action: RuntimeAction,
        family: Option<RuntimeFamily>,
        ordinal: Option<usize>,
        producer: Option<ProducerRoute>,
        level: Option<usize>,
        aborting: bool,
    },
    Complete,
}

impl DriverStage {
    pub(crate) fn layer(&mut self, operation: &'static str) {
        *self = Self::Layer { operation, action: DriverAction::Validate,
            family: None, member: None, source: None, destination: None, level: None };
    }
    pub(crate) fn member(&mut self, value: usize) {
        if let Self::Layer { family, member, source, destination, action, .. } = self {
            *family = None; *member = Some(value); *source = None; *destination = None;
            *action = DriverAction::Locate;
        }
    }
    pub(crate) fn source(&mut self, value: ProducerFamily, ordinal: usize) {
        if let Self::Layer { family, source, destination, action, .. } = self {
            *family = Some(value); *source = Some(ordinal); *destination = None;
            *action = DriverAction::Locate;
        }
    }
    pub(crate) fn ordinal(&mut self, value: usize) {
        if let Self::Layer { family, source, destination, action, .. } = self {
            *family = None; *source = Some(value); *destination = None;
            *action = DriverAction::Locate;
        }
    }
    pub(crate) fn destination(&mut self, value: usize) {
        if let Self::Layer { destination, action, .. } = self {
            *destination = Some(value); *action = DriverAction::Inputs;
        }
    }
    pub(crate) fn level(&mut self, value: usize) {
        if let Self::Layer { level, .. } = self { *level = Some(value); }
    }
    pub(crate) fn action(&mut self, value: DriverAction) {
        if let Self::Layer { action, .. } = self { *action = value; }
    }
    pub(crate) fn runtime(&mut self, action: RuntimeAction) {
        *self = Self::Runtime { action, family: None, ordinal: None,
            producer: None, level: None, aborting: false };
    }
    pub(crate) fn runtime_family(&mut self, action: RuntimeAction, family: RuntimeFamily) {
        *self = Self::Runtime { action, family: Some(family), ordinal: None,
            producer: None, level: None, aborting: false };
    }
    pub(crate) fn runtime_parent(&mut self, action: RuntimeAction, level: usize) {
        *self = Self::Runtime { action, family: None, ordinal: None,
            producer: None, level: Some(level), aborting: false };
    }
    pub(crate) fn runtime_step(&mut self, action: RuntimeAction, ordinal: usize, producer: ProducerRoute) {
        *self = Self::Runtime { action, family: None, ordinal: Some(ordinal),
            producer: Some(producer), level: None, aborting: false };
    }
    /// Keep the original failed gate/route while terminal cleanup is attempted.
    /// A returned cleanup error retains true; successful abort resets it before
    /// returning the original operation error. No failure owner is inspected.
    pub(crate) fn runtime_abort(&mut self, value: bool) {
        if let Self::Runtime { aborting, .. } = self { *aborting = value; }
    }
}

/// Shared, allocation-free census used before any driver/layer invocation and
/// again for retained recursive caller frames. Includes setter arguments and
/// match bindings as well as the diagnostic value and its mutable reborrows.
pub(crate) fn frame_bytes() -> usize {
    size_of::<[DriverStage; 8]>() + size_of::<[&mut DriverStage; 8]>()
        + size_of::<[DriverAction; 8]>() + size_of::<[Option<ProducerFamily>; 8]>()
        + size_of::<[Option<usize>; 32]>() + size_of::<[&'static str; 8]>()
}

/// Execution and dispatch each retain this before runtime entry. Includes the
/// complete stage/borrow census above plus setter arguments, returned family/
/// route copies, optional constructor fields and the abort match reborrow.
/// The enclosing retained-requirement sites apply their checked x8 factor.
pub(crate) fn runtime_frame_bytes() -> usize {
    frame_bytes()
        + size_of::<[RuntimeAction; 8]>() + size_of::<[RuntimeFamily; 8]>()
        + size_of::<[Option<RuntimeFamily>; 8]>() + size_of::<[ProducerRoute; 8]>()
        + size_of::<[Option<ProducerRoute>; 8]>() + size_of::<[usize; 8]>()
        + size_of::<[bool; 8]>() + size_of::<[&mut bool; 8]>()
}
