//! One immutable OuterHostV1 split of the already closed native backend.
use super::*;
use crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperationPlan;
use crate::opencl::{Limits, WorkflowRuntimePlan};

pub(super) struct NativePartitionPlan {
    pub(super) limits: Limits,
    pub(super) native: NativeLinearMapReservationPlan,
    pub(super) startup: Requirements,
    pub(super) wrappers: Requirements,
    pub(super) pcs: Requirements,
    pub(super) preparation: Requirements,
    pub(super) verifier: Requirements,
    pub(super) complete: Requirements,
}

impl NativePartitionPlan {
    pub(super) fn new(source: &LinearMapNativeOperationPlan<'_>, limits: Limits, backend: Bytes)
        -> Result<Self, LinearMapNativeOperationFailure>
    {
        if backend.host == 0 || backend.host > MAX_NATIVE_BYTES
            || backend.device != MAX_DEVICE_BYTES || backend.device != limits.device_bytes
        {
            return Err(LinearMapNativeOperationFailure::Resource);
        }
        let startup = WorkflowRuntimePlan::outer_host_v1(limits)
            .and_then(|plan| plan.requirement()).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        // The one-byte PCS model extracts only fixed source wrapper inventory;
        // it performs no physical selection, runtime start or PCS admission.
        let census = source.reservation_plan_outer_host_v1(1)?;
        let wrappers = census.wrapper_requirement();
        let operation_host = backend.host.checked_sub(startup.get(Category::PhaseScratch).host)
            .and_then(|bytes| bytes.checked_sub(wrappers.get(Category::PhaseScratch).host))
            .filter(|bytes| *bytes != 0).ok_or(LinearMapNativeOperationFailure::Resource)?;
        let native = source.reservation_plan_outer_host_v1(
            usize::try_from(operation_host).map_err(|_| LinearMapNativeOperationFailure::Overflow)?)?;
        if native.preparation().geometry().rows() > limits.max_rows {
            return Err(LinearMapNativeOperationFailure::Resource);
        }
        let pcs = native.pcs_requirement();
        let preparation = native.preparation_requirement().map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        let verifier = native.verifier_requirement();
        if native.wrapper_requirement() != wrappers
            || !contains(startup, native.startup_requirement())
            || startup.get(Category::PhaseScratch).device
                != native.startup_requirement().get(Category::PhaseScratch).device
        {
            return Err(LinearMapNativeOperationFailure::SourceDrift);
        }
        let backend_requirement = combine(combine(startup, wrappers)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?, pcs).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        if backend_requirement.total().map_err(|_| LinearMapNativeOperationFailure::Resource)? != backend {
            return Err(LinearMapNativeOperationFailure::Resource);
        }
        let complete = combine(combine(backend_requirement, preparation)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?, verifier).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        Ok(Self { limits, native, startup, wrappers, pcs, preparation, verifier, complete })
    }

    pub(super) fn runtime(&self) -> Result<WorkflowRuntimePlan, LinearMapNativeOperationFailure> {
        let runtime = WorkflowRuntimePlan::outer_host_v1(self.limits)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        if runtime.requirement().map_err(|_| LinearMapNativeOperationFailure::Resource)? != self.startup {
            return Err(LinearMapNativeOperationFailure::SourceDrift);
        }
        Ok(runtime)
    }
}
