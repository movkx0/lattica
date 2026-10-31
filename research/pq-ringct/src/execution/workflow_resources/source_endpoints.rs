//! Exact endpoint preparation before ordinary Session retirement. Results are
//! fixed source metadata, never proof or native execution evidence.
use super::{planning::WorkflowPlanning, types::{combine, contains, WorkflowError, MAX_NATIVE_BYTES}};
use crate::{
    execution::{
        phase_lifecycle::{PhaseLease, Status},
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        ProvingContext,
    },
    graph_crypto::PairedRequestPlan,
};

#[cfg(not(debug_assertions))]
mod metadata;
#[cfg(not(debug_assertions))]
pub(super) use metadata::metadata_endpoint_query_requirements;
#[cfg(not(debug_assertions))]
pub(crate) use metadata::METADATA_ENDPOINT_QUERY_FRAME_BYTES;

/// Only the concrete planning gate below constructs this operation-local
/// borrow. The backend is charged separately from source compiler scratch.
pub(crate) struct SourceEndpointAccess<'claims> {
    context: &'claims ProvingContext,
    ledger: &'claims Ledger,
    held: &'claims Reservation,
    scratch: Requirements,
    backend: Bytes,
}

impl SourceEndpointAccess<'_> {
    pub(crate) fn context(&self) -> &ProvingContext { self.context }
    pub(crate) fn ledger(&self) -> &Ledger { self.ledger }
    pub(crate) fn operation_host_bytes(&self) -> u64 { self.backend.host }
    pub(crate) fn require_scratch(&self, request: Requirements) -> Result<(), WorkflowError> {
        if !self.held.belongs_to(self.ledger) || !contains(self.scratch, request)
            || !contains(self.held.requirements(), request)
        { return Err(WorkflowError::Planning); }
        Ok(())
    }
}

fn gate_scratch() -> Result<Requirements, WorkflowError> {
    use core::mem::size_of;
    let bytes = [size_of::<SourceEndpointAccess<'static>>(),
        size_of::<PhaseLease<'static, 'static>>(), size_of::<Requirements>(),
        size_of::<std::cell::Ref<'static, Reservation>>(),
        size_of::<Result<(), WorkflowError>>(), size_of::<crate::graph_crypto::PairedFailure>(),
        size_of::<Bytes>(), size_of::<String>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|bytes| bytes.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

fn admission_requirements(scratch: Requirements, backend: Bytes, bootstrap_device: u64)
    -> Result<(Requirements, Requirements), WorkflowError>
{
    if backend.host == 0 || backend.host > MAX_NATIVE_BYTES
        || bootstrap_device == 0 || bootstrap_device > 8 << 30
        || backend.device != bootstrap_device
    { return Err(WorkflowError::BackendAllowance); }
    let scratch = combine(scratch, gate_scratch()?)?;
    let requirements = combine(scratch, Requirements::single(Category::PhaseScratch, backend))?;
    Ok((scratch, requirements))
}

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_aes_endpoints(&mut self, plan: &mut crate::graph_crypto::OwnedAesRequestPlan<'_>)
        -> Result<(), WorkflowError>
    {
        let checked = (|| {
            if self.failed || !self.closure_reserved || self.failed_source_pool.is_some()
                || self.capability.status() != Status::Ready
            { return Err(WorkflowError::Poisoned); }
            if !plan.belongs_to(self.capability.ledger())
                || plan.compiled_source_fingerprint() != self.compiled_source
            { return Err(WorkflowError::Identity); }
            self.context.check_legacy_gpu_dispatch().map_err(|_| WorkflowError::Planning)?;
            let (scratch, backend) = plan.endpoint_preparation_requirements()
                .map_err(|_| WorkflowError::Planning)?;
            if self.managed_device != 8 << 30 || backend.device != self.managed_device {
                return Err(WorkflowError::BackendAllowance);
            }
            // The immutable endpoint source requires the unchanged complete
            // managed envelope. Its authentic startup original already owns
            // the prefix; this phase preclaims only the exact residual.
            let bootstrap_device = self.capability.source_bootstrap_device_bytes()?;
            let backend = Bytes { host: backend.host, device: bootstrap_device };
            let (scratch, requirements) = admission_requirements(scratch, backend, bootstrap_device)?;
            Ok((scratch, backend, requirements))
        })();
        // No failed attempt can resume source planning, even if backend cleanup
        // succeeds. Original plan metadata continues to own any stored result.
        self.failed = true;
        let (scratch, backend, requirements) = checked?;
        let phase = self.capability.admit(requirements)?;
        let result = {
            let original = phase.original_for_source()?;
            let access = SourceEndpointAccess { context: self.context,
                ledger: phase.ledger(), held: &original, scratch, backend };
            plan.prepare_endpoints_before_closure(&access).map_err(|_| WorkflowError::Planning)
        };
        // End every source/Session/claim borrow before the actual prepared
        // release and queue drain. A cleanup refusal leaves the context poisoned.
        phase.complete_after_cleanup()?;
        result?;
        self.failed = false;
        Ok(())
    }

    pub(crate) fn prepare_paired_endpoints(&mut self, plan: &mut PairedRequestPlan<'_>)
        -> Result<(), WorkflowError>
    {
        let checked = (|| {
            if self.failed || !self.closure_reserved || self.failed_source_pool.is_some()
                || self.capability.status() != Status::Ready
            { return Err(WorkflowError::Poisoned); }
            if !plan.belongs_to(self.capability.ledger())
                || plan.compiled_source_fingerprint() != self.compiled_source
            { return Err(WorkflowError::Identity); }
            self.context.check_legacy_gpu_dispatch().map_err(|_| WorkflowError::Planning)?;
            let (scratch, backend) = plan.endpoint_preparation_requirements()
                .map_err(|_| WorkflowError::Planning)?;
            if self.managed_device != 8 << 30 || backend.device != self.managed_device {
                return Err(WorkflowError::BackendAllowance);
            }
            // The immutable endpoint source requires the unchanged complete
            // managed envelope. Its authentic startup original already owns
            // the prefix; this phase preclaims only the exact residual.
            let bootstrap_device = self.capability.source_bootstrap_device_bytes()?;
            let backend = Bytes { host: backend.host, device: bootstrap_device };
            let (scratch, requirements) = admission_requirements(scratch, backend, bootstrap_device)?;
            Ok((scratch, backend, requirements))
        })();
        // No failed attempt can resume source planning, even if backend cleanup
        // succeeds. Original plan metadata continues to own any stored result.
        self.failed = true;
        let (scratch, backend, requirements) = checked?;
        let phase = self.capability.admit(requirements)?;
        let result = {
            let original = phase.original_for_source()?;
            let access = SourceEndpointAccess { context: self.context,
                ledger: phase.ledger(), held: &original, scratch, backend };
            plan.prepare_endpoints_before_closure(&access).map_err(|_| WorkflowError::Planning)
        };
        // End every source/Session/claim borrow before the actual prepared
        // release and queue drain. A cleanup refusal leaves the context poisoned.
        phase.complete_after_cleanup()?;
        result?;
        self.failed = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_backend_cannot_borrow_compiler_or_report_credit() {
        let mut source = Requirements::single(Category::SymbolicCompiler, Bytes { host: 64, device: 0 });
        source.add(Category::Report, Bytes { host: 32, device: 0 }).unwrap();
        let backend = Bytes { host: 80 << 10, device: 8 << 30 };
        let (scratch, complete) = admission_requirements(source, backend, backend.device).unwrap();
        assert_eq!(complete.get(Category::SymbolicCompiler), source.get(Category::SymbolicCompiler));
        assert_eq!(complete.get(Category::Report), source.get(Category::Report));
        assert_eq!(complete.get(Category::PhaseScratch).host,
            scratch.get(Category::PhaseScratch).host + backend.host);
        assert_eq!(complete.get(Category::PhaseScratch).device, backend.device);
        assert!(admission_requirements(source, Bytes { host: 0, ..backend }, backend.device).is_err());
        assert!(admission_requirements(source, Bytes { host: MAX_NATIVE_BYTES + 1, ..backend }, backend.device).is_err());
        assert!(admission_requirements(source, Bytes { device: backend.device - 1, ..backend }, backend.device).is_err());
        assert!(admission_requirements(source, backend, backend.device - 1).is_err());
    }

    #[test]
    fn endpoint_source_accepts_only_the_authenticated_startup_residual() {
        let source = Requirements::single(Category::Report, Bytes { host: 64, device: 0 });
        let residual = (8u64 << 30) - (64u64 << 20);
        let backend = Bytes { host: 80 << 10, device: residual };
        let (_, complete) = admission_requirements(source, backend, residual).unwrap();
        assert_eq!(complete.get(Category::PhaseScratch).device, residual);
        assert!(admission_requirements(source, Bytes { device: 8 << 30, ..backend }, residual).is_err());
        assert!(admission_requirements(source, Bytes { device: 0, ..backend }, 0).is_err());
        assert!(admission_requirements(source, Bytes { device: (8 << 30) + 1, ..backend }, (8 << 30) + 1).is_err());
    }

    #[test]
    fn source_access_requires_same_original_ledger_and_each_source_category() {
        let context = ProvingContext::cpu(1024).unwrap();
        let capability = context.phase_capability(Bytes::ZERO).unwrap();
        let ledger = capability.ledger();
        let scratch = Requirements::single(Category::Report, Bytes { host: 64, device: 0 });
        let held = ledger.admit_phase(scratch).unwrap();
        let access = SourceEndpointAccess { context: &context, ledger, held: &held,
            scratch, backend: Bytes { host: 32, device: 8 << 30 } };
        assert!(access.require_scratch(scratch).is_ok());
        assert!(access.require_scratch(Requirements::single(Category::SymbolicCompiler,
            Bytes { host: 1, device: 0 })).is_err());
        assert!(access.require_scratch(Requirements::single(Category::Report,
            Bytes { host: 65, device: 0 })).is_err());
        let other_context = ProvingContext::cpu(1024).unwrap();
        let other = other_context.phase_capability(Bytes::ZERO).unwrap();
        let wrong = SourceEndpointAccess { context: &context, ledger: other.ledger(),
            held: &held, scratch, backend: access.backend };
        assert!(wrong.require_scratch(scratch).is_err());
    }
}
