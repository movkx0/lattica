//! A fresh prefix epoch borrows original compiled owners, then retires before
//! normal registration. Sibling tokens stay inside their compiler slots.
use super::*;
use crate::graph_crypto::PairedCompiled;
use lattica_prover_p3::block_v2::machine::backend::identity_cpu::{
    BorrowedIdentityBatchPlan, IdentityBatchFootprint, IdentityBatchReport,
    PendingBorrowedIdentityBatch, MAX_IDENTITY_STREAMS,
};

pub(crate) struct PairedIdentityPeers<'request> {
    pub(crate) owners: [Option<Retained<PairedCompiled<'request>>>; MAX_IDENTITY_STREAMS - 1],
}
impl Default for PairedIdentityPeers<'_> {
    fn default() -> Self {
        Self {
            owners: core::array::from_fn(|_| None),
        }
    }
}

#[derive(serde::Serialize)]
pub(super) struct PrefixEpoch {
    pub(super) batch: Option<u64>,
    pub(super) job_capacity: usize,
    pub(super) jobs: [Option<u64>; MAX_IDENTITY_STREAMS],
    pub(super) footprint: Option<IdentityBatchFootprint>,
    pub(super) startup: Option<StartupTiming>,
    pub(super) retirement:
        Option<lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::Retirement>,
    pub(super) totals:
        Option<crate::execution::owned_workflow_observation::IdentityPreprocessingTotals>,
}
impl Default for PrefixEpoch {
    fn default() -> Self {
        Self {
            batch: None,
            job_capacity: MAX_IDENTITY_STREAMS,
            jobs: [None; MAX_IDENTITY_STREAMS],
            footprint: None,
            startup: None,
            retirement: None,
            totals: None,
        }
    }
}
impl PrefixEpoch {
    pub(super) fn is_empty(&self) -> bool {
        self.startup.is_none()
    }
}
#[derive(Clone, Copy, serde::Serialize)]
pub(super) struct PrefixUse {
    batch: u64,
    job: u64,
}

pub(super) fn forwarding_bytes() -> Result<usize, OuterOwnedError> {
    use core::mem::size_of;
    [
        size_of::<PairedIdentityPeers<'static>>(),
        size_of::<RetirementGuard<'static, PairedIdentityPeers<'static>>>(),
        size_of::<PrefixEpoch>(),
        size_of::<IdentityBatchReport>(),
        size_of::<IdentityBatchFootprint>(),
        size_of::<BorrowedIdentityBatchPlan<'static>>(),
        size_of::<PendingBorrowedIdentityBatch<'static>>(),
        size_of::<[super::super::super::types::SlotId; MAX_IDENTITY_STREAMS]>(),
        size_of::<[Option<usize>; MAX_IDENTITY_STREAMS - 1]>(),
    ]
    .into_iter()
    .try_fold(1usize << 20, |sum, n| {
        sum.checked_add(8 * n).ok_or(OuterOwnedError::Partition)
    })
}

/// All owners passed here are in the caller's RetirementGuard for this exact
/// state, including on unwind. This function neither admits quota nor retries.
pub(super) unsafe fn prepare<'request>(
    access: &ExecutionAccess<'_>,
    phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>,
    operation: &PairedOuterOperation<'_, 'request>,
    peers: &PairedIdentityPeers<'request>,
    backend: Bytes,
    telemetry: &mut PrefixEpoch,
    retirement: &RetirementState,
) -> Result<(), OuterOwnedError> {
    let request_plan = operation.identity_plan();
    let (nodes, count) = request_plan
        .identity_cohort(operation.identity_node())
        .map_err(OuterOwnedError::Operation)?;
    if count == 0 {
        if peers.owners.iter().any(Option::is_some) {
            return Err(OuterOwnedError::Authority);
        }
        return Ok(());
    }
    if peers.owners[..count - 1].iter().any(Option::is_none)
        || peers.owners[count - 1..].iter().any(Option::is_some)
    {
        return Err(OuterOwnedError::Authority);
    }
    operation
        .borrowed_parts(access)
        .map_err(OuterOwnedError::Operation)?;
    if !operation
        .identity_compiler()
        .identity_prefix_is_empty()
        .map_err(OuterOwnedError::Operation)?
    {
        return Err(OuterOwnedError::Authority);
    }
    for (peer, node) in peers.owners.iter().flatten().zip(&nodes[1..count]) {
        operation
            .validate_identity_peer(peer, *node, access)
            .map_err(OuterOwnedError::Operation)?;
        if !peer
            .get()
            .identity_prefix_is_empty()
            .map_err(OuterOwnedError::Operation)?
        {
            return Err(OuterOwnedError::Authority);
        }
    }
    let plan = OuterRuntimePartitionPlan::new(source.limits(), backend)
        .map_err(|_| OuterOwnedError::Partition)?;
    let startup_requirement = plan.startup_requirement();
    let wrapper_requirement = plan.wrapper_requirement();
    let pcs_requirement = plan.pcs_requirement();
    let expected = request_plan
        .identity_footprint(operation.identity_node())
        .map_err(OuterOwnedError::Operation)?
        .ok_or(OuterOwnedError::Partition)?;
    if expected.host_bytes > plan.operation_host() as u64
        || expected.managed_bytes > pcs_requirement.get(Category::PhaseScratch).device
    {
        return Err(OuterOwnedError::Partition);
    }
    let mut partition = phase
        .partition_originals(plan.complete_requirement())
        .map_err(|_| OuterOwnedError::Partition)?;
    let ledger = partition.ledger().clone();
    let startup = partition
        .split(startup_requirement)
        .map_err(|_| OuterOwnedError::Partition)?;
    let wrappers = RetirementGuard::new(
        partition
            .split(wrapper_requirement)
            .map_err(|_| OuterOwnedError::Partition)?,
        retirement,
    );
    let pcs = RetirementGuard::new(
        partition
            .split(pcs_requirement)
            .map_err(|_| OuterOwnedError::Partition)?,
        retirement,
    );
    let pending = match plan.into_startup_plan().claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            restore(
                partition,
                startup,
                wrappers.into_original(),
                pcs.into_original(),
            )?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    retirement.arm();
    let (session, timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, timing, startup)) => {
            retirement.after_failed_start();
            telemetry.startup = Some(timing);
            restore(
                partition,
                startup,
                wrappers.into_original(),
                pcs.into_original(),
            )?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    telemetry.startup = Some(timing);
    let attempted = (|| {
        let guard = session
            .check_reserved_runtime(&ledger)
            .map_err(|_| OuterOwnedError::Runtime)?;
        drop(guard);
        let mut programs = Vec::new();
        programs
            .try_reserve_exact(count)
            .map_err(|_| OuterOwnedError::Partition)?;
        if programs.capacity() != count {
            return Err(OuterOwnedError::Partition);
        }
        programs.push((
            nodes[0] as u64,
            operation.identity_compiler().borrowed_parts().0,
        ));
        for (peer, node) in peers.owners.iter().flatten().zip(&nodes[1..count]) {
            programs.push((*node as u64, peer.get().borrowed_parts().0));
        }
        let batch = request_plan
            .identity_context()
            .map_err(OuterOwnedError::Operation)?
            .plan_borrowed(
                request_plan.identity_limits(),
                programs,
                expected.host_bytes,
                expected.managed_bytes,
            )
            .map_err(|_| OuterOwnedError::Partition)?;
        if batch.footprint().borrowed_program_host_bytes > expected.borrowed_program_host_bytes {
            return Err(OuterOwnedError::Partition);
        }
        batch
            .execute(Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            })
            .map_err(|_| OuterOwnedError::Setup)
    })();
    let attempted = RetirementGuard::new(attempted, retirement);
    let retired = session
        .finish_reserved_with_owner(&ledger)
        .map_err(|_| OuterOwnedError::Runtime)?;
    telemetry.retirement = Some(retired.receipt());
    let startup = retired
        .into_outer_host_original(&ledger)
        .map_err(|(_error, owner)| {
            core::mem::forget(owner);
            OuterOwnedError::Runtime
        })?;
    retirement.after_authenticated_retirement();
    // Prefixes contain weak handles to the real GPU lease and cannot become
    // usable until this originating epoch is actually destroyed.
    let result = (|| {
        let (tokens, report) = attempted
            .into_original()?
            .complete_after_retirement()
            .map_err(|_| OuterOwnedError::Runtime)?;
        if tokens.len() != count {
            return Err(OuterOwnedError::Authority);
        }
        telemetry.batch = Some(report.batch);
        telemetry.footprint = Some(report.footprint);
        for (target, node) in telemetry.jobs.iter_mut().zip(&nodes[..count]) {
            *target = Some(*node as u64);
        }
        for (i, token) in tokens.into_iter().enumerate() {
            if token.job() != nodes[i] as u64 {
                return Err(OuterOwnedError::Authority);
            }
            let compiler = if i == 0 {
                operation.identity_compiler()
            } else {
                peers.owners[i - 1]
                    .as_ref()
                    .ok_or(OuterOwnedError::Authority)?
                    .get()
            };
            compiler
                .install_identity_prefix(token)
                .map_err(OuterOwnedError::Operation)?;
        }
        telemetry.totals = Some(
            access
                .context()
                .record_owned_identity_batch(&report)
                .map_err(|_| OuterOwnedError::Report)?,
        );
        Ok(())
    })();
    restore(
        partition,
        startup,
        wrappers.into_original(),
        pcs.into_original(),
    )?;
    result
}

pub(super) fn register(
    operation: &PairedOuterOperation<'_, '_>,
    program: &Arc<lattica_prover_p3::block_v2::machine::Program>,
    host: u64,
    request: Request,
    used: &mut Option<PrefixUse>,
) -> Result<(RegisteredProgram, lattica_prover_p3::block_v2::machine::backend::identity_cpu::RegistrationReports), OuterOwnedError> {
    let plan = operation.identity_plan();
    let prefix = operation
        .identity_compiler()
        .take_identity_prefix()
        .map_err(OuterOwnedError::Operation)?;
    let required = plan.identity_limits().parallel()
        && plan.node_sources()[operation.identity_node()]
            .group
            .is_some();
    match (required, prefix) {
        (true, Some(prefix)) => {
            *used = Some(PrefixUse {
                batch: prefix.batch(),
                job: prefix.job(),
            });
            RegisteredProgram::new_with_cpu_identity_prefix_and_report(
                MachineAir::from_shared_program(Arc::clone(program)),
                host,
                request,
                plan.identity_context()
                                    .map_err(OuterOwnedError::Operation)?,
                operation.identity_node() as u64,
                prefix,
            )
            .map_err(|_| OuterOwnedError::Setup)
        }
        (false, None) => RegisteredProgram::new_with_cpu_identity_and_report(
            MachineAir::from_shared_program(Arc::clone(program)),
            host,
            request,
        )
        .map_err(|_| OuterOwnedError::Setup),
        _ => Err(OuterOwnedError::Authority),
    }
}
