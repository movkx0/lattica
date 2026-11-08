//! One-shot identity prefixes for the imported-proof research driver.
use super::*;
use lattica_prover_p3::block_v2::machine::backend::identity_batch::{
    CompletedIdentityPrefix, IdentityBatchContext, IdentityBatchLimits,
};
use lattica_prover_p3::block_v2::machine::backend::identity_cpu;
pub(super) struct IdentityQueue {
    pub context: IdentityBatchContext,
    pending: Vec<(Arc<Program>, CompletedIdentityPrefix)>,
    next: u64,
    reports: Vec<Value>,
    cpu: Arc<identity_cpu::IdentityCpuContext>,
    cpu_pending: Vec<(Arc<Program>, identity_cpu::CompletedIdentityPrefix)>,
    cpu_reports: Vec<Value>,
}
impl IdentityQueue {
    pub fn new() -> Self {
        Self {
            context: IdentityBatchContext::new(),
            pending: Vec::new(),
            next: 0,
            reports: Vec::new(),
            cpu: Arc::new(identity_cpu::IdentityCpuContext::new()),
            cpu_pending: Vec::new(),
            cpu_reports: Vec::new(),
        }
    }
    pub fn take(&mut self, program: &Arc<Program>) -> Option<CompletedIdentityPrefix> {
        let index = self
            .pending
            .iter()
            .position(|(p, _)| Arc::ptr_eq(p, program))?;
        Some(self.pending.swap_remove(index).1)
    }
}
impl ProvingContext {
    /// The imported path uses the owned GPU witness/PCS phase admission in
    /// RegisteredProgram. A full host-LDE estimate is not its storage layout.
    /// This route check never replaces registration's partitioned host budget,
    /// managed-device allocation checks, retained-tree admission or phase guards.
    pub(crate) fn check_aggregation_gpu_route(&self, program: &Program) -> Result<(), String> {
        if self.policy() != Policy::GpuRequired
            || self.session.is_none()
            || std::env::var("LATTICA_V2_GPU_WITNESS").as_deref() != Ok("1")
            || program.height() > 1 << 20
            || program.construction_host_bytes() > 2 << 30
        {
            return Err("imported aggregation requires bounded owned GPU proving".into());
        }
        Ok(())
    }
    pub(crate) fn aggregation_cpu_authority(&self) -> Arc<identity_cpu::IdentityCpuContext> {
        Arc::clone(&self.aggregation_identity.borrow().cpu)
    }
    pub(crate) fn install_aggregation_cpu_prefixes(
        &self,
        prefixes: Vec<(
            Arc<Program>,
            identity_cpu::CompletedIdentityPrefix,
            identity_cpu::CpuWorkerReport,
        )>,
    ) -> Result<(), String> {
        self.release_prepared()?;
        let mut queue = self.aggregation_identity.borrow_mut();
        if !queue.pending.is_empty()
            || !queue.cpu_pending.is_empty()
            || prefixes.len() > 4
            || queue.cpu_reports.len() + prefixes.len() > 4096
        {
            return Err("CPU identity queue capacity or unconsumed prefixes".into());
        }
        for (program, prefix, report) in prefixes {
            queue
                .cpu_reports
                .push(serde_json::to_value(report).map_err(error)?);
            queue.cpu_pending.push((program, prefix));
        }
        Ok(())
    }

    pub(crate) fn prepare_aggregation_identities(
        &self,
        programs: &[Arc<Program>],
    ) -> Result<(), String> {
        self.check_legacy_gpu_dispatch()?;
        if self.policy() != Policy::GpuRequired || programs.is_empty() || programs.len() > 4 {
            return Err("aggregation identity batch exceeds four admitted ready jobs".into());
        }
        self.release_prepared()?;
        let mut queue = self
            .aggregation_identity
            .try_borrow_mut()
            .map_err(|_| "identity queue reentrant")?;
        if !queue.pending.is_empty() || !queue.cpu_pending.is_empty() || queue.reports.len() >= 4096
        {
            return Err("identity queue is not empty or report capacity exceeded".into());
        }
        let first = queue.next;
        queue.next = first
            .checked_add(programs.len() as u64)
            .ok_or("identity job overflow")?;
        let borrowed = programs
            .iter()
            .enumerate()
            .map(|(i, p)| (first + i as u64, p))
            .collect();
        let pending = queue
            .context
            .plan_borrowed(
                IdentityBatchLimits::batched(4).map_err(str::to_owned)?,
                borrowed,
                12 << 30,
                8 << 30,
            )?
            .execute(self.request)?;
        let (prefixes, report) = pending.complete_in_current_epoch()?;
        eprintln!(
            "gpu_aggregation_identity_batch streams={} hash_wall_ns={} device_ns={}",
            report.streams, report.hash_wall_ns, report.device_ns
        );
        queue
            .reports
            .push(serde_json::to_value(&report).map_err(error)?);
        queue.pending = programs.iter().cloned().zip(prefixes).collect();
        Ok(())
    }
    pub(crate) fn aggregation_identity_report(&self) -> Result<Value, String> {
        let queue = self
            .aggregation_identity
            .try_borrow()
            .map_err(|_| "identity queue reentrant")?;
        if !queue.pending.is_empty() || !queue.cpu_pending.is_empty() {
            return Err("unconsumed aggregation identity prefixes".into());
        }
        Ok(
            json!({"batches":queue.reports,"cpu_lookahead":queue.cpu_reports,"ready_job_ceiling":4,"larger_batches_admitted":false}),
        )
    }
    pub(super) fn register_aggregation_program(
        &self,
        program: Arc<Program>,
        host_bytes: u64,
    ) -> Result<RegisteredProgram, String> {
        let mut queue = self.aggregation_identity.borrow_mut();
        if let Some(index) = queue
            .cpu_pending
            .iter()
            .position(|(p, _)| Arc::ptr_eq(p, &program))
        {
            let prefix = queue.cpu_pending.swap_remove(index).1;
            let job = prefix.job();
            RegisteredProgram::new_with_cpu_identity_prefix_and_report(
                MachineAir::from_shared_program(program),
                host_bytes,
                self.request,
                &queue.cpu,
                job,
                prefix,
            )
            .map(|(registered, _)| registered)
            .map_err(|e| format!("{e:?}"))
        } else if let Some(prefix) = queue.take(&program) {
            let job = prefix.job();
            RegisteredProgram::new_with_identity_prefix_and_report(
                MachineAir::from_shared_program(program),
                host_bytes,
                self.request,
                &queue.context,
                job,
                prefix,
            )
            .map(|(registered, _)| registered)
            .map_err(|e| format!("{e:?}"))
        } else {
            RegisteredProgram::new_with_cpu_identity(
                MachineAir::from_shared_program(program),
                host_bytes,
                self.request,
            )
            .map_err(|e| format!("{e:?}"))
        }
    }
}
