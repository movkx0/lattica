//! One-shot identity prefixes for the imported-proof research driver.
use super::*;
use lattica_prover_p3::block_v2::machine::backend::identity_batch::{
    CompletedIdentityPrefix, IdentityBatchContext, IdentityBatchLimits,
};
use lattica_prover_p3::block_v2::machine::backend::identity_cpu;

pub(crate) struct ConsumedProof {
    pub height: usize,
    pub cap: Vec<[Val; 4]>,
    pub verifier: Arc<RegisteredVerifier>,
    pub proof: BatchProof<Config>,
}

pub(crate) struct PreparationPool {
    pool: Option<rayon::ThreadPool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}
impl std::ops::Deref for PreparationPool {
    type Target = rayon::ThreadPool;
    fn deref(&self) -> &Self::Target {
        self.pool.as_ref().expect("live preparation pool")
    }
}
impl PreparationPool {
    fn new() -> Result<Self, String> {
        let workers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (handles, errors) = (Arc::clone(&workers), Arc::clone(&failures));
        let built = rayon::ThreadPoolBuilder::new().num_threads(2).spawn_handler(move |thread| {
            let errors = Arc::clone(&errors);
            let handle = std::thread::Builder::new().name(format!("aggregation-prepare-{}", thread.index()))
                .spawn(move || {
                    let source = crate::graph_proofs::compiled_source_fingerprint();
                    let geometry = lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope::begin_with_precomputed(source);
                    let native = crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(source);
                    if geometry.is_err() || native.is_err() { errors.lock().unwrap().push("worker cache initialization failed"); }
                    thread.run();
                    drop((native, geometry));
                })?;
            handles.lock().unwrap().push(handle);
            Ok(())
        }).build();
        let handles = std::mem::take(&mut *workers.lock().unwrap());
        let mut owner = Self {
            pool: None,
            workers: handles,
        };
        owner.pool = Some(built.map_err(error)?);
        owner.broadcast(|_| ());
        if !failures.lock().unwrap().is_empty() {
            return Err("persistent worker cache initialization failed".into());
        }
        Ok(owner)
    }
    fn retire(&mut self) -> Result<usize, String> {
        drop(self.pool.take());
        let count = self.workers.len();
        let mut failed = false;
        for worker in self.workers.drain(..) {
            failed |= worker.join().is_err();
        }
        if failed {
            return Err("persistent preparation worker failed during shutdown".into());
        }
        Ok(count)
    }
    fn close(mut self) -> Result<usize, String> {
        self.retire()
    }
}
impl Drop for PreparationPool {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}
pub(super) struct IdentityQueue {
    consuming: bool,
    pool: Option<Arc<PreparationPool>>,
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
            consuming: false,
            pool: None,
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
    pub(crate) fn prove_aggregation_once(
        &self,
        program: Arc<Program>,
        public: &Vec<Val>,
        witness: &Vec<Val>,
    ) -> Result<ConsumedProof, String> {
        use lattica_prover_p3::block_v2::{
            gpu_hash::device::DeviceSession,
            machine::{OuterBackendPlan, RegisteredGpuLimits},
        };
        self.check_legacy_gpu_dispatch()?;
        self.check_aggregation_gpu_route(&program)?;
        crate::gpu_aggregation::memory::check_program(&program)?;
        if !self.consuming_aggregation() {
            return Err("consuming aggregation profile required".into());
        }
        self.release_prepared()?;
        self.diagnostics.mark_stark_work_attempted();
        let session = DeviceSession::new()?;
        let limits = self.aggregation_backend_limits()?;
        let native = crate::gpu_aggregation::policy::current()
            .backend_host_bytes
            .checked_sub(limits.retained_tree_host_bytes())
            .ok_or("host tree quota exhausts aggregation backend phase")?;
        let admission = OuterBackendPlan::new(&program, public, witness, limits, native)?
            .admit_in_session(&session)?;
        let footprint = admission.footprint();
        eprintln!(
            "gpu_aggregation_consuming_admission rows={} public_values={} device_peak_bytes={} backend_scope_host_bytes={}",
            program.height(),
            program.public_values(),
            footprint.device_phase_peak_bytes,
            footprint.backend_scope_host_bytes
        );
        let started = Instant::now();
        let timing = crate::gpu_aggregation::telemetry::Span::start("registration");
        let registered =
            self.register_aggregation_program(Arc::clone(&program), admission.host_budget_bytes())?;
        drop(timing);
        let registration_seconds = started.elapsed().as_secs_f64();
        session.aggregation_memory_checkpoint("aggregation registration")?;
        let cap = registered.preprocessing_cap().roots().to_vec();
        let verifier = Arc::new(registered.verifier());
        {
            let mut state = self.registry.borrow_mut();
            state.registrations += 1;
            state.registered_active_rows += program.active_rows() as u64;
            state.registered_padded_rows += program.height() as u64;
            state.registration_seconds += registration_seconds;
            state.registration_setup_seconds += started.elapsed().as_secs_f64();
        }
        let started = Instant::now();
        let timing = crate::gpu_aggregation::telemetry::Span::start("gpu-proof");
        let result = registered
            .into_prove_outer_with_request_and_report(&admission, self.request)
            .map_err(error);
        self.diagnostics.prove_finished(
            started.elapsed().as_secs_f64(),
            result.is_ok(),
            program.active_rows(),
            program.height(),
        );
        drop(timing);
        let (proof, _report) = result?;
        session.aggregation_memory_checkpoint("aggregation proof complete")?;
        let started = Instant::now();
        let timing = crate::gpu_aggregation::telemetry::Span::start("verification");
        let verified = verifier.verify(&proof, public);
        drop(timing);
        self.diagnostics
            .verify_finished(started.elapsed().as_secs_f64(), verified.is_ok());
        verified?;
        Ok(ConsumedProof {
            height: program.height(),
            cap,
            verifier,
            proof,
        })
    }
    pub(crate) fn aggregation_backend_limits(
        &self,
    ) -> Result<lattica_prover_p3::block_v2::machine::RegisteredGpuLimits, String> {
        use lattica_prover_p3::block_v2::machine::RegisteredGpuLimits;
        if std::env::var("LATTICA_V2_GPU_AGGREGATION_V4").as_deref() == Ok("1") {
            let device = self
                .session
                .as_ref()
                .ok_or("aggregation needs live session")?
                .limits()
                .device_bytes;
            let reserve = std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES")
                .map_err(error)?
                .parse()
                .map_err(error)?;
            RegisteredGpuLimits::new_aggregation(
                self.host_profile.worker_bytes(),
                device,
                reserve,
                self.aggregation_row_limit(),
            )?
            .with_aggregation_tree_quota(crate::gpu_aggregation::policy::current().tree_host_bytes)
        } else {
            RegisteredGpuLimits::new(
                self.host_profile.worker_bytes(),
                8 << 30,
                4 << 30,
                self.aggregation_row_limit(),
            )
        }
    }
    pub(crate) fn configure_consuming_aggregation(&self) -> Result<(), String> {
        let mut queue = self.aggregation_identity.borrow_mut();
        if queue.consuming || !queue.pending.is_empty() || !queue.cpu_pending.is_empty() {
            return Err("consuming aggregation must be configured before preparation".into());
        }
        self.release_prepared()?;
        let pool = PreparationPool::new()?;
        queue.consuming = true;
        queue.pool = Some(Arc::new(pool));
        Ok(())
    }
    pub(crate) fn consuming_aggregation(&self) -> bool {
        self.aggregation_identity.borrow().consuming
    }
    pub(crate) fn aggregation_pool(&self) -> Option<Arc<PreparationPool>> {
        self.aggregation_identity.borrow().pool.clone()
    }
    pub(super) fn finish_aggregation_preparation(&self) -> Result<usize, String> {
        let Some(pool) = self.aggregation_identity.borrow_mut().pool.take() else {
            return Ok(0);
        };
        let pool =
            Arc::try_unwrap(pool).map_err(|_| "preparation pool still borrowed at shutdown")?;
        let count = pool.close()?;
        eprintln!(
            "gpu_aggregation_preparation_shutdown joined_workers={count} all_scopes_complete=true"
        );
        Ok(count)
    }
    pub(crate) fn aggregation_row_limit(&self) -> usize {
        if self.consuming_aggregation() {
            self.session
                .as_ref()
                .map(|s| s.limits().max_rows)
                .unwrap_or(crate::gpu_aggregation::MAX_CONSUMING_ROWS)
        } else {
            crate::gpu_aggregation::MAX_RECURSIVE_ROWS
        }
    }
    /// The imported path uses the owned GPU witness/PCS phase admission in
    /// RegisteredProgram. A full host-LDE estimate is not its storage layout.
    /// This route check never replaces registration's partitioned host budget,
    /// managed-device allocation checks, retained-tree admission or phase guards.
    pub(crate) fn check_aggregation_gpu_route(&self, program: &Program) -> Result<(), String> {
        if self.policy() != Policy::GpuRequired
            || self.session.is_none()
            || std::env::var("LATTICA_V2_GPU_WITNESS").as_deref() != Ok("1")
            || program.height() > self.aggregation_row_limit()
            || program.construction_host_bytes()
                > crate::gpu_aggregation::policy::current().program_bytes
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
            || prefixes.len() > crate::gpu_aggregation::policy::current().live_jobs
            || queue.cpu_reports.len() + prefixes.len()
                > 4096
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

#[cfg(test)]
mod preparation_pool_tests {
    use super::*;
    #[test]
    fn persistent_workers_keep_their_ids_and_join_before_returning() {
        let pool = PreparationPool::new().unwrap();
        let first = pool.broadcast(|_| std::thread::current().id());
        let second = pool.broadcast(|_| std::thread::current().id());
        assert_eq!(first, second);
        assert_eq!(pool.close().unwrap(), 2);
    }
}
