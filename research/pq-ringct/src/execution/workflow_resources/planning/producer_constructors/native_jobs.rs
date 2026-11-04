//! Every result remains covered by its extra original until the normal typed
//! constructor has validated and adopted it on the coordinator.
use super::*;
use crate::metadata_parallel::{self as workers, Error};
use crate::graph_tree::metadata::verifier::linear_map::Cache as LinearMapCache;
use crate::spend_pipeline::full_workflow::native_numbers::{Binding, Job, Ready, TRANSIENT_LIMIT};

pub(crate) const MAX_NATIVE_JOBS: usize = 512;
struct Entry<'a> { member: usize, batch: usize, ready: Ready<'a> }
pub(crate) struct Batch<'a> {
    entries: Vec<Option<Entry<'a>>>,
    _original: Reservation,
}
impl<'a> Batch<'a> {
    pub(crate) fn new(original: Reservation, capacity: usize) -> Result<Self, WorkflowError> {
        if capacity > MAX_NATIVE_JOBS { return Err(WorkflowError::Planning); }
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| WorkflowError::Planning)?;
        if entries.capacity() > capacity.saturating_mul(2) { return Err(WorkflowError::Planning); }
        Ok(Self { entries, _original: original })
    }
    pub(crate) fn insert(&mut self, member: usize, batch: usize, ready: Ready<'a>) -> Result<(), WorkflowError> {
        if self.entries.len() == self.entries.capacity() || self.entries.iter().flatten().any(|row| row.member == member && row.batch == batch) {
            return Err(WorkflowError::Identity);
        }
        self.entries.push(Some(Entry { member, batch, ready })); Ok(())
    }
    fn take(&mut self, member: usize, batch: usize) -> Result<Option<Ready<'a>>, WorkflowError> {
        let Some(slot) = self.entries.iter_mut().find(|row| row.as_ref().is_some_and(|row| row.member == member && row.batch == batch)) else { return Ok(None); };
        Ok(Some(slot.take().ok_or(WorkflowError::Identity)?.ready))
    }
    pub(crate) fn backing_bytes(count: usize) -> Result<usize, WorkflowError> {
        count.checked_mul(2 * size_of::<Option<Entry<'static>>>())
            .and_then(|n| n.checked_add(8 * size_of::<Self>())).ok_or(WorkflowError::Overflow)
    }
}
macro_rules! take {
    ($method:ident, $variant:ident, $module:ident) => {
        impl<'a> Batch<'a> {
            pub(crate) fn $method(&mut self, member: usize, batch: usize)
                -> Result<Option<crate::spend_pipeline::full_workflow::$module::MetadataNumbers<'a>>, WorkflowError> {
                match self.take(member, batch)? { Some(Ready::$variant(value)) => Ok(Some(value)), None => Ok(None), _ => Err(WorkflowError::Identity) }
            }
        }
    };
}
take!(affine, Affine, affine_native);
take!(ntt, Ntt, ntt_native);
take!(mul, Mul, mul_native);
take!(g_bound, GBound, g_bound_native);
take!(permutation, Permutation, permutation_native);
impl<'a> Batch<'a> {
    pub(crate) fn linear_map(&mut self, member: usize, batch: usize)
        -> Result<Option<crate::spend_pipeline::full_workflow::linear_map_native::MetadataNumbers<'a>>, WorkflowError> {
        match self.take(member, batch)? { Some(Ready::LinearMap(value)) => Ok(Some(*value)), None => Ok(None), _ => Err(WorkflowError::Identity) }
    }
}

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_native_numbers<'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'a>)
        -> Result<Option<Batch<'a>>, WorkflowError> {
        self.check_metadata(inventory)?;
        let ceiling = lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling();
        if ceiling < 2 || !crate::preparation_options::concurrency_enabled("native")
            || !crate::preparation_options::metadata_workers_enabled("native") { return Ok(None); }
        let Some(cache) = inventory.scope().case_verifier_cache() else { return Ok(None); };
        let mut count = 0usize;
        let mut retained = 0usize;
        for member in inventory.members() {
            for index in 0..member.get().algebra().batches().len() {
                if let Some(job) = Job::from_original(member, index).map_err(|_| WorkflowError::Identity)? {
                    count = count.checked_add(1).ok_or(WorkflowError::Overflow)?;
                    if count > MAX_NATIVE_JOBS { return Ok(None); }
                    retained = retained.checked_add(job.retained_bytes()).ok_or(WorkflowError::Overflow)?;
                }
            }
        }
        if count < 2 { return Ok(None); }
        type Input<'a> = (usize, usize, Job<'a>, Binding);
        retained = retained.checked_add(LinearMapCache::allowance_bytes()).and_then(|n| n.checked_add(Batch::backing_bytes(count).ok()?))
            .and_then(|n| n.checked_add(count.checked_mul(2 * size_of::<Input<'static>>())?))
            .ok_or(WorkflowError::Overflow)?;
        let transient = TRANSIENT_LIMIT.checked_add(4 << 20).ok_or(WorkflowError::Overflow)?;
        let plan = match workers::Plan::new(ceiling, count.min(workers::MAX_JOBS),
            usize::try_from(self.capability.ledger().remaining().host).unwrap_or(usize::MAX), retained, transient) {
            Ok(plan) if plan.width >= 2 => plan, _ => return Ok(None),
        };
        let original = self.capability.ledger().reserve(Category::PhaseScratch,
            Bytes { host: plan.host_bytes as u64, device: 0 })?;
        self.failed = true;
        let result = (|| {
            let mut batch = Batch::new(original, count)?;
            let linear_maps = LinearMapCache::new(LinearMapCache::allowance_bytes()).map_err(|_| WorkflowError::Planning)?;
            let mut inputs = Vec::new();
            inputs.try_reserve_exact(count).map_err(|_| WorkflowError::Planning)?;
            if inputs.capacity() > 2 * count { return Err(WorkflowError::Planning); }
            for (member, source) in inventory.members().iter().enumerate() {
                for index in 0..source.get().algebra().batches().len() {
                    if let Some(job) = Job::from_original(source, index).map_err(|_| WorkflowError::Identity)? {
                        inputs.push((member, index, job, Binding::new(inventory.scope(), source)));
                    }
                }
            }
            if inputs.len() != count { return Err(WorkflowError::Identity); }
            let (_, statistics) = workers::pool::scoped(plan, |_| Ok(()), |_, index: usize| {
                let input = inputs.get(index).ok_or(Error::Geometry)?;
                input.2.prepare_bounded(input.3.clone(), cache, &linear_maps).map_err(|_| Error::Worker)
            }, |pool, caller| {
                let mut issued = 0;
                let mut received = 0;
                while received < count {
                    while issued < count && pool.outstanding() < workers::MAX_JOBS {
                        pool.submit(0, inputs[issued].2.retained_bytes(), issued)?; issued += 1;
                    }
                    while let Some(done) = pool.try_receive()? {
                        let input = inputs.get(done.id).ok_or(Error::Geometry)?;
                        if let Some(value) = done.value { batch.insert(input.0, input.1, value).map_err(|_| Error::Publication)?; }
                        received += 1;
                    }
                    if received < count && !caller.help()? { pool.wait()?; }
                }
                Ok(())
            }).map_err(|_| WorkflowError::Planning)?;
            workers::report("native_data", statistics);
            Ok(Some(batch))
        })();
        if result.is_ok() { self.failed = false; }
        result
    }
}
