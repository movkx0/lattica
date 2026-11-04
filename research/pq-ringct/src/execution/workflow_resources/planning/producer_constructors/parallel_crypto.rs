//! Case-local numeric jobs; original owners never leave the coordinator.
use super::*;
use crate::component_tree::native_shape::cache;
use crate::graph_crypto::{Request, RequestDescriptor, PairedRequestPlan, OwnedAesRequestPlan,
    PairedRequestNumbers, OwnedAesRequestNumbers, ShakeWrapperLayout, IdentityKeyPlan};
use crate::graph_tree::GraphContext;
use crate::metadata_parallel::{self as parallel, Error as WorkerError};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{self,
    HeightEnvelopeCacheScope, HeightEnvelopeCacheStatistics};

pub(crate) enum Numbers<'a> { Shake(PairedRequestNumbers<'a>), Aes(OwnedAesRequestNumbers<'a>) }
pub(crate) struct Batch<'a> {
    values: [Option<Numbers<'a>>; parallel::MAX_JOBS],
    // Results and snapshots are destroyed before their additional original.
    _original: Reservation,
}
impl<'a> Batch<'a> {
    pub(crate) fn shake(&mut self, index: usize) -> Result<PairedRequestNumbers<'a>, WorkflowError> {
        match self.values.get_mut(index).and_then(Option::take) {
            Some(Numbers::Shake(value)) => Ok(value), _ => Err(WorkflowError::Identity),
        }
    }
    pub(crate) fn aes(&mut self, index: usize) -> Result<OwnedAesRequestNumbers<'a>, WorkflowError> {
        match self.values.get_mut(index).and_then(Option::take) {
            Some(Numbers::Aes(value)) => Ok(value), _ => Err(WorkflowError::Identity),
        }
    }
}
struct Input<'a> { request: &'a Request, context: GraphContext }
struct Completion<'a> {
    value: Numbers<'a>,
    native: Option<cache::WorkerStatistics>,
    registered: Option<HeightEnvelopeCacheStatistics>,
}

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_parallel_crypto<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>) -> Result<Option<Batch<'a>>, WorkflowError>
    {
        self.check_metadata(inventory)?;
        let ceiling = shape::metadata_cpu_worker_ceiling();
        if ceiling < 2 || !crate::preparation_options::metadata_workers_enabled("crypto")
            || cache::snapshot().is_err() || HeightEnvelopeCacheScope::snapshot().is_err() {
            return Ok(None);
        }
        let layout = inventory.scope().layout();
        let mut inputs: [Option<Input<'a>>; parallel::MAX_JOBS] = core::array::from_fn(|_| None);
        let mut costs = [0usize; parallel::MAX_JOBS];
        let mut count = 0;
        let mut retained = 0usize;
        let mut frames = 0usize;
        for member in inventory.members() {
            let prepared = member.get();
            for request in prepared.crypto().requests() {
                if count == inputs.len() { return Ok(None); }
                let (required, frame) = match request.descriptor() {
                    RequestDescriptor::Shake(_) => (PairedRequestPlan::planning_requirements(request, layout), PairedRequestPlan::numeric_frame_bytes()),
                    RequestDescriptor::Aes(_) => (OwnedAesRequestPlan::planning_requirements(request), OwnedAesRequestPlan::numeric_frame_bytes()),
                };
                retained = retained.checked_add(usize::try_from(required.map_err(|_| WorkflowError::Planning)?.total()?.host)
                    .map_err(|_| WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow)?;
                frames = frames.max(frame.map_err(|_| WorkflowError::Planning)?);
                costs[count] = request.segments().len();
                inputs[count] = Some(Input { request, context: prepared.context().clone() });
                count += 1;
            }
        }
        if count < 2 { return Ok(None); }
        let keys_plan = IdentityKeyPlan::new(inputs[..count].iter().flatten().map(|input| input.request), ceiling)
            .map_err(|_| WorkflowError::Planning)?;
        retained = retained.checked_add(keys_plan.retained_bytes()).ok_or(WorkflowError::Overflow)?;
        // The fixed allowance covers the cohort lookup arrays and both numeric
        // TLS readers, in addition to the existing request forwarding census.
        let transient = frames.checked_add(cache::RESERVED_BYTES)
            .and_then(|n| n.checked_add(shape::HEIGHT_ENVELOPE_CACHE_RESERVED_BYTES))
            .and_then(|n| n.checked_add(4 << 20)).ok_or(WorkflowError::Overflow)?;
        let budget = usize::try_from(self.capability.ledger().remaining().host).unwrap_or(usize::MAX);
        let plan = match parallel::Plan::new(ceiling, count, budget, retained, transient) {
            Ok(plan) if plan.width >= 2 => plan,
            _ => return Ok(None),
        };
        let hashes = match parallel::Plan::new(ceiling, keys_plan.jobs(), budget, retained, transient) {
            Ok(plan) if plan.width >= 2 => plan,
            _ => return Ok(None),
        };
        let original = self.capability.ledger().reserve(Category::PhaseScratch,
            Bytes { host: plan.host_bytes.max(hashes.host_bytes) as u64, device: 0 })?;
        self.failed = true;
        let result = (|| {
            // Cold compilation, when needed, finishes under the existing
            // scratch original before the new pool is started.
            for input in inputs[..count].iter().flatten() {
                crate::graph_crypto::warm_request_bounds(input.request, layout, &self.scratch,
                    self.capability.ledger()).map_err(|_| WorkflowError::Planning)?;
            }
            let native = cache::snapshot().map_err(|_| WorkflowError::Planning)?;
            let registered = HeightEnvelopeCacheScope::snapshot().map_err(|_| WorkflowError::Planning)?;
            let mut batch = Batch { values: core::array::from_fn(|_| None), _original: original };
            let keys = keys_plan.derive(hashes).map_err(|_| WorkflowError::Planning)?;
            let stats = parallel::run(plan, &costs[..count], |caller| {
                if caller { return Ok(None); }
                Ok(Some((cache::Scope::begin_read_only(&native).map_err(|_| WorkerError::Worker)?,
                    HeightEnvelopeCacheScope::begin_read_only(&registered).map_err(|_| WorkerError::Worker)?)))
            }, |readers, index| {
                let input = inputs[index].as_ref().ok_or(WorkerError::Geometry)?;
                let value = match input.request.descriptor() {
                    RequestDescriptor::Shake(_) => Numbers::Shake(PairedRequestNumbers::derive_with_keys(input.request, input.context.clone(), layout,
                        Some(keys.get(index).map_err(|_| WorkerError::Worker)?))
                        .map_err(|_| WorkerError::Worker)?),
                    RequestDescriptor::Aes(_) => Numbers::Aes(OwnedAesRequestNumbers::derive_with_keys(input.request, input.context.clone(), None,
                        Some(keys.get(index).map_err(|_| WorkerError::Worker)?))
                        .map_err(|_| WorkerError::Worker)?),
                };
                let (native, registered) = match readers {
                    Some((native, registered)) => (Some(native.take_worker_statistics()), Some(registered.take_worker_statistics())),
                    None => (None, None),
                };
                Ok(Completion { value, native, registered })
            }, |index, completed| {
                if let Some(s) = completed.native { cache::absorb_worker(s).map_err(|_| WorkerError::Publication)?; }
                if let Some(s) = completed.registered { HeightEnvelopeCacheScope::absorb_worker(s).map_err(|_| WorkerError::Publication)?; }
                batch.values[index] = Some(completed.value);
                Ok(())
            }).map_err(|_| WorkflowError::Planning)?;
            parallel::report("crypto", stats);
            Ok(Some(batch))
        })();
        if result.is_ok() { self.failed = false; }
        result
    }
}
