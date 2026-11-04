//! Per-request continuations for the case pool. The last shard moves its
//! private buffers into the ordinary ordered tree assembler on that lane.
use super::{identity_keys::RequestIdentityKeys, numeric_leaves::{self, Leaf, RequestLeaves}};
use crate::{component_tree::{native_shape::cache, paired_runtime::PairedFailure},
    execution::{retained_resources::{Ledger, Reservation}, workflow_resources::CryptoNumbers},
    graph_crypto::{Request, RequestDescriptor, ShakeWrapperLayout, PairedRequestPlan,
        OwnedAesRequestPlan, PairedRequestNumbers, OwnedAesRequestNumbers},
    graph_tree::GraphContext};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{self,
    HeightEnvelopeCacheScope, HeightEnvelopeCacheSnapshot, HeightEnvelopeCacheStatistics};
use std::sync::Mutex;
type Result<T> = core::result::Result<T, PairedFailure>;
const MAX: usize = crate::metadata_parallel::MAX_JOBS;
const REQUESTS: usize = 7;

#[derive(Clone, Copy)]
enum Kind { Keys, Leaves }
#[derive(Clone, Copy)]
struct Shard { request: usize, first: usize, count: usize, weight: usize, kind: Kind }
impl Shard {
    fn cost(self) -> Result<usize> { self.count.checked_mul(self.weight).ok_or(PairedFailure::Overflow) }
}
struct Pending { keys: Vec<[u8; 32]>, leaves: Vec<Option<Leaf>>, remaining: u64 }
pub(crate) struct Plan<'a> {
    requests: &'a [Request], context: GraphContext, layout: ShakeWrapperLayout,
    shards: [Option<Shard>; MAX], jobs: usize, retained: usize, transient: usize,
}
pub(crate) struct Member<'a> {
    plan: Plan<'a>, pending: [Mutex<Pending>; REQUESTS],
    native: cache::Snapshot, registered: HeightEnvelopeCacheSnapshot,
}
pub(crate) struct Completion<'a> {
    pub(crate) request: usize, pub(crate) numbers: Option<CryptoNumbers<'a>>,
    statistics: Option<(cache::WorkerStatistics, HeightEnvelopeCacheStatistics)>,
}
impl Completion<'_> {
    pub(crate) fn absorb(&mut self) -> Result<()> {
        if let Some((a, b)) = self.statistics.take() {
            cache::absorb_worker(a).map_err(|_| PairedFailure::Source)?;
            HeightEnvelopeCacheScope::absorb_worker(b).map_err(|_| PairedFailure::Source)?;
        }
        Ok(())
    }
}
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(PairedFailure::Overflow) }
impl<'a> Plan<'a> {
    /// This census allocates nothing. A separately held original must cover
    /// every request result, snapshot, shard and assembly forwarding buffer.
    pub(crate) fn new(requests: &'a [Request], context: GraphContext,
        layout: ShakeWrapperLayout, width: usize) -> Result<Self> {
        if requests.len() != REQUESTS || !(1..=16).contains(&width) { return Err(PairedFailure::Coverage); }
        let mut plan = Self { requests, context, layout, shards: [None; MAX], jobs: 0,
            retained: 8 * (core::mem::size_of::<Member<'static>>()
                + core::mem::size_of::<crate::execution::workflow_resources::PreparedCryptoBatch<'static>>() + 4096), transient: 0 };
        for (index, request) in requests.iter().enumerate() {
            let keys = request.segments().len();
            let leaves = numeric_leaves::count(request, layout)?;
            if keys == 0 || leaves == 0 { return Err(PairedFailure::Coverage); }
            let (required, frame, weight) = match request.descriptor() {
                RequestDescriptor::Shake(d) => (PairedRequestPlan::planning_requirements(request, layout)?,
                    PairedRequestPlan::numeric_frame_bytes()?, add(d.input_len, 256)?),
                RequestDescriptor::Aes(_) => (OwnedAesRequestPlan::planning_requirements(request)?,
                    OwnedAesRequestPlan::numeric_frame_bytes()?, 288),
            };
            plan.retained = add(plan.retained, usize::try_from(required.total().map_err(|_| PairedFailure::Overflow)?.host)
                .map_err(|_| PairedFailure::Overflow)?)?;
            plan.retained = add(plan.retained, keys.checked_mul(4 * 32).ok_or(PairedFailure::Overflow)?)?;
            plan.retained = add(plan.retained, leaves.checked_mul(4 * core::mem::size_of::<Option<Leaf>>()).ok_or(PairedFailure::Overflow)?)?;
            plan.transient = plan.transient.max(frame);
            for (kind, count, weight) in [(Kind::Keys, keys, weight), (Kind::Leaves, leaves, 4096)] {
                plan.shards[plan.jobs] = Some(Shard { request: index, first: 0, count, weight, kind });
                plan.jobs += 1;
            }
        }
        let target = MAX.min(plan.jobs.max(4 * width));
        while plan.jobs < target {
            let mut largest = None;
            let mut cost = 0;
            for index in 0..plan.jobs {
                let shard = plan.shards[index].ok_or(PairedFailure::Coverage)?;
                if shard.count > 1 && shard.cost()? > cost { largest = Some(index); cost = shard.cost()?; }
            }
            let Some(index) = largest else { break; };
            let shard = plan.shards[index].ok_or(PairedFailure::Coverage)?;
            let left = shard.count / 2;
            plan.shards[index] = Some(Shard { count: left, ..shard });
            plan.shards[plan.jobs] = Some(Shard { first: add(shard.first, left)?, count: shard.count - left, ..shard });
            plan.jobs += 1;
        }
        plan.transient = add(plan.transient, cache::RESERVED_BYTES + shape::HEIGHT_ENVELOPE_CACHE_RESERVED_BYTES + (4 << 20))?;
        Ok(plan)
    }
    pub(crate) fn retained_bytes(&self) -> usize { self.retained }
    pub(crate) fn transient_bytes(&self) -> usize { self.transient }
    pub(crate) fn prepare(self, admitted: usize, scratch: &Reservation, ledger: &Ledger) -> Result<Option<Member<'a>>> {
        if admitted < self.retained || !scratch.belongs_to(ledger)
            || scratch.requirements().get(crate::execution::retained_resources::Category::PhaseScratch).host < self.transient as u64 {
            return Err(PairedFailure::Capacity);
        }
        let warmed = (|| {
            for request in self.requests {
                super::numeric_bounds::warm_cached_request_bounds(request, self.layout)?;
            }
            Ok::<_, PairedFailure>(())
        })();
        // No compiler ran and no request buffers exist yet. Ordinary metadata
        // planning retries missing geometry after the case pool has joined.
        if warmed.is_err() { return Ok(None); }
        let native = cache::snapshot().map_err(|_| PairedFailure::Source)?;
        let registered = HeightEnvelopeCacheScope::snapshot().map_err(|_| PairedFailure::Source)?;
        let mut pending = core::array::from_fn(|_| Mutex::new(Pending { keys: Vec::new(), leaves: Vec::new(), remaining: 0 }));
        for (index, request) in self.requests.iter().enumerate() {
            let slot = pending[index].get_mut().map_err(|_| PairedFailure::Source)?;
            let keys = request.segments().len();
            let leaves = numeric_leaves::count(request, self.layout)?;
            slot.keys.try_reserve_exact(keys).map_err(|_| PairedFailure::Capacity)?;
            slot.leaves.try_reserve_exact(leaves).map_err(|_| PairedFailure::Capacity)?;
            if slot.keys.capacity() > 2 * keys || slot.leaves.capacity() > 2 * leaves { return Err(PairedFailure::Capacity); }
            slot.keys.resize(keys, [0; 32]); slot.leaves.resize(leaves, None);
            for job in 0..self.jobs {
                if self.shards[job].is_some_and(|shard| shard.request == index) { slot.remaining |= 1u64 << job; }
            }
        }
        Ok(Some(Member { plan: self, pending, native, registered }))
    }
}
impl<'a> Member<'a> {
    pub(crate) fn jobs(&self) -> usize { self.plan.jobs }
    pub(crate) fn cost(&self, index: usize) -> Result<usize> {
        self.plan.shards.get(index).copied().flatten().ok_or(PairedFailure::Coverage)?.cost()
    }
    pub(crate) fn compute(&self, index: usize, caller: bool) -> Result<Completion<'a>> {
        let readers = if caller { None } else { Some((cache::Scope::begin_read_only(&self.native)
            .map_err(|_| PairedFailure::Source)?, HeightEnvelopeCacheScope::begin_read_only(&self.registered)
            .map_err(|_| PairedFailure::Source)?)) };
        let shard = self.plan.shards.get(index).copied().flatten().ok_or(PairedFailure::Coverage)?;
        let request = &self.plan.requests[shard.request];
        let end = add(shard.first, shard.count)?;
        let mut keys = Vec::new();
        let mut leaves = Vec::new();
        match shard.kind {
            Kind::Keys => {
                keys.try_reserve_exact(shard.count).map_err(|_| PairedFailure::Capacity)?;
                if keys.capacity() > 2 * shard.count { return Err(PairedFailure::Capacity); }
                for i in shard.first..end { keys.push(request.cache_key(i).map_err(|_| PairedFailure::Source)?); }
            }
            Kind::Leaves => leaves = numeric_leaves::prepare(request, self.plan.layout, shard.first, shard.count)?,
        }
        let complete = {
            let mut pending = self.pending[shard.request].lock().map_err(|_| PairedFailure::Source)?;
            let bit = 1u64.checked_shl(index as u32).ok_or(PairedFailure::Coverage)?;
            if pending.remaining & bit == 0 { return Err(PairedFailure::Coverage); }
            match shard.kind {
                Kind::Keys => pending.keys.get_mut(shard.first..end).ok_or(PairedFailure::Coverage)?.copy_from_slice(&keys),
                Kind::Leaves => {
                    let destination = pending.leaves.get_mut(shard.first..end).ok_or(PairedFailure::Coverage)?;
                    for (slot, value) in destination.iter_mut().zip(leaves) {
                        if slot.replace(value).is_some() { return Err(PairedFailure::Coverage); }
                    }
                }
            }
            pending.remaining &= !bit;
            (pending.remaining == 0).then(|| (core::mem::take(&mut pending.keys), core::mem::take(&mut pending.leaves)))
        };
        // No coordinator round trip, case barrier or nested worker pool.
        let numbers = if let Some((keys, leaves)) = complete {
            let keys = RequestIdentityKeys::from_shards(request, keys)?;
            let leaves = RequestLeaves::from_shards(request, self.plan.layout, leaves)?;
            Some(match request.descriptor() {
                RequestDescriptor::Shake(_) => CryptoNumbers::Shake(PairedRequestNumbers::derive_prepared(request,
                    self.plan.context.clone(), self.plan.layout, Some(&keys), Some(&leaves))?),
                RequestDescriptor::Aes(_) => CryptoNumbers::Aes(OwnedAesRequestNumbers::derive_prepared(request,
                    self.plan.context.clone(), None, Some(&keys), Some(&leaves))?),
            })
        } else { None };
        Ok(Completion { request: shard.request, numbers,
            statistics: readers.as_ref().map(|(a, b)| (a.take_worker_statistics(), b.take_worker_statistics())) })
    }
}
