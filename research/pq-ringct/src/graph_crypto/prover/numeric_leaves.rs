//! Independently prepared leaf numbers, sealed to the exact immutable request.
//! Tree assembly still uses the original ordered carry/merge algorithm.
use crate::component_tree::{native_shape::{cache, cohort}, paired_runtime::{source, ComponentSourceFacts, PairedFailure}};
use crate::execution::retained_resources::Requirements;
use crate::graph_crypto::{Request, RequestDescriptor, ShakeWrapperLayout, ShakeWrapperSpan};
use crate::metadata_parallel::{self as workers, Error};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{HeightEnvelopeCacheScope, HeightEnvelopeCacheSnapshot};
type Result<T> = core::result::Result<T, PairedFailure>;
type Pair = (Requirements, Requirements);
const MAX: usize = workers::MAX_JOBS;

#[derive(Clone, Copy)]
pub(super) enum Leaf {
    Shake { span: ShakeWrapperSpan, source: ComponentSourceFacts, native: [Option<Pair>; 2], compiler: Pair },
    Aes { index: usize, source: ComponentSourceFacts, native: Pair, compiler: Pair },
}
pub(crate) struct RequestLeaves<'a> {
    request: &'a Request,
    layout: ShakeWrapperLayout,
    source: [u8; 32],
    values: Vec<Option<Leaf>>,
}
impl RequestLeaves<'_> {
    pub(super) fn for_request(&self, request: &Request, layout: ShakeWrapperLayout) -> Result<&Self> {
        if !core::ptr::eq(self.request, request) || self.layout != layout
            || self.source != crate::graph_proofs::compiled_source_fingerprint()
            || self.values.len() != count(request, layout)? {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(self)
    }
    pub(super) fn for_aes_request(&self, request: &Request) -> Result<&Self> {
        if !matches!(request.descriptor(), RequestDescriptor::Aes(_)) { return Err(PairedFailure::SourceDrift); }
        self.for_request(request, self.layout)
    }
    pub(super) fn shake(&self, index: usize, expected: ShakeWrapperSpan) -> Result<(ComponentSourceFacts, [Option<Pair>; 2], Pair)> {
        match self.values.get(index).copied().flatten() {
            Some(Leaf::Shake { span, source, native, compiler }) if span == expected => Ok((source, native, compiler)),
            _ => Err(PairedFailure::SourceDrift),
        }
    }
    pub(super) fn aes(&self, expected: usize) -> Result<(ComponentSourceFacts, Pair, Pair)> {
        match self.values.get(expected).copied().flatten() {
            Some(Leaf::Aes { index, source, native, compiler }) if index == expected => Ok((source, native, compiler)),
            _ => Err(PairedFailure::SourceDrift),
        }
    }
}
impl<'a> RequestLeaves<'a> {
    pub(super) fn from_shards(request: &'a Request, layout: ShakeWrapperLayout,
        values: Vec<Option<Leaf>>) -> Result<Self> {
        if values.len() != count(request, layout)? || values.iter().any(Option::is_none) {
            return Err(PairedFailure::Coverage);
        }
        Ok(Self { request, layout, values, source: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
pub(crate) struct Leaves<'a> { requests: [Option<RequestLeaves<'a>>; MAX] }
impl<'a> Leaves<'a> {
    pub(crate) fn get(&self, index: usize) -> Result<&RequestLeaves<'a>> {
        self.requests.get(index).and_then(Option::as_ref).ok_or(PairedFailure::Coverage)
    }
}
#[derive(Clone, Copy)]
struct Shard { request: usize, first: usize, count: usize }
pub(crate) struct NumericLeafPlan<'a> {
    requests: [Option<&'a Request>; MAX], count: usize, layout: ShakeWrapperLayout,
    shards: [Option<Shard>; MAX], jobs: usize, retained: usize,
}
pub(super) fn count(request: &Request, layout: ShakeWrapperLayout) -> Result<usize> {
    match request.descriptor() {
        RequestDescriptor::Shake(_) => Ok(request.shake_wrapper_schedule(layout).map_err(|_| PairedFailure::Coverage)?.groups().len()),
        RequestDescriptor::Aes(_) => Ok(request.segments().len()),
    }
}
impl<'a> NumericLeafPlan<'a> {
    pub(crate) fn new(requests: impl Iterator<Item = &'a Request>, layout: ShakeWrapperLayout, ceiling: usize) -> Result<Self> {
        if !(1..=16).contains(&ceiling) { return Err(PairedFailure::Coverage); }
        let mut plan = Self { requests: [None; MAX], count: 0, layout, shards: [None; MAX], jobs: 0, retained: 0 };
        let mut leaves = 0usize;
        for request in requests {
            let count = count(request, layout)?;
            if plan.count == MAX || count == 0 { return Err(PairedFailure::Coverage); }
            leaves = leaves.checked_add(count).ok_or(PairedFailure::Overflow)?;
            plan.requests[plan.count] = Some(request);
            plan.shards[plan.count] = Some(Shard { request: plan.count, first: 0, count });
            plan.count += 1;
        }
        if plan.count == 0 { return Err(PairedFailure::Coverage); }
        plan.jobs = plan.count;
        let target = MAX.min(plan.count.max(4 * ceiling));
        while plan.jobs < target {
            let largest = (0..plan.jobs).filter(|&i| plan.shards[i].is_some_and(|s| s.count > 1))
                .max_by_key(|&i| plan.shards[i].map(|s| s.count).unwrap_or(0));
            let Some(index) = largest else { break; };
            let shard = plan.shards[index].ok_or(PairedFailure::Coverage)?;
            let left = shard.count / 2;
            plan.shards[index] = Some(Shard { count: left, ..shard });
            plan.shards[plan.jobs] = Some(Shard { first: shard.first + left, count: shard.count - left, ..shard });
            plan.jobs += 1;
        }
        plan.retained = leaves.checked_mul(4 * core::mem::size_of::<Option<Leaf>>())
            .and_then(|n| n.checked_add(8 * (core::mem::size_of::<Self>() + core::mem::size_of::<Leaves<'static>>())))
            .ok_or(PairedFailure::Overflow)?;
        Ok(plan)
    }
    pub(crate) fn jobs(&self) -> usize { self.jobs }
    pub(crate) fn retained_bytes(&self) -> usize { self.retained }
    /// The enclosing case reservation funds all destination and shard vectors.
    pub(crate) fn derive(&self, admission: workers::Plan, native: &cache::Snapshot,
        registered: &HeightEnvelopeCacheSnapshot) -> Result<Leaves<'a>> {
        let mut leaves = Leaves { requests: core::array::from_fn(|_| None) };
        for (index, request) in self.requests[..self.count].iter().enumerate() {
            let request = request.ok_or(PairedFailure::Coverage)?;
            let count = count(request, self.layout)?;
            let mut values = Vec::new();
            values.try_reserve_exact(count).map_err(|_| PairedFailure::Capacity)?;
            if values.capacity() > 2 * count { return Err(PairedFailure::Capacity); }
            values.resize(count, None);
            leaves.requests[index] = Some(RequestLeaves { request, layout: self.layout,
                source: crate::graph_proofs::compiled_source_fingerprint(), values });
        }
        let mut costs = [0; MAX];
        for (index, cost) in costs[..self.jobs].iter_mut().enumerate() {
            *cost = self.shards[index].ok_or(PairedFailure::Coverage)?.count;
        }
        let stats = workers::run(admission, &costs[..self.jobs], |caller| {
            if caller { return Ok(None); }
            Ok(Some((cache::Scope::begin_read_only(native).map_err(|_| Error::Worker)?,
                HeightEnvelopeCacheScope::begin_read_only(registered).map_err(|_| Error::Worker)?)))
        }, |readers, index| {
            let shard = self.shards[index].ok_or(Error::Geometry)?;
            let request = self.requests[shard.request].ok_or(Error::Geometry)?;
            let values = prepare(request, self.layout, shard.first, shard.count).map_err(|_| Error::Worker)?;
            let statistics = readers.as_ref().map(|(a, b)| (a.take_worker_statistics(), b.take_worker_statistics()));
            Ok((values, statistics))
        }, |index, (values, statistics)| {
            let shard = self.shards[index].ok_or(Error::Geometry)?;
            if values.len() != shard.count { return Err(Error::Publication); }
            let destination = &mut leaves.requests[shard.request].as_mut().ok_or(Error::Publication)?.values;
            for (slot, value) in destination[shard.first..shard.first + shard.count].iter_mut().zip(values) {
                if slot.replace(value).is_some() { return Err(Error::Publication); }
            }
            if let Some((a, b)) = statistics {
                cache::absorb_worker(a).map_err(|_| Error::Publication)?;
                HeightEnvelopeCacheScope::absorb_worker(b).map_err(|_| Error::Publication)?;
            }
            Ok(())
        }).map_err(|_| PairedFailure::Source)?;
        workers::report("crypto_leaves", stats);
        Ok(leaves)
    }
}
pub(super) fn prepare(request: &Request, layout: ShakeWrapperLayout, first: usize, count: usize) -> Result<Vec<Leaf>> {
    let end = first.checked_add(count).ok_or(PairedFailure::Overflow)?;
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| PairedFailure::Capacity)?;
    if values.capacity() > 2 * count { return Err(PairedFailure::Capacity); }
    match request.descriptor() {
        RequestDescriptor::Shake(_) => {
            let schedule = request.shake_wrapper_schedule(layout).map_err(|_| PairedFailure::Coverage)?;
            if end > schedule.groups().len() { return Err(PairedFailure::Coverage); }
            for span in schedule.groups().skip(first).take(count) {
                let source = source::GroupBlueprint::new(request, span)?.inspect()?;
                let mut native = [None; 2];
                for (offset, slot) in native[..span.segment_count].iter_mut().enumerate() {
                    *slot = Some(super::paired::memory::native_requirements(request, span.first_segment + offset)?);
                }
                let compiler = source::compiler_requirements(source, source::CompilerGeometry::Group(span.segment_count))?;
                values.push(Leaf::Shake { span, source, native, compiler });
            }
        }
        RequestDescriptor::Aes(_) => {
            if end > request.segments().len() { return Err(PairedFailure::Coverage); }
            for start in (first..end).step_by(cohort::MAX) {
                let count = cohort::MAX.min(end - start);
                let blueprint = source::AesBlueprint::new(request, start)?;
                let mut requests = [blueprint.metadata_request(); cohort::MAX];
                for (offset, slot) in requests[..count].iter_mut().enumerate() {
                    *slot = source::AesBlueprint::new(request, start + offset)?.metadata_request();
                }
                let mut cores = cohort::bounds_exact(&requests[..count], source::construction()).map_err(|_| PairedFailure::Source)?;
                for (offset, core) in cores[..count].iter_mut().enumerate() {
                    let index = start + offset;
                    let blueprint = source::AesBlueprint::new(request, index)?;
                    let source = blueprint.inspect_bound(core.take().ok_or(PairedFailure::SourceDrift)?)?;
                    values.push(Leaf::Aes { index, source,
                        native: super::owned_aes::memory::native_requirements(request, index)?,
                        compiler: blueprint.compiler_requirements(source)? });
                }
            }
        }
    }
    Ok(values)
}
