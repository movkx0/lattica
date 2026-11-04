//! Bounded segment hashing for immutable requests. Keys retain their exact
//! request binding; no caller-supplied digest can become a numeric source.
use crate::graph_crypto::{Request, RequestDescriptor};
use crate::component_tree::paired_runtime::PairedFailure;
use crate::metadata_parallel::{self as parallel, Error as WorkerError};
type Result<T> = core::result::Result<T, PairedFailure>;

const MAX: usize = parallel::MAX_JOBS;
type Key = [u8; 32];

#[derive(Clone, Copy)]
struct Shard { request: usize, first: usize, count: usize, per_key: usize }
impl Shard {
    fn cost(self) -> Result<usize> {
        self.count.checked_mul(self.per_key).ok_or(PairedFailure::Overflow)
    }
}
pub(crate) struct IdentityKeyPlan<'a> {
    requests: [Option<&'a Request>; MAX],
    count: usize,
    shards: [Option<Shard>; MAX],
    jobs: usize,
    retained: usize,
}
pub(crate) struct RequestIdentityKeys<'a> {
    request: &'a Request,
    source: [u8; 32],
    values: Vec<Key>,
}
impl RequestIdentityKeys<'_> {
    pub(crate) fn for_request(&self, request: &Request) -> Result<&[Key]> {
        if !core::ptr::eq(self.request, request)
            || self.source != crate::graph_proofs::compiled_source_fingerprint()
            || self.values.len() != request.segments().len() {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(&self.values)
    }
}
impl<'a> RequestIdentityKeys<'a> {
    pub(super) fn from_shards(request: &'a Request, values: Vec<Key>) -> Result<Self> {
        if values.len() != request.segments().len() { return Err(PairedFailure::Coverage); }
        Ok(Self { request, values, source: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
pub(crate) struct IdentityKeys<'a> { requests: [Option<RequestIdentityKeys<'a>>; MAX] }
impl<'a> IdentityKeys<'a> {
    pub(crate) fn get(&self, index: usize) -> Result<&RequestIdentityKeys<'a>> {
        self.requests.get(index).and_then(Option::as_ref).ok_or(PairedFailure::Coverage)
    }
}
impl<'a> IdentityKeyPlan<'a> {
    pub(crate) fn new(requests: impl Iterator<Item = &'a Request>, ceiling: usize) -> Result<Self> {
        if !(1..=16).contains(&ceiling) { return Err(PairedFailure::Coverage); }
        let mut plan = Self { requests: [None; MAX], count: 0, shards: [None; MAX], jobs: 0, retained: 0 };
        let mut keys = 0usize;
        for request in requests {
            if plan.count == MAX || request.segments().is_empty() { return Err(PairedFailure::Coverage); }
            let per_key = match request.descriptor() {
                RequestDescriptor::Shake(descriptor) => descriptor.input_len,
                RequestDescriptor::Aes(_) => 32,
            }.checked_add(256).ok_or(PairedFailure::Overflow)?;
            let count = request.segments().len();
            keys = keys.checked_add(count).ok_or(PairedFailure::Overflow)?;
            let shard = Shard { request: plan.count, first: 0, count, per_key };
            shard.cost()?;
            plan.requests[plan.count] = Some(request);
            plan.shards[plan.count] = Some(shard);
            plan.count += 1;
        }
        if plan.count == 0 { return Err(PairedFailure::Coverage); }
        plan.jobs = plan.count;
        // Four ready tasks per lane absorb unequal payload/segment counts.
        // Split the most expensive remaining span, preserving each key's index.
        let target = MAX.min(plan.count.max(4 * ceiling));
        while plan.jobs < target {
            let mut largest = None;
            let mut largest_cost = 0;
            for index in 0..plan.jobs {
                let shard = plan.shards[index].ok_or(PairedFailure::Coverage)?;
                let cost = shard.cost()?;
                if shard.count > 1 && cost > largest_cost { largest = Some(index); largest_cost = cost; }
            }
            let Some(index) = largest else { break; };
            let shard = plan.shards[index].ok_or(PairedFailure::Coverage)?;
            let left = shard.count / 2;
            plan.shards[index] = Some(Shard { count: left, ..shard });
            plan.shards[plan.jobs] = Some(Shard { first: shard.first.checked_add(left).ok_or(PairedFailure::Overflow)?,
                count: shard.count - left, ..shard });
            plan.jobs += 1;
        }
        // All destination keys and all in-flight/completed shard vectors stay
        // funded, including the allowed allocation-capacity overlap.
        plan.retained = keys.checked_mul(4 * core::mem::size_of::<Key>())
            .and_then(|n| n.checked_add(8 * core::mem::size_of::<IdentityKeys<'static>>()))
            .ok_or(PairedFailure::Overflow)?;
        Ok(plan)
    }
    pub(crate) fn jobs(&self) -> usize { self.jobs }
    pub(crate) fn retained_bytes(&self) -> usize { self.retained }
    /// Caller holds the complete extra numeric original through this result.
    pub(crate) fn derive(&self, admission: parallel::Plan) -> Result<IdentityKeys<'a>> {
        let mut result = IdentityKeys { requests: core::array::from_fn(|_| None) };
        for (index, request) in self.requests[..self.count].iter().enumerate() {
            let request = request.ok_or(PairedFailure::Coverage)?;
            let mut values = Vec::new();
            values.try_reserve_exact(request.segments().len()).map_err(|_| PairedFailure::Capacity)?;
            if values.capacity() > request.segments().len().checked_mul(2).ok_or(PairedFailure::Overflow)? {
                return Err(PairedFailure::Capacity);
            }
            values.resize(request.segments().len(), [0; 32]);
            result.requests[index] = Some(RequestIdentityKeys { request,
                source: crate::graph_proofs::compiled_source_fingerprint(), values });
        }
        let mut costs = [0; MAX];
        for (index, cost) in costs[..self.jobs].iter_mut().enumerate() {
            *cost = self.shards[index].ok_or(PairedFailure::Coverage)?.cost()?;
        }
        let stats = parallel::run(admission, &costs[..self.jobs], |_| Ok(()), |_, index| {
            let shard = self.shards[index].ok_or(WorkerError::Geometry)?;
            let request = self.requests[shard.request].ok_or(WorkerError::Geometry)?;
            let mut values = Vec::new();
            values.try_reserve_exact(shard.count).map_err(|_| WorkerError::Budget)?;
            if values.capacity() > 2 * shard.count { return Err(WorkerError::Budget); }
            for index in shard.first..shard.first + shard.count {
                values.push(request.cache_key(index).map_err(|_| WorkerError::Worker)?);
            }
            Ok(values)
        }, |index, values| {
            let shard = self.shards[index].ok_or(WorkerError::Geometry)?;
            if values.len() != shard.count { return Err(WorkerError::Publication); }
            result.requests[shard.request].as_mut().ok_or(WorkerError::Publication)?
                .values.get_mut(shard.first..shard.first + shard.count)
                .ok_or(WorkerError::Publication)?.copy_from_slice(&values);
            Ok(())
        }).map_err(|_| PairedFailure::Source)?;
        parallel::report("crypto_hash", stats);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_crypto::{Admission, Payload, Policy};
    fn request(input_len: usize) -> Request {
        Request::new([7; 32], 3, 0,
            RequestDescriptor::Shake(crate::shake_air::Descriptor { input_len, output_len: 256 }),
            Payload::Shake(vec![93; input_len]), Policy { maximum_aes_blocks: 8,
                maximum_shake_permutations: 1, child_memory_budget_bytes: 24 << 30,
                admission: Admission::Estimated }).unwrap()
    }
    #[test]
    fn sharded_keys_preserve_every_segment_and_exact_request_binding() {
        let a = request(136 * 3);
        let b = request(136 * 9);
        let alias = request(136 * 3);
        for ceiling in [1, 2, 4, 8, 16] {
            let plan = IdentityKeyPlan::new([&a, &b].into_iter(), ceiling).unwrap();
            let admission = parallel::Plan::new(ceiling, plan.jobs(), usize::MAX,
                plan.retained_bytes(), 0).unwrap();
            let keys = plan.derive(admission).unwrap();
            for (index, request) in [&a, &b].into_iter().enumerate() {
                let actual = keys.get(index).unwrap().for_request(request).unwrap();
                let expected: Vec<_> = (0..request.segments().len()).map(|i| request.cache_key(i).unwrap()).collect();
                assert_eq!(actual, expected);
            }
            assert!(keys.get(0).unwrap().for_request(&alias).is_err());
            let mut wrong = keys;
            wrong.requests[0].as_mut().unwrap().source[0] ^= 1;
            assert!(wrong.get(0).unwrap().for_request(&a).is_err());
        }
    }
}
