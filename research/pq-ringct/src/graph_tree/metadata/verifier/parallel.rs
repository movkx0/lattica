//! Deduplicate and fund numeric recordings before dispatch; never hold the case
//! cache mutex while a worker records an AIR.
use super::*;
use crate::execution::retained_resources::{Bytes, Category, Ledger};
use crate::metadata_parallel::{self as workers, Error};

// Short recordings reuse each lane for up to two descriptors. Pair a large
// census with a small one so this does not introduce a large serial tail.
// The number of jobs still grows with the descriptor inventory; no fixed
// worker cap is imposed on larger cases.
fn recording_groups(costs: &[usize]) -> Result<([[usize; 2]; CAPACITY], [usize; CAPACITY], usize), ()> {
    if !(2..=CAPACITY).contains(&costs.len()) || costs.contains(&0) { return Err(()); }
    let mut order: [usize; CAPACITY] = core::array::from_fn(|i| i);
    order[..costs.len()].sort_unstable_by(|&a, &b| costs[b].cmp(&costs[a]).then(a.cmp(&b)));
    let count = costs.len().div_ceil(2).max(2);
    let mut groups = [[usize::MAX; 2]; CAPACITY];
    let mut totals = [0; CAPACITY];
    for index in 0..count {
        groups[index][0] = order[index];
        totals[index] = costs[order[index]];
        if index < costs.len() - count {
            let tail = order[costs.len() - 1 - index];
            groups[index][1] = tail;
            totals[index] = totals[index].checked_add(costs[tail]).ok_or(())?;
        }
    }
    Ok((groups, totals, count))
}

impl Key {
    pub(crate) fn numeric_host_bytes(self) -> Result<usize, ()> {
        match self {
            Self::Ntt(kind) => owned_ntt::verification_memory::numeric_host_bytes(kind),
            Self::Mul(kind) => owned_mul::verification_memory::numeric_host_bytes(kind),
            Self::Permutation(kind) => owned_permutation::verification_memory::numeric_host_bytes(kind),
        }.map_err(|_| ())
    }
    fn compute(self, bytes: usize) -> Result<Value, Error> {
        match self {
            Self::Ntt(kind) => owned_ntt::verification_memory::numeric_plan(kind, bytes).map(Value::Ntt),
            Self::Mul(kind) => owned_mul::verification_memory::numeric_plan(kind, bytes).map(Value::Mul),
            Self::Permutation(kind) => owned_permutation::verification_memory::numeric_plan(kind, bytes).map(Value::Permutation),
        }.map_err(|_| Error::Worker)
    }
}
impl Value {
    fn key(self) -> Key {
        match self {
            Self::Ntt(plan) => Key::Ntt(plan.descriptor()),
            Self::Mul(plan) => Key::Mul(plan.descriptor()),
            Self::Permutation(plan) => Key::Permutation(plan.descriptor()),
        }
    }
}
impl Cache {
    fn validate_numeric_identity(&self) -> Result<(), ()> {
        if self.source != crate::graph_proofs::native_numeric_source_fingerprint()
            || self.profile != profile::CANDIDATE_PROFILE_ID { return Err(()); }
        Ok(())
    }
}
impl VerifierCache {
    pub(crate) fn prewarm(&self, requested: &[Key], ledger: &Ledger, ceiling: usize) -> Result<(), ()> {
        if ceiling < 2 || !crate::preparation_options::verifier_reuse()
            || !crate::preparation_options::metadata_workers_enabled("native") { return Ok(()); }
        let mut keys = [None; CAPACITY];
        let mut costs = [0usize; CAPACITY];
        let mut count = 0usize;
        {
            let cache = self.verifiers.lock().map_err(|_| ())?;
            cache.validate_numeric_identity()?;
            if !cache.case_owned { return Ok(()); }
            for &key in requested {
                if cache.entries[..cache.len].iter().flatten().any(|(stored, _)| *stored == key)
                    || keys[..count].contains(&Some(key)) { continue; }
                if cache.len + count == CAPACITY { return Ok(()); }
                costs[count] = key.numeric_host_bytes()?;
                keys[count] = Some(key);
                count += 1;
            }
        }
        if count < 2 { return Ok(()); }
        let transient = *costs[..count].iter().max().ok_or(())?;
        let retained = 8 * core::mem::size_of::<[Option<Value>; CAPACITY]>();
        let (groups, grouped_costs, jobs) = recording_groups(&costs[..count])?;
        let plan = match workers::Plan::new(ceiling, jobs,
            usize::try_from(ledger.remaining().host).unwrap_or(usize::MAX), retained, transient) {
            Ok(plan) if plan.width >= 2 => plan,
            _ => return Ok(()),
        };
        // The real case ledger covers every concurrent local recording. The
        // local recorders/ledgers have all died before this original retires.
        let _original = ledger.reserve(Category::PhaseScratch,
            Bytes { host: plan.host_bytes as u64, device: 0 }).map_err(|_| ())?;
        let mut completed = [None; CAPACITY];
        let mut stats = workers::run(plan, &grouped_costs[..jobs], |_| Ok(()), |_, job| {
            let mut values = [None; 2];
            for (slot, index) in groups[job].into_iter().enumerate() {
                if index != usize::MAX {
                    values[slot] = Some((index, keys[index].ok_or(Error::Geometry)?.compute(costs[index])?));
                }
            }
            Ok(values)
        }, |_, values| {
            for (index, value) in values.into_iter().flatten() {
                if value.key() != keys[index].ok_or(Error::Geometry)?
                    || completed[index].replace(value).is_some() { return Err(Error::Publication); }
            }
            Ok(())
        }).map_err(|_| ())?;
        let publication = std::time::Instant::now();
        let mut cache = self.verifiers.lock().map_err(|_| ())?;
        cache.validate_numeric_identity()?;
        // Publish in the original descriptor order after every worker joins.
        for index in 0..count {
            let key = keys[index].ok_or(())?;
            let value = completed[index].take().ok_or(())?;
            // Only the coordinator publishes into this case during prewarming.
            if cache.len >= CAPACITY || cache.entries[..cache.len].iter().flatten().any(|(stored, _)| *stored == key) {
                return Err(());
            }
            let position = cache.len;
            cache.entries[position] = Some((key, value));
            cache.len += 1;
            reuse_count(ReuseCounter::VerifierRecordings);
            crate::preparation_options::next_count(crate::preparation_options::NextCounter::CaseRecordings);
        }
        drop(cache);
        let elapsed = publication.elapsed().as_nanos();
        stats.publication_ns += elapsed;
        stats.wall_ns += elapsed;
        workers::report("native", stats);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    #[test]
    fn recording_groups_cover_each_descriptor_once_and_grow_beyond_eight_lanes() {
        for count in 2..=CAPACITY {
            let costs: Vec<_> = (1..=count).map(|n| n * n).collect();
            let (groups, totals, jobs) = recording_groups(&costs).unwrap();
            let mut found: Vec<_> = groups[..jobs].iter().flatten().copied().filter(|i| *i != usize::MAX).collect();
            found.sort_unstable();
            assert_eq!(found, (0..count).collect::<Vec<_>>());
            for (group, total) in groups[..jobs].iter().zip(&totals[..jobs]) {
                assert_eq!(*total, group.iter().filter(|i| **i != usize::MAX).map(|i| costs[*i]).sum::<usize>());
            }
            assert_eq!(jobs, count.div_ceil(2).max(2));
        }
    }
    #[test]
    fn unique_recordings_publish_once_and_release_the_parallel_original() {
        let ntt = NttDescriptor::new(crate::rust_verify::Q, 1).unwrap();
        let mul = MulDescriptor::new(crate::rust_verify::Q, 1).unwrap();
        let cache = VerifierCache::new(true);
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        cache.prewarm(&[Key::Ntt(ntt), Key::Mul(mul), Key::Ntt(ntt)], &ledger, 4).unwrap();
        assert_eq!(cache.verifiers.lock().unwrap().len, 2);
        cache.verifier_ntt(ntt, || panic!("prefilled descriptor recorded again")).unwrap();
        cache.verifier_mul(mul, || panic!("prefilled descriptor recorded again")).unwrap();
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    #[test]
    fn insufficient_parallel_budget_leaves_serial_construction_available() {
        let keys = [Key::Ntt(NttDescriptor::new(crate::rust_verify::Q, 1).unwrap()),
            Key::Mul(MulDescriptor::new(crate::rust_verify::Q, 1).unwrap())];
        let cache = VerifierCache::new(true);
        let ledger = Ledger::new(WorkerAllowance { host: 1, device: 0 });
        cache.prewarm(&keys, &ledger, 4).unwrap();
        assert_eq!(cache.verifiers.lock().unwrap().len, 0);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
