//! Linear-map descriptors contain all coefficients. Keep each exact numeric
//! plan behind a pointer instead of widening every fixed cache/queue slot.
use super::*;
use crate::graph_proofs::owned_linear_map::verification_memory::Plan;
use lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::LinearMapDescriptor;

struct Entries { values: [Option<Box<Plan>>; CAPACITY], len: usize }
pub(crate) struct Cache {
    entries: std::sync::Mutex<Entries>, source: [u8; 32], profile: [u8; 32],
}
impl Cache {
    pub(crate) const fn allowance_bytes() -> usize { CAPACITY * core::mem::size_of::<Plan>() + 8 * Self::frame_bytes() }
    pub(crate) const fn frame_bytes() -> usize { 4 * core::mem::size_of::<Plan>() + core::mem::size_of::<LinearMapDescriptor>() }
    pub(crate) fn new(admitted: usize) -> Result<Self, ()> {
        if admitted != Self::allowance_bytes() { return Err(()); }
        Ok(Self { entries: std::sync::Mutex::new(Entries { values: core::array::from_fn(|_| None), len: 0 }),
            source: crate::graph_proofs::native_numeric_source_fingerprint(), profile: profile::CANDIDATE_PROFILE_ID })
    }
    pub(crate) fn resolve(&self, descriptor: LinearMapDescriptor, record: impl FnOnce() -> Result<Plan, ()>) -> Result<Plan, ()> {
        if self.source != crate::graph_proofs::native_numeric_source_fingerprint()
            || self.profile != profile::CANDIDATE_PROFILE_ID { return Err(()); }
        let mut entries = self.entries.lock().map_err(|_| ())?;
        if crate::preparation_options::verifier_reuse() {
            if let Some(plan) = entries.values[..entries.len].iter().flatten().find(|plan| plan.has_descriptor(&descriptor)) {
                reuse_count(ReuseCounter::VerifierHits);
                crate::preparation_options::next_count(crate::preparation_options::NextCounter::CaseHits);
                return Ok(**plan);
            }
        }
        reuse_count(ReuseCounter::VerifierRecordings);
        crate::preparation_options::next_count(crate::preparation_options::NextCounter::CaseRecordings);
        let plan = record()?;
        if !plan.has_descriptor(&descriptor) { return Err(()); }
        if crate::preparation_options::verifier_reuse() {
            let index = entries.len;
            if index == CAPACITY { reuse_count(ReuseCounter::VerifierOverflow); }
            else { entries.values[index] = Some(Box::new(plan)); entries.len += 1; }
        }
        Ok(plan)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_coefficients_are_checked_and_each_cold_plan_is_recorded_once() {
        let a = LinearMapDescriptor::new(&[[0, 3]; 2], &[[1; 256]], &[0; 256]).unwrap();
        let b = LinearMapDescriptor::new(&[[0, 3]; 2], &[[2; 256]], &[0; 256]).unwrap();
        use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
        assert!(core::mem::size_of::<Cache>() < 4 << 10);
        assert!(Cache::new(Cache::allowance_bytes() - 1).is_err());
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let original = ledger.reserve(Category::PhaseScratch, Bytes { host: Cache::allowance_bytes() as u64, device: 0 }).unwrap();
        let cache = Cache::new(Cache::allowance_bytes()).unwrap();
        let reference = crate::graph_proofs::owned_linear_map::verification_memory::recorded_test_plan(a);
        assert!(cache.resolve(b, || Ok(reference)).is_err());
        let value = cache.resolve(a, || Ok(reference)).unwrap();
        assert!(value.has_descriptor(&a));
        std::thread::scope(|threads| {
            for _ in 0..4 { threads.spawn(|| { assert!(cache.resolve(a, || panic!("recorded twice")).unwrap().has_descriptor(&a)); }); }
        });
        assert!(cache.resolve(b, || Err(())).is_err());
        assert_eq!(cache.entries.lock().unwrap().len, 1);
        drop(cache);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
