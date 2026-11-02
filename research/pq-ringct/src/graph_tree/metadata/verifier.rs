//! Fixed, graph-owned numeric plans. No replay, witness, reservation or proof
//! authority is retained; the issuer still records and checks its own census.
use crate::graph_proofs::{owned_mul, owned_ntt, owned_permutation};
use crate::preparation_options::{reuse_count, ReuseCounter};
use lattica_prover_p3::block_v2::{
    native_gpu::{
        mul_preparation::MulDescriptor, ntt_preparation::NttDescriptor,
        permutation_preparation::PermutationDescriptor,
    },
    profile,
};

const CAPACITY: usize = 64;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Ntt(NttDescriptor),
    Mul(MulDescriptor),
    Permutation(PermutationDescriptor),
}
#[derive(Clone, Copy)]
enum Value {
    Ntt(owned_ntt::verification_memory::Plan),
    Mul(owned_mul::verification_memory::Plan),
    Permutation(owned_permutation::verification_memory::Plan),
}
pub(super) struct Cache {
    source: [u8; 32],
    profile: [u8; 32],
    entries: [Option<(Key, Value)>; CAPACITY],
    len: usize,
}
impl Cache {
    pub(super) fn new() -> Self {
        Self {
            source: crate::graph_proofs::native_numeric_source_fingerprint(),
            profile: profile::CANDIDATE_PROFILE_ID,
            entries: [None; CAPACITY],
            len: 0,
        }
    }
    fn resolve(
        &mut self,
        key: Key,
        record: impl FnOnce() -> Result<Value, ()>,
    ) -> Result<Value, ()> {
        if self.source != crate::graph_proofs::native_numeric_source_fingerprint()
            || self.profile != profile::CANDIDATE_PROFILE_ID
        {
            return Err(());
        }
        if crate::preparation_options::verifier_reuse() {
            if let Some((_, value)) = self.entries[..self.len]
                .iter()
                .flatten()
                .find(|(k, _)| *k == key)
            {
                reuse_count(ReuseCounter::VerifierHits);
                return Ok(*value);
            }
        }
        reuse_count(ReuseCounter::VerifierRecordings);
        let value = record()?;
        let actual = match value {
            Value::Ntt(plan) => Key::Ntt(plan.descriptor()),
            Value::Mul(plan) => Key::Mul(plan.descriptor()),
            Value::Permutation(plan) => Key::Permutation(plan.descriptor()),
        };
        if key != actual {
            return Err(());
        }
        if crate::preparation_options::verifier_reuse() {
            if self.len < CAPACITY {
                self.entries[self.len] = Some((key, value));
                self.len += 1;
            } else {
                reuse_count(ReuseCounter::VerifierOverflow);
            }
        }
        Ok(value)
    }
}
macro_rules! method {
    ($method:ident, $variant:ident, $descriptor:ty, $plan:ty) => {
        pub(crate) fn $method(
            &self,
            descriptor: $descriptor,
            record: impl FnOnce() -> Result<$plan, ()>,
        ) -> Result<$plan, ()> {
            // The lock also makes a concurrent miss record at most once. The
            // closed recorder does not access this graph's metadata cache.
            let mut cache = self.verifiers.lock().map_err(|_| ())?;
            match cache.resolve(Key::$variant(descriptor), || record().map(Value::$variant))? {
                Value::$variant(plan) => Ok(plan),
                _ => Err(()),
            }
        }
    };
}
impl super::GraphMetadata {
    method!(
        verifier_ntt,
        Ntt,
        NttDescriptor,
        owned_ntt::verification_memory::Plan
    );
    method!(
        verifier_mul,
        Mul,
        MulDescriptor,
        owned_mul::verification_memory::Plan
    );
    method!(
        verifier_permutation,
        Permutation,
        PermutationDescriptor,
        owned_permutation::verification_memory::Plan
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn equal(a: Value, b: Value) -> bool {
        match (a, b) {
            (Value::Ntt(a), Value::Ntt(b)) => a.same_census(b),
            (Value::Mul(a), Value::Mul(b)) => a.same_census(b),
            (Value::Permutation(a), Value::Permutation(b)) => a.same_census(b),
            _ => false,
        }
    }
    #[test]
    fn numeric_cache_matches_fresh_recordings_and_rejects_wrong_keys_and_source() {
        let mut cache = Cache::new();
        let mut cases = Vec::new();
        for q in [crate::rust_verify::Q, crate::rust_verify::QHAT] {
            for count in [1, 3] {
                let d = NttDescriptor::new(q, count).unwrap();
                cases.push((
                    Key::Ntt(d),
                    Value::Ntt(owned_ntt::verification_memory::recorded_test_plan(d)),
                ));
                let d = MulDescriptor::new(q, count).unwrap();
                cases.push((
                    Key::Mul(d),
                    Value::Mul(owned_mul::verification_memory::recorded_test_plan(d)),
                ));
            }
        }
        for code in [1, 2] {
            let d = PermutationDescriptor::from_code(code).unwrap();
            cases.push((
                Key::Permutation(d),
                Value::Permutation(owned_permutation::verification_memory::recorded_test_plan(
                    d,
                )),
            ));
        }
        for &(key, value) in &cases {
            assert!(cache.resolve(key, || Err(())).is_err());
            assert!(equal(cache.resolve(key, || Ok(value)).unwrap(), value));
            let fresh = match key {
                Key::Ntt(d) => Value::Ntt(owned_ntt::verification_memory::recorded_test_plan(d)),
                Key::Mul(d) => Value::Mul(owned_mul::verification_memory::recorded_test_plan(d)),
                Key::Permutation(d) => Value::Permutation(
                    owned_permutation::verification_memory::recorded_test_plan(d),
                ),
            };
            assert!(equal(
                cache
                    .resolve(key, || panic!("numeric hit recorded again"))
                    .unwrap(),
                fresh
            ));
        }
        assert_eq!(cache.len, cases.len());
        let missing = Key::Ntt(NttDescriptor::new(crate::rust_verify::Q, 2).unwrap());
        assert!(cache.resolve(missing, || Ok(cases[0].1)).is_err());
        assert_eq!(cache.len, cases.len());
        let old = cases[0];
        cache.source[0] ^= 1;
        assert!(cache
            .resolve(old.0, || panic!("source mismatch reached recorder"))
            .is_err());
        cache.source[0] ^= 1;
        cache.profile[0] ^= 1;
        assert!(cache
            .resolve(old.0, || panic!("profile mismatch reached recorder"))
            .is_err());
        // Capacity is fixed and the original uncached recorder remains usable.
        let mut full = Cache::new();
        full.entries.fill(Some(old));
        full.len = CAPACITY;
        let next = cases[1];
        let mut recordings = 0;
        for _ in 0..2 {
            assert!(equal(
                full.resolve(next.0, || {
                    recordings += 1;
                    Ok(next.1)
                })
                .unwrap(),
                next.1
            ));
        }
        assert_eq!(recordings, 2);
        assert_eq!(full.len, CAPACITY);
        assert!(equal(
            full.resolve(old.0, || panic!("full cache lost an existing entry"))
                .unwrap(),
            old.1
        ));
    }
}
