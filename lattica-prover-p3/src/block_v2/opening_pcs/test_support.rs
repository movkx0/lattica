use super::Challenger;
use crate::config::Val;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};

/// Upstream's parallel grinder may choose any valid nonce. Independently check
/// the GPU witnesses on the CPU and use them for an otherwise unchanged upstream
/// proof, so the byte comparison does not depend on CPU thread scheduling.
#[derive(Clone)]
pub(super) struct ReplayPow {
    pub(super) inner: Challenger,
    pub(super) witnesses: std::collections::VecDeque<(usize, Val)>,
}
impl<T> CanObserve<T> for ReplayPow
where
    Challenger: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
}
impl CanSample<Val> for ReplayPow {
    fn sample(&mut self) -> Val {
        self.inner.sample()
    }
}
impl CanSampleBits<usize> for ReplayPow {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}
impl FieldChallenger<Val> for ReplayPow {}
impl GrindingChallenger for ReplayPow {
    type Witness = Val;
    fn grind(&mut self, bits: usize) -> Val {
        let (expected_bits, witness) = self.witnesses.pop_front().unwrap();
        assert_eq!(bits, expected_bits);
        assert!(self.inner.check_witness(bits, witness));
        witness
    }
}
