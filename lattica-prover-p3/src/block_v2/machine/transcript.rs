//! Exact p3-challenger 0.6.1 duplex schedule (including prefix-free absorbs).
use super::circuit::Extension;
use super::program::Val;
use super::{ProgramBuilder, Wire};
use p3_field::PrimeCharacteristicRing;

pub struct Transcript {
    state: [Wire; 8],
    input: Vec<Wire>,
    output: Vec<Wire>,
}
impl Transcript {
    pub fn new(b: &mut ProgramBuilder) -> Self {
        let zero = b.constant(Val::ZERO);
        Self {
            state: [zero; 8],
            input: vec![],
            output: vec![],
        }
    }
    fn duplex(&mut self, b: &mut ProgramBuilder) {
        let n = self.input.len();
        if n != 0 {
            let zero = b.constant(Val::ZERO);
            self.state[..4].fill(zero);
            self.state[..n].copy_from_slice(&self.input);
            let count = b.constant(Val::from_usize(n));
            self.state[4] = b.add(self.state[4], count);
            self.input.clear();
        }
        self.state = b.poseidon(self.state);
        self.output = self.state[..4].to_vec();
    }
    pub fn observe(&mut self, b: &mut ProgramBuilder, value: Wire) {
        self.output.clear();
        self.input.push(value);
        if self.input.len() == 4 {
            self.duplex(b);
        }
    }
    pub fn observe_slice(&mut self, b: &mut ProgramBuilder, values: &[Wire]) {
        for &v in values {
            self.observe(b, v);
        }
    }
    pub fn sample(&mut self, b: &mut ProgramBuilder) -> Wire {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplex(b);
        }
        self.output.pop().unwrap()
    }
    pub fn sample_ext(&mut self, b: &mut ProgramBuilder) -> Extension {
        core::array::from_fn(|_| self.sample(b))
    }
    pub fn sample_bits(&mut self, b: &mut ProgramBuilder, count: usize) -> Vec<Wire> {
        assert!(count < 64);
        let value = self.sample(b);
        b.bits(value)[..count].to_vec()
    }
    pub fn check_pow(&mut self, b: &mut ProgramBuilder, bits: usize, witness: Wire) {
        // Upstream skips observation entirely when bits == 0.
        if bits == 0 {
            return;
        }
        self.observe(b, witness);
        for bit in self.sample_bits(b, bits) {
            b.assert_zero(bit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Challenger;
    use p3_challenger::{CanObserve, CanSample, CanSampleBits};
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    #[test]
    fn native_transcript_schedule_and_canonical_bits() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut t = Transcript::new(&mut b);
        let mut native = Challenger::new(default_goldilocks_poseidon2_8());
        for n in [0, 1, 4, 7, 16, 3] {
            for i in 0..n {
                let v = Val::from_usize(i + n * 100);
                let w = b.constant(v);
                t.observe(&mut b, w);
                native.observe(v);
            }
            for _ in 0..7 {
                let sample = t.sample(&mut b);
                let expected: Val = native.sample();
                let expected = b.constant(expected);
                b.assert_equal(sample, expected);
            }
            let bits = t.sample_bits(&mut b, 23);
            let expected = native.sample_bits(23);
            for (i, bit) in bits.into_iter().enumerate() {
                let v = b.constant(Val::from_usize((expected >> i) & 1));
                b.assert_equal(bit, v);
            }
        }
        b.finish(None).unwrap().evaluate(&[], &[]).unwrap();
    }

    #[test]
    fn grinding_matches_native_and_rejects_wrong_witness() {
        use p3_challenger::GrindingChallenger;
        let mut native = Challenger::new(default_goldilocks_poseidon2_8());
        native.observe(Val::from_u64(123));
        let before = native.clone();
        let witness = native.grind(16);
        let next: Val = native.sample();
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut transcript = Transcript::new(&mut b);
        let observed = b.constant(Val::from_u64(123));
        transcript.observe(&mut b, observed);
        let input = b.input();
        transcript.check_pow(&mut b, 16, input);
        let actual = transcript.sample(&mut b);
        let expected = b.constant(next);
        b.assert_equal(actual, expected);
        let program = b.finish(None).unwrap();
        program.evaluate(&[], &[witness]).unwrap();
        let mut bad = witness + Val::ONE;
        while before.clone().check_witness(16, bad) {
            bad += Val::ONE;
        }
        assert!(program.evaluate(&[], &[bad]).is_err());
    }
}
