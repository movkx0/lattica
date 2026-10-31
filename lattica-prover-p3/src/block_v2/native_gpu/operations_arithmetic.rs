//! Bounded raw arithmetic for graph witness preparation. These descriptors hold
//! only public operation metadata; they never hold a host-generated AIR trace.
//! Results are raw coefficients (including unchanged signed two's-complement
//! words), not field-canonicalized trace values or a proof of the operation.
use super::OperationContext;

const Q: u64 = 167_770_241;
const QHAT: u64 = 3_489_661_057;
const MAX_WORDS: usize = 128 * 256;

#[derive(Clone, Copy, Debug)]
pub enum CanonicalOperation {
    Add,
    Subtract,
    Montgomery,
}

#[derive(Clone, Copy, Debug)]
pub enum SignedOperation {
    Negate,
    Subtract,
}

#[derive(Clone, Debug)]
pub struct ArithmeticOperationSpec {
    pub(crate) metadata: Vec<u64>,
    pub(crate) input_words: usize,
    pub(crate) output_words: usize,
    pub(crate) work_items: usize,
}

impl ArithmeticOperationSpec {
    fn modulus(modulus: u64) -> Result<(), String> {
        if !matches!(modulus, Q | QHAT) {
            return Err("unsupported raw MatRiCT modulus".into());
        }
        Ok(())
    }

    fn new(
        opcode: u64,
        modulus: u64,
        count: usize,
        input_words: usize,
        output_words: usize,
        work_items: usize,
    ) -> Result<Self, String> {
        if count == 0
            || count > MAX_WORDS
            || input_words == 0
            || input_words > 2 * MAX_WORDS
            || output_words == 0
            || output_words > MAX_WORDS
            || work_items == 0
            || work_items > MAX_WORDS
        {
            return Err("raw arithmetic exceeds bounded operation geometry".into());
        }
        Ok(Self {
            metadata: vec![opcode, modulus, count as u64, output_words as u64],
            input_words,
            output_words,
            work_items,
        })
    }

    /// Elementwise binary arithmetic. Input is left[count], then right[count].
    /// Every input coefficient must be canonical for the selected modulus.
    pub fn canonical(kind: CanonicalOperation, count: usize, modulus: u64) -> Result<Self, String> {
        Self::modulus(modulus)?;
        let opcode = match kind {
            CanonicalOperation::Add => 1,
            CanonicalOperation::Subtract => 2,
            CanonicalOperation::Montgomery => 3,
        };
        Self::new(
            opcode,
            modulus,
            count,
            count
                .checked_mul(2)
                .ok_or("raw arithmetic count overflow")?,
            count,
            count,
        )
    }

    /// Signed original i64 inputs, encoded as u64 words. Reduction accepts the
    /// entire i64 range, including i64::MIN, without a host arithmetic pass.
    pub fn signed_to_canonical(count: usize, modulus: u64) -> Result<Self, String> {
        Self::modulus(modulus)?;
        Self::new(4, modulus, count, count, count, count)
    }

    /// Signed i64 words in and out. Subtraction input is left[count], then
    /// right[count]. Overflow is rejected by the GPU, never wrapped or clamped.
    pub fn signed(kind: SignedOperation, count: usize) -> Result<Self, String> {
        let (opcode, factor) = match kind {
            SignedOperation::Negate => (5, 1),
            SignedOperation::Subtract => (6, 2),
        };
        Self::new(
            opcode,
            0,
            count,
            count
                .checked_mul(factor)
                .ok_or("raw arithmetic count overflow")?,
            count,
            count,
        )
    }

    /// Signed polynomials in, canonical polynomials out. Each public butterfly
    /// is [address_a,address_b,factor_u,factor_v], with ordinary modular factors
    /// as in ArithmeticSpec::ntt. Final permutation addresses 64 four-word blocks.
    pub fn ntt(
        modulus: u64,
        count: usize,
        steps: &[[u64; 4]],
        permutation: &[u64],
    ) -> Result<Self, String> {
        Self::modulus(modulus)?;
        if count == 0
            || count > 128
            || steps.len() != 768
            || permutation.len() != 64
            || steps.iter().any(|s| {
                s[0] >= 256 || s[1] >= 256 || s[0] == s[1] || s[2] >= modulus || s[3] >= modulus
            })
            || !Self::permutation_is_valid(permutation, 64)
        {
            return Err("invalid raw NTT schedule".into());
        }
        let mut spec = Self::new(7, modulus, count, count * 256, count * 256, count)?;
        spec.metadata.extend(steps.iter().flatten().copied());
        spec.metadata.extend_from_slice(permutation);
        Ok(spec)
    }

    /// Canonical polynomial pairs, serialized left[256],right[256] for each
    /// pair. Public terms are [factor,negative] in block/i/j order, using the
    /// same ordinary modular factors as ArithmeticSpec::mul.
    pub fn mul(modulus: u64, count: usize, terms: &[[u64; 2]]) -> Result<Self, String> {
        Self::modulus(modulus)?;
        if count == 0
            || count > 128
            || terms.len() != 64 * 16
            || terms.iter().any(|t| t[0] >= modulus || t[1] > 1)
        {
            return Err("invalid raw multiplication schedule".into());
        }
        let mut spec = Self::new(8, modulus, count, count * 512, count * 256, count * 64)?;
        spec.metadata.extend(terms.iter().flatten().copied());
        Ok(spec)
    }

    /// Canonical Q automorphism. Factors use ordinary modular multiplication,
    /// exactly as ArithmeticSpec::permutation(1,...).
    pub fn automorphism(sources: &[u64], factors: &[u64]) -> Result<Self, String> {
        if !Self::permutation_is_valid(sources, 256)
            || factors.len() != 256
            || factors.iter().any(|&v| v >= Q)
        {
            return Err("invalid raw automorphism schedule".into());
        }
        let mut spec = Self::new(9, Q, 1, 256, 256, 256)?;
        spec.metadata.extend_from_slice(sources);
        spec.metadata.extend_from_slice(factors);
        Ok(spec)
    }

    /// Signed permutation with optional negation. The GPU checks i64 overflow.
    pub fn inverse_challenge(sources: &[u64], negative: &[bool]) -> Result<Self, String> {
        if !Self::permutation_is_valid(sources, 256) || negative.len() != 256 {
            return Err("invalid raw signed permutation schedule".into());
        }
        let mut spec = Self::new(10, 0, 1, 256, 256, 256)?;
        spec.metadata.extend_from_slice(sources);
        spec.metadata.extend(negative.iter().map(|&v| u64::from(v)));
        Ok(spec)
    }

    fn permutation_is_valid(sources: &[u64], count: usize) -> bool {
        if sources.len() != count {
            return false;
        }
        let mut seen = [false; 256];
        for &source in sources {
            if source >= count as u64 || seen[source as usize] {
                return false;
            }
            seen[source as usize] = true;
        }
        true
    }

    pub fn raw_input_words(&self) -> usize {
        self.input_words
    }

    pub fn output_words(&self) -> usize {
        self.output_words
    }

    pub(crate) fn staging_bytes(&self) -> Result<usize, String> {
        self.input_words
            .checked_add(self.output_words)
            .and_then(|v| v.checked_add(self.metadata.capacity()))
            .and_then(|v| v.checked_add(self.work_items))
            .and_then(|v| v.checked_mul(8))
            .filter(|&v| v <= 64 << 20)
            .ok_or_else(|| "raw arithmetic staging exceeds bound".into())
    }
}

impl OperationContext<'_> {
    /// Admit metadata, raw staging, status, and result before the caller builds
    /// its serialized input. No private arithmetic is performed by admission.
    pub fn admit_arithmetic_operation(&self, spec: &ArithmeticOperationSpec) -> Result<(), String> {
        self.execute(|| self.admit_host_bytes(spec.staging_bytes()?))
    }

    /// Execute an admitted raw operation. Full AIR traces are never constructed
    /// or read back; only the bounded result coefficient vector returns here.
    pub fn arithmetic_output(
        &self,
        spec: &ArithmeticOperationSpec,
        input: &[u64],
    ) -> Result<Vec<u64>, String> {
        self.execute(|| {
            self.admit_host_bytes(spec.staging_bytes()?)?;
            if input.len() != spec.input_words {
                return Err("raw arithmetic input length mismatch".into());
            }
            #[cfg(feature = "gpu")]
            {
                self.session
                    .research_arithmetic_output(spec, input, self.host_allowance, self.run)
            }
            #[cfg(not(feature = "gpu"))]
            {
                Err("raw graph arithmetic requires OpenCL".into())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_operation_admission_rejects_unsafe_geometry() {
        for count in [0, MAX_WORDS + 1, usize::MAX] {
            assert!(ArithmeticOperationSpec::canonical(CanonicalOperation::Add, count, Q).is_err());
            assert!(ArithmeticOperationSpec::signed(SignedOperation::Subtract, count).is_err());
        }
        assert!(ArithmeticOperationSpec::signed_to_canonical(1, Q + 1).is_err());
        let steps = [[0, 128, 1, 1]; 768];
        let mut permutation: [u64; 64] = core::array::from_fn(|i| i as u64);
        assert!(ArithmeticOperationSpec::ntt(QHAT, 128, &steps, &permutation).is_ok());
        permutation[63] = 0;
        assert!(ArithmeticOperationSpec::ntt(QHAT, 1, &steps, &permutation).is_err());
        let mut bad_steps = steps;
        bad_steps[767][0] = 256;
        assert!(ArithmeticOperationSpec::ntt(Q, 1, &bad_steps, &permutation).is_err());
        let terms = [[QHAT - 1, 0]; 1024];
        let spec = ArithmeticOperationSpec::mul(QHAT, 128, &terms).unwrap();
        assert_eq!(spec.raw_input_words(), 65536);
        assert_eq!(spec.output_words(), 32768);
        assert!(spec.staging_bytes().unwrap() < 1 << 20);
        assert!(ArithmeticOperationSpec::mul(Q, 1, &terms).is_err());
        let sources: [u64; 256] = core::array::from_fn(|i| i as u64);
        assert!(ArithmeticOperationSpec::automorphism(&sources, &[1; 256]).is_ok());
        assert!(ArithmeticOperationSpec::automorphism(&sources, &[Q; 256]).is_err());
    }
}
