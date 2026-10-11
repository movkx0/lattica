//! Block-v2 transcript adapter. The root wallet/legacy challenger is unchanged.
//! GPU selection is explicit and immutable for a challenger family. No device
//! state is reconstructed on the host and no failed GPU operation falls back.
use crate::config::{Challenger as CpuChallenger, Perm, Val};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_symmetric::{Hash, MerkleCap};
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod observation;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod resources;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod scalars;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::gpu_hash::device::{DeviceSession, DeviceTranscript, TranscriptAttempt};

enum Backend {
    Cpu(CpuChallenger),
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    Gpu(DeviceTranscript),
}

pub struct CandidateChallenger {
    inner: Backend,
}

impl CandidateChallenger {
    /// The default remains the original CPU transcript, including custom
    /// permutations used by independent reference callers.
    pub fn new(permutation: Perm) -> Self {
        CpuChallenger::new(permutation).into()
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn new_gpu(session: &DeviceSession) -> Result<Self, String> {
        Ok(Self {
            inner: Backend::Gpu(session.new_transcript()?),
        })
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn new_gpu_registered(session: &DeviceSession) -> Result<Self, String> {
        resources::check_worker(true)?;
        Ok(Self {
            inner: Backend::Gpu(session.new_transcript_bounded(resources::LIVE_STATES)?),
        })
    }

    pub(crate) fn is_gpu(&self) -> bool {
        match &self.inner {
            Backend::Cpu(_) => false,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Gpu(_) => true,
        }
    }

    pub(crate) fn backend_name(&self) -> &'static str {
        if self.is_gpu() {
            "opencl"
        } else {
            "cpu"
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        match &self.inner {
            Backend::Cpu(_) => Ok(()),
            Backend::Gpu(gpu) => gpu.check_session(session),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn begin_attempt(&self) -> Result<Option<TranscriptAttempt>, String> {
        match &self.inner {
            Backend::Cpu(_) => Ok(None),
            Backend::Gpu(gpu) => gpu.begin_attempt().map(Some),
        }
    }

    fn observe_values(&mut self, values: impl IntoIterator<Item = Val>) {
        match &mut self.inner {
            Backend::Cpu(cpu) => {
                for value in values {
                    cpu.observe(value);
                }
            }
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Gpu(gpu) => {
                // Bound host staging as well as device upload. Chunking does
                // not insert a transcript boundary or flush pending inputs.
                let mut values = values.into_iter();
                loop {
                    let words: Vec<_> = values
                        .by_ref()
                        .take(resources::BATCH_WORDS)
                        .map(|value| value.as_canonical_u64())
                        .collect();
                    let result = gpu.observe(&words);
                    checked(gpu, result);
                    if words.len() < resources::BATCH_WORDS {
                        break;
                    }
                }
            }
        }
    }

    /// Batches the fixed FRI query list without changing sample order.
    pub(crate) fn sample_bits_vec(&mut self, bits: usize, count: usize) -> Vec<usize> {
        match &mut self.inner {
            Backend::Cpu(cpu) => (0..count).map(|_| cpu.sample_bits(bits)).collect(),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Gpu(gpu) => {
                if count == 0 {
                    let result = gpu.observe(&[]);
                    checked(gpu, result);
                    return Vec::new();
                }
                let result = gpu.sample_bits(bits, count);
                checked(gpu, result)
                    .into_iter()
                    .map(|n| n as usize)
                    .collect()
            }
        }
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn checked<T>(gpu: &DeviceTranscript, result: Result<T, String>) -> T {
    result.unwrap_or_else(|error| {
        // Also covers admission failures after an earlier chunk in a trait
        // call. Infallible upstream traits must fail the complete attempt.
        gpu.retire();
        panic!("GPU transcript failed; no CPU fallback: {error}")
    })
}

impl From<CpuChallenger> for CandidateChallenger {
    fn from(cpu: CpuChallenger) -> Self {
        Self {
            inner: Backend::Cpu(cpu),
        }
    }
}

impl Clone for CandidateChallenger {
    fn clone(&self) -> Self {
        Self {
            inner: match &self.inner {
                Backend::Cpu(cpu) => Backend::Cpu(cpu.clone()),
                #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
                Backend::Gpu(gpu) => Backend::Gpu(checked(gpu, gpu.snapshot())),
            },
        }
    }
}

impl CanObserve<Val> for CandidateChallenger {
    fn observe(&mut self, value: Val) {
        self.observe_values([value]);
    }
    fn observe_slice(&mut self, values: &[Val]) {
        self.observe_values(values.iter().copied());
    }
}

impl<const N: usize> CanObserve<[Val; N]> for CandidateChallenger {
    fn observe(&mut self, values: [Val; N]) {
        self.observe_values(values);
    }
}

impl<const N: usize> CanObserve<Hash<Val, Val, N>> for CandidateChallenger {
    fn observe(&mut self, values: Hash<Val, Val, N>) {
        self.observe_values(values);
    }
}

impl<const N: usize> CanObserve<&MerkleCap<Val, [Val; N]>> for CandidateChallenger {
    fn observe(&mut self, cap: &MerkleCap<Val, [Val; N]>) {
        self.observe_values(cap.roots().iter().flat_map(|digest| digest.iter().copied()));
    }
}

impl<const N: usize> CanObserve<MerkleCap<Val, [Val; N]>> for CandidateChallenger {
    fn observe(&mut self, cap: MerkleCap<Val, [Val; N]>) {
        self.observe(&cap);
    }
}

impl CanObserve<Vec<Vec<Val>>> for CandidateChallenger {
    fn observe(&mut self, values: Vec<Vec<Val>>) {
        self.observe_values(values.into_iter().flatten());
    }
}

impl<A: BasedVectorSpace<Val>> CanSample<A> for CandidateChallenger {
    fn sample(&mut self) -> A {
        match &mut self.inner {
            Backend::Cpu(cpu) => cpu.sample(),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Gpu(gpu) => {
                let result = gpu.sample_fields(A::DIMENSION);
                let words = checked(gpu, result);
                // Canonicalization and masking were done on GPU. This only
                // assembles the existing public field/extension representation.
                A::from_basis_coefficients_fn(|i| Val::new(words[i]))
            }
        }
    }
}

impl FieldChallenger<Val> for CandidateChallenger {
    fn sample_algebra_element<A: BasedVectorSpace<Val>>(&mut self) -> A {
        <Self as CanSample<A>>::sample(self)
    }
    fn observe_algebra_element<A: BasedVectorSpace<Val>>(&mut self, value: A) {
        self.observe_values(value.as_basis_coefficients_slice().iter().copied());
    }
    fn observe_algebra_slice<A: BasedVectorSpace<Val> + Clone>(&mut self, values: &[A]) {
        self.observe_values(
            values
                .iter()
                .flat_map(|value| value.as_basis_coefficients_slice().iter().copied()),
        );
    }
}

impl CanSampleBits<usize> for CandidateChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.sample_bits_vec(bits, 1)[0]
    }
}

impl GrindingChallenger for CandidateChallenger {
    type Witness = Val;
    fn grind(&mut self, bits: usize) -> Val {
        match &mut self.inner {
            Backend::Cpu(cpu) => cpu.grind(bits),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Gpu(gpu) => {
                let result = gpu.grind(bits);
                Val::new(checked(gpu, result))
            }
        }
    }
    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        if bits == 0 {
            // Preserve the upstream no-op and still reject a retired GPU family.
            let _ = self.grind(0);
            return true;
        }
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

#[cfg(test)]
mod tests;
