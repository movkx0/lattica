//! The two protocol fields supported by the hiding PCS adapter.
//!
//! Field selection also pins the resident FRI parameters. In particular, adding
//! the legacy quadratic profile must not broaden candidate cubic admission.
use crate::config::Val;
use p3_field::{ExtensionField, TwoAdicField};

/// Extension bases implemented by the GPU arithmetic and public AIR bytecode.
/// This identity contains no runtime handles or backend-specific proof policy.
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub trait FriExtension: ExtensionField<Val> {
    const DEVICE_EXTENSION: crate::gpu_matrix::Extension;
}
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
impl FriExtension for crate::config::Challenge {
    const DEVICE_EXTENSION: crate::gpu_matrix::Extension = crate::gpu_matrix::Extension::Quadratic;
}
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
impl FriExtension for super::profile::Challenge {
    const DEVICE_EXTENSION: crate::gpu_matrix::Extension = crate::gpu_matrix::Extension::Cubic;
}

pub(crate) type ProvingConfig<E> =
    p3_uni_stark::StarkConfig<super::quotient_pcs::CandidatePcs<E>, E, super::profile::Challenger>;

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::config::Challenge {}
    impl Sealed for super::super::profile::Challenge {}
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub trait BackendField: super::opening_pcs::OpeningField {}
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
impl<T: super::opening_pcs::OpeningField> BackendField for T {}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
pub trait BackendField: ExtensionField<Val> {}
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
impl<T: ExtensionField<Val>> BackendField for T {}

/// Sealed to the pinned quadratic and cubic Goldilocks extension bases.
pub trait PcsField: ExtensionField<Val> + TwoAdicField + BackendField + sealed::Sealed {
    const MAX_LOG_ARITY: usize;
    const NUM_QUERIES: usize;
}

impl PcsField for crate::config::Challenge {
    const MAX_LOG_ARITY: usize = 4;
    const NUM_QUERIES: usize = crate::config::NUM_QUERIES;
}

impl PcsField for super::profile::Challenge {
    const MAX_LOG_ARITY: usize = 1;
    const NUM_QUERIES: usize = super::profile::NUM_QUERIES;
}
