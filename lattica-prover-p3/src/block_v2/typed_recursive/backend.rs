//! Session-local backend selection. Devices and prepared programs remain local;
//! requests, registries, statements and proof artifacts keep their existing types.
use super::*;
use crate::proving::{Report, Run};

#[cfg(feature = "gpu-cuda")]
mod cuda;
#[cfg(feature = "gpu-cuda")]
pub(crate) use cuda::Limits as CudaLimits;

#[derive(Clone, Default)]
pub(super) enum Backend {
    #[default]
    Existing,
    #[cfg(feature = "gpu-cuda")]
    Cuda(std::sync::Arc<cuda::Context>),
}

pub(super) enum Prepared {
    Existing(RegistryProgram),
    #[cfg(feature = "gpu-cuda")]
    Cuda(cuda::Prepared),
}

impl Backend {
    pub(super) fn request<T>(
        &self,
        entry: &'static str,
        body: impl FnOnce(&Run) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match self {
            Self::Existing => super::super::statements::request(entry, body),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => context.request(entry, body),
        }
    }

    pub(super) fn derive<T>(
        &self,
        request: &Run,
        id: &'static str,
        body: impl FnOnce(&mut super::super::statements::Derivation<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match self {
            Self::Existing => super::super::statements::derive_in(request, id, body),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => {
                super::super::statements::derive_cuda_in(&context.public, request, id, body)
            }
        }
    }

    pub(super) fn compile_reported<T>(
        &self,
        request: &Run,
        height: usize,
        keys: usize,
        body: impl FnOnce(&programs::RegistryPrefix) -> Result<T, Error>,
    ) -> Result<(T, Report), Error> {
        match self {
            Self::Existing => {
                super::super::statements::compile_in_reported(request, height, keys, body)
            }
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => super::super::statements::compile_cuda_in_reported(
                &context.public,
                request,
                height,
                keys,
                body,
            ),
        }
    }

    pub(super) fn prepare(
        &self,
        air: MachineAir,
        budget: u64,
        request: &Run,
        cap: &[[Val; 4]],
    ) -> Result<Prepared, Error> {
        match self {
            Self::Existing => Ok(Prepared::Existing(
                RegistryProgram::new_in_run(
                    air,
                    budget,
                    request.child(
                        "preprocessing",
                        "block_v2_preprocessing",
                        profile::preprocessing_capabilities(),
                    )?,
                    cap,
                )
                .map_err(|e| format!("{e:?}"))?,
            )),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => Ok(Prepared::Cuda(context.prepare(air, budget, request, cap)?)),
        }
    }

    pub(super) fn input_values(&self) -> Option<u64> {
        match self {
            Self::Existing => None,
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => Some(context.limits.construction.input_values as u64),
        }
    }

    pub(super) fn admit_compilation(
        &self,
        budget: u64,
        retained_sources: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Existing => Ok(()),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(context) => context.admit_compilation(budget, retained_sources),
        }
    }
}

impl Prepared {
    pub(super) fn retained_source_bytes(&self) -> usize {
        match self {
            Self::Existing(_) => 0, // Existing worker accounting is unchanged.
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(p) => p.source_host_bytes,
        }
    }

    pub(super) fn air(&self) -> &MachineAir {
        match self {
            Self::Existing(p) => p.air(),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(p) => &p.air,
        }
    }

    pub(super) fn preprocessing_matches(&self, cap: &[[Val; 4]]) -> Result<bool, Error> {
        Ok(match self {
            Self::Existing(p) => p.preprocessing_cap().roots() == cap,
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(p) => p.machine.preprocessing_cap()?.roots() == cap,
        })
    }

    pub(super) fn reuse_preprocessing(&self, request: &Run) -> Result<(), Error> {
        match self {
            Self::Existing(p) => Ok(p.reuse_preprocessing(request)?),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(p) => Ok(p.machine.reuse_preprocessing(request)?),
        }
    }

    pub(super) fn prove(
        &self,
        public: &[Val],
        witness: &[Val],
        request: &Run,
    ) -> Result<p3_batch_stark::BatchProof<profile::Config>, Error> {
        match self {
            Self::Existing(p) => Ok(p
                .prove_in_run(
                    public,
                    witness,
                    request.child(
                        "proof",
                        "block_v2_registered_program",
                        profile::registered_proof_capabilities(),
                    )?,
                )
                .map_err(|e| format!("{e:?}"))?),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda(p) => p.prove(public, witness, request),
        }
    }
}
