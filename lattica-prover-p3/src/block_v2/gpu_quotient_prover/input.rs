//! Explicit main-trace inputs. Device traces are consumed by the main
//! commitment; downstream stages recover rows from retained GPU prefixes.
use super::*;
use crate::block_v2::gpu_hash::device::{DeviceMatrix, DeviceSession, Extension, RowOrder};

pub(crate) struct ProvingInstance<'a, SC: SGC, A> {
    pub(super) metadata: InstanceMetadata<'a, SC, A>,
    pub(super) trace: TraceInput<'a, Val<SC>>,
}

pub(super) struct InstanceMetadata<'a, SC: SGC, A> {
    pub(super) air: &'a A,
    pub(super) public_values: &'a [Val<SC>],
}

pub(super) enum TraceInput<'a, F> {
    Host(&'a RowMajorMatrix<F>),
    Device(DeviceMatrix),
}

impl<'a, SC: SGC, A> ProvingInstance<'a, SC, A> {
    pub(crate) fn from_host(instance: &'a StarkInstance<'_, SC, A>) -> Self {
        Self {
            metadata: InstanceMetadata {
                air: instance.air,
                public_values: &instance.public_values,
            },
            trace: TraceInput::Host(instance.trace),
        }
    }

    /// Ownership crosses the prover boundary: no host trace or placeholder
    /// matrix is required, and the input allocation can end after commitment.
    pub(crate) fn from_device(
        air: &'a A,
        trace: DeviceMatrix,
        public_values: &'a [Val<SC>],
    ) -> Self {
        Self {
            metadata: InstanceMetadata { air, public_values },
            trace: TraceInput::Device(trace),
        }
    }
}

impl<'a, F: Clone + Send + Sync> TraceInput<'a, F> {
    pub(super) fn height(&self) -> usize {
        match self {
            Self::Host(matrix) => matrix.height(),
            Self::Device(matrix) => matrix.spec().rows(),
        }
    }

    pub(super) fn host(&self) -> Option<&'a RowMajorMatrix<F>> {
        match self {
            Self::Host(matrix) => Some(matrix),
            Self::Device(_) => None,
        }
    }

    pub(super) fn validate_device(
        &self,
        session: &DeviceSession,
        width: usize,
    ) -> Result<(), String> {
        let Self::Device(matrix) = self else {
            return Err("mixed host/device main traces are not supported".into());
        };
        session.alias_private(matrix)?;
        let spec = matrix.spec();
        if spec.extension() != Extension::Base
            || spec.order() != RowOrder::Natural
            || spec.shift() != 1
            || spec.columns() != width
        {
            return Err("device main trace does not match its AIR layout".into());
        }
        super::super::gpu_hash::device::TraceCommitShape::new(
            spec,
            super::super::profile::NUM_RANDOM_CODEWORDS,
        )?;
        Ok(())
    }
}
