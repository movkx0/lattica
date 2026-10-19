//! Public preprocessing recipes have independent per-consumer failure scopes;
//! private commitments retain the original shared retirement behavior.
use super::*;
use crate::cuda_compute::random::{PublicPreprocessingSalts, PublicReplaySalts};

pub(super) enum SaltSource<'a> {
    Private(&'a DeviceRandom),
    Public(&'a PublicPreprocessingSalts),
}

pub(super) enum RetainedSalts {
    Private(ReplaySalts),
    Public(PublicReplaySalts),
}

impl SaltSource<'_> {
    pub(super) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        match self {
            Self::Private(s) => s.check_runtime(runtime),
            Self::Public(s) => s.check_runtime(runtime),
        }
    }
    pub(super) fn family(&self) -> Option<DeviceRandom> {
        match self {
            Self::Private(s) => Some((*s).clone()),
            Self::Public(_) => None,
        }
    }
    pub(super) fn preflight(&self, specs: &[MatrixSpec], pending: &[usize]) -> Result<()> {
        match self {
            Self::Private(s) => s.preflight_salt_recipes(specs, pending),
            Self::Public(s) => s.preflight(specs, pending),
        }
    }
    pub(super) fn prepare(&self, specs: &[MatrixSpec]) -> Result<Vec<RetainedSalts>> {
        Ok(match self {
            Self::Private(s) => s
                .prepare_salt_replay_specs(specs)?
                .into_iter()
                .map(RetainedSalts::Private)
                .collect(),
            Self::Public(s) => s
                .prepare(specs)?
                .into_iter()
                .map(RetainedSalts::Public)
                .collect(),
        })
    }
}

impl RetainedSalts {
    pub(super) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        match self {
            Self::Private(s) => s.check_runtime(runtime),
            Self::Public(s) => s.check_runtime(runtime),
        }
    }
    pub(super) fn preflight(&self, pending: &[usize]) -> Result<()> {
        match self {
            Self::Private(s) => s.preflight(pending),
            Self::Public(s) => s.preflight(pending),
        }
    }
    pub(super) fn with_materialized<T>(
        &self,
        consume: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Private(s) => s.with_materialized(consume),
            Self::Public(s) => s.with_materialized(consume),
        }
    }
    pub(super) fn query_rows(&self, indices: &[u64], host_bytes: usize) -> Result<Vec<u64>> {
        match self {
            Self::Private(s) => s.query_rows(indices, host_bytes),
            Self::Public(s) => s.query_rows(indices, host_bytes),
        }
    }
}
