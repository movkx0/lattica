//! Internal source-fixed selection. These values cannot be supplied through
//! public numeric budgets, environment fallback or a detached proof receipt.
use super::*;
use crate::block_v2::gpu_hash::{
    device::{ringct_runtime::Footprint, AesSourceDeviceCensus},
    engine::retained_storage::RetainedTreeStorageMode,
};

const HOST_TREES: usize = 8 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TreeProfile {
    Device,
    OuterHostV1,
}

fn original_token(expected: Footprint, token: &Reservation, ledger: &Ledger) -> Result<usize> {
    let claimed = only(token, Category::PhaseScratch, ledger)?;
    if expected.driver_context_reserve as u64 != CONTEXT_DEVICE
        || claimed.host < expected.requested_host_bytes as u64
        || claimed.device != expected.managed_device_bytes as u64
    {
        return Err(Error::Authority);
    }
    Ok(expected.managed_device_bytes)
}

impl TreeProfile {
    pub(super) fn phase_wrapper_host_bytes(self) -> Result<usize> {
        wrapper_host_bytes()?
            .checked_add(self.additional_wrapper_host_bytes()?)
            .ok_or(Error::Admission)
    }

    pub(super) fn additional_wrapper_host_bytes(self) -> Result<usize> {
        match self {
            Self::Device => Ok(0),
            Self::OuterHostV1 => {
                AesSourceDeviceCensus::host_transfer_wrapper_bytes().map_err(|_| Error::Admission)
            }
        }
    }

    fn startup(self) -> Result<StartupPlan> {
        match self {
            Self::Device => StartupPlan::new(),
            Self::OuterHostV1 => StartupPlan::outer_host_v1(),
        }
        .map_err(|_| Error::Runtime)
    }

    pub(super) fn check_startup(self, token: &Reservation, ledger: &Ledger) -> Result<usize> {
        let expected = self.startup()?.footprint();
        self.check_source(expected)?;
        original_token(expected, token, ledger)
    }

    fn check_source(self, source: Footprint) -> Result<()> {
        let valid = match self {
            Self::Device => {
                source.retained_tree_host_bytes == 0
                    && source.retained_tree_quota_wrapper_bytes == 0
            }
            Self::OuterHostV1 => {
                source.retained_tree_host_bytes == HOST_TREES
                    && source.retained_tree_quota_wrapper_bytes > 0
            }
        };
        if !valid {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub(super) fn check_runtime(
        self,
        runtime: &Runtime,
        token: &Reservation,
        ledger: &Ledger,
    ) -> Result<usize> {
        let expected = self.startup()?.footprint();
        self.check_source(expected)?;
        // The concrete runtime includes the exact source-built HostQuota Arc
        // charge and source fingerprint. The later same-lock capacity check
        // additionally binds its original epoch/device and actual tree quota.
        if runtime.footprint() != expected {
            return Err(Error::Runtime);
        }
        original_token(expected, token, ledger)
    }

    fn check_graph(
        self,
        mode: RetainedTreeStorageMode,
        quota: usize,
        complete_graph: usize,
    ) -> Result<()> {
        let valid = match self {
            Self::Device => {
                mode == RetainedTreeStorageMode::Device && quota == 0 && complete_graph == 0
            }
            Self::OuterHostV1 => {
                mode == RetainedTreeStorageMode::HostBacking
                    && quota == HOST_TREES
                    && complete_graph > 0
                    && complete_graph <= quota
            }
        };
        if !valid {
            return Err(Error::Admission);
        }
        Ok(())
    }

    pub(super) fn check_plan(self, footprint: NativeAesPcsFootprint) -> Result<()> {
        self.check_graph(
            footprint.retained_tree_storage_mode,
            footprint.selected_tree_host_quota_bytes,
            footprint.required_tree_host_bytes,
        )
    }
}
