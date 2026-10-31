//! Sealed retirement of an actual Runtime under its original startup owner.
//! The marker and original reservation cannot be independently extracted.
use super::*;
use crate::block_v2::gpu_hash::engine::owned_runtime::RuntimeBinding;
use crate::ringct_research_quota::{Category, Ledger, Requirements, Reservation};

/// The exact engine is already retired and its Runtime/Selection destroyed.
/// Binding backing remains charged by the actual startup reservation last.
/// No public constructor, marker clone or raw-token extraction is available.
#[must_use = "retain this original owner through matching native phase extraction"]
pub struct RetiredRuntime {
    binding: RuntimeBinding,
    footprint: Footprint,
    receipt: Retirement,
    sole_binding_at_retirement: bool,
    original: Reservation,
}

impl RetiredRuntime {
    pub fn receipt(&self) -> Retirement {
        self.receipt
    }

    pub(crate) fn matches(&self, binding: &RuntimeBinding) -> bool {
        self.binding.same_original(binding)
            && self.binding.is_retired()
            && self.receipt.managed_live_bytes == 0
            && self.receipt.host_tree_live_bytes == 0
            && self.receipt.lease_released
    }

    pub(crate) fn footprint(&self) -> Footprint {
        self.footprint
    }

    pub(crate) fn original(&self) -> &Reservation {
        &self.original
    }

    /// Only a core consumer that has destroyed its matching phase binding
    /// calls this. The marker dies before the actual original token escapes.
    pub(crate) fn into_original(self) -> Reservation {
        let Self {
            binding,
            footprint: _,
            receipt: _,
            sole_binding_at_retirement: _,
            original,
        } = self;
        drop(binding);
        original
    }
}

pub(super) fn additional_host_bytes() -> usize {
    // Include success/refusal paths and moved/final headers independently.
    // Arc control-block backing is retained after its last strong owner dies.
    2 * size_of::<RetiredRuntime>()
        + 2 * size_of::<RuntimeBinding>()
        + 2 * size_of::<core::result::Result<RetiredRuntime, (Error, Runtime, Reservation)>>()
        + size_of::<Requirements>()
        + size_of::<Ledger>()
        + RuntimeBinding::retained_allocation_bytes()
        + outer_startup::additional_host_bytes()
}

impl Runtime {
    pub(crate) fn bind_original(&self) -> Result<RuntimeBinding, Error> {
        self.epoch.bind_original().map_err(|_| Error::Lifecycle)
    }

    /// Retire this actual runtime, destroy all selection/environment storage,
    /// then issue an opaque marker bundled with the actual startup claim.
    /// Numerical receipts are not accepted as ownership or identity.
    ///
    /// # Safety
    /// `original` must be the exact reservation that has backed this Runtime
    /// since its source-closed Session startup, in the supplied ledger. The
    /// immutable process/exclusive-device contract lasts through this call.
    /// The research Session moves its private original field, never a receipt.
    pub unsafe fn retire_with_original(
        mut self,
        original: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<RetiredRuntime, (Error, Self, Reservation)> {
        let footprint = self.footprint();
        let bytes = original.requirements().get(Category::PhaseScratch);
        if !original.belongs_to(ledger)
            || original.requirements() != Requirements::single(Category::PhaseScratch, bytes)
            || bytes.host < footprint.requested_host_bytes as u64
            || bytes.device != footprint.managed_device_bytes as u64
        {
            return Err((Error::Resource, self, original));
        }
        let binding = match self.bind_original() {
            Ok(binding) => binding,
            Err(error) => return Err((error, self, original)),
        };
        // This fact must be captured before the final strong owner dies.
        // Native extraction still matches its own separate phase binding;
        // the outer-only bridge refuses that path even if it is later dropped.
        let sole_binding_at_retirement = binding.is_sole_live_binding();
        // Existing retirement checks the actual last two strong owners,
        // drains both queues and aborts on uncertain cleanup. Weak adds none.
        let receipt = self.retire();
        if receipt.managed_live_bytes != 0
            || receipt.host_tree_live_bytes != 0
            || !receipt.lease_released
        {
            std::process::abort();
        }
        drop(self);
        if !binding.is_retired() {
            std::process::abort();
        }
        Ok(RetiredRuntime {
            binding,
            footprint,
            receipt,
            sole_binding_at_retirement,
            original,
        })
    }
}

mod outer_startup;
