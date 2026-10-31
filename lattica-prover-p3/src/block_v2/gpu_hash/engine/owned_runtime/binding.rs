//! Opaque identity for the exact original lease allocation. Weak ownership
//! prevents allocation reuse while leaving exact-last-strong-owner retirement
//! unchanged. No raw epoch, clone or upgrade operation escapes this module.
use super::*;
use std::sync::Weak;

pub(crate) struct RuntimeBinding {
    epoch: Weak<JobLease>,
    selected_device: ocl::Device,
}

fn same_epoch_and_device<T, D: PartialEq>(
    first: &Weak<T>,
    first_device: &D,
    second: &Weak<T>,
    second_device: &D,
) -> bool {
    Weak::ptr_eq(first, second) && first_device == second_device
}

// Weak::weak_count is not informative after the final strong owner dies.
// Capture this only while the actual runtime is live, before retirement.
fn sole_live_binding<T>(epoch: &Weak<T>) -> bool {
    epoch.strong_count() != 0 && epoch.weak_count() == 1
}

impl RuntimeBinding {
    /// Charge this entire allocation independently wherever a binding may
    /// outlive the startup owner. Weak keeps ArcInner allocated after JobLease
    /// destruction; its inline header is counted separately by each owner.
    pub(crate) fn retained_allocation_bytes() -> usize {
        crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<JobLease>()
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        same_epoch_and_device(
            &self.epoch,
            &self.selected_device,
            &other.epoch,
            &other.selected_device,
        )
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.epoch.strong_count() == 0
    }

    /// No Clone/upgrade operation escapes this module. Runtime is thread
    /// bound, and its consuming retirement makes no call that issues another
    /// binding between this observation and destroying the last strong owner.
    pub(crate) fn is_sole_live_binding(&self) -> bool {
        sole_live_binding(&self.epoch)
    }
}

impl OwnedRuntime {
    pub(crate) fn bind_original(&self) -> Result<RuntimeBinding> {
        self.check_live()?;
        Ok(RuntimeBinding {
            epoch: Arc::downgrade(self.epoch.as_ref().ok_or("runtime already retired")?),
            selected_device: self.selected_device,
        })
    }
}

#[cfg(test)]
mod tests;
