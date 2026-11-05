//! Opaque identity for the exact original lease allocation. Weak ownership
//! prevents allocation reuse while leaving exact-last-strong-owner retirement
//! unchanged. No raw epoch, clone or upgrade operation escapes this module.
use super::*;
use std::sync::Weak;

pub(crate) struct RuntimeBinding {
    epoch: Weak<JobLease>,
    bindings: Weak<()>,
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
fn sole_live_binding<T>(epoch: &Weak<T>, bindings: &Weak<()>) -> bool {
    epoch.strong_count() != 0 && bindings.strong_count() != 0 && bindings.weak_count() == 1
}

impl RuntimeBinding {
    /// Charge both allocations independently wherever a binding may outlive
    /// the startup owner. Weak retains the lease and binding-marker backing
    /// after their strong owners die; inline headers are charged separately.
    pub(crate) fn retained_allocation_bytes() -> usize {
        crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<JobLease>()
            + OwnedRuntime::binding_allocation_bytes()
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.bindings, &other.bindings)
            && same_epoch_and_device(
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
        sole_live_binding(&self.epoch, &self.bindings)
    }
}

impl OwnedRuntime {
    pub(crate) fn bind_original(&self) -> Result<RuntimeBinding> {
        self.check_live()?;
        Ok(RuntimeBinding {
            epoch: Arc::downgrade(self.epoch.as_ref().ok_or("runtime already retired")?),
            bindings: Arc::downgrade(&self.binding_owner),
            selected_device: self.selected_device,
        })
    }
}

#[cfg(test)]
mod tests;
