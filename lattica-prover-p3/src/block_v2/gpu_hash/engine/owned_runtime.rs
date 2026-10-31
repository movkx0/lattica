//! A fresh engine epoch returned while INITIALIZE is still held. The enclosing
//! guarded worker retains its real host reservation and immutable environment
//! owner after this field. This owner is neither quota nor dispatch authority.
//! It retires the exact global Engine after all session/capacity/helper owners.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info"
))]
use super::*;
use crate::gpu_device::process_memory;

type Result<T> = core::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Retirement {
    pub(crate) managed_live_bytes: usize,
    /// Peak of this exact Engine's managed allocations. Excludes opaque
    /// context/driver/process storage and is not a sampled VRAM measurement.
    pub(crate) managed_peak_bytes: usize,
    pub(crate) host_tree_live_bytes: usize,
    pub(crate) lease_released: bool,
}

/// Only the source-owned explicit initializer constructs this extra epoch
/// alias, before publishing the Engine and releasing INITIALIZE. Ordinary
/// shutdown sees the alias and refuses to retire this runtime prematurely.
/// No Clone or epoch extraction is provided.
pub(crate) struct OwnedRuntime {
    epoch: Option<Arc<JobLease>>,
    // Exact selected handle used to initialize this epoch. Never queried from
    // ProQue under a capacity lock: Queue::device would allocate a driver reply.
    selected_device: ocl::Device,
    _thread_bound: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl OwnedRuntime {
    pub(super) fn new(epoch: Arc<JobLease>, selected_device: ocl::Device) -> Self {
        Self {
            epoch: Some(epoch),
            selected_device,
            _thread_bound: core::marker::PhantomData,
        }
    }

    /// Recheck the exact runtime before a new operation. Active configuration,
    /// session and capacity owners may still borrow this epoch; retirement
    /// separately requires that every such owner has already been dropped.
    pub(crate) fn check_live(&self) -> Result<()> {
        let epoch = self.epoch.as_ref().ok_or("runtime already retired")?;
        let _initialize = INITIALIZE
            .lock()
            .map_err(|_| "GPU initialization poisoned")?;
        let slot = ENGINE.get().ok_or("owned runtime engine missing")?;
        let slot = slot.lock().map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_ref().ok_or("owned runtime engine missing")?;
        exact_epoch(epoch, &engine._job_lease)
    }

    /// Caller already owns the Engine lock. Never re-lock INITIALIZE/ENGINE or
    /// inspect the driver here; capacity admission uses this exact live epoch.
    pub(super) fn check_engine(&self, engine: &Engine) -> Result<()> {
        let epoch = self.epoch.as_ref().ok_or("runtime already retired")?;
        exact_epoch(epoch, &engine._job_lease)
    }

    pub(super) fn selected_device(&self) -> ocl::Device {
        self.selected_device
    }

    /// Synchronize both GPU queues and sample this process while the exact
    /// engine remains locked. The sampler kills/waits its helper on every exit;
    /// no Child or output buffer can outlive this call and its enclosing quota.
    /// Report formatting/storage belongs to the caller, which receives an
    /// inline observation rather than an allocation-backed diagnostics object.
    pub(crate) fn checkpoint(&self, uuid: &str) -> Result<process_memory::Checkpoint> {
        let epoch = self.epoch.as_ref().ok_or("runtime already retired")?;
        let _initialize = INITIALIZE
            .lock()
            .map_err(|_| "GPU initialization poisoned")?;
        let slot = ENGINE.get().ok_or("owned runtime engine missing")?;
        let mut slot = slot.lock().map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_mut().ok_or("owned runtime engine missing")?;
        exact_epoch(epoch, &engine._job_lease)?;
        engine
            .fence()
            .finish()
            .map_err(|_| "owned runtime drain failed")?;
        engine
            .resolve_timing()
            .map_err(|_| "owned runtime timing failed")?;
        let live = engine
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live;
        let observation = process_memory::sample(uuid, std::process::id())
            .map_err(|_| "owned runtime process observation failed")?;
        observation
            .checkpoint(live, engine.limits.managed_bytes, DRIVER_RESERVE_BYTES)
            .map_err(|_| "owned runtime process envelope rejected")
    }

    fn try_retire(&mut self) -> Result<Retirement> {
        let epoch = self.epoch.as_ref().ok_or("runtime already retired")?;
        let _initialize = INITIALIZE
            .lock()
            .map_err(|_| "GPU initialization poisoned")?;
        let slot = ENGINE.get().ok_or("owned runtime engine missing")?;
        let mut slot = slot.lock().map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_mut().ok_or("owned runtime engine missing")?;
        exact_last_owner(epoch, &engine._job_lease)?;
        // No aliases can appear through a new DeviceSession while ENGINE is
        // locked. All existing sessions/trees/capacity leases were rejected by
        // the exact count above. Runtime exclusivity stays held throughout.
        engine
            .fence()
            .finish()
            .map_err(|_| "owned runtime drain failed")?;
        engine
            .resolve_timing()
            .map_err(|_| "owned runtime timing failed")?;
        let accounting = Arc::clone(&engine.accounting);
        let tree_storage = Arc::clone(&engine.tree_storage);
        let engine = slot.take().ok_or("owned runtime engine missing")?;
        drop(engine);
        let (managed_live_bytes, managed_peak_bytes) = {
            let accounting = accounting.lock().map_err(|_| "GPU accounting poisoned")?;
            (accounting.live, accounting.peak)
        };
        let host_tree_live_bytes = tree_storage.live();
        if managed_live_bytes != 0 || host_tree_live_bytes != 0 {
            return Err("owned runtime allocations survived retirement");
        }
        // Drop the observation aliases before releasing the job lease. If any
        // fallible check above failed, epoch remains Some and the guarded worker
        // must abort while its enclosing quota token is still alive.
        drop(tree_storage);
        drop(accounting);
        drop(self.epoch.take());
        Ok(Retirement {
            managed_live_bytes,
            managed_peak_bytes,
            host_tree_live_bytes,
            lease_released: true,
        })
    }

    /// A completion receipt is available only after checked terminal cleanup.
    /// Uncertain cleanup cannot return an error that lets the enclosing quota
    /// release while the original engine/helper may still be alive.
    pub(crate) fn retire(&mut self) -> Retirement {
        match self.try_retire() {
            Ok(retirement) => retirement,
            Err(_) => std::process::abort(),
        }
    }

    pub(crate) fn finish(mut self) -> Retirement {
        self.retire()
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if self.epoch.is_some() && self.try_retire().is_err() {
            std::process::abort();
        }
    }
}

fn exact_epoch<T>(owner: &Arc<T>, engine: &Arc<T>) -> Result<()> {
    if !Arc::ptr_eq(owner, engine) {
        return Err("owned runtime epoch changed");
    }
    Ok(())
}

fn exact_last_owner<T>(owner: &Arc<T>, engine: &Arc<T>) -> Result<()> {
    exact_epoch(owner, engine)?;
    if Arc::strong_count(engine) != 2 {
        return Err("owned runtime sessions or capacity owners remain live");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_epoch_check_refuses_replacement_even_when_alias_counts_match() {
        let original = Arc::new(());
        let owner = Arc::clone(&original);
        let replacement = Arc::new(());
        let replacement_owner = Arc::clone(&replacement);
        assert!(exact_last_owner(&owner, &replacement).is_err());
        exact_last_owner(&owner, &original).unwrap();
        exact_last_owner(&replacement_owner, &replacement).unwrap();
    }

    #[test]
    fn terminal_epoch_check_waits_for_every_session_and_capacity_alias() {
        let engine = Arc::new(());
        let owner = Arc::clone(&engine);
        let session = Arc::clone(&engine);
        let capacity = Arc::clone(&engine);
        assert!(exact_last_owner(&owner, &engine).is_err());
        drop(session);
        assert!(exact_last_owner(&owner, &engine).is_err());
        drop(capacity);
        exact_last_owner(&owner, &engine).unwrap();
    }
}

#[cfg(feature = "ringct-research-quota")]
mod binding;
#[cfg(feature = "ringct-research-quota")]
pub(crate) use binding::RuntimeBinding;
