//! Allocation windows for one serial worker job, including cached allocations
//! live at its start. These are managed reservation counters, not physical VRAM
//! measurements, admission authority, or proof/worker completion receipts.
use super::{Accounting, ENGINE};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug)]
pub(super) struct WindowState {
    start_live_bytes: usize,
    start_allocations: u64,
    pub(super) peak_bytes: usize,
    pub(super) max_new_allocation_bytes: usize,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct MemoryUsage {
    pub start_live_bytes: usize,
    pub end_live_bytes: usize,
    pub peak_bytes: usize,
    pub cumulative_peak_bytes: usize,
    pub allocations: u64,
    pub max_new_allocation_bytes: usize,
    pub retained_tree_bytes: usize,
    pub retained_trees: usize,
    pub device_matrix_bytes: usize,
    pub device_matrices: usize,
    pub managed_limit_bytes: usize,
    pub allocation_limit_bytes: usize,
}

/// One window may be active per engine. Dropping an unfinished window clears
/// only its measurement state; allocation leases and lifetime peaks survive.
/// The accounting Arc also allows a shutdown window to observe final release
/// after the engine has been retired, without keeping device resources alive.
pub(crate) struct MemoryWindow {
    accounting: Arc<Mutex<Accounting>>,
    managed_limit_bytes: usize,
    allocation_limit_bytes: usize,
    armed: bool,
}

impl MemoryWindow {
    fn new(
        accounting: Arc<Mutex<Accounting>>,
        managed_limit_bytes: usize,
        allocation_limit_bytes: usize,
    ) -> Result<Self, String> {
        {
            let mut a = accounting.lock().map_err(|_| "GPU accounting poisoned")?;
            if a.memory_window.is_some() {
                return Err("GPU memory windows must not overlap".into());
            }
            a.memory_window = Some(WindowState {
                start_live_bytes: a.live,
                start_allocations: a.allocations,
                peak_bytes: a.live,
                max_new_allocation_bytes: 0,
            });
        }
        Ok(Self {
            accounting,
            managed_limit_bytes,
            allocation_limit_bytes,
            armed: true,
        })
    }

    /// The caller drains its work before reporting a successful boundary. No
    /// fence or counter reset is hidden here, and all transient reservations
    /// are counted even when they have already been released.
    pub(crate) fn finish(mut self) -> Result<MemoryUsage, String> {
        let mut a = self
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?;
        let window = a.memory_window.take().ok_or("GPU memory window missing")?;
        self.armed = false;
        Ok(MemoryUsage {
            start_live_bytes: window.start_live_bytes,
            end_live_bytes: a.live,
            peak_bytes: window.peak_bytes,
            cumulative_peak_bytes: a.peak,
            allocations: a.allocations - window.start_allocations,
            max_new_allocation_bytes: window.max_new_allocation_bytes,
            retained_tree_bytes: a.retained_live,
            retained_trees: a.retained_trees,
            device_matrix_bytes: a.device_live,
            device_matrices: a.device_buffers,
            managed_limit_bytes: self.managed_limit_bytes,
            allocation_limit_bytes: self.allocation_limit_bytes,
        })
    }
}

impl Drop for MemoryWindow {
    fn drop(&mut self) {
        if self.armed {
            // A poisoned allocator is already unusable. Do not double-panic
            // while unwinding, or touch its allocation/lease counters.
            if let Ok(mut a) = self.accounting.lock() {
                a.memory_window = None;
            }
        }
    }
}

pub(crate) fn begin_memory_window() -> Result<Option<MemoryWindow>, String> {
    let Some(engine) = ENGINE.get() else {
        return Ok(None);
    };
    let guard = engine.lock().map_err(|_| "GPU engine poisoned")?;
    guard
        .as_ref()
        .map(|e| MemoryWindow::new(e.accounting.clone(), e.limits.managed_bytes, e.max_alloc))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::super::reserve;
    use super::*;

    #[test]
    fn windows_include_retained_baselines_and_short_lived_peaks() {
        let a = Arc::new(Mutex::new(Accounting::default()));
        let mut cache = reserve(&a, 20, 100).unwrap();
        cache.mark_retained().unwrap();
        let first = MemoryWindow::new(a.clone(), 100, 80).unwrap();
        drop(reserve(&a, 70, 100).unwrap());
        let first = first.finish().unwrap();
        assert_eq!(
            (
                first.start_live_bytes,
                first.end_live_bytes,
                first.peak_bytes
            ),
            (20, 20, 90)
        );
        assert_eq!((first.allocations, first.max_new_allocation_bytes), (1, 70));
        assert_eq!((first.retained_tree_bytes, first.retained_trees), (20, 1));
        let second = MemoryWindow::new(a.clone(), 100, 80).unwrap();
        drop(reserve(&a, 10, 100).unwrap());
        let second = second.finish().unwrap();
        assert_eq!((second.peak_bytes, second.cumulative_peak_bytes), (30, 90));
        assert_eq!(
            (second.managed_limit_bytes, second.allocation_limit_bytes),
            (100, 80)
        );
        let shutdown = MemoryWindow::new(a.clone(), 100, 80).unwrap();
        drop(cache);
        let shutdown = shutdown.finish().unwrap();
        assert_eq!(
            (
                shutdown.start_live_bytes,
                shutdown.end_live_bytes,
                shutdown.peak_bytes
            ),
            (20, 0, 20)
        );
        assert_eq!(
            (shutdown.retained_tree_bytes, shutdown.retained_trees),
            (0, 0)
        );
        assert_eq!(shutdown.allocations, 0);
        assert_eq!(a.lock().unwrap().peak, 90);
    }

    #[test]
    fn overlapping_and_aborted_windows_preserve_leases_and_cumulative_counters() {
        let a = Arc::new(Mutex::new(Accounting::default()));
        let cache = reserve(&a, 20, 100).unwrap();
        let aborted = MemoryWindow::new(a.clone(), 100, 80).unwrap();
        assert!(MemoryWindow::new(a.clone(), 100, 80).is_err());
        drop(reserve(&a, 50, 100).unwrap());
        drop(aborted);
        let next = MemoryWindow::new(a.clone(), 100, 80)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(
            (next.start_live_bytes, next.end_live_bytes, next.peak_bytes),
            (20, 20, 20)
        );
        assert_eq!((next.allocations, next.cumulative_peak_bytes), (0, 70));
        drop(cache);
        assert_eq!(a.lock().unwrap().live, 0);
    }

    #[test]
    fn rejected_reservations_do_not_inflate_window_usage() {
        let a = Arc::new(Mutex::new(Accounting::default()));
        let cache = reserve(&a, 20, 100).unwrap();
        let window = MemoryWindow::new(a.clone(), 100, 80).unwrap();
        assert!(reserve(&a, 81, 100).is_err());
        assert!(reserve(&a, usize::MAX, 100).is_err());
        let report = window.finish().unwrap();
        assert_eq!((report.peak_bytes, report.cumulative_peak_bytes), (20, 20));
        assert_eq!(
            (report.allocations, report.max_new_allocation_bytes),
            (0, 0)
        );
        drop(cache);
    }
}
