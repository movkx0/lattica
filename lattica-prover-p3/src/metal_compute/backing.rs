//! Allocation-free accounting shared by Metal and the large host allocator.
//! Small runtime allocations and driver memory remain inside the RSS headroom.
//! Resident worker estimates inform scheduling, never allocation admission.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static ACTIVE: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn activate() {
    ACTIVE.store(true, Ordering::SeqCst);
}
pub(crate) struct Ticket(usize);
pub(crate) fn charge(bytes: usize) -> Option<Ticket> {
    if !ACTIVE.load(Ordering::SeqCst) {
        return Some(Ticket(0));
    }
    let prior = LIVE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(bytes))
        .ok()?;
    PEAK.fetch_max(prior + bytes, Ordering::Relaxed);
    Some(Ticket(bytes))
}
impl Ticket {
    pub(crate) fn into_raw(mut self) -> usize {
        let n = self.0;
        self.0 = 0;
        n
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        release(self.0);
    }
}
pub(crate) fn release(bytes: usize) {
    if bytes != 0 {
        LIVE.fetch_sub(bytes, Ordering::SeqCst);
    }
}
pub(crate) fn snapshot() -> (usize, usize) {
    (LIVE.load(Ordering::SeqCst), PEAK.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "process-global accounting; run in its own process"]
    fn backing_tracks_above_estimate_and_rejects_only_overflow() {
        super::activate();
        let ticket = super::charge(17usize << 30).unwrap();
        let extra = super::charge(192 << 20).unwrap();
        assert_eq!(
            super::snapshot(),
            ((17usize << 30) + (192 << 20), (17usize << 30) + (192 << 20))
        );
        assert!(super::charge(usize::MAX).is_none());
        drop(ticket);
        drop(extra);
        assert_eq!(super::snapshot().0, 0);
        assert!(super::charge(32).is_some());
    }
}
