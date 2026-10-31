//! One-way per-session selection of the existing quotient interpreter. This
//! policy owns no GPU authority or host quota. Ordinary sessions retain the
//! existing automatic specialization behavior; the fixed note path pins this
//! state before any quotient preparation and checks it through the same lease.
use std::sync::atomic::{AtomicU8, Ordering};

const INTERPRETER: u8 = 1;
const PREPARATION_STARTED: u8 = 2;

#[derive(Default)]
pub(super) struct Policy(AtomicU8);

/// Source-built before Context/Program construction. The same non-cloneable
/// owner moves from NoteDevicePlan into its lease; only then may it bind the
/// newly created proof Session. This closes precontext census ordering without
/// accepting a caller-created policy flag or requiring a premature Context.
pub(crate) struct NoteQuotientPlan {
    policy: Policy,
}

impl NoteQuotientPlan {
    pub(crate) fn new() -> Self {
        Self {
            policy: Policy(AtomicU8::new(INTERPRETER)),
        }
    }

    pub(crate) fn source_specialization_allowed(&self) -> bool {
        !self.policy.interpreter_is_pinned()
    }

    pub(crate) fn bind_session(&self, session: &super::DeviceSession) -> Result<(), &'static str> {
        if self.source_specialization_allowed() {
            return Err("note quotient plan is not pinned");
        }
        session.pin_note_quotient_interpreter()
    }

    pub(crate) fn check_session(&self, session: &super::DeviceSession) -> bool {
        !self.source_specialization_allowed() && session.note_quotient_interpreter_is_pinned()
    }
}

impl Policy {
    /// Pin only a fresh session. Once any preparation starts, changing policy
    /// would not retire an already compiled specialized program and is refused.
    fn pin_interpreter(&self) -> Result<(), &'static str> {
        self.0
            .compare_exchange(0, INTERPRETER, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "quotient interpreter must be pinned once before preparation")
    }

    pub(super) fn interpreter_is_pinned(&self) -> bool {
        self.0.load(Ordering::Acquire) & INTERPRETER != 0
    }

    /// Mark before calling the optional compiler, not after its first
    /// allocation. Cloned sessions share this exact AtomicU8 via Session's Arc.
    pub(super) fn begin_preparation(&self) -> bool {
        self.0.fetch_or(PREPARATION_STARTED, Ordering::AcqRel) & INTERPRETER == 0
    }
}

impl super::DeviceSession {
    pub(crate) fn pin_note_quotient_interpreter(&self) -> Result<(), &'static str> {
        self.session.quotient_policy.pin_interpreter()
    }

    pub(crate) fn note_quotient_interpreter_is_pinned(&self) -> bool {
        self.session.quotient_policy.interpreter_is_pinned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn ordinary_sessions_keep_specialization_and_refuse_late_note_selection() {
        let policy = Policy::default();
        assert!(!policy.interpreter_is_pinned());
        assert!(policy.begin_preparation());
        assert!(policy.pin_interpreter().is_err());
        assert!(policy.begin_preparation());
        assert!(!policy.interpreter_is_pinned());
    }

    #[test]
    fn note_pin_prevents_every_specialization_attempt_and_cannot_be_reset() {
        let policy = Policy::default();
        policy.pin_interpreter().unwrap();
        assert!(policy.interpreter_is_pinned());
        assert!(policy.pin_interpreter().is_err());
        for _ in 0..3 {
            assert!(!policy.begin_preparation());
            assert!(policy.interpreter_is_pinned());
        }
    }

    #[test]
    fn concurrent_pin_and_prepare_have_one_consistent_shared_selection() {
        let policy = Arc::new(Policy::default());
        let barrier = Arc::new(Barrier::new(2));
        let thread_policy = Arc::clone(&policy);
        let thread_barrier = Arc::clone(&barrier);
        let preparation = std::thread::spawn(move || {
            thread_barrier.wait();
            thread_policy.begin_preparation()
        });
        barrier.wait();
        let pinned = policy.pin_interpreter().is_ok();
        let specialization = preparation.join().unwrap();
        assert_eq!(specialization, !pinned);
        assert_eq!(policy.interpreter_is_pinned(), pinned);
        assert_eq!(policy.begin_preparation(), specialization);
        assert!(policy.pin_interpreter().is_err());
    }
}
