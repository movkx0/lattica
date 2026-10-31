//! Pins original generation claims until the real terminal authenticates cleanup.
use crate::execution::{generation_terminal::NativeGenerationTerminal, retained_resources::Ledger};

pub(super) struct GenerationRetirementGuard<T> {
    held: Option<T>,
    started: bool,
}
impl<T> GenerationRetirementGuard<T> {
    pub(super) fn new(held: T) -> Self { Self { held: Some(held), started: false } }
    pub(super) fn get(&self) -> &T { self.held.as_ref().expect("owned generation frame") }
    pub(super) fn get_mut(&mut self) -> &mut T { self.held.as_mut().expect("owned generation frame") }
    pub(super) fn started(&mut self) { self.started = true; }
    pub(super) fn after_retirement(mut self, terminal: &NativeGenerationTerminal,
        ledger: &Ledger, expected: usize) -> Result<T, &'static str>
    {
        if !self.started || !terminal.belongs_to(ledger) || terminal.spend_count() != expected {
            return Err("generation retirement receipt does not match original owners");
        }
        self.started = false;
        Ok(self.held.take().expect("retired generation frame"))
    }
}
impl<T> Drop for GenerationRetirementGuard<T> {
    fn drop(&mut self) {
        if self.started {
            if let Some(held) = self.held.take() { core::mem::forget(held); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Bytes, Category, WorkerAllowance};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    #[test]
    fn generation_failure_keeps_original_claims_across_unwind() {
        let ledger = Ledger::new(WorkerAllowance { host: 64, device: 0 });
        let original = ledger.reserve(Category::NativeProof, Bytes { host: 64, device: 0 }).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut guard = GenerationRetirementGuard::new(original);
            guard.started();
            panic!("injected generation failure without authenticated retirement");
        }));
        assert!(result.is_err());
        assert_eq!(ledger.snapshot().current.host, 64);
        assert!(ledger.reserve(Category::NativeProof, Bytes { host: 1, device: 0 }).is_err());
    }
    #[test]
    fn undispatched_generation_frame_releases_without_fabricated_receipt() {
        let ledger = Ledger::new(WorkerAllowance { host: 64, device: 0 });
        let original = ledger.reserve(Category::NativeProof, Bytes { host: 64, device: 0 }).unwrap();
        drop(GenerationRetirementGuard::new(original));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
