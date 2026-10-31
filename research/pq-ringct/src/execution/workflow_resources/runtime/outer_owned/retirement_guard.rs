//! Keep compiled inputs and their originals pinned if retirement is uncertain.
//! This private guard grants no dispatch or retirement authority.
use std::cell::Cell;

pub(super) struct RetirementGuard<T> {
    payload: Option<T>,
    required: Cell<bool>,
}
impl<T> RetirementGuard<T> {
    pub(super) fn new(payload: T) -> Self {
        Self { payload: Some(payload), required: Cell::new(false) }
    }
    pub(super) fn get(&self) -> &T { self.payload.as_ref().expect("owned outer operation") }
    pub(super) fn required(&self) -> &Cell<bool> { &self.required }
}
impl<T> Drop for RetirementGuard<T> {
    fn drop(&mut self) {
        if self.required.get() {
            // No actual retirement receipt: retain the payload AND its original
            // claims, including on unwinding. The workflow's pool is poisoned.
            if let Some(payload) = self.payload.take() { core::mem::forget(payload); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn original_input_survives_unwind_without_an_actual_retirement_receipt() {
        let ledger = Ledger::new(WorkerAllowance { host: 16, device: 0 });
        let original = ledger.reserve(Category::CompilerInputs, Bytes { host: 16, device: 0 }).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let input = RetirementGuard::new(original);
            input.required().set(true);
            panic!("injected failure after runtime start");
        }));
        assert!(result.is_err());
        assert_eq!(ledger.snapshot().current, Bytes { host: 16, device: 0 });
        assert!(ledger.reserve(Category::CompilerInputs, Bytes { host: 1, device: 0 }).is_err());
    }

    #[test]
    fn original_is_released_after_retirement_or_before_runtime_start() {
        let ledger = Ledger::new(WorkerAllowance { host: 16, device: 0 });
        for started in [false, true] {
            let original = ledger.reserve(Category::CompilerInputs, Bytes { host: 16, device: 0 }).unwrap();
            let input = RetirementGuard::new(original);
            input.required().set(started);
            if started { input.required().set(false); }
            drop(input);
            assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        }
    }
}
