//! Payload and original-claim retention while a concrete runtime is outstanding.
//! The private latch grants no dispatch or retirement authority. Only the
//! final issuers change it after real no-start refusal or sealed retirement.
use std::cell::Cell;

pub(in crate::execution::workflow_resources::runtime) struct RetirementGuard<'a, T> {
    held: Option<T>,
    required: &'a Cell<bool>,
}
impl<'a, T> RetirementGuard<'a, T> {
    pub(in crate::execution::workflow_resources::runtime) fn new(held: T, required: &'a Cell<bool>) -> Self {
        Self { held: Some(held), required }
    }
    pub(in crate::execution::workflow_resources::runtime) fn get(&self) -> &T {
        self.held.as_ref().expect("original final stage owner")
    }
    pub(in crate::execution::workflow_resources::runtime) fn get_mut(&mut self) -> &mut T {
        self.held.as_mut().expect("original final stage owner")
    }
    pub(in crate::execution::workflow_resources::runtime) fn into_retired(mut self)
        -> Result<T, super::FinalFailure>
    {
        if self.required.get() { return Err(super::FinalFailure::Runtime); }
        Ok(self.held.take().expect("retired final stage owner"))
    }
}
impl<T> Drop for RetirementGuard<'_, T> {
    fn drop(&mut self) {
        if self.required.get() {
            if let Some(held) = self.held.take() { core::mem::forget(held); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn final_input_and_raw_originals_survive_uncertain_retirement() {
        let ledger = Ledger::new(WorkerAllowance { host: 96, device: 0 });
        let input = ledger.reserve(Category::CompilerInputs, Bytes { host: 32, device: 0 }).unwrap();
        let raw = ledger.reserve(Category::PhaseScratch, Bytes { host: 64, device: 0 }).unwrap();
        let failed = catch_unwind(AssertUnwindSafe(|| {
            let required = Cell::new(false);
            let _input = RetirementGuard::new(input, &required);
            let _raw = RetirementGuard::new(raw, &required);
            required.set(true);
            panic!("injected final stage failure before retirement");
        }));
        assert!(failed.is_err());
        assert_eq!(ledger.snapshot().current, Bytes { host: 96, device: 0 });
        assert!(ledger.reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 }).is_err());
    }

    #[test]
    fn unstarted_final_owner_returns_its_same_original() {
        let ledger = Ledger::new(WorkerAllowance { host: 32, device: 0 });
        let original = ledger.reserve(Category::CompilerInputs, Bytes { host: 32, device: 0 }).unwrap();
        let required = Cell::new(false);
        let original = RetirementGuard::new(original, &required).into_retired().unwrap();
        assert!(original.belongs_to(&ledger));
        assert_eq!(ledger.snapshot().current.host, 32);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn produced_payload_survives_a_later_error_until_the_outer_retirement_gate() {
        struct Payload<'a>(&'a Cell<bool>);
        impl Drop for Payload<'_> { fn drop(&mut self) { self.0.set(true); } }
        let ledger = Ledger::new(WorkerAllowance { host: 32, device: 0 });
        let original = ledger.reserve(Category::NativeProof, Bytes { host: 32, device: 0 }).unwrap();
        let destroyed = Cell::new(false);
        let required = Cell::new(false);
        let claim = RetirementGuard::new(original, &required);
        let mut output = RetirementGuard::new(None, &required);
        required.set(true);
        let later_error: Result<(), ()> = (|| {
            *output.get_mut() = Some(Payload(&destroyed));
            Err(())
        })();
        assert!(later_error.is_err());
        assert!(!destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 32);
        // Guard-only state-machine test: no actual runtime/receipt is forged.
        required.set(false);
        drop(output.into_retired().unwrap());
        assert!(destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 32);
        drop(claim.into_retired().unwrap());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn uncertain_final_output_preserves_payload_and_unsplit_slot_original() {
        struct Payload<'a>(&'a Cell<bool>);
        impl Drop for Payload<'_> { fn drop(&mut self) { self.0.set(true); } }
        let ledger = Ledger::new(WorkerAllowance { host: 32, device: 0 });
        let original = ledger.reserve(Category::NativeProof, Bytes { host: 32, device: 0 }).unwrap();
        let destroyed = Cell::new(false);
        let required = Cell::new(true);
        let claim = RetirementGuard::new(original, &required);
        let output = RetirementGuard::new(Some(Payload(&destroyed)), &required);
        drop(output);
        drop(claim);
        assert!(!destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 32);
    }

    #[test]
    fn callback_output_survives_its_helpers_later_report_refusal() {
        struct Payload<'a>(&'a Cell<bool>);
        impl Drop for Payload<'_> { fn drop(&mut self) { self.0.set(true); } }
        // Models the callback/report ordering of native_gpu::with_operations;
        // this helper supplies no actual runtime or retirement evidence.
        fn callback_then_refuse_report(callback: impl FnOnce() -> Result<(), ()>) -> Result<(), ()> {
            callback()?;
            Err(())
        }
        let ledger = Ledger::new(WorkerAllowance { host: 32, device: 0 });
        let original = ledger.reserve(Category::CompilerInputs, Bytes { host: 32, device: 0 }).unwrap();
        let required = Cell::new(false);
        let destroyed = Cell::new(false);
        let claim = RetirementGuard::new(original, &required);
        let mut compiled = RetirementGuard::new(None, &required);
        required.set(true);
        let result = callback_then_refuse_report(|| {
            *compiled.get_mut() = Some(Payload(&destroyed));
            Ok(())
        });
        assert!(result.is_err());
        assert!(!destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 32);
        required.set(false);
        drop(compiled.into_retired().unwrap());
        assert!(destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 32);
        drop(claim.into_retired().unwrap());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
