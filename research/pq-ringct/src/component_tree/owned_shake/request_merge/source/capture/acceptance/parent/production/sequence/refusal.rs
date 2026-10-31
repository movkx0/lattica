//! Closed, ordinary returned-error seams. No callbacks, fabricated proofs,
//! detached continuations, asynchronous-fault or unwind qualification.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Probe {
    AfterPreissue,
    BeforeFirstStart,
    AfterFirstProducer,
    AfterFirstAcceptance,
}

impl Probe {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::AfterPreissue => "returned-refusal-after-preissue",
            Self::BeforeFirstStart => "returned-refusal-before-first-start",
            Self::AfterFirstProducer => "returned-refusal-after-first-producer",
            Self::AfterFirstAcceptance => "returned-refusal-after-first-acceptance",
        }
    }

    // These are the exact reached-seam receipt requirements. The coordinator
    // must audit the real stage receipts independently; this is not a receipt
    // source, an accepted-proof object or a compiler reclamation counter.
    pub(super) fn receipt_counts(self) -> (usize, usize, usize) {
        match self {
            Self::AfterPreissue => (0, 0, 0),
            Self::BeforeFirstStart => (NATIVE, 0, 0),
            Self::AfterFirstProducer => (NATIVE, 1, 0),
            Self::AfterFirstAcceptance => (NATIVE, 1, 1),
        }
    }
}

impl<'group, 'bound, 'source, 'request> Attempt<'group, 'bound, 'source, 'request> {
    // Consuming, initial-only selection: never accepts an intermediate owner
    // or mutates a running sequence. Its complete layout is already included
    // in the caller claim before PendingNativeHashx is constructed.
    pub(super) fn with_probe(mut self, probe: Probe) -> Result<Self> {
        let state = &mut self.state;
        if state.probe.is_some()
            || state.next != 0
            || state.pending_native.is_none()
            || state.prepared_native.is_some()
            || state.first.is_some()
            || state.originals.is_some()
            || state.bank.is_none()
            || state.report.native_proofs != 0
            || state.report.leaf_proofs != 0
            || state.report.parent_proofs != 0
        {
            return Err(Error::Authority);
        }
        state.probe = Some(probe);
        Ok(self)
    }
}

impl State<'_, '_, '_, '_> {
    pub(super) fn return_refusal_if_selected(&self, reached: Probe) -> AttemptResult<()> {
        if self.probe != Some(reached) {
            return Ok(());
        }
        let (native, _, installed) = reached.receipt_counts();
        let preissue = reached == Probe::AfterPreissue;
        // Check the actual private progress/frontier before issuing the typed
        // trip. A real error before this point keeps its original Cause and
        // cannot be reclassified as a qualified injected refusal.
        if self.report.native_proofs != native
            || self.report.leaf_proofs != installed
            || self.report.parent_proofs != 0
            || self.next != installed
            || self.pending_native.is_some()
            || self.prepared_native.is_some() != preissue
            || self.first.is_some() != preissue
            || self.bank.is_some() != preissue
            || self.originals.is_some() != (installed == 1)
            || self.accepted_leaves[0].is_some() != (installed == 1)
            || self.accepted_leaves[1..].iter().any(Option::is_some)
            || self.accepted_parents.iter().any(Option::is_some)
            || self.retained_support[0].is_some() != (installed == 1)
            || self.retained_support[1..].iter().any(Option::is_some)
            || self.ready_parents.iter().any(Option::is_none)
            || self.native_children[..2].iter().any(Option::is_some)
            || self.native_children[2..]
                .iter()
                .any(|child| child.is_some() == preissue)
        {
            return Err(Error::Authority.into());
        }
        Err(Cause::Injected(reached))
    }
}

#[test]
fn injected_failure_retains_original_caller_until_final_classification() {
    use crate::execution::retained_resources::WorkerAllowance;

    for probe in [
        Probe::AfterPreissue,
        Probe::BeforeFirstStart,
        Probe::AfterFirstProducer,
        Probe::AfterFirstAcceptance,
    ] {
        let requirements = attempt_requirement().unwrap();
        let bytes = requirements.total().unwrap();
        let ledger = Ledger::new(WorkerAllowance {
            host: bytes.host,
            device: 0,
        });
        let caller = ledger.admit_phase(requirements).unwrap();
        let before = ledger.snapshot();
        let failure = Failure {
            cause: Cause::Injected(probe),
            #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
            interior: None,
            caller,
        };
        assert!(matches!(&failure.cause, Cause::Injected(actual) if *actual == probe));
        assert!(failure.caller.belongs_to(&ledger));
        assert_eq!(failure.caller.requirements(), requirements);
        assert_eq!(ledger.snapshot(), before);
        assert!(ledger
            .reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 })
            .is_err());
        drop(failure);
        let terminal = ledger.snapshot();
        assert_eq!(terminal.current, Bytes::ZERO);
        assert!(terminal.categories.iter().all(|c| c.current == Bytes::ZERO));
        assert_eq!(terminal.peak, before.peak);
    }
}
