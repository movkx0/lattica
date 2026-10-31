use super::{
    runtime::ExecutionAccess,
    types::{PhaseBinding, SlotId, SlotSpec, WorkflowError},
};
use crate::execution::{
    phase_lifecycle::{OwnedPhase, PhaseLease},
    retained_resources::{Category, Ledger, Requirements, Reservation},
};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Barrier {
    Idle,
    Active,
    Poisoned,
    Retired,
}

enum Slot {
    Available(Reservation),
    InUse,
    Pending(Reservation),
}

struct PoolState {
    barrier: Barrier,
    slots: Vec<Slot>,
}

/// The same original reservations are moved out of, and back into, this pool.
/// Reclamation never calls Ledger::reserve/admit_phase or creates new credit.
pub(super) struct SlotPool {
    state: RefCell<PoolState>,
    ledger: Ledger,
    // Last: Rc/Vec/control backing dies before this original is released.
    _bookkeeping: Reservation,
}

impl SlotPool {
    pub(super) fn ledger(&self) -> &Ledger { &self.ledger }

    pub(super) fn bookkeeping_bytes(slots: usize) -> Result<u64, WorkflowError> {
        let bytes = slots
            .checked_mul(2)
            .and_then(|n| n.checked_mul(core::mem::size_of::<Slot>()))
            .and_then(|n| n.checked_add(core::mem::size_of::<Self>()))
            .and_then(|n| n.checked_add(2 * core::mem::size_of::<usize>()))
            .ok_or(WorkflowError::Overflow)?;
        u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)
    }

    pub(super) fn bookkeeping_requirements(slots: usize) -> Result<Requirements, WorkflowError> {
        Ok(Requirements::single(Category::RegisteredMetadata,
            crate::execution::retained_resources::Bytes { host: Self::bookkeeping_bytes(slots)?, device: 0 }))
    }

    pub(super) fn new(
        phase: &mut OwnedPhase<'_>,
        specs: &[SlotSpec],
    ) -> Result<Rc<Self>, WorkflowError> {
        let ledger = phase.ledger().clone();
        Self::build(ledger, specs, |requirements| {
            phase.split(requirements).map_err(WorkflowError::from)
        })
    }

    pub(super) fn new_borrowed(
        phase: &mut PhaseLease<'_, '_>,
        specs: &[SlotSpec],
    ) -> Result<Rc<Self>, WorkflowError> {
        let ledger = phase.ledger().clone();
        Self::build(ledger, specs, |requirements| {
            phase.split(requirements).map_err(WorkflowError::from)
        })
    }

    fn build(
        ledger: Ledger,
        specs: &[SlotSpec],
        mut split: impl FnMut(
            crate::execution::retained_resources::Requirements,
        ) -> Result<Reservation, WorkflowError>,
    ) -> Result<Rc<Self>, WorkflowError> {
        let bookkeeping = split(Self::bookkeeping_requirements(specs.len())?)?;
        if !bookkeeping.belongs_to(&ledger) { return Err(WorkflowError::SlotAuthority); }
        // Original admission precedes either Vec or Rc allocation and follows
        // every retained output/failure that keeps this pool alive.
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(specs.len())
            .map_err(|_| WorkflowError::Allocation)?;
        if slots.capacity() > specs.len().checked_mul(2).ok_or(WorkflowError::Overflow)? {
            return Err(WorkflowError::Allocation);
        }
        for spec in specs {
            slots.push(Slot::Available(split(spec.requirements)?));
        }
        Ok(Rc::new(Self {
            state: RefCell::new(PoolState {
                barrier: Barrier::Idle,
                slots,
            }),
            ledger,
            _bookkeeping: bookkeeping,
        }))
    }

    pub(super) fn begin(&self) -> Result<(), WorkflowError> {
        let mut state = self.state.borrow_mut();
        if state.barrier != Barrier::Idle {
            return Err(WorkflowError::Poisoned);
        }
        state.barrier = Barrier::Active;
        Ok(())
    }

    pub(super) fn is_live(&self, slot: SlotId) -> bool {
        matches!(self.state.borrow().slots.get(slot.index()), Some(Slot::InUse))
    }

    pub(super) fn is_available(&self, slot: SlotId) -> bool {
        matches!(
            self.state.borrow().slots.get(slot.index()),
            Some(Slot::Available(_))
        )
    }

    pub(super) fn claim(self: &Rc<Self>, slot: SlotId) -> Result<SlotClaim, WorkflowError> {
        let mut state = self.state.borrow_mut();
        if state.barrier != Barrier::Active {
            return Err(WorkflowError::Poisoned);
        }
        let entry = state.slots.get_mut(slot.index()).ok_or(WorkflowError::Slot)?;
        let previous = core::mem::replace(entry, Slot::InUse);
        match previous {
            Slot::Available(original) => {
                if !original.belongs_to(&self.ledger) {
                    *entry = Slot::Available(original);
                    return Err(WorkflowError::SlotAuthority);
                }
                Ok(SlotClaim {
                    expected: original.requirements(),
                    original: Some(original),
                    pool: Rc::clone(self),
                    slot,
                })
            }
            previous => {
                *entry = previous;
                Err(WorkflowError::SlotBusy)
            }
        }
    }

    /// This is called only after actual context cleanup succeeds, never from
    /// a caller report or output destructor. Pending reservations stay original.
    pub(super) fn after_cleanup(&self) -> Result<(), WorkflowError> {
        let mut state = self.state.borrow_mut();
        if state.barrier != Barrier::Active {
            return Err(WorkflowError::Poisoned);
        }
        for slot in &mut state.slots {
            if matches!(slot, Slot::Pending(_)) {
                let Slot::Pending(original) = core::mem::replace(slot, Slot::InUse) else {
                    unreachable!("checked pending slot")
                };
                *slot = Slot::Available(original);
            }
        }
        state.barrier = Barrier::Idle;
        Ok(())
    }

    pub(super) fn poison(&self) {
        self.state.borrow_mut().barrier = Barrier::Poisoned;
    }

    pub(super) fn retire(&self) -> Result<(), WorkflowError> {
        let mut state = self.state.borrow_mut();
        if state.barrier != Barrier::Idle {
            return Err(WorkflowError::Poisoned);
        }
        state.barrier = Barrier::Retired;
        Ok(())
    }

    pub(super) fn retire_after_cleanup(&self) {
        let mut state = self.state.borrow_mut();
        for slot in &mut state.slots {
            if matches!(slot, Slot::Pending(_)) {
                let Slot::Pending(original) = core::mem::replace(slot, Slot::InUse) else {
                    unreachable!("checked pending slot")
                };
                *slot = Slot::Available(original);
            }
        }
        state.barrier = Barrier::Retired;
    }

    fn restore(&self, slot: SlotId, original: Reservation) {
        let mut state = self.state.borrow_mut();
        // Private construction guarantees both invariants. On a future bug,
        // fail closed without dropping a claim still needed by backend work.
        if !original.belongs_to(&self.ledger)
            || !matches!(state.slots.get(slot.index()), Some(Slot::InUse))
        {
            state.barrier = Barrier::Poisoned;
            core::mem::forget(original);
            return;
        }
        state.slots[slot.index()] = match state.barrier {
            Barrier::Idle | Barrier::Retired => Slot::Available(original),
            Barrier::Active | Barrier::Poisoned => Slot::Pending(original),
        };
    }
}

impl Drop for SlotPool {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if matches!(state.barrier, Barrier::Active | Barrier::Poisoned) {
            // No successful retirement evidence: retain only fixed original
            // accounting tokens, as ContextPhases does for backend scratch.
            // Actual payloads have already died before their slots came here.
            for slot in &mut state.slots {
                match core::mem::replace(slot, Slot::InUse) {
                    Slot::Available(original) | Slot::Pending(original) => {
                        core::mem::forget(original);
                    }
                    Slot::InUse => {}
                }
            }
        }
    }
}

pub(super) struct SlotClaim {
    original: Option<Reservation>,
    expected: Requirements,
    pool: Rc<SlotPool>,
    slot: SlotId,
}

impl SlotClaim {
    /// Named immutable-source path only: no caller may submit numeric retained
    /// requirements. Both the checked graph and the successful cleanup token
    /// must belong to the concrete source owner kept by the caller.
    pub(super) fn retain_completed_graph(&mut self,
        graph: &crate::spend_pipeline::full_workflow::PreparedGraphSources,
        cleanup: &super::source::CompletedSourceCleanup<'_>) -> Result<(), WorkflowError>
    {
        let full = graph.initial_output_requirements().map_err(|_| WorkflowError::Planning)?;
        let retained = graph.retained_graph_host_bytes().map_err(|_| WorkflowError::Planning)?;
        let state = self.pool.state.try_borrow().map_err(|_| WorkflowError::Poisoned)?;
        let original = self.original.as_ref().ok_or(WorkflowError::SlotAuthority)?;
        if !cleanup.authorizes(&self.pool, self, graph as *const _ as *const ())
            || state.barrier != Barrier::Retired
            || state.slots.len() != 2 || self.slot != SlotId::new(0)
            || !matches!(state.slots.get(self.slot.index()), Some(Slot::InUse))
            || !original.belongs_to(&self.pool.ledger)
            || original.requirements() != self.expected || self.expected != full
            || full.get(Category::SymbolicCompiler).device != 0
        { return Err(WorkflowError::SlotAuthority); }
        let release = full.get(Category::SymbolicCompiler).host.checked_sub(retained)
            .ok_or(WorkflowError::SlotAuthority)?;
        drop(state);
        // Splitting is checked and leaves the full original unchanged on error.
        // The graph remains immutably owned by SourceRetained. All metadata,
        // failure and pool backing stays charged; only unused graph host backing
        // is released, after actual source cleanup, and without readmission.
        let original = self.original.as_mut().expect("checked source original");
        let surplus = original.split(Requirements::single(Category::SymbolicCompiler,
            crate::execution::retained_resources::Bytes { host: release, device: 0 }))?;
        self.expected = original.requirements();
        drop(surplus);
        Ok(())
    }

    pub(super) fn graph_retention_frame_bytes() -> Result<usize, WorkflowError> {
        use core::mem::size_of;
        [size_of::<[Requirements; 6]>(), size_of::<[crate::execution::retained_resources::Bytes; 6]>(),
            size_of::<Reservation>(), size_of::<Result<Reservation, crate::execution::retained_resources::Error>>(),
            size_of::<Result<Requirements, crate::spend_pipeline::full_workflow::SourcePreparationError>>(),
            size_of::<Result<u64, crate::spend_pipeline::full_workflow::SourcePreparationError>>(),
            size_of::<std::cell::Ref<'static, PoolState>>(),
            size_of::<Result<(), WorkflowError>>(), size_of::<[usize; 8]>(),
            size_of::<[&crate::spend_pipeline::full_workflow::PreparedGraphSources; 4]>(),
            size_of::<[&mut SlotClaim; 2]>(), size_of::<[&Reservation; 2]>()]
            .into_iter().try_fold(0usize, usize::checked_add).and_then(|n| n.checked_mul(8))
            .ok_or(WorkflowError::Overflow)
    }

    pub(super) fn split(&mut self, request: Requirements) -> Result<Reservation, WorkflowError> {
        self.original.as_mut().ok_or(WorkflowError::SlotAuthority)?
            .split(request).map_err(WorkflowError::from)
    }

    pub(super) fn reunite(&mut self, original: Reservation) -> Result<(), (WorkflowError, Reservation)> {
        if !original.belongs_to(&self.pool.ledger) {
            return Err((WorkflowError::SlotAuthority, original));
        }
        let Some(held) = self.original.as_ref() else {
            return Err((WorkflowError::SlotAuthority, original));
        };
        let mut total = held.requirements();
        for category in Category::ALL {
            if let Err(error) = total.add(category, original.requirements().get(category)) {
                return Err((error.into(), original));
            }
        }
        if !super::types::contains(self.expected, total) {
            return Err((WorkflowError::SlotAuthority, original));
        }
        let held = self.original.take().expect("checked original slot");
        match held.reunite(original) {
            Ok(held) => { self.original = Some(held); Ok(()) }
            Err((error, held, original)) => {
                self.original = Some(held);
                Err((error.into(), original))
            }
        }
    }

    pub(super) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original
            .as_ref()
            .is_some_and(|original| original.belongs_to(ledger))
    }
}

impl Drop for SlotClaim {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            if original.requirements() != self.expected {
                self.pool.poison();
                core::mem::forget(original);
                return;
            }
            self.pool.restore(self.slot, original);
        }
    }
}

/// Implemented only by execution-owned adapters for concrete core-owned
/// outputs. No caller-provided payload, proof attachment or destructor callback
/// is accepted. Every payload dies before its original claims are returned.
pub(in crate::execution) trait OriginalOutput {
    fn destroy_into_originals(self) -> [Option<Reservation>; 4];
}

/// Core proof/key/report owners temporarily contain the original slot claims.
/// This owner returns those same claims after payload death; the residual slot
/// never claims to own bytes which are still held inside the core output.
pub(crate) struct RetainedOriginal<T: OriginalOutput> {
    payload: Option<T>,
    claim: SlotClaim,
    binding: PhaseBinding,
}

pub(crate) type RetainedNative<T> = RetainedOriginal<T>;

impl<T: OriginalOutput> RetainedOriginal<T> {
    pub(crate) fn get(&self) -> &T { self.payload.as_ref().expect("retained original output") }
    pub(crate) fn slot_id(&self) -> SlotId { self.claim.slot }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn belongs_to(&self, access: &ExecutionAccess<'_>) -> bool {
        Rc::ptr_eq(&self.claim.pool, access.pool())
    }
    pub(super) fn produced(payload: T, claim: SlotClaim, binding: PhaseBinding) -> Self {
        Self { payload: Some(payload), claim, binding }
    }
}

impl<T: OriginalOutput> Drop for RetainedOriginal<T> {
    fn drop(&mut self) {
        if let Some(payload) = self.payload.take() {
            for original in payload.destroy_into_originals().into_iter().flatten() {
                if let Err((_error, original)) = self.claim.reunite(original) {
                    self.claim.pool.poison();
                    core::mem::forget(original);
                }
            }
        }
    }
}

/// Move-only produced value. Rust destroys fields in declaration order: the
/// payload dies before its original claim returns to the pool. No constructor,
/// mutable reference, extraction, clone, or arbitrary attachment is exposed.
#[must_use]
pub(crate) struct Retained<T> {
    payload: T,
    claim: SlotClaim,
    binding: PhaseBinding,
}

impl<T> Retained<T> {
    pub(crate) fn get(&self) -> &T {
        &self.payload
    }

    pub(crate) fn slot_id(&self) -> SlotId {
        self.claim.slot
    }

    pub(crate) fn binding(&self) -> PhaseBinding {
        self.binding
    }

    pub(crate) fn belongs_to(&self, access: &ExecutionAccess<'_>) -> bool {
        Rc::ptr_eq(&self.claim.pool, access.pool())
    }

    pub(super) fn produced(payload: T, claim: SlotClaim, binding: PhaseBinding) -> Self {
        Self {
            payload,
            claim,
            binding,
        }
    }
}

/// Failure payload and fixed cleanup status precede their ORIGINAL output
/// claim. Existing heap-owning backend errors must be reduced while the phase
/// remains active; only each concrete operation's bounded error type is kept.
#[must_use]
pub(crate) struct RetainedFailure<E> {
    error: Option<E>,
    status: Option<WorkflowError>,
    claim: SlotClaim,
}

impl<E> RetainedFailure<E> {
    pub(crate) fn get(&self) -> Option<&E> {
        self.error.as_ref()
    }

    pub(crate) fn status(&self) -> Option<&WorkflowError> {
        self.status.as_ref()
    }

    pub(super) fn produced(
        error: Option<E>,
        status: Option<WorkflowError>,
        claim: SlotClaim,
    ) -> Self {
        Self { error, status, claim }
    }

    pub(super) fn with_status(mut self, status: WorkflowError) -> Self {
        self.status = Some(status);
        self
    }
}

impl<E: core::fmt::Debug> core::fmt::Debug for RetainedFailure<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetainedFailure")
            .field("error", &self.error)
            .field("status", &self.status)
            .field("slot", &self.claim.slot)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum PhaseFailure<E> {
    /// Inline refusal before operation execution; never a detached E or report.
    Admission(WorkflowError),
    Retained(RetainedFailure<E>),
}
