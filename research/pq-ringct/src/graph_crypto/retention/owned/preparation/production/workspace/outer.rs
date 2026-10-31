//! Opaque native-to-outer originals; no full request dispatch or token getters.
use super::*;
use crate::opencl::Session;
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::RetiredRuntime,
    machine::{OuterBackendAdmission, PreissuedOuterBackend, Program},
    native_gpu::owned_shake::{
        BoundHashxOuterBackend, HashxOuterBackend, HashxOuterScratch, PreissuedHashxOuterBackend,
        RetiredHashxOuterBackend,
    },
};
use std::sync::Arc;

pub(crate) struct PreissuedHashxOuter<'request> {
    backend: PreissuedHashxOuterBackend,
    sequence: Option<succession::Sequence>,
    owner: &'request ReservedShakeRequest,
    ledger: Ledger,
    bridge: Reservation,
}

pub(crate) struct RetiredHashxOuter<'request> {
    backend: RetiredHashxOuterBackend,
    sequence: Option<succession::Ready>,
    owner: &'request ReservedShakeRequest,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
    ledger: Ledger,
    bookkeeping: Reservation,
    bridge: Reservation,
}

pub(crate) struct PreparedHashxOuter<'inputs, 'request> {
    runtime: PendingRuntime,
    backend: HashxOuterBackend<'inputs>,
    sequence: Option<succession::Ready>,
    owner: &'request ReservedShakeRequest,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
    ledger: Ledger,
    bookkeeping: Reservation,
    bridge: Reservation,
}

pub(crate) struct ActiveHashxOuter<'inputs, 'request> {
    // The actual runtime dies before all original phase/support reservations.
    session: Session,
    backend: HashxOuterBackend<'inputs>,
    sequence: Option<succession::Ready>,
    owner: &'request ReservedShakeRequest,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
    ledger: Ledger,
    bookkeeping: Reservation,
    bridge: Reservation,
}

/// Returned only by consuming the same actual ActiveHashxOuter Session.
/// It retains every original claim but no compiler/Program/witness borrow.
pub(crate) struct RetiredHashxOuterOriginals<'request> {
    runtime: RetiredRuntime,
    scratch: HashxOuterScratch,
    sequence: Option<succession::Ready>,
    owner: &'request ReservedShakeRequest,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
    ledger: Ledger,
    bookkeeping: Reservation,
    bridge: Reservation,
}

fn bridge_requirement() -> Result<Requirements> {
    let parts = [
        checked_frames::<PreissuedHashxOuter<'static>>(8)?,
        checked_frames::<RetiredHashxOuter<'static>>(8)?,
        checked_frames::<PreparedHashxOuter<'static, 'static>>(8)?,
        checked_frames::<ActiveHashxOuter<'static, 'static>>(8)?,
        checked_frames::<RetiredHashxOuterOriginals<'static>>(8)?,
        checked_frames::<Result<PreissuedHashxOuter<'static>>>(8)?,
        checked_frames::<Result<RetiredHashxOuter<'static>>>(8)?,
        checked_frames::<Result<PreparedHashxOuter<'static, 'static>>>(8)?,
        checked_frames::<Result<ActiveHashxOuter<'static, 'static>>>(8)?,
        checked_frames::<Result<RetiredHashxOuterOriginals<'static>>>(8)?,
        checked_frames::<Result<CompletedNativeHashx<'static>>>(8)?,
        checked_frames::<CompletedNativeHashx<'static>>(8)?,
        checked_frames::<PreparedNativeHashx<'static>>(8)?,
        checked_frames::<PendingNativeHashx<'static>>(8)?,
        checked_frames::<Result<PendingNativeHashx<'static>>>(8)?,
        checked_frames::<ExhaustedScratch<'static>>(8)?,
        checked_frames::<Option<&PreissuedHashxOuter<'static>>>(8)?,
        checked_frames::<BoundHashxOuterBackend<'static>>(8)?,
        checked_frames::<Session>(8)?,
        checked_frames::<RetiredRuntime>(8)?,
        checked_frames::<Snapshot>(16)?,
        checked_frames::<Requirements>(16)?,
        checked_frames::<Result<Requirements>>(8)?,
        checked_frames::<Result<()>>(16)?,
        checked_frames::<Result<Bytes>>(8)?,
        checked_frames::<Option<&Reservation>>(8)?,
        checked_frames::<Result<()>>(8)?,
        checked_frames::<bool>(8)?,
        checked_frames::<Reservation>(16)?,
        checked_frames::<Ledger>(8)?,
        checked_frames::<Retirement>(8)?,
        checked_frames::<Result<Retirement>>(8)?,
        checked_frames::<core::result::Result<Session, crate::opencl::RuntimeError>>(8)?,
        checked_frames::<core::result::Result<RetiredRuntime, crate::opencl::RuntimeError>>(8)?,
        // The cross-component request check is a separate pre-native caller.
        // Retain its full original-capacity helper and forwarding frames too.
        checked_frames::<&PreparedNativeHashx<'static>>(8)?,
        checked_frames::<&ReservedShakeRequest>(8)?,
        checked_frames::<&Ledger>(8)?,
        checked_frames::<Result<()>>(8)?,
        super::capacity::additional_host_bytes()?,
        PreissuedHashxOuterBackend::additional_host_bytes().map_err(|_| Error::Overflow)?,
        PendingRuntime::hashx_outer_restoration_host_bytes(),
        // One retained private Rc referent survives even if the native owner
        // dies first. Include counters/padding without sharing credit.
        8 * size_of::<usize>(),
        32 << 10,
    ];
    let host = parts
        .iter()
        .try_fold(size_of_val(&parts) * 8, |sum, &part| {
            sum.checked_add(part).ok_or(Error::Overflow)
        })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

pub(super) fn check_bridge(bridge: &Reservation, ledger: &Ledger) -> Result<()> {
    if !bridge.belongs_to(ledger) || bridge.requirements() != bridge_requirement()? {
        return Err(Error::Authority);
    }
    Ok(())
}

fn children_moved(next: usize, native_remaining: usize, attachments_remaining: usize) -> bool {
    next == SEGMENTS && native_remaining == 0 && attachments_remaining == 0
}

fn native_entry(enabled: bool, bound: bool, pending: bool, ticket: bool) -> bool {
    if enabled {
        bound && !pending && ticket
    } else {
        !bound && !pending && !ticket
    }
}

impl<'request> PendingNativeHashx<'request> {
    /// Explicit component opt-in before prepare derives the immutable PCS
    /// capacity. No bound can be enlarged after the first native admission.
    pub(crate) fn with_outer_bridge(mut self) -> Result<Self> {
        source(self.owner, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        if self.outer_bridge.is_some() {
            return Err(Error::Authority);
        }
        self.outer_bridge = Some(
            self.ledger
                .admit_phase(bridge_requirement()?)
                .map_err(|_| Error::Admission)?,
        );
        Ok(self)
    }
}

impl<'request> PreparedNativeHashx<'request> {
    /// Match the outer producer's exact original request before source planning
    /// or binding. Equal source geometry alone cannot correlate two requests.
    /// This only borrows checked owners and performs no allocation or admission.
    pub(crate) fn check_outer_request(
        &self,
        expected: &ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<()> {
        if !core::ptr::eq(self.owner, expected)
            || !self.owner.belongs_to(ledger)
            || !self.outer_enabled
            || self.outer_bound
        {
            return Err(Error::Authority);
        }
        source(expected, ledger)?;
        check_bookkeeping(&self.bookkeeping, ledger)?;
        check_bridge(self.outer_bridge.as_ref().ok_or(Error::Authority)?, ledger)?;
        succession::check_pending(
            self.outer_sequence_enabled,
            self.outer_sequence.as_ref(),
            ledger,
        )?;
        self.outer_continuation_capacity()?;
        Ok(())
    }

    pub(crate) fn bind_outer_backend(
        &mut self,
        backend: PreissuedOuterBackend,
    ) -> Result<PreissuedHashxOuter<'request>> {
        self.outer_continuation_capacity()?;
        if !self.outer_enabled || self.outer_bound {
            return Err(Error::Authority);
        }
        let bridge = self.outer_bridge.as_ref().ok_or(Error::Authority)?;
        check_bridge(bridge, &self.ledger)?;
        succession::check_pending(
            self.outer_sequence_enabled,
            self.outer_sequence.as_ref(),
            &self.ledger,
        )?;
        let current = self.current.as_ref().ok_or(Error::Authority)?;
        let backend = current
            .runtime
            .prebind_hashx_outer_backend(
                &current.phase,
                backend,
                current.preparation.reservation(),
                &current.verification,
                bridge,
                &self.ledger,
            )
            .map_err(|_| Error::Phase)?;
        self.outer_bound = true;
        Ok(PreissuedHashxOuter {
            backend,
            sequence: self
                .outer_sequence
                .take()
                .map(succession::Sequence::Pending),
            owner: self.owner,
            ledger: self.ledger.clone(),
            bridge: self.outer_bridge.take().ok_or(Error::Authority)?,
        })
    }

    pub(super) fn check_outer_start(
        &self,
        ticket: Option<&PreissuedHashxOuter<'request>>,
    ) -> Result<()> {
        if !native_entry(
            self.outer_enabled,
            self.outer_bound,
            self.outer_bridge.is_some(),
            ticket.is_some(),
        ) {
            return Err(Error::Authority);
        }
        if !self.outer_enabled {
            return if !self.outer_sequence_enabled && self.outer_sequence.is_none() {
                Ok(())
            } else {
                Err(Error::Authority)
            };
        }
        let ticket = ticket.ok_or(Error::Authority)?;
        check_bridge(&ticket.bridge, &self.ledger)?;
        if !core::ptr::eq(ticket.owner, self.owner) || !ticket.owner.belongs_to(&ticket.ledger) {
            return Err(Error::Authority);
        }
        if self.outer_sequence.is_some() || self.outer_sequence_enabled != ticket.sequence.is_some()
        {
            return Err(Error::Authority);
        }
        if let Some(sequence) = &ticket.sequence {
            sequence.check_before_native(&ticket.backend, &self.ledger)?;
        }
        ticket
            .backend
            .check_first(
                &self.current.as_ref().ok_or(Error::Authority)?.phase,
                &self.ledger,
            )
            .map_err(|_| Error::Authority)
    }

    /// The immutable ticket borrow keeps its original independent metadata
    /// claim alive across all ten native attempts. There is no default fallback.
    /// # Safety
    /// Retain the original immutable process/exclusive physical-device guard.
    pub(crate) unsafe fn produce_for_outer(
        self,
        ticket: &PreissuedHashxOuter<'request>,
    ) -> Result<CompletedNativeHashx<'request>> {
        unsafe { self.produce_inner(Some(ticket)) }
    }
}

impl<'request> PreissuedHashxOuter<'request> {
    /// Terminal consuming refusal: no ticket, fallback or retry escapes.
    pub(crate) fn finish_native(
        self,
        completed: CompletedNativeHashx<'request>,
    ) -> Result<RetiredHashxOuter<'request>> {
        source(self.owner, &self.ledger)?;
        check_bridge(&self.bridge, &self.ledger)?;
        check_bookkeeping(&completed.bookkeeping, &self.ledger)?;
        if !core::ptr::eq(self.owner, completed.owner)
            || !completed.owner.belongs_to(&completed.ledger)
            || !children_moved(
                completed.next_child,
                completed.retained_native_count(),
                completed
                    .attachments
                    .iter()
                    .filter(|slot| slot.is_some())
                    .count(),
            )
            || !completed
                .scratch
                .preparation
                .is_for(self.owner, SEGMENTS - 1, &self.ledger)
            || !completed.scratch.verification.belongs_to(&self.ledger)
            || completed.scratch.verification.requirements()
                != VerificationPlan::component_requirement()
        {
            return Err(Error::Authority);
        }
        let before = self.ledger.snapshot();
        let sequence = self
            .sequence
            .map(succession::Sequence::into_ready)
            .transpose()?;
        let CompletedNativeHashx {
            scratch,
            bookkeeping,
            ..
        } = completed;
        let ExhaustedScratch {
            originals,
            preparation,
            verification,
        } = scratch;
        let backend = self
            .backend
            .complete(
                originals,
                preparation.reservation(),
                &verification,
                &self.ledger,
            )
            .map_err(|_| Error::Retirement)?;
        if self.ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        Ok(RetiredHashxOuter {
            backend,
            sequence,
            owner: self.owner,
            preparation,
            verification,
            ledger: self.ledger,
            bookkeeping,
            bridge: self.bridge,
        })
    }
}

impl<'request> RetiredHashxOuter<'request> {
    /// Source backend/selection binding uses the original preissued plan only.
    /// # Safety
    /// Preserve the same immutable/exclusive guard through actual outer finish.
    pub(crate) unsafe fn bind<'inputs>(
        self,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
    ) -> Result<PreparedHashxOuter<'inputs, 'request>> {
        source(self.owner, &self.ledger)?;
        check_bridge(&self.bridge, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        let before = self.ledger.snapshot();
        let backend = self
            .backend
            .bind(program, public, witness)
            .map_err(|_| Error::Phase)?;
        let (mut runtime, backend) =
            PendingRuntime::restore_bound_hashx_outer(backend, &self.ledger, limits())
                .map_err(|_| Error::Runtime)?;
        backend
            .scratch()
            .check_originals(
                self.preparation.reservation(),
                &self.verification,
                &self.ledger,
            )
            .map_err(|_| Error::Authority)?;
        if runtime.reserved_bytes()
            != backend
                .scratch()
                .startup_requirements()
                .get(Category::PhaseScratch)
            || runtime.reserved_tree_host_bytes() != 8 << 30
            || self.ledger.snapshot() != before
        {
            return Err(Error::Authority);
        }
        succession::check_ready(
            self.sequence.as_ref(),
            backend.scratch(),
            self.preparation.reservation(),
            &self.verification,
            &self.ledger,
        )?;
        let guard = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        drop(guard);
        Ok(PreparedHashxOuter {
            runtime,
            backend,
            sequence: self.sequence,
            owner: self.owner,
            preparation: self.preparation,
            verification: self.verification,
            ledger: self.ledger,
            bookkeeping: self.bookkeeping,
            bridge: self.bridge,
        })
    }
}

impl<'inputs, 'request> PreparedHashxOuter<'inputs, 'request> {
    /// # Safety
    /// The original process/device guard survives every success/failure cleanup.
    pub(crate) unsafe fn start(self) -> Result<ActiveHashxOuter<'inputs, 'request>> {
        check_bridge(&self.bridge, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        succession::check_ready(
            self.sequence.as_ref(),
            self.backend.scratch(),
            self.preparation.reservation(),
            &self.verification,
            &self.ledger,
        )?;
        self.backend
            .scratch()
            .check_originals(
                self.preparation.reservation(),
                &self.verification,
                &self.ledger,
            )
            .map_err(|_| Error::Authority)?;
        if !self
            .preparation
            .is_for(self.owner, SEGMENTS - 1, &self.ledger)
            || !self.runtime.belongs_to(&self.ledger)
        {
            return Err(Error::Authority);
        }
        self.backend
            .backend()
            .check_execution_selection()
            .map_err(|_| Error::Runtime)?;
        let session = unsafe { self.runtime.start() }.map_err(|_| Error::Runtime)?;
        Ok(ActiveHashxOuter {
            session,
            backend: self.backend,
            sequence: self.sequence,
            owner: self.owner,
            preparation: self.preparation,
            verification: self.verification,
            ledger: self.ledger,
            bookkeeping: self.bookkeeping,
            bridge: self.bridge,
        })
    }
}

impl<'inputs, 'request> ActiveHashxOuter<'inputs, 'request> {
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }
    pub(crate) fn backend(&self) -> &OuterBackendAdmission<'inputs> {
        self.backend.backend()
    }

    /// Consume the actual Session even after the caller's returned proof error.
    /// This seals runtime retirement only; B separately requires proof success.
    pub(crate) fn finish(self) -> Result<RetiredHashxOuterOriginals<'request>> {
        let before = self.ledger.snapshot();
        let runtime = self
            .session
            .finish_reserved_with_owner(&self.ledger)
            .map_err(|_| Error::Runtime)?;
        if !retirement_is_complete(runtime.receipt()) {
            std::process::abort();
        }
        let scratch = self.backend.into_retired_scratch();
        let retired = RetiredHashxOuterOriginals {
            runtime,
            scratch,
            sequence: self.sequence,
            owner: self.owner,
            preparation: self.preparation,
            verification: self.verification,
            ledger: self.ledger,
            bookkeeping: self.bookkeeping,
            bridge: self.bridge,
        };
        retired.check(retired.owner, &retired.ledger)?;
        if retired.ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        Ok(retired)
    }
}

impl RetiredHashxOuterOriginals<'_> {
    /// Numeric evidence only. No constructor or original-token extraction.
    pub(crate) fn check(
        &self,
        request: &ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Retirement> {
        source(self.owner, ledger)?;
        check_bridge(&self.bridge, ledger)?;
        check_bookkeeping(&self.bookkeeping, ledger)?;
        succession::check_ready(
            self.sequence.as_ref(),
            &self.scratch,
            self.preparation.reservation(),
            &self.verification,
            ledger,
        )?;
        self.scratch
            .check_originals(self.preparation.reservation(), &self.verification, ledger)
            .map_err(|_| Error::Authority)?;
        let receipt = self.runtime.receipt();
        if !core::ptr::eq(self.owner, request)
            || !self.preparation.is_for(self.owner, SEGMENTS - 1, ledger)
            || !self.runtime.belongs_to(ledger)
            || self.runtime.startup_requirements() != self.scratch.startup_requirements()
            || !retirement_is_complete(receipt)
            || receipt.managed_peak_bytes == 0
            || receipt.managed_peak_bytes as u64 > DEVICE_BYTES
        {
            return Err(Error::Authority);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;

mod succession;
pub(crate) use succession::HashxOuterStep;
