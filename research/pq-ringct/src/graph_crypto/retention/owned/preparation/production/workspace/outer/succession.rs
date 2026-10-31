//! Fixed minimal HashX component order, with every future backend preissued
//! before native zero. Retirement is never evidence that a proof succeeded.
use super::*;
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::{Footprint, StartupPlan},
    native_gpu::owned_shake::HashxOuterSuccessors,
};

const SUCCESSORS: usize = 8;

/// Execution order only. B separately authenticates each source and successful
/// child/parent proof before deciding to advance the opaque runtime originals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum HashxOuterStep {
    Leaf0 = 0,
    Leaf1 = 1,
    Parent0 = 2,
    Leaf2 = 3,
    Leaf3 = 4,
    Parent1 = 5,
    Parent2 = 6,
    Leaf4 = 7,
    Parent3 = 8,
}

fn step(ordinal: usize) -> Result<HashxOuterStep> {
    [
        HashxOuterStep::Leaf0,
        HashxOuterStep::Leaf1,
        HashxOuterStep::Parent0,
        HashxOuterStep::Leaf2,
        HashxOuterStep::Leaf3,
        HashxOuterStep::Parent1,
        HashxOuterStep::Parent2,
        HashxOuterStep::Leaf4,
        HashxOuterStep::Parent3,
    ]
    .get(ordinal)
    .copied()
    .ok_or(Error::Authority)
}

pub(super) enum Sequence {
    Pending(Reservation),
    Ready(Ready),
}

/// Full exact backing/source plans die before their independent original claim.
pub(super) struct Ready {
    core: HashxOuterSuccessors,
    original: Reservation,
}

// Keep the moved backend before the queue's independent original claim even
// when subsequent runtime restoration or preflight returns an error.
struct BoundSuccessor<'inputs> {
    backend: HashxOuterBackend<'inputs>,
    sequence: Ready,
}

fn sequence_requirement() -> Result<Requirements> {
    let parts = [
        HashxOuterSuccessors::additional_host_bytes().map_err(|_| Error::Overflow)?,
        checked_frames::<Sequence>(8)?,
        checked_frames::<Ready>(8)?,
        checked_frames::<BoundSuccessor<'static>>(8)?,
        checked_frames::<Option<Sequence>>(8)?,
        checked_frames::<Option<Ready>>(8)?,
        checked_frames::<Result<Ready>>(8)?,
        checked_frames::<Result<Option<Ready>>>(8)?,
        checked_frames::<Option<Result<Ready>>>(8)?,
        checked_frames::<[PreissuedOuterBackend; SUCCESSORS]>(8)?,
        checked_frames::<PreissuedHashxOuter<'static>>(8)?,
        checked_frames::<Result<PreissuedHashxOuter<'static>>>(8)?,
        checked_frames::<PendingNativeHashx<'static>>(8)?,
        checked_frames::<Result<PendingNativeHashx<'static>>>(8)?,
        checked_frames::<PreparedNativeHashx<'static>>(8)?,
        checked_frames::<RetiredHashxOuterOriginals<'static>>(8)?,
        checked_frames::<Result<RetiredHashxOuterOriginals<'static>>>(8)?,
        checked_frames::<PreparedHashxOuter<'static, 'static>>(8)?,
        checked_frames::<Result<PreparedHashxOuter<'static, 'static>>>(8)?,
        checked_frames::<HashxOuterBackend<'static>>(8)?,
        checked_frames::<HashxOuterScratch>(8)?,
        checked_frames::<(HashxOuterBackend<'static>, HashxOuterSuccessors)>(8)?,
        checked_frames::<
            core::result::Result<
                (HashxOuterBackend<'static>, HashxOuterSuccessors),
                lattica_prover_p3::block_v2::native_gpu::owned_shake::Error,
            >,
        >(8)?,
        checked_frames::<
            core::result::Result<
                HashxOuterSuccessors,
                lattica_prover_p3::block_v2::native_gpu::owned_shake::Error,
            >,
        >(8)?,
        checked_frames::<
            core::result::Result<(), lattica_prover_p3::block_v2::native_gpu::owned_shake::Error>,
        >(8)?,
        checked_frames::<
            core::result::Result<PendingRuntime, (crate::opencl::RuntimeError, RetiredRuntime)>,
        >(8)?,
        checked_frames::<(crate::opencl::RuntimeError, RetiredRuntime)>(8)?,
        checked_frames::<PendingRuntime>(8)?,
        checked_frames::<RetiredRuntime>(8)?,
        checked_frames::<StartupPlan>(8)?,
        checked_frames::<Footprint>(8)?,
        checked_frames::<Snapshot>(16)?,
        checked_frames::<Requirements>(8)?,
        checked_frames::<Result<Requirements>>(8)?,
        checked_frames::<Reservation>(8)?,
        checked_frames::<Ledger>(8)?,
        checked_frames::<Retirement>(8)?,
        checked_frames::<Result<Retirement>>(8)?,
        checked_frames::<Option<&Reservation>>(8)?,
        checked_frames::<Option<&Ready>>(8)?,
        checked_frames::<HashxOuterStep>(8)?,
        checked_frames::<Result<HashxOuterStep>>(8)?,
        checked_frames::<[HashxOuterStep; SUCCESSORS + 1]>(8)?,
        checked_frames::<Result<()>>(8)?,
        checked_frames::<usize>(8)?,
        checked_frames::<bool>(8)?,
        // Existing startup claim covers sealed outer-startup restoration's
        // original internals. These complete enclosing restoration/preflight
        // owners are additive, with no sharing or inlining credit.
        PendingRuntime::hashx_restoration_host_bytes(),
        PendingRuntime::hashx_outer_restoration_host_bytes(),
        32 << 10,
    ];
    let host = parts
        .iter()
        .try_fold(size_of_val(&parts) * 8, |sum, &bytes| {
            sum.checked_add(bytes).ok_or(Error::Overflow)
        })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

fn check_sequence(original: &Reservation, ledger: &Ledger) -> Result<()> {
    if !original.belongs_to(ledger) || original.requirements() != sequence_requirement()? {
        return Err(Error::Authority);
    }
    Ok(())
}

pub(super) fn check_pending(
    enabled: bool,
    original: Option<&Reservation>,
    ledger: &Ledger,
) -> Result<()> {
    if enabled != original.is_some() {
        return Err(Error::Authority);
    }
    if let Some(original) = original {
        check_sequence(original, ledger)?;
    }
    Ok(())
}

impl Sequence {
    pub(super) fn check_before_native(
        &self,
        first: &PreissuedHashxOuterBackend,
        ledger: &Ledger,
    ) -> Result<()> {
        let Self::Ready(ready) = self else {
            return Err(Error::Authority);
        };
        check_sequence(&ready.original, ledger)?;
        ready
            .core
            .check_before_native(first, ledger)
            .map_err(|_| Error::Authority)
    }

    pub(super) fn into_ready(self) -> Result<Ready> {
        match self {
            Self::Ready(ready) => Ok(ready),
            Self::Pending(_) => Err(Error::Authority),
        }
    }
}

pub(super) fn check_ready(
    ready: Option<&Ready>,
    scratch: &HashxOuterScratch,
    preparation: &Reservation,
    verifier: &Reservation,
    ledger: &Ledger,
) -> Result<()> {
    match ready {
        None if scratch.outer_step() == 0 => Ok(()),
        None => Err(Error::Authority),
        Some(ready) => {
            check_sequence(&ready.original, ledger)?;
            ready
                .core
                .check_originals(scratch, preparation, verifier, ledger)
                .map_err(|_| Error::Authority)
        }
    }
}

impl<'request> PendingNativeHashx<'request> {
    /// Opt into the exact nine-phase outer sequence before prepare assigns PCS.
    /// This installs the ordinary first-outer bridge if it was not requested yet.
    pub(crate) fn with_outer_sequence(mut self) -> Result<Self> {
        source(self.owner, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        if self.outer_sequence.is_some() {
            return Err(Error::Authority);
        }
        if self.outer_bridge.is_none() {
            self = self.with_outer_bridge()?;
        }
        check_bridge(
            self.outer_bridge.as_ref().ok_or(Error::Authority)?,
            &self.ledger,
        )?;
        self.outer_sequence = Some(
            self.ledger
                .admit_phase(sequence_requirement()?)
                .map_err(|_| Error::Admission)?,
        );
        Ok(self)
    }
}

impl<'request> PreissuedHashxOuter<'request> {
    /// Consuming one-shot binding of all eight original future source plans.
    /// A first-only ticket has no sequence claim and cannot gain successors.
    /// An already configured ticket cannot replace or append a backend.
    pub(crate) fn with_successors(
        mut self,
        backends: [PreissuedOuterBackend; SUCCESSORS],
    ) -> Result<Self> {
        source(self.owner, &self.ledger)?;
        check_bridge(&self.bridge, &self.ledger)?;
        let Some(Sequence::Pending(original)) = self.sequence.take() else {
            return Err(Error::Authority);
        };
        check_sequence(&original, &self.ledger)?;
        let core = self
            .backend
            .preissue_successors(backends, &original, &self.ledger)
            .map_err(|_| Error::Phase)?;
        self.sequence = Some(Sequence::Ready(Ready { core, original }));
        Ok(self)
    }
}

impl<'request> RetiredHashxOuterOriginals<'request> {
    /// This is execution position only. It grants no accepted proof or graph.
    pub(crate) fn outer_step(&self) -> Result<HashxOuterStep> {
        self.check(self.owner, &self.ledger)?;
        step(self.scratch.outer_step())
    }

    /// B must authenticate the previous successful leaf/parent and exact next
    /// compiler source before this call. A checks lifecycle/order only.
    /// # Safety
    /// Keep the original immutable process/exclusive-device guard continuously.
    pub(crate) unsafe fn bind_successor<'inputs>(
        self,
        expected: HashxOuterStep,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
    ) -> Result<PreparedHashxOuter<'inputs, 'request>> {
        self.check(self.owner, &self.ledger)?;
        let before = self.ledger.snapshot();
        let Ready { core, original } = self.sequence.ok_or(Error::Authority)?;
        check_sequence(&original, &self.ledger)?;
        let (backend, core) = core
            .bind_successor(
                self.scratch,
                expected as usize,
                program,
                public,
                witness,
                self.preparation.reservation(),
                &self.verification,
                &self.ledger,
            )
            .map_err(|_| Error::Phase)?;
        let bound = BoundSuccessor {
            backend,
            sequence: Ready { core, original },
        };
        let mut runtime =
            PendingRuntime::restore_retired_outer_host_v1(self.runtime, &self.ledger, limits())
                .map_err(|_| Error::Runtime)?;
        check_ready(
            Some(&bound.sequence),
            bound.backend.scratch(),
            self.preparation.reservation(),
            &self.verification,
            &self.ledger,
        )?;
        if runtime.reserved_bytes()
            != bound
                .backend
                .scratch()
                .startup_requirements()
                .get(Category::PhaseScratch)
            || runtime.reserved_tree_host_bytes() != 8 << 30
            || self.ledger.snapshot() != before
        {
            return Err(Error::Authority);
        }
        let guard = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        drop(guard);
        Ok(PreparedHashxOuter {
            runtime,
            backend: bound.backend,
            sequence: Some(bound.sequence),
            owner: self.owner,
            preparation: self.preparation,
            verification: self.verification,
            ledger: self.ledger,
            bookkeeping: self.bookkeeping,
            bridge: self.bridge,
        })
    }
}

#[cfg(test)]
mod tests;
