//! Exact two/three-singleton source-preissued native continuation.
//! These owners never construct a source request or authorize a retry.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::NativeShakeSuccessor;

pub(crate) struct FutureNativeSingleton<'request> {
    source: ClaimedSource<'request>,
    ledger: Ledger,
}

pub(crate) struct ReadyNativeSingleton<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    successor: NativeShakeSuccessor,
    preparation: PendingNativePreparation<'request>,
    verifier: VerificationPlan,
    verification: Reservation,
    startup: Bytes,
    ledger: Ledger,
    bookkeeping: Reservation,
}

pub(crate) type NativeCompletionError<'request> = (Error, FutureNativeSingleton<'request>);
pub(crate) type NativeSuccessorError<'request> = (
    Error,
    ReadyNativeSingleton<'request>,
    VerifiedNativeSingletonWithOriginals<'request>,
);

fn future_index(owner: &ReservedShakeRequest, index: usize) -> Result<()> {
    let partition = owner.request().shake_partition().ok_or(Error::Source)?;
    let count = partition.segments().len();
    if !(2..=3).contains(&count)
        || index == 0
        || index >= count
        || partition
            .segments()
            .iter()
            .any(|air| !matches!(air, ShakeSegmentAir::Single(_)))
    {
        return Err(Error::Source);
    }
    Ok(())
}

pub(super) fn additional_host_bytes() -> usize {
    // Internal constructors/forwarding destructure full owning values. The
    // enclosing sequence separately calls the caller-frame helper below.
    4 * size_of::<FutureNativeSingleton<'static>>()
        + 4 * size_of::<ReadyNativeSingleton<'static>>()
        + 4 * size_of::<ClaimedSource<'static>>()
        + 4 * size_of::<Result<FutureNativeSingleton<'static>>>()
        + 4 * size_of::<
            core::result::Result<ReadyNativeSingleton<'static>, NativeCompletionError<'static>>,
        >()
        + 4 * size_of::<
            core::result::Result<
                (
                    VerifiedNativeSingleton<'static>,
                    PreparedNativeSingleton<'static>,
                ),
                NativeSuccessorError<'static>,
            >,
        >()
        + 4 * size_of::<NativeShakeSuccessor>()
        + 4 * size_of::<Result<OuterContinuationCapacity>>()
        + 4 * size_of::<OuterContinuationCapacity>()
        + 4 * size_of::<Requirements>()
        + 4 * size_of::<Bytes>()
        + 4 * size_of::<Result<()>>()
}

impl<'request> FutureNativeSingleton<'request> {
    /// Additional caller frames for a fixed sequence, beyond the source owner
    /// and this module's internal frames. The caller must charge this before
    /// constructing any future and before deriving the first PCS capacity.
    pub(crate) fn additional_sequence_caller_host_bytes(max_successors: usize) -> Result<usize> {
        if !(1..=2).contains(&max_successors) {
            return Err(Error::Source);
        }
        let mut bytes = 0usize;
        for value in [
            2 * size_of::<FutureNativeSingleton<'static>>(),
            2 * size_of::<ReadyNativeSingleton<'static>>(),
            2 * size_of::<Option<FutureNativeSingleton<'static>>>(),
            2 * size_of::<Option<ReadyNativeSingleton<'static>>>(),
            2 * size_of::<Result<FutureNativeSingleton<'static>>>(),
            2 * size_of::<
                core::result::Result<ReadyNativeSingleton<'static>, NativeCompletionError<'static>>,
            >(),
            4 * size_of::<
                core::result::Result<
                    (
                        VerifiedNativeSingleton<'static>,
                        PreparedNativeSingleton<'static>,
                    ),
                    NativeSuccessorError<'static>,
                >,
            >(),
            2 * size_of::<(
                VerifiedNativeSingleton<'static>,
                PreparedNativeSingleton<'static>,
            )>(),
            4 * size_of::<NativeCompletionError<'static>>(),
            4 * size_of::<NativeSuccessorError<'static>>(),
        ] {
            bytes = bytes.checked_add(value).ok_or(Error::Overflow)?;
        }
        bytes.checked_mul(max_successors).ok_or(Error::Overflow)
    }

    /// Reserve every future source/preparation/output/report/verification and
    /// bookkeeping owner before the first phase derives its original PCS size.
    pub(crate) fn reserve_before_native(
        owner: &'request ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        future_index(owner, index)?;
        if !owner.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let source = SourcePlan::new(owner, index)?;
        let original = ledger
            .admit_phase(source.requirements)
            .map_err(|_| Error::Admission)?;
        let source = source.claim_for(owner, index, original, ledger)?;
        Ok(Self {
            source,
            ledger: ledger.clone(),
        })
    }

    /// Bind to the actual unattempted first owner, not a copied numeric budget.
    /// No new reservation, source allocation, environment query or plan follows.
    pub(crate) fn complete_before_native(
        self,
        first: &PreparedNativeSingleton<'request>,
    ) -> core::result::Result<ReadyNativeSingleton<'request>, NativeCompletionError<'request>> {
        let checked = (|| -> Result<OuterContinuationCapacity> {
            future_index(self.source.owner, self.source.index)?;
            if !core::ptr::eq(self.source.owner, first.owner)
                || first.index != 0
                || !first.owner.belongs_to(&self.ledger)
                || !self.source.preparation.is_for(
                    self.source.owner,
                    self.source.index,
                    &first.ledger,
                )
                || !self.source.verification.belongs_to(&first.ledger)
                || self.source.verification.requirements()
                    != VerificationPlan::component_requirement()
                || !self.source.bookkeeping.belongs_to(&first.ledger)
                || self.source.bookkeeping.requirements() != bookkeeping_requirement()?
            {
                return Err(Error::Authority);
            }
            first.outer_continuation_capacity()
        })();
        let capacity = match checked {
            Ok(value) => value,
            Err(error) => return Err((error, self)),
        };
        let Self { source, ledger } = self;
        let ClaimedSource {
            owner,
            index,
            preparation,
            output,
            verifier,
            verification,
            bookkeeping,
        } = source;
        match first.phase.preissue_outer_host_successor(
            preparation.census(),
            preparation.reservation(),
            output,
            &verification,
            &ledger,
        ) {
            Ok(successor) => Ok(ReadyNativeSingleton {
                owner,
                index,
                successor,
                preparation,
                verifier,
                verification,
                startup: capacity.startup,
                ledger,
                bookkeeping,
            }),
            Err((_, output)) => Err((
                Error::Phase,
                Self {
                    source: ClaimedSource {
                        owner,
                        index,
                        preparation,
                        output,
                        verifier,
                        verification,
                        bookkeeping,
                    },
                    ledger,
                },
            )),
        }
    }
}

impl<'request> ReadyNativeSingleton<'request> {
    /// Consume only the correlated privately issued verified predecessor and
    /// its actual original retirement. Missing/reordered/different-request
    /// inputs refuse before moving any original claim and return both owners.
    pub(crate) fn finish_native(
        self,
        previous: VerifiedNativeSingletonWithOriginals<'request>,
    ) -> core::result::Result<
        (
            VerifiedNativeSingleton<'request>,
            PreparedNativeSingleton<'request>,
        ),
        NativeSuccessorError<'request>,
    > {
        let checked = (|| -> Result<()> {
            future_index(self.owner, self.index)?;
            let previous_index = self.index.checked_sub(1).ok_or(Error::Source)?;
            if !previous
                .verified
                .is_for(self.owner, previous_index, &self.ledger)
                || !previous.originals.belongs_to(&self.ledger)
                || previous.originals.retirement() != previous.verified.retirement()
                || previous.originals.startup_requirements()
                    != Requirements::single(Category::PhaseScratch, self.startup)
                || !self
                    .preparation
                    .is_for(self.owner, self.index, &self.ledger)
                || !self.verification.belongs_to(&self.ledger)
                || self.verification.requirements() != VerificationPlan::component_requirement()
                || !self.bookkeeping.belongs_to(&self.ledger)
                || self.bookkeeping.requirements() != bookkeeping_requirement()?
            {
                return Err(Error::Authority);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, self, previous));
        }
        let Self {
            owner,
            index,
            successor,
            preparation,
            verifier,
            verification,
            startup,
            ledger,
            bookkeeping,
        } = self;
        let VerifiedNativeSingletonWithOriginals {
            verified,
            originals,
        } = previous;
        match PendingRuntime::restore_native_successor_outer_host_v1(
            successor,
            originals,
            preparation.reservation(),
            &verification,
            &ledger,
            Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            },
        ) {
            Ok((runtime, phase)) => Ok((
                verified,
                PreparedNativeSingleton {
                    owner,
                    index,
                    phase,
                    preparation,
                    runtime,
                    verifier,
                    verification,
                    ledger,
                    bookkeeping,
                },
            )),
            Err((_, successor, originals)) => Err((
                Error::Runtime,
                Self {
                    owner,
                    index,
                    successor,
                    preparation,
                    verifier,
                    verification,
                    startup,
                    ledger,
                    bookkeeping,
                },
                VerifiedNativeSingletonWithOriginals {
                    verified,
                    originals,
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests;
