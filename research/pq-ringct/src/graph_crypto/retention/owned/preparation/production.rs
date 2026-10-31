//! Closed one-shot singleton producer. Source planning and original claims
//! precede runtime startup; the same phase owners survive exact retirement.
//! This is a native research component, not complete transaction acceptance.
use super::{NativePreparationPlan, PendingNativePreparation};
use crate::{
    component_tree::shake_verification_memory::{
        Plan as VerificationPlan, VerificationFailure, VerificationReceipt,
    },
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    graph_crypto::{Payload, ReservedShakeRequest},
    opencl::{Limits, PendingRuntime},
    shake_air::{
        lane::{batch::ShakeSegmentAir, LaneShakeProof},
        PUBLIC_VALUES,
    },
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Retirement,
        native_gpu::{
            owned_shake::NativeShakePhase,
            shake_output::{OwnedShakeProof, PendingShakeOutput, ShakeOutputPlan},
        },
    },
    config::Val,
    proving::Report,
};

const HOST_BYTES: u64 = 32 << 30;
const DEVICE_BYTES: u64 = 8 << 30;
const MAX_ROWS: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authority,
    Source,
    Admission,
    Preparation,
    Output,
    Phase,
    Runtime,
    Retirement,
    Verification,
    Overflow,
}
type Result<T> = core::result::Result<T, Error>;

/// Source-only plan. A fixed singleton is selected from the original immutable
/// request before any environment/physical inspection or runtime construction.
struct SourcePlan<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    preparation: NativePreparationPlan<'request>,
    output: ShakeOutputPlan,
    verifier: VerificationPlan,
    requirements: Requirements,
}

fn include(total: &mut Requirements, component: Requirements) -> Result<()> {
    for category in Category::ALL {
        total
            .add(category, component.get(category))
            .map_err(|_| Error::Overflow)?;
    }
    Ok(())
}

/// A separate original claim owns this orchestration's inline records and its
/// one exact public Vec during independent verification. No output claim or
/// runtime/preparation overlap is credited, including embedded owner headers.
fn bookkeeping_requirement() -> Result<Requirements> {
    let mut bytes = PUBLIC_VALUES
        .checked_mul(size_of::<Val>())
        .ok_or(Error::Overflow)?;
    for item in [
        size_of::<SourcePlan<'static>>(),
        size_of::<ClaimedSource<'static>>(),
        size_of::<PreparedNativeSingleton<'static>>(),
        size_of::<VerifiedNativeSingleton<'static>>(),
        size_of::<VerificationReceipt>(),
        size_of::<VerificationFailure>(),
        size_of::<Retirement>(),
        size_of::<Vec<Val>>(),
        size_of::<Ledger>(),
        4 * size_of::<Requirements>(),
        2 * size_of::<Error>(),
        continuity::additional_host_bytes(),
    ] {
        bytes = bytes.checked_add(item).ok_or(Error::Overflow)?;
    }
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

impl<'request> SourcePlan<'request> {
    fn new(owner: &'request ReservedShakeRequest, index: usize) -> Result<Self> {
        let preparation = NativePreparationPlan::new(owner, index).map_err(|_| Error::Source)?;
        if !matches!(preparation.air, ShakeSegmentAir::Single(_))
            || preparation.census().geometry().permutations() != 1
            || preparation.census().geometry().rows() != 4096
            || preparation.census().geometry().width() != 517
        {
            return Err(Error::Source);
        }
        let output = ShakeOutputPlan::new(preparation.census()).map_err(|_| Error::Output)?;
        let verifier = VerificationPlan::new(preparation.air).map_err(|_| Error::Verification)?;
        let mut requirements = preparation.requirements();
        for component in [
            output.proof_requirement(),
            output.report_requirement(),
            VerificationPlan::component_requirement(),
            bookkeeping_requirement()?,
        ] {
            include(&mut requirements, component)?;
        }
        Ok(Self {
            owner,
            index,
            preparation,
            output,
            verifier,
            requirements,
        })
    }

    fn is_for(&self, owner: &ReservedShakeRequest, index: usize) -> bool {
        core::ptr::eq(self.owner, owner)
            && self.index == index
            && self.preparation.is_for(owner, index)
    }

    /// Split only the original complete source claim. Runtime/PCS/OpenCL
    /// owners are separately admitted before any start/record/proof operation.
    fn claim_for(
        self,
        owner: &ReservedShakeRequest,
        index: usize,
        mut original: Reservation,
        ledger: &Ledger,
    ) -> Result<ClaimedSource<'request>> {
        let allowance = ledger.snapshot().allowance;
        if !self.is_for(owner, index)
            || !owner.belongs_to(ledger)
            || !original.belongs_to(ledger)
            || original.requirements() != self.requirements
            || allowance.host == 0
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device != DEVICE_BYTES
        {
            return Err(Error::Authority);
        }
        let preparation_token = original
            .split(self.preparation.requirements())
            .map_err(|_| Error::Authority)?;
        let proof = original
            .split(self.output.proof_requirement())
            .map_err(|_| Error::Authority)?;
        let report = original
            .split(self.output.report_requirement())
            .map_err(|_| Error::Authority)?;
        let verification = original
            .split(VerificationPlan::component_requirement())
            .map_err(|_| Error::Authority)?;
        if original.requirements() != bookkeeping_requirement()? {
            return Err(Error::Authority);
        }
        let preparation = self
            .preparation
            .claim_for(owner, index, preparation_token, ledger)
            .map_err(|_| Error::Preparation)?;
        let output = self
            .output
            .claim(proof, report, ledger)
            .map_err(|_| Error::Output)?;
        Ok(ClaimedSource {
            owner: self.owner,
            index: self.index,
            preparation,
            output,
            verifier: self.verifier,
            verification,
            bookkeeping: original,
        })
    }
}

struct ClaimedSource<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    preparation: PendingNativePreparation<'request>,
    output: PendingShakeOutput,
    verifier: VerificationPlan,
    verification: Reservation,
    bookkeeping: Reservation,
}

/// This owner can execute only its retained singleton once. Its source token
/// cannot be retargeted; no caller supplies an AIR, callback, witness generator,
/// policy, proof, or numeric memory allowance.
pub(crate) struct PreparedNativeSingleton<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    phase: NativeShakePhase,
    preparation: PendingNativePreparation<'request>,
    runtime: PendingRuntime,
    verifier: VerificationPlan,
    verification: Reservation,
    ledger: Ledger,
    bookkeeping: Reservation,
}

impl<'request> PreparedNativeSingleton<'request> {
    /// # Safety
    /// The dedicated coordinator guard must keep the environment immutable and
    /// exclude unrelated GPU startup/shutdown/work from this preflight through
    /// produce/retirement, or through destruction without dispatch.
    pub(crate) unsafe fn new(
        owner: &'request ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        if !owner.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let source = SourcePlan::new(owner, index)?;
        let original = ledger
            .admit_phase(source.requirements)
            .map_err(|_| Error::Admission)?;
        let claimed = source.claim_for(owner, index, original, ledger)?;
        let mut runtime = PendingRuntime::reserve(
            ledger,
            Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            },
        )
        .map_err(|_| Error::Runtime)?;
        if !runtime.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        // SAFETY: inherited from this entry's explicit guarded-process contract.
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        // The original prep/runtime/output/verifier claims are already held.
        // The core source planner admits its complete PCS/OpenCL partitions
        // before any runtime start, AIR recording, entropy or GPU dispatch.
        let phase = unsafe {
            NativeShakePhase::new(
                claimed.preparation.census(),
                claimed.preparation.reservation(),
                preflight.reservation(),
                claimed.output,
                &claimed.verification,
                ledger,
            )
        }
        .map_err(|_| Error::Phase)?;
        drop(preflight);
        Ok(Self {
            owner: claimed.owner,
            index: claimed.index,
            phase,
            preparation: claimed.preparation,
            runtime,
            verifier: claimed.verifier,
            verification: claimed.verification,
            ledger: ledger.clone(),
            bookkeeping: claimed.bookkeeping,
        })
    }

    /// # Safety
    /// The same sealed-process contract as new must remain valid until exact
    /// original runtime retirement. Native proof generation is always fresh
    /// and GPU-required; there is no retry or fallback after an attempt starts.
    pub(crate) unsafe fn produce(mut self) -> Result<VerifiedNativeSingleton<'request>> {
        if !self.owner.belongs_to(&self.ledger)
            || !self
                .preparation
                .is_for(self.owner, self.index, &self.ledger)
            || !self.runtime.belongs_to(&self.ledger)
            || !self.verification.belongs_to(&self.ledger)
            || self.verification.requirements() != VerificationPlan::component_requirement()
            || !self.bookkeeping.belongs_to(&self.ledger)
            || self.bookkeeping.requirements() != bookkeeping_requirement()?
        {
            return Err(Error::Authority);
        }
        let Payload::Shake(input) = &self.owner.request().payload else {
            return Err(Error::Source);
        };
        let expected_geometry = self.preparation.census().geometry();
        // SAFETY: caller retains the same immutable/environment/exclusive guard.
        let session = unsafe { self.runtime.start() }.map_err(|_| Error::Runtime)?;
        // Errors leave this local scope first, releasing all core/runtime and
        // exclusive recording borrows before explicit retirement below.
        let attempted = (|| {
            let checked = session
                .check_reserved_runtime(&self.ledger)
                .map_err(|_| Error::Runtime)?;
            let runtime = checked.borrow_core().map_err(|_| Error::Runtime)?;
            let recording = self
                .preparation
                .record(&self.ledger)
                .map_err(|_| Error::Preparation)?;
            // SAFETY: this closed call retains the exact original runtime and
            // all complete phase claims; only the original request bytes enter.
            unsafe {
                self.phase.produce(
                    recording,
                    input,
                    runtime.runtime(),
                    runtime.reservation(),
                    &self.verification,
                )
            }
            .map_err(|_| Error::Phase)
        })();
        let retirement = session.finish_reserved().map_err(|_| Error::Runtime)?;
        // Core retirement already aborts uncertain cleanup. Defend the same
        // ownership rule here before any phase reservation could be released.
        if !retirement_is_complete(retirement) {
            std::process::abort();
        }
        if retirement.managed_peak_bytes == 0 || retirement.managed_peak_bytes as u64 > DEVICE_BYTES
        {
            return Err(Error::Retirement);
        }
        // These owners outlive the exact runtime on both success and failure.
        drop(self.phase);
        drop(self.preparation);
        let output = attempted?;
        if !output.belongs_to(&self.ledger) || output.geometry() != expected_geometry {
            return Err(Error::Authority);
        }
        let air = self
            .owner
            .request()
            .shake_partition()
            .and_then(|p| p.segments().get(self.index))
            .ok_or(Error::Source)?;
        let verification = verify_output(
            self.verifier,
            air,
            &output,
            self.verification,
            &self.bookkeeping,
            &self.ledger,
        )?;
        Ok(VerifiedNativeSingleton {
            output,
            owner: self.owner,
            index: self.index,
            verification,
            retirement,
            bookkeeping: self.bookkeeping,
        })
    }
}

fn retirement_is_complete(retirement: Retirement) -> bool {
    retirement.managed_live_bytes == 0
        && retirement.host_tree_live_bytes == 0
        && retirement.lease_released
}

fn verify_output(
    plan: VerificationPlan,
    air: &ShakeSegmentAir,
    output: &OwnedShakeProof,
    verification: Reservation,
    bookkeeping: &Reservation,
    ledger: &Ledger,
) -> Result<VerificationReceipt> {
    if !output.belongs_to(ledger)
        || !bookkeeping.belongs_to(ledger)
        || bookkeeping.requirements() != bookkeeping_requirement()?
        || !verification.belongs_to(ledger)
        || verification.requirements() != VerificationPlan::component_requirement()
    {
        return Err(Error::Authority);
    }
    let artifact = output.artifact();
    let mut public = Vec::new();
    public
        .try_reserve_exact(PUBLIC_VALUES)
        .map_err(|_| Error::Admission)?;
    if public.capacity() != PUBLIC_VALUES {
        return Err(Error::Admission);
    }
    public.extend_from_slice(&artifact.public_values);
    plan.admit_pre_reserved(
        air,
        &artifact.proof,
        &public,
        output.proof_reservation(),
        verification,
        ledger,
    )
    .map_err(|_| Error::Verification)?
    .verify()
    .map_err(|_| Error::Verification)
}

/// The core proof/report keep their original reservations. Research identity,
/// independent-verification receipt and exact retirement stay inline under a
/// separate original claim, destroyed after all output payloads.
pub(crate) struct VerifiedNativeSingleton<'request> {
    output: OwnedShakeProof,
    owner: &'request ReservedShakeRequest,
    index: usize,
    verification: VerificationReceipt,
    retirement: Retirement,
    bookkeeping: Reservation,
}

impl VerifiedNativeSingleton<'_> {
    pub(crate) fn artifact(&self) -> &LaneShakeProof {
        self.output.artifact()
    }
    pub(crate) fn report(&self) -> &Report {
        self.output.report()
    }
    pub(crate) fn verification(&self) -> VerificationReceipt {
        self.verification
    }
    pub(crate) fn retirement(&self) -> Retirement {
        self.retirement
    }
    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn is_for(
        &self,
        owner: &ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> bool {
        core::ptr::eq(self.owner, owner)
            && self.index == index
            && owner.belongs_to(ledger)
            && self.output.belongs_to(ledger)
            && self.bookkeeping.belongs_to(ledger)
            && bookkeeping_requirement().is_ok_and(|r| self.bookkeeping.requirements() == r)
            && NativePreparationPlan::new(owner, index)
                .is_ok_and(|p| p.census().geometry() == self.output.geometry())
            && retirement_is_complete(self.retirement)
    }
}

#[cfg(test)]
mod tests;

mod attachment;
pub(crate) use attachment::MetadataOwner as PreparedNativeSingletonAttachment;
pub(in crate::graph_crypto::retention::owned) use attachment::NativeSingletonChild;

mod host;

mod continuity;
pub(crate) use continuity::{
    FutureNativeSingleton, NativeCompletionError, NativeSuccessorError, OuterContinuationCapacity,
    ReadyNativeSingleton, VerifiedNativeSingletonWithOriginals,
};

mod workspace;
pub(in crate::graph_crypto::retention::owned) use workspace::NativeSegmentChild;
pub(crate) use workspace::{
    ActiveHashxOuter, CompletedNativeHashx, HashxOuterStep, PendingNativeHashx,
    PreissuedHashxOuter, PreparedHashxOuter, PreparedNativeHashx, ProjectedHashxQuota,
    RetiredHashxOuter, RetiredHashxOuterOriginals,
};
