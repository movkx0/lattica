//! Closed all-native-first HashX component with original scratch succession.
//! This grants no transaction/request-recursive dispatch authority. Every AIR
//! recording, configuration, trace and proof is fresh; no prepared artifact is cached.
use super::*;
use crate::execution::retained_resources::Snapshot;
use crate::graph_crypto::{RequestDescriptor, ReservedNativeChild};
use core::mem::size_of_val;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::{
    NativeHashxPhase, NativeHashxSuccessor, RetiredHashxReservations,
};

const SEGMENTS: usize = 10;
const COUNTS: [usize; SEGMENTS] = [16, 16, 16, 16, 16, 16, 16, 8, 1, 1];

struct SegmentSource<'request> {
    preparation: NativePreparationPlan<'request>,
    output: ShakeOutputPlan,
    verifier: VerificationPlan,
}

/// Entire source, all outputs/attachments, one preparation and one verifier
/// component are admitted before the actual first native PCS capacity is derived.
pub(crate) struct PendingNativeHashx<'request> {
    owner: &'request ReservedShakeRequest,
    preparation: PendingNativePreparation<'request>,
    future: [Option<SegmentSource<'request>>; SEGMENTS],
    outputs: [Option<PendingShakeOutput>; SEGMENTS],
    verifiers: [Option<VerificationPlan>; SEGMENTS],
    retained: [Option<Reservation>; SEGMENTS],
    attachments: [Option<attachment::PreparedAttachment<'request>>; SEGMENTS],
    verification: Reservation,
    outer_bridge: Option<Reservation>,
    outer_sequence: Option<Reservation>,
    ledger: Ledger,
    bookkeeping: Reservation,
}

struct PreparedNativeSegment<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    runtime: PendingRuntime,
    phase: NativeHashxPhase,
    preparation: PendingNativePreparation<'request>,
    verifier: VerificationPlan,
    verification: Reservation,
    retained: Reservation,
}

struct PreissuedNativeSegment<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    preparation: NativePreparationPlan<'request>,
    successor: NativeHashxSuccessor,
    verifier: VerificationPlan,
    retained: Reservation,
}

/// Only genuine retired and independently verified native production issues it.
/// The private fields cannot be separated into caller-provided restore parts.
struct NativeSegmentCompletion<'request> {
    verified: VerifiedNativeSegment<'request>,
    originals: RetiredHashxReservations,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
}

pub(crate) struct PreparedNativeHashx<'request> {
    owner: &'request ReservedShakeRequest,
    current: Option<PreparedNativeSegment<'request>>,
    successors: [Option<PreissuedNativeSegment<'request>>; SEGMENTS - 1],
    attachments: [Option<attachment::PreparedAttachment<'request>>; SEGMENTS],
    outer_bridge: Option<Reservation>,
    outer_bound: bool,
    outer_enabled: bool,
    outer_sequence: Option<Reservation>,
    outer_sequence_enabled: bool,
    ledger: Ledger,
    bookkeeping: Reservation,
}

struct ExhaustedScratch<'request> {
    originals: RetiredHashxReservations,
    preparation: PendingNativePreparation<'request>,
    verification: Reservation,
}

/// A terminal component result, not a further native continuation. All ten
/// original outputs are retained. No raw scratch-token accessor exists.
pub(crate) struct CompletedNativeHashx<'request> {
    owner: &'request ReservedShakeRequest,
    segments: [Option<VerifiedNativeSegment<'request>>; SEGMENTS],
    attachments: [Option<attachment::PreparedAttachment<'request>>; SEGMENTS],
    scratch: ExhaustedScratch<'request>,
    next_child: usize,
    ledger: Ledger,
    bookkeeping: Reservation,
}

/// Original immutable native artifact/report and retained identity claim.
/// Only this module can construct it after actual independent verification.
struct VerifiedNativeSegment<'request> {
    output: OwnedShakeProof,
    owner: &'request ReservedShakeRequest,
    index: usize,
    verification: VerificationReceipt,
    retirement: Retirement,
    retained: Reservation,
}

type TransitionResult<'request> = core::result::Result<
    (
        VerifiedNativeSegment<'request>,
        PreparedNativeSegment<'request>,
    ),
    (
        Error,
        PreissuedNativeSegment<'request>,
        NativeSegmentCompletion<'request>,
    ),
>;

fn limits() -> Limits {
    Limits {
        host_bytes: HOST_BYTES,
        device_bytes: DEVICE_BYTES,
        max_rows: MAX_ROWS,
    }
}

fn checked_frames<T>(copies: usize) -> Result<usize> {
    size_of::<T>().checked_mul(copies).ok_or(Error::Overflow)
}

fn retained_requirement() -> Result<Requirements> {
    let bytes = checked_frames::<VerifiedNativeSegment<'static>>(8)?
        .checked_add(8 * size_of::<VerificationReceipt>())
        .and_then(|b| b.checked_add(8 * size_of::<Retirement>()))
        .and_then(|b| b.checked_add(8 * size_of::<Requirements>()))
        .ok_or(Error::Overflow)?;
    Ok(Requirements::single(
        Category::RegisteredMetadata,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

fn bookkeeping_requirement() -> Result<Requirements> {
    // Whole values and complete owning Result/tuple/array slots are additive.
    // Eight copies cover source/caller/return/destructure and closure slots;
    // no inlining, tail-call or move-elision credit is taken. Dynamic native
    // source/verifier helper storage is charged by its own exact census below.
    let parts = [
        checked_frames::<PendingNativeHashx<'static>>(8)?,
        checked_frames::<PreparedNativeHashx<'static>>(8)?,
        checked_frames::<CompletedNativeHashx<'static>>(8)?,
        checked_frames::<Result<PendingNativeHashx<'static>>>(8)?,
        checked_frames::<Result<PreparedNativeHashx<'static>>>(8)?,
        checked_frames::<Result<CompletedNativeHashx<'static>>>(8)?,
        // The default produce -> produce_inner forwarding frame is additional
        // even when no outer bridge is selected. Take no move-elision credit.
        checked_frames::<PreparedNativeHashx<'static>>(8)?,
        checked_frames::<Result<CompletedNativeHashx<'static>>>(8)?,
        checked_frames::<Option<&PreissuedHashxOuter<'static>>>(8)?,
        // The default entry also refuses any detached sequence opt-in before
        // dispatch. Charge its additional optional-claim and scalar checks.
        checked_frames::<Option<&Reservation>>(8)?,
        checked_frames::<bool>(8)?,
        checked_frames::<Result<()>>(8)?,
        checked_frames::<PreparedNativeSegment<'static>>(8)?,
        checked_frames::<PreissuedNativeSegment<'static>>(8)?,
        checked_frames::<NativeSegmentCompletion<'static>>(8)?,
        checked_frames::<ExhaustedScratch<'static>>(8)?,
        checked_frames::<Result<NativeSegmentCompletion<'static>>>(8)?,
        checked_frames::<TransitionResult<'static>>(8)?,
        checked_frames::<[Option<SegmentSource<'static>>; SEGMENTS]>(8)?,
        checked_frames::<[Option<VerifiedNativeSegment<'static>>; SEGMENTS]>(8)?,
        checked_frames::<[Option<PreissuedNativeSegment<'static>>; SEGMENTS - 1]>(8)?,
        checked_frames::<[Option<attachment::PreparedAttachment<'static>>; SEGMENTS]>(8)?,
        checked_frames::<[Option<PendingShakeOutput>; SEGMENTS]>(8)?,
        checked_frames::<[Option<VerificationPlan>; SEGMENTS]>(8)?,
        checked_frames::<[Option<Reservation>; SEGMENTS]>(8)?,
        checked_frames::<core::result::Result<NativePreparationPlan<'static>, super::super::Error>>(
            8,
        )?,
        checked_frames::<
            core::result::Result<
                ShakeOutputPlan,
                lattica_prover_p3::block_v2::native_gpu::shake_output::Error,
            >,
        >(8)?,
        checked_frames::<
            core::result::Result<
                PendingShakeOutput,
                lattica_prover_p3::block_v2::native_gpu::shake_output::Error,
            >,
        >(8)?,
        checked_frames::<
            core::result::Result<
                NativeShakePhase,
                lattica_prover_p3::block_v2::native_gpu::owned_shake::Error,
            >,
        >(8)?,
        checked_frames::<core::result::Result<VerificationPlan, &'static str>>(8)?,
        checked_frames::<
            core::result::Result<
                crate::component_tree::shake_verification_memory::AdmittedVerification<'static>,
                &'static str,
            >,
        >(8)?,
        checked_frames::<(
            VerifiedNativeSegment<'static>,
            PreparedNativeSegment<'static>,
        )>(8)?,
        checked_frames::<Option<Requirements>>(8)?,
        checked_frames::<Result<Requirements>>(8)?,
        checked_frames::<Result<OwnedShakeProof>>(8)?,
        checked_frames::<Result<(VerificationReceipt, Reservation)>>(8)?,
        checked_frames::<Result<ReservedNativeChild<'static>>>(8)?,
        checked_frames::<Snapshot>(16)?,
        checked_frames::<Requirements>(32)?,
        checked_frames::<Reservation>(16)?,
        checked_frames::<Ledger>(16)?,
        checked_frames::<Limits>(8)?,
        checked_frames::<Vec<Val>>(8)?,
        checked_frames::<[usize; SEGMENTS]>(8)?,
        checked_frames::<[Val; PUBLIC_VALUES]>(4)?,
        // Exact native, runtime-restoration and B049 full verifier caller frames.
        NativeHashxPhase::additional_host_bytes().map_err(|_| Error::Overflow)?,
        PendingRuntime::hashx_restoration_host_bytes(),
        VerificationPlan::retaining_original_caller_host_bytes().map_err(|_| Error::Overflow)?,
        capacity::additional_host_bytes()?,
        quota_projection::additional_host_bytes()?,
        PUBLIC_VALUES * size_of::<Val>(),
        // Fixed iterator/closure/checked-arithmetic locals and bounded diagnostic
        // texts. Native planner String storage is additionally in core's census.
        32 << 10,
    ];
    let bytes = parts.iter().try_fold(size_of_val(&parts) * 8, |a, &b| {
        a.checked_add(b).ok_or(Error::Overflow)
    })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

fn source(owner: &ReservedShakeRequest, ledger: &Ledger) -> Result<()> {
    let allowance = ledger.snapshot().allowance;
    if !owner.belongs_to(ledger)
        || allowance.host == 0
        || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
        || allowance.device != DEVICE_BYTES
    {
        return Err(Error::Authority);
    }
    let RequestDescriptor::Shake(descriptor) = owner.request().descriptor() else {
        return Err(Error::Source);
    };
    let bounds = owner.bounds();
    if descriptor.input_len != 16_416
        || descriptor.output_len != 137
        || bounds.selected_segments != SEGMENTS
        || bounds.total_permutations != 122
        || owner.request().segments().len() != SEGMENTS
    {
        return Err(Error::Source);
    }
    let mut first = 0usize;
    for (index, (&count, info)) in COUNTS.iter().zip(owner.request().segments()).enumerate() {
        if info.first_unit != first
            || info.units != count
            || info.height != count * 4096
            || info.width != if index < 8 { 518 } else { 517 }
        {
            return Err(Error::Source);
        }
        first = first.checked_add(count).ok_or(Error::Overflow)?;
    }
    if first != 122 {
        return Err(Error::Source);
    }
    Ok(())
}

fn check_bookkeeping(bookkeeping: &Reservation, ledger: &Ledger) -> Result<()> {
    if !bookkeeping.belongs_to(ledger) || bookkeeping.requirements() != bookkeeping_requirement()? {
        return Err(Error::Authority);
    }
    Ok(())
}

impl<'request> PendingNativeHashx<'request> {
    pub(crate) fn reserve_before_native(
        owner: &'request ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self> {
        source(owner, ledger)?;
        let bookkeeping = ledger
            .admit_phase(bookkeeping_requirement()?)
            .map_err(|_| Error::Admission)?;
        let mut future: [Option<SegmentSource<'request>>; SEGMENTS] =
            core::array::from_fn(|_| None);
        let mut requirements = VerificationPlan::component_requirement();
        let mut preparation_requirement = None;
        for (index, slot) in future.iter_mut().enumerate() {
            let preparation =
                NativePreparationPlan::new(owner, index).map_err(|_| Error::Source)?;
            match preparation_requirement {
                None => {
                    preparation_requirement = Some(preparation.requirements());
                    include(&mut requirements, preparation.requirements())?;
                }
                Some(original) if original == preparation.requirements() => {}
                Some(_) => return Err(Error::Preparation),
            }
            let output = ShakeOutputPlan::new(preparation.census()).map_err(|_| Error::Output)?;
            let verifier =
                VerificationPlan::new(preparation.air).map_err(|_| Error::Verification)?;
            for part in [
                output.proof_requirement(),
                output.report_requirement(),
                retained_requirement()?,
            ] {
                include(&mut requirements, part)?;
            }
            *slot = Some(SegmentSource {
                preparation,
                output,
                verifier,
            });
        }
        let mut original = ledger
            .admit_phase(requirements)
            .map_err(|_| Error::Admission)?;
        let verification = original
            .split(VerificationPlan::component_requirement())
            .map_err(|_| Error::Authority)?;
        let mut outputs = core::array::from_fn(|_| None);
        let mut verifiers = core::array::from_fn(|_| None);
        let mut retained = core::array::from_fn(|_| None);
        let mut attachments = core::array::from_fn(|_| None);
        for index in 0..SEGMENTS {
            let item = future[index].as_ref().ok_or(Error::Source)?;
            let proof = original
                .split(item.output.proof_requirement())
                .map_err(|_| Error::Authority)?;
            let report = original
                .split(item.output.report_requirement())
                .map_err(|_| Error::Authority)?;
            outputs[index] = Some(
                item.output
                    .claim(proof, report, ledger)
                    .map_err(|_| Error::Output)?,
            );
            verifiers[index] = Some(item.verifier);
            retained[index] = Some(
                original
                    .split(retained_requirement()?)
                    .map_err(|_| Error::Authority)?,
            );
            attachments[index] = Some(attachment::PreparedAttachment::reserve_before_native(
                owner, index, ledger,
            )?);
        }
        let first = future[0].take().ok_or(Error::Source)?;
        if original.requirements() != first.preparation.requirements() {
            return Err(Error::Authority);
        }
        let preparation = first
            .preparation
            .claim_for(owner, 0, original, ledger)
            .map_err(|_| Error::Preparation)?;
        Ok(Self {
            owner,
            preparation,
            future,
            outputs,
            verifiers,
            retained,
            attachments,
            verification,
            outer_bridge: None,
            outer_sequence: None,
            ledger: ledger.clone(),
            bookkeeping,
        })
    }

    /// Component-only source completion. A full request must separately retain
    /// all B compiler/parent/output closure before invoking this entry.
    /// # Safety
    /// The exact immutable outer_host_v1 environment and exclusive physical
    /// device guard must remain held through all runtime retirement/destruction.
    pub(crate) unsafe fn prepare(mut self) -> Result<PreparedNativeHashx<'request>> {
        source(self.owner, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        let mut runtime = PendingRuntime::reserve_outer_host_v1(&self.ledger, limits())
            .map_err(|_| Error::Runtime)?;
        if !runtime.belongs_to(&self.ledger) || runtime.reserved_tree_host_bytes() != 8 << 30 {
            return Err(Error::Authority);
        }
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        let phase = unsafe {
            NativeShakePhase::new_outer_host_v1(
                self.preparation.census(),
                self.preparation.reservation(),
                preflight.reservation(),
                self.outputs[0].take().ok_or(Error::Output)?,
                &self.verification,
                &self.ledger,
            )
        }
        .map_err(|_| Error::Phase)?;
        drop(preflight);
        let phase = NativeHashxPhase::new(phase, &self.bookkeeping, &self.ledger)
            .map_err(|_| Error::Phase)?;
        let mut successors = core::array::from_fn(|_| None);
        for index in 1..SEGMENTS {
            let item = self.future[index].take().ok_or(Error::Source)?;
            if item.preparation.requirements() != self.preparation.plan.requirements {
                return Err(Error::Preparation);
            }
            let successor = phase
                .preissue_successor(
                    item.preparation.census(),
                    self.preparation.reservation(),
                    self.outputs[index].take().ok_or(Error::Output)?,
                    &self.verification,
                    &self.ledger,
                )
                .map_err(|_| Error::Phase)?;
            successors[index - 1] = Some(PreissuedNativeSegment {
                owner: self.owner,
                index,
                preparation: item.preparation,
                successor,
                verifier: self.verifiers[index].take().ok_or(Error::Verification)?,
                retained: self.retained[index].take().ok_or(Error::Authority)?,
            });
        }
        let current = PreparedNativeSegment {
            owner: self.owner,
            index: 0,
            runtime,
            phase,
            preparation: self.preparation,
            verifier: self.verifiers[0].take().ok_or(Error::Verification)?,
            verification: self.verification,
            retained: self.retained[0].take().ok_or(Error::Authority)?,
        };
        Ok(PreparedNativeHashx {
            owner: self.owner,
            current: Some(current),
            successors,
            attachments: self.attachments,
            outer_bound: false,
            outer_enabled: self.outer_bridge.is_some(),
            outer_bridge: self.outer_bridge,
            outer_sequence_enabled: self.outer_sequence.is_some(),
            outer_sequence: self.outer_sequence,
            ledger: self.ledger,
            bookkeeping: self.bookkeeping,
        })
    }
}

impl VerifiedNativeSegment<'_> {
    fn is_for(&self, owner: &ReservedShakeRequest, index: usize, ledger: &Ledger) -> bool {
        core::ptr::eq(self.owner, owner)
            && self.index == index
            && owner.belongs_to(ledger)
            && self.output.belongs_to(ledger)
            && self.retained.belongs_to(ledger)
            && retained_requirement().is_ok_and(|required| self.retained.requirements() == required)
            && retirement_is_complete(self.retirement)
            && self.retirement.managed_peak_bytes > 0
            && self.retirement.managed_peak_bytes as u64 <= DEVICE_BYTES
    }
}

fn verify_retaining(
    plan: VerificationPlan,
    preparation: &PendingNativePreparation<'_>,
    output: &OwnedShakeProof,
    verification: Reservation,
    bookkeeping: &Reservation,
    ledger: &Ledger,
) -> Result<(VerificationReceipt, Reservation)> {
    check_bookkeeping(bookkeeping, ledger)?;
    if !preparation.is_for(preparation.plan.owner, preparation.index(), ledger)
        || !output.belongs_to(ledger)
        || output.geometry() != preparation.census().geometry()
        || !verification.belongs_to(ledger)
        || verification.requirements() != VerificationPlan::component_requirement()
    {
        return Err(Error::Authority);
    }
    let mut public = Vec::new();
    public
        .try_reserve_exact(PUBLIC_VALUES)
        .map_err(|_| Error::Admission)?;
    if public.capacity() != PUBLIC_VALUES {
        return Err(Error::Admission);
    }
    public.extend_from_slice(&output.artifact().public_values);
    let admitted = plan
        .admit_pre_reserved(
            preparation.air(),
            &output.artifact().proof,
            &public,
            output.proof_reservation(),
            verification,
            ledger,
        )
        .map_err(|_| Error::Verification)?;
    let result = admitted.verify_retaining_original();
    // B049 has already destroyed verifier/configuration payloads. End this
    // caller's original public allocation before returning the shared component.
    drop(public);
    match result {
        Ok((receipt, original)) => Ok((receipt, original)),
        Err((_, original)) => {
            drop(original);
            Err(Error::Verification)
        }
    }
}

impl<'request> PreparedNativeSegment<'request> {
    unsafe fn produce(
        mut self,
        bookkeeping: &Reservation,
        ledger: &Ledger,
    ) -> Result<NativeSegmentCompletion<'request>> {
        check_bookkeeping(bookkeeping, ledger)?;
        if !self.preparation.is_for(self.owner, self.index, ledger)
            || !self.runtime.belongs_to(ledger)
            || !self.verification.belongs_to(ledger)
            || self.verification.requirements() != VerificationPlan::component_requirement()
            || !self.retained.belongs_to(ledger)
            || self.retained.requirements() != retained_requirement()?
        {
            return Err(Error::Authority);
        }
        let Payload::Shake(input) = &self.owner.request().payload else {
            return Err(Error::Source);
        };
        let expected = self.preparation.census().geometry();
        let session = unsafe { self.runtime.start() }.map_err(|_| Error::Runtime)?;
        let attempted = (|| {
            let checked = session
                .check_reserved_runtime(ledger)
                .map_err(|_| Error::Runtime)?;
            let runtime = checked.borrow_core().map_err(|_| Error::Runtime)?;
            let recording = self
                .preparation
                .record(ledger)
                .map_err(|_| Error::Preparation)?;
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
        // All borrowed runtime/recording/configuration locals ended above.
        // Retire even when the native attempt failed; no retry path exists.
        let before_retirement = ledger.snapshot();
        let retired = session
            .finish_reserved_with_owner(ledger)
            .map_err(|_| Error::Runtime)?;
        if ledger.snapshot() != before_retirement {
            return Err(Error::Retirement);
        }
        let retirement = retired.receipt();
        if !retirement_is_complete(retirement) {
            std::process::abort();
        }
        let originals = self
            .phase
            .into_retired_reservations(retired, ledger)
            .map_err(|_| Error::Retirement)?;
        if ledger.snapshot() != before_retirement
            || !originals.belongs_to(ledger)
            || originals.retirement() != retirement
            || retirement.managed_peak_bytes == 0
            || retirement.managed_peak_bytes as u64 > DEVICE_BYTES
        {
            return Err(Error::Retirement);
        }
        let output = attempted?;
        if !output.belongs_to(ledger) || output.geometry() != expected {
            return Err(Error::Authority);
        }
        let before_verification = ledger.snapshot();
        let (verification, original_verifier) = verify_retaining(
            self.verifier,
            &self.preparation,
            &output,
            self.verification,
            bookkeeping,
            ledger,
        )?;
        if ledger.snapshot() != before_verification {
            return Err(Error::Authority);
        }
        Ok(NativeSegmentCompletion {
            verified: VerifiedNativeSegment {
                output,
                owner: self.owner,
                index: self.index,
                verification,
                retirement,
                retained: self.retained,
            },
            originals,
            preparation: self.preparation,
            verification: original_verifier,
        })
    }
}

impl<'request> PreissuedNativeSegment<'request> {
    fn advance(
        self,
        previous: NativeSegmentCompletion<'request>,
        bookkeeping: &Reservation,
        ledger: &Ledger,
    ) -> TransitionResult<'request> {
        let checked = (|| -> Result<()> {
            check_bookkeeping(bookkeeping, ledger)?;
            let prior = previous.verified.index;
            if self.index != prior.checked_add(1).ok_or(Error::Overflow)?
                || !previous.verified.is_for(self.owner, prior, ledger)
                || !previous.preparation.is_for(self.owner, prior, ledger)
                || !self.preparation.is_for(self.owner, self.index)
                || self.preparation.requirements() != previous.preparation.plan.requirements
                || !previous.originals.belongs_to(ledger)
                || previous.originals.retirement() != previous.verified.retirement
                || !previous.verification.belongs_to(ledger)
                || previous.verification.requirements() != VerificationPlan::component_requirement()
                || !self.retained.belongs_to(ledger)
                || self.retained.requirements() != retained_requirement()?
            {
                return Err(Error::Authority);
            }
            let prior_geometry = previous.preparation.census().geometry();
            let next = self.preparation.census().geometry();
            if prior_geometry
                .first_permutation()
                .checked_add(prior_geometry.permutations())
                != Some(next.first_permutation())
            {
                return Err(Error::Source);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, self, previous));
        }
        let NativeSegmentCompletion {
            verified,
            originals,
            preparation: old_preparation,
            verification,
        } = previous;
        let Self {
            owner,
            index,
            preparation,
            successor,
            verifier,
            retained,
        } = self;
        match PendingRuntime::restore_hashx_successor_outer_host_v1(
            successor,
            originals,
            old_preparation.reservation(),
            &verification,
            ledger,
            limits(),
        ) {
            Err((_, successor, originals)) => Err((
                Error::Runtime,
                Self {
                    owner,
                    index,
                    preparation,
                    successor,
                    verifier,
                    retained,
                },
                NativeSegmentCompletion {
                    verified,
                    originals,
                    preparation: old_preparation,
                    verification,
                },
            )),
            Ok((runtime, phase)) => {
                // Every original caller/native/verifier payload has died.
                // Only here move the exact original mixed-category scratch.
                let PendingNativePreparation {
                    plan: old_plan,
                    reservation,
                } = old_preparation;
                drop(old_plan);
                let preparation = PendingNativePreparation {
                    plan: preparation,
                    reservation,
                };
                Ok((
                    verified,
                    PreparedNativeSegment {
                        owner,
                        index,
                        runtime,
                        phase,
                        preparation,
                        verifier,
                        verification,
                        retained,
                    },
                ))
            }
        }
    }
}

impl<'request> PreparedNativeHashx<'request> {
    /// Component diagnostic only. Numeric capacity never conveys a claim.
    pub(crate) fn original_pcs_bytes(&self) -> Result<Bytes> {
        self.current
            .as_ref()
            .ok_or(Error::Authority)?
            .phase
            .original_pcs_bytes(&self.ledger)
            .map_err(|_| Error::Phase)
    }

    /// # Safety
    /// Keep the same immutable process/exclusive-device guard through every
    /// actual runtime retirement. This executes ten fresh native proofs only.
    pub(crate) unsafe fn produce(self) -> Result<CompletedNativeHashx<'request>> {
        unsafe { self.produce_inner(None) }
    }

    unsafe fn produce_inner(
        mut self,
        outer: Option<&PreissuedHashxOuter<'request>>,
    ) -> Result<CompletedNativeHashx<'request>> {
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        self.check_outer_start(outer)?;
        let mut segments = core::array::from_fn(|_| None);
        for index in 0..SEGMENTS {
            let current = self.current.take().ok_or(Error::Authority)?;
            if current.index != index {
                return Err(Error::Authority);
            }
            let completion = unsafe { current.produce(&self.bookkeeping, &self.ledger) }?;
            if index + 1 == SEGMENTS {
                let NativeSegmentCompletion {
                    verified,
                    originals,
                    preparation,
                    verification,
                } = completion;
                segments[index] = Some(verified);
                return Ok(CompletedNativeHashx {
                    owner: self.owner,
                    segments,
                    attachments: self.attachments,
                    scratch: ExhaustedScratch {
                        originals,
                        preparation,
                        verification,
                    },
                    next_child: 0,
                    ledger: self.ledger,
                    bookkeeping: self.bookkeeping,
                });
            }
            let successor = self.successors[index].take().ok_or(Error::Authority)?;
            let before = self.ledger.snapshot();
            let (verified, next) = successor
                .advance(completion, &self.bookkeeping, &self.ledger)
                .map_err(|_| Error::Authority)?;
            if self.ledger.snapshot() != before {
                return Err(Error::Authority);
            }
            segments[index] = Some(verified);
            self.current = Some(next);
        }
        Err(Error::Authority)
    }
}

impl<'request> CompletedNativeHashx<'request> {
    pub(crate) fn report(&self, index: usize) -> Option<&Report> {
        self.segments
            .get(index)?
            .as_ref()
            .map(|segment| segment.output.report())
    }
    pub(crate) fn retirement(&self) -> Retirement {
        self.scratch.originals.retirement()
    }
    pub(crate) fn retained_native_count(&self) -> usize {
        self.segments.iter().filter(|s| s.is_some()).count()
    }

    /// Consume only the next original verified owner into its source-preissued
    /// compiler attachment. Scratch remains private and terminal in this owner.
    pub(crate) fn take_next_child(
        &mut self,
        index: usize,
        ledger: &Ledger,
    ) -> Result<ReservedNativeChild<'request>> {
        check_bookkeeping(&self.bookkeeping, ledger)?;
        if !self.owner.belongs_to(ledger)
            || !self.scratch.originals.belongs_to(ledger)
            || !self
                .scratch
                .preparation
                .is_for(self.owner, SEGMENTS - 1, ledger)
            || !self.scratch.verification.belongs_to(ledger)
            || self.scratch.verification.requirements() != VerificationPlan::component_requirement()
            || index != self.next_child
            || index >= SEGMENTS
        {
            return Err(Error::Authority);
        }
        let produced = self.segments[index].as_ref().ok_or(Error::Authority)?;
        let attachment = self.attachments[index].as_ref().ok_or(Error::Authority)?;
        attachment.check(produced, ledger)?;
        // All checks and proof-shape audits occur before transfer. The final
        // private attachment construction is infallible and allocates nothing.
        let produced = self.segments[index].take().ok_or(Error::Authority)?;
        let attachment = self.attachments[index].take().ok_or(Error::Authority)?;
        self.next_child += 1;
        Ok(attachment.finish(produced))
    }
}

mod attachment;
pub(in crate::graph_crypto::retention::owned) use attachment::NativeSegmentChild;

mod capacity;

mod quota_projection;
pub(crate) use quota_projection::ProjectedHashxQuota;

mod outer;
pub(crate) use outer::{
    ActiveHashxOuter, HashxOuterStep, PreissuedHashxOuter, PreparedHashxOuter, RetiredHashxOuter,
    RetiredHashxOuterOriginals,
};

#[cfg(test)]
mod tests;
