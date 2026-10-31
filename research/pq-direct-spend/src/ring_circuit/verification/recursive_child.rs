//! Private provenance bridge from complete independent verification to the
//! recursive constraint qualifier. No transport claim or public report can
//! construct either owner. The original proof stays owned until qualification
//! finishes or fails; the GPU session has already been retired on return.
use super::*;
use crate::ring_circuit::recursion::{self, SourceBound};
use std::mem::size_of;
use std::{cell::Cell, mem::MaybeUninit};

const ROOTS: usize = 1 << profile::CAP_HEIGHT;

// One exact-capacity public allocation follows the private source owner through
// all moves. No inline cap array is materialized at capture or transfer.
pub(super) struct TrustedCap(Vec<[Val; 4]>);

impl TrustedCap {
    pub(super) fn capture(registered: &RegisteredProgram) -> Result<Self, VerificationFailure> {
        let roots = registered.preprocessing_cap().roots();
        if roots.len() != ROOTS || registered.preprocessing_cap().root_capacity() != ROOTS {
            return Err(VerificationFailure::new(
                "recursive_cap",
                true,
                false,
                &Error::Geometry,
            ));
        }
        // The unchanged enclosing caller admission includes this backing and
        // the complete fallible allocation/result frames before registration.
        let mut cap = Vec::new();
        cap.try_reserve_exact(ROOTS).map_err(|_| {
            VerificationFailure::new("recursive_cap_storage", true, false, &Error::ResourceLimit)
        })?;
        if cap.capacity() != ROOTS {
            return Err(VerificationFailure::new(
                "recursive_cap_storage",
                true,
                false,
                &Error::ResourceLimit,
            ));
        }
        cap.extend_from_slice(roots);
        Ok(Self(cap))
    }
}

fn cap_storage_bytes() -> Result<usize, Error> {
    [
        // Exactly one allocation remains live throughout the closed child and
        // outer lifetimes. All moved owners carry its sole Vec, never a clone.
        size_of::<[[Val; 4]; ROOTS]>(),
        8 * size_of::<Vec<[Val; 4]>>(),
        8 * size_of::<Result<TrustedCap, VerificationFailure>>(),
        8 * size_of::<Result<(), std::collections::TryReserveError>>(),
        4 * size_of::<std::collections::TryReserveError>(),
        8 * size_of::<&[[Val; 4]]>(),
        16 * size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::ResourceLimit)
    })
}

// A sealed allocation source can only return the actual allocation or null.
// The forced failure source is constructed solely by tests below.
struct ReportAllocation<'a> {
    forced_null_attempts: Option<&'a Cell<usize>>,
}

impl ReportAllocation<'_> {
    fn slot<T>(self) -> Result<Box<MaybeUninit<T>>, ()> {
        let layout = std::alloc::Layout::new::<MaybeUninit<T>>();
        // Production instantiates only VerificationReport. The private small
        // test probe exercises identical allocation/initialization/drop code
        // without manufacturing an accepted report or verified child.
        if layout.size() == 0
            || layout.size() > size_of::<VerificationReport>()
            || layout.align() > std::mem::align_of::<VerificationReport>()
        {
            return Err(());
        }
        let pointer = if let Some(attempts) = self.forced_null_attempts {
            attempts.set(attempts.get().saturating_add(1));
            std::ptr::null_mut()
        } else {
            // SAFETY: the exact nonzero layout was checked above.
            unsafe { std::alloc::alloc(layout) }.cast::<MaybeUninit<T>>()
        };
        if pointer.is_null() {
            return Err(());
        }
        // SAFETY: a unique aligned allocation of the exact layout backs this
        // slot. MaybeUninit permits uninitialized bytes; its Box deallocates
        // them without running T's destructor if verification later fails.
        Ok(unsafe { Box::from_raw(pointer) })
    }
}

fn initialize_report_slot<T>(mut slot: Box<MaybeUninit<T>>, value: T) -> Box<T> {
    slot.as_mut().write(value);
    // SAFETY: the sole slot was just fully initialized by write. The Box
    // remains the value's unique owner, with unchanged allocation and layout.
    unsafe { slot.assume_init() }
}

fn report_storage_bytes() -> Result<usize, Error> {
    [
        // One backing, retained from pre-registration admission through the
        // completed recursive report. Moving a Box never copies this backing.
        size_of::<VerificationReport>(),
        // The actual report still crosses by-value write/argument boundaries
        // once at initialization. Preserve a separate four-frame overlap for
        // these transfers in addition to the unchanged original verifier's
        // report and Result frames.
        4 * size_of::<VerificationReport>(),
        8 * size_of::<Box<MaybeUninit<VerificationReport>>>(),
        8 * size_of::<Box<VerificationReport>>(),
        8 * size_of::<Result<Box<MaybeUninit<VerificationReport>>, VerificationFailure>>(),
        8 * size_of::<Result<Box<MaybeUninit<VerificationReport>>, ()>>(),
        8 * size_of::<std::alloc::Layout>(),
        8 * size_of::<*mut MaybeUninit<VerificationReport>>(),
        4 * size_of::<ReportAllocation<'static>>(),
        4 * size_of::<Option<&Cell<usize>>>(),
        4 * size_of::<&Cell<usize>>(),
        4 * size_of::<Cell<usize>>(),
        8 * size_of::<usize>(),
        8 * size_of::<&Statement>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::ResourceLimit)
    })
}

fn prepare_report_slot(
    statement: &Statement,
    allocation: ReportAllocation<'_>,
) -> Result<Box<MaybeUninit<VerificationReport>>, VerificationFailure> {
    // The complete feature-specific caller census must fit before this first
    // allocation and before public reconstruction or any GPU work.
    reconstruction::caller_bytes(statement)
        .map_err(|error| VerificationFailure::new("caller_storage", false, false, &error))?;
    allocation.slot::<VerificationReport>().map_err(|()| {
        VerificationFailure::new(
            "recursive_report_storage",
            false,
            false,
            &Error::ResourceLimit,
        )
    })
}

pub(super) struct RecursiveEvidence {
    cap: TrustedCap,
    bound: SourceBound,
}

impl RecursiveEvidence {
    pub(super) fn new(cap: TrustedCap, bound: SourceBound) -> Self {
        Self { cap, bound }
    }
}

pub(in crate::ring_circuit) struct VerifiedRecursiveChild {
    artifact: Artifact,
    report: Box<VerificationReport>,
    evidence: RecursiveEvidence,
}

/// The original independently reconstructed expected-public cap and source
/// shape. Only consumption of a numerically verified original child creates
/// this owner. It contains no original child proof, template, verifier or GPU
/// state, and is deliberately neither cloneable nor deserializable.
#[cfg(feature = "ring-recursive-outer-experiment")]
pub(in crate::ring_circuit) struct ExpectedRecursiveSource {
    public: [Val; 4],
    context: Context,
    representation: CompilerRepresentation,
    evidence: RecursiveEvidence,
}

#[cfg(feature = "ring-recursive-outer-experiment")]
impl ExpectedRecursiveSource {
    pub(in crate::ring_circuit) fn context(&self) -> Context {
        self.context
    }
    pub(in crate::ring_circuit) fn representation(&self) -> CompilerRepresentation {
        self.representation
    }
    pub(in crate::ring_circuit) fn public(&self) -> [Val; 4] {
        self.public
    }
    pub(in crate::ring_circuit) fn cap(&self) -> &[[Val; 4]] {
        &self.evidence.cap.0
    }
    pub(in crate::ring_circuit) fn bound(&self) -> &SourceBound {
        &self.evidence.bound
    }
}

impl VerifiedRecursiveChild {
    pub(in crate::ring_circuit) fn proof(&self) -> &p3_batch_stark::BatchProof<profile::Config> {
        self.artifact.proof()
    }

    pub(in crate::ring_circuit) fn public(&self) -> [Val; 4] {
        // verify_inner compared the immutable envelope with independently
        // supplied public inputs before producing this move-only owner.
        self.artifact.public()
    }

    pub(in crate::ring_circuit) fn cap(&self) -> &[[Val; 4]] {
        &self.evidence.cap.0
    }

    pub(in crate::ring_circuit) fn bound(&self) -> &SourceBound {
        &self.evidence.bound
    }

    pub(in crate::ring_circuit) fn terminal(&self) -> TerminalReceipt {
        self.report.terminal
    }

    pub(in crate::ring_circuit) fn into_report(self) -> Box<VerificationReport> {
        // The child proof and trusted cap die here, not in a caller-managed
        // cache. This consumes the sole owner and conveys no reusable receipt.
        self.report
    }

    #[cfg(feature = "ring-recursive-outer-experiment")]
    pub(in crate::ring_circuit) fn into_outer_source(
        self,
    ) -> (ExpectedRecursiveSource, Box<VerificationReport>) {
        let Self {
            artifact,
            report,
            evidence,
        } = self;
        let public = artifact.public();
        let context = artifact.context();
        let representation = artifact.representation();
        // The actual recursive ProofInputs already own their necessary proof
        // fields. Release the original child before any outer GPU phase.
        drop(artifact);
        (
            ExpectedRecursiveSource {
                public,
                context,
                representation,
                evidence,
            },
            report,
        )
    }
}

/// Additional fixed caller frames, all charged inside the existing 1 MiB
/// verifier caller reservation. No independent extra host budget is created.
pub(super) fn caller_bytes() -> Result<usize, Error> {
    #[cfg(feature = "ring-recursive-outer-experiment")]
    let outer_bytes = 8 * size_of::<ExpectedRecursiveSource>();
    #[cfg(not(feature = "ring-recursive-outer-experiment"))]
    let outer_bytes = 0;
    let bytes = [
        cap_storage_bytes()?,
        report_storage_bytes()?,
        // capture -> tuple -> finish -> IndependentVerifier -> evidence moves.
        16 * size_of::<TrustedCap>(),
        8 * size_of::<SourceBound>(),
        6 * size_of::<Option<RecursiveEvidence>>(),
        4 * size_of::<VerifiedRecursiveChild>(),
        4 * size_of::<Result<VerifiedRecursiveChild, VerificationFailure>>(),
        recursion::inline_bytes()?,
        outer_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::ResourceLimit)
    })?;
    // This is a ceiling, not a post-allocation observation. All types above
    // have fixed inline layout and no constructor is invoked by this census.
    if bytes > 192 << 10 {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

pub(in crate::ring_circuit) fn verify_for_recursion(
    mut artifact: Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
) -> Result<VerifiedRecursiveChild, VerificationFailure> {
    // Admission includes all entry/result slots before public reconstruction
    // and before any fresh verifier setup. Identity reuse is deliberately not
    // selectable through this initial recursive research path.
    let report_slot = prepare_report_slot(
        expected_statement,
        ReportAllocation {
            forced_null_attempts: None,
        },
    )?;
    let mut evidence = None;
    let report = super::verify_inner(
        &mut artifact,
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
        None,
        Some(&mut evidence),
    )?;
    let evidence = evidence.ok_or_else(|| {
        VerificationFailure::new("recursive_evidence", true, true, &Error::Geometry)
    })?;
    let report = initialize_report_slot(report_slot, report);
    Ok(VerifiedRecursiveChild {
        artifact,
        report,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DropProbe(std::rc::Rc<Cell<usize>>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn recursive_report_slot_drops_only_initialized_values_once() {
        let uninitialized = ReportAllocation {
            forced_null_attempts: None,
        }
        .slot::<DropProbe>()
        .unwrap();
        // Running DropProbe::drop here would read an uninitialized Rc. The
        // actual production slot owner must only free the allocation.
        drop(uninitialized);

        let drops = std::rc::Rc::new(Cell::new(0));
        let slot = ReportAllocation {
            forced_null_attempts: None,
        }
        .slot::<DropProbe>()
        .unwrap();
        let initialized = initialize_report_slot(slot, DropProbe(drops.clone()));
        assert_eq!(drops.get(), 0);
        drop(initialized);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn recursive_report_storage_fits_before_verifier_setup() {
        let (statement, witness) = crate::ring::fixture(Context([0x74; 32])).unwrap();
        drop(witness);
        let slot = prepare_report_slot(
            &statement,
            ReportAllocation {
                forced_null_attempts: None,
            },
        )
        .unwrap();
        // An uninitialized slot has no report destructor to run. Failure of
        // later verification follows this same ordinary Box cleanup path.
        drop(slot);
    }

    #[test]
    fn recursive_report_allocation_failure_precedes_verifier_setup() {
        let (statement, witness) = crate::ring::fixture(Context([0x75; 32])).unwrap();
        drop(witness);
        let attempts = Cell::new(0);
        let result = prepare_report_slot(
            &statement,
            ReportAllocation {
                forced_null_attempts: Some(&attempts),
            },
        );
        let failure = match result {
            Ok(_) => panic!("forced null report allocation succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(attempts.get(), 1);
        assert_eq!(failure.phase, "recursive_report_storage");
        assert!(!failure.gpu_registration_started);
        assert!(!failure.cpu_verification_started);
        assert!(failure.terminal.is_none());
    }

    #[test]
    fn recursive_report_caller_refusal_precedes_allocation() {
        let (mut statement, witness) = crate::ring::fixture(Context([0x76; 32])).unwrap();
        drop(witness);
        statement.ring.reserve_exact(64);
        let attempts = Cell::new(0);
        let result = prepare_report_slot(
            &statement,
            ReportAllocation {
                forced_null_attempts: Some(&attempts),
            },
        );
        let failure = match result {
            Ok(_) => panic!("oversized caller allocated a report slot"),
            Err(failure) => failure,
        };
        assert_eq!(attempts.get(), 0);
        assert_eq!(failure.phase, "caller_storage");
        assert!(!failure.gpu_registration_started);
        assert!(!failure.cpu_verification_started);
        assert!(failure.terminal.is_none());
    }

    #[test]
    fn recursive_inline_owners_fit_inside_existing_verifier_caller_allowance() {
        #[cfg(feature = "ring-recursive-outer-experiment")]
        {
            let orchestration = recursion::outer::qualification_timing::caller_bytes().unwrap();
            assert!(orchestration <= CALLER_ORCHESTRATION_BYTES);
            eprintln!(
                "direct_ring_recursive_outer_orchestration_bytes actual={orchestration} timing_additional={} allowance={CALLER_ORCHESTRATION_BYTES}",
                recursion::outer::qualification_timing::TIMING_ADDITIONAL_BYTES,
            );
        }
        let (statement, witness) = crate::ring::fixture(Context([0x73; 32])).unwrap();
        drop(witness);
        let components = [
            ("cap_storage", cap_storage_bytes().unwrap()),
            ("report_storage", report_storage_bytes().unwrap()),
            ("trusted_cap_16", 16 * size_of::<TrustedCap>()),
            ("source_bound_8", 8 * size_of::<SourceBound>()),
            (
                "optional_evidence_6",
                6 * size_of::<Option<RecursiveEvidence>>(),
            ),
            ("verified_child_4", 4 * size_of::<VerifiedRecursiveChild>()),
            (
                "child_result_4",
                4 * size_of::<Result<VerifiedRecursiveChild, VerificationFailure>>(),
            ),
            ("recursive_inline", recursion::inline_bytes().unwrap()),
        ];
        for (component, bytes) in components {
            eprintln!("direct_ring_recursive_caller_component name={component} bytes={bytes}");
        }
        #[cfg(feature = "ring-recursive-outer-experiment")]
        eprintln!(
            "direct_ring_recursive_caller_component name=expected_source_8 bytes={}",
            8 * size_of::<ExpectedRecursiveSource>()
        );
        let bytes = reconstruction::caller_bytes(&statement).unwrap();
        assert!(bytes <= REGISTERED_GPU_CALLER_HOST_BYTES);
        assert!(caller_bytes().unwrap() > 0);
        eprintln!(
            "direct_ring_recursive_caller_bytes actual={bytes} allowance={REGISTERED_GPU_CALLER_HOST_BYTES} remaining={}",
            REGISTERED_GPU_CALLER_HOST_BYTES - bytes,
        );
        let mut statement = statement;
        statement.ring.reserve_exact(64);
        assert_eq!(
            reconstruction::caller_bytes(&statement),
            Err(Error::ResourceLimit)
        );
    }
}
