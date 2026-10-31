//! One fixed native ntt continuation under original workflow reservations.
//! This internal research boundary accepts no AIR callback, generator, proof
//! or proving entropy. Its source-closed research caller owns input authenticity,
//! exact runtime lifecycle and independent CPU verification.
use super::{
    ntt_output::{OwnedNttProof, PendingNttOutput},
    ntt_preparation::NttPreparationPlan,
    ntt_recording::PreparedNtt,
};
use crate::block_v2::{
    gpu_hash::device::ringct_runtime::{Runtime, StartupPlan},
    machine::{NativeNttPcsFootprint, NativeNttPcsPlan, RegisteredGpuLimits},
};
use crate::proving::proof_storage::native_ntt_ocl::FixedNativeNttOclStorage;
use crate::ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;

mod execution;
mod input;
pub use input::NttInput;
mod quota_projection;

mod tree_profile;
use tree_profile::TreeProfile;
mod trace_admission;
pub use trace_admission::NativeNttTraceFootprint;
mod preissued;
pub use preissued::{NativeNttReservationPlan, PreissuedNativeNttPlan};
mod retirement;
pub use retirement::RetiredNativeReservations;

const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_DEVICE: u64 = 4 << 30;
const NATIVE_HOST: usize = 24 << 30;
const MAX_ROWS: usize = 1 << 20;
const MAX_VERIFIER_HOST: u64 = 512 << 20;
const MAX_VERIFIER_COUNT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    Geometry,
    Preparation,
    Planner,
    Admission,
    Runtime,
    AlreadyAttempted,
    Configuration,
    Entropy,
    Normalization,
    Trace,
    Public,
    Proof,
    Report,
    Output,
}
type Result<T> = core::result::Result<T, Error>;

fn only(token: &Reservation, category: Category, ledger: &Ledger) -> Result<Bytes> {
    let bytes = token.requirements().get(category);
    if !token.belongs_to(ledger) || token.requirements() != Requirements::single(category, bytes) {
        return Err(Error::Authority);
    }
    Ok(bytes)
}

fn check_ledger(ledger: &Ledger) -> Result<()> {
    let allowance = ledger.snapshot().allowance;
    if allowance.host == 0 || allowance.host > WORKER_HOST || allowance.device != MANAGED_DEVICE {
        return Err(Error::Authority);
    }
    Ok(())
}

fn check_preparation(
    census: NttPreparationPlan,
    token: &Reservation,
    ledger: &Ledger,
) -> Result<()> {
    let symbolic = census
        .host()
        .prepared_partition_bytes()
        .map_err(|_| Error::Preparation)?;
    let other = census
        .host()
        .required_host_bytes()
        .checked_sub(symbolic)
        .and_then(|n| n.checked_add(super::ntt_recording::additional_host_bytes()))
        .ok_or(Error::Preparation)?;
    let requirements = token.requirements();
    if !token.belongs_to(ledger)
        || requirements.get(Category::SymbolicCompiler)
            != (Bytes {
                host: symbolic as u64,
                device: 0,
            })
        || requirements.get(Category::PhaseScratch).host < other as u64
        || requirements.get(Category::PhaseScratch).device != 0
        || Category::ALL.into_iter().any(|category| {
            !matches!(
                category,
                Category::SymbolicCompiler | Category::PhaseScratch
            ) && requirements.get(category) != Bytes::ZERO
        })
    {
        return Err(Error::Authority);
    }
    Ok(())
}

fn check_verifier(token: &Reservation, ledger: &Ledger) -> Result<Requirements> {
    let bytes = only(token, Category::IndependentVerifier, ledger)?;
    if bytes.device != 0 || bytes.host == 0 || bytes.host > MAX_VERIFIER_HOST {
        return Err(Error::Authority);
    }
    Ok(token.requirements())
}

fn check_exact_verifier(token: &Reservation, expected: Requirements, ledger: &Ledger) -> Result<()> {
    if check_verifier(token, ledger)? != expected { return Err(Error::Authority); }
    Ok(())
}

#[cfg(test)]
fn check_startup(token: &Reservation, ledger: &Ledger) -> Result<usize> {
    TreeProfile::Device.check_startup(token, ledger)
}

fn wrapper_host_bytes() -> Result<usize> {
    FixedNativeNttOclStorage::fixed()
        .map_err(|_| Error::Admission)?
        .required_host_bytes()
        .checked_add(2 * size_of::<NativeNttPhase>() + size_of::<Error>())
        .and_then(|bytes| bytes.checked_add(execution::additional_host_bytes()))
        .and_then(|bytes| bytes.checked_add(retirement::additional_wrapper_host_bytes()))
        .and_then(|bytes| bytes.checked_add(quota_projection::additional_host_bytes()))
        .and_then(|bytes| bytes.checked_add(preissued::additional_wrapper_host_bytes()))
        .ok_or(Error::Admission)
}

fn begin_attempt(attempted: &mut bool) -> Result<()> {
    if *attempted {
        return Err(Error::AlreadyAttempted);
    }
    *attempted = true;
    Ok(())
}

/// Keeps PCS and OpenCL backing reserved after proof construction. The closed
/// caller must retain this owner until its exact Runtime completes retirement,
/// including every refusal or unwind after runtime startup. Production does not
/// expose this owner outside that reviewed research wrapper.
#[must_use = "retain the phase through exact runtime retirement"]
pub struct NativeNttPhase {
    tree_profile: TreeProfile,
    preparation: NttPreparationPlan,
    // Captured from the exact source-planned original at preissue. No public
    // numeric setter can widen this private packet/phase requirement.
    verifier: Requirements,
    pcs: NativeNttPcsPlan,
    trace: NativeNttTraceFootprint,
    output: Option<PendingNttOutput>,
    attempted: bool,
    succeeded: bool,
    retirement_binding: Option<retirement::RuntimeBinding>,
    ledger: Ledger,
    // All dynamic phase payload/claims are destroyed before these backing
    // reservations. The research wrapper additionally orders runtime first.
    wrappers: Reservation,
    pcs_owner: Reservation,
}

impl NativeNttPhase {
    /// A PCS component inventory only, not a complete-workflow qualification.
    pub fn footprint(&self) -> NativeNttPcsFootprint {
        self.pcs.footprint()
    }

    pub fn attempted(&self) -> bool {
        self.attempted
    }

    pub fn trace_footprint(&self) -> NativeNttTraceFootprint {
        self.trace
    }

    /// # Safety
    /// The caller must be the closed source orchestration: `prepared` and
    /// `input` must belong to its exact immutable original auxiliary request,
    /// and runtime/runtime_owner must be the original admitted runtime pair.
    /// Keep self, original preparation and verifier claims alive until this
    /// exact runtime has retired on both success and failure. This method never
    /// authorizes a retry or fallback; the first attempt consumes its state.
    pub unsafe fn produce(
        &mut self,
        prepared: PreparedNtt<'_>,
        input: NttInput<'_>,
        runtime: &Runtime,
        runtime_owner: &Reservation,
        verifier: &Reservation,
    ) -> Result<OwnedNttProof> {
        begin_attempt(&mut self.attempted)?;
        let result = execution::produce(self, prepared, input, runtime, runtime_owner, verifier);
        self.succeeded = result.is_ok();
        result
    }
}

#[cfg(test)]
mod verifier_original_tests {
    use super::*;
    use crate::ringct_research_quota::WorkerAllowance;

    fn required(host: u64) -> Requirements {
        Requirements::single(Category::IndependentVerifier, Bytes { host, device: 0 })
    }

    #[test]
    fn ntt_verifier_original_requires_exact_preissued_bytes_ledger_and_category() {
        let ledger = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
        let other = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
        let original = ledger.admit_phase(required(421_318_048)).unwrap();
        assert!(check_exact_verifier(&original, original.requirements(), &ledger).is_ok());
        assert_eq!(check_exact_verifier(&original, required(421_318_047), &ledger), Err(Error::Authority));
        assert_eq!(check_exact_verifier(&original, required(421_318_049), &ledger), Err(Error::Authority));
        assert_eq!(check_exact_verifier(&original, original.requirements(), &other), Err(Error::Authority));
        let wrong = ledger.admit_phase(Requirements::single(Category::PhaseScratch,
            Bytes { host: 421_318_048, device: 0 })).unwrap();
        assert_eq!(check_verifier(&wrong, &ledger), Err(Error::Authority));
        drop(wrong);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn ntt_verifier_ceiling_and_count_refuse_without_runtime_or_proof() {
        let ledger = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
        for (bytes, accepted) in [(1, true), (MAX_VERIFIER_HOST, true), (MAX_VERIFIER_HOST + 1, false)] {
            let original = ledger.admit_phase(required(bytes)).unwrap();
            assert_eq!(check_verifier(&original, &ledger).is_ok(), accepted);
        }
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        use crate::block_v2::native_gpu::ntt_preparation::{NttDescriptor, Q};
        for count in [33, 64, 128] {
            let preparation = NttPreparationPlan::new(NttDescriptor::new(Q, count).unwrap()).unwrap();
            assert!(matches!(NativeNttReservationPlan::outer_host_v1(preparation, 1), Err(Error::Geometry)));
        }
    }
}
