//! One fixed native g_bound continuation under original workflow reservations.
//! This internal research boundary accepts no AIR callback, generator, proof
//! or proving entropy. Its source-closed research caller owns input authenticity,
//! exact runtime lifecycle and independent CPU verification.
use super::{
    g_bound_output::{OwnedGBoundProof, PendingGBoundOutput},
    g_bound_preparation::GBoundPreparationPlan,
    g_bound_recording::PreparedGBound,
};
use crate::block_v2::{
    gpu_hash::device::ringct_runtime::{Runtime, StartupPlan},
    machine::{NativeGBoundPcsFootprint, NativeGBoundPcsPlan, RegisteredGpuLimits},
};
use crate::proving::proof_storage::native_g_bound_ocl::FixedNativeGBoundOclStorage;
use crate::ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;

mod execution;
mod input;
pub use input::GBoundInput;
mod quota_projection;

mod tree_profile;
use tree_profile::TreeProfile;
mod trace_admission;
pub use trace_admission::NativeGBoundTraceFootprint;
mod preissued;
pub use preissued::{NativeGBoundReservationPlan, PreissuedNativeGBoundPlan};
mod retirement;
pub use retirement::RetiredNativeReservations;

const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_DEVICE: u64 = 4 << 30;
const NATIVE_HOST: usize = 24 << 30;
const MAX_ROWS: usize = 1 << 20;
const VERIFIER_HOST: u64 = 64 << 20;

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
    census: GBoundPreparationPlan,
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
        .and_then(|n| n.checked_add(super::g_bound_recording::additional_host_bytes()))
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

fn check_verifier(token: &Reservation, ledger: &Ledger) -> Result<()> {
    if only(token, Category::IndependentVerifier, ledger)?
        != (Bytes {
            host: VERIFIER_HOST,
            device: 0,
        })
    {
        return Err(Error::Authority);
    }
    Ok(())
}

#[cfg(test)]
fn check_startup(token: &Reservation, ledger: &Ledger) -> Result<usize> {
    TreeProfile::Device.check_startup(token, ledger)
}

fn wrapper_host_bytes() -> Result<usize> {
    FixedNativeGBoundOclStorage::fixed()
        .map_err(|_| Error::Admission)?
        .required_host_bytes()
        .checked_add(2 * size_of::<NativeGBoundPhase>() + size_of::<Error>())
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
pub struct NativeGBoundPhase {
    tree_profile: TreeProfile,
    preparation: GBoundPreparationPlan,
    pcs: NativeGBoundPcsPlan,
    trace: NativeGBoundTraceFootprint,
    output: Option<PendingGBoundOutput>,
    attempted: bool,
    succeeded: bool,
    retirement_binding: Option<retirement::RuntimeBinding>,
    ledger: Ledger,
    // All dynamic phase payload/claims are destroyed before these backing
    // reservations. The research wrapper additionally orders runtime first.
    wrappers: Reservation,
    pcs_owner: Reservation,
}

impl NativeGBoundPhase {
    /// A PCS component inventory only, not a complete-workflow qualification.
    pub fn footprint(&self) -> NativeGBoundPcsFootprint {
        self.pcs.footprint()
    }

    pub fn attempted(&self) -> bool {
        self.attempted
    }

    pub fn trace_footprint(&self) -> NativeGBoundTraceFootprint {
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
        prepared: PreparedGBound<'_>,
        input: GBoundInput<'_>,
        runtime: &Runtime,
        runtime_owner: &Reservation,
        verifier: &Reservation,
    ) -> Result<OwnedGBoundProof> {
        begin_attempt(&mut self.attempted)?;
        let result = execution::produce(self, prepared, input, runtime, runtime_owner, verifier);
        self.succeeded = result.is_ok();
        result
    }
}
