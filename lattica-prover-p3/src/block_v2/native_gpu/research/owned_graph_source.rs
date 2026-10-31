//! One fixed native graph-source continuation under original workflow reservations.
//! This internal research boundary accepts no AIR callback, generator, proof
//! or proving entropy. Its source-closed research caller owns input authenticity,
//! exact runtime lifecycle and independent CPU verification.
use super::{
    graph_source_output::{OwnedGraphSourceProof, PendingGraphSourceOutput},
    graph_source_preparation::GraphSourcePreparationPlan,
    graph_source_recording::PreparedGraphSource,
};
use crate::block_v2::{
    gpu_hash::device::ringct_runtime::{Runtime, StartupPlan},
    machine::{NativeGraphSourcePcsFootprint, NativeGraphSourcePcsPlan, RegisteredGpuLimits},
};
use crate::proving::proof_storage::native_graph_source_ocl::FixedNativeGraphSourceOclStorage;
use crate::ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;

mod execution;
mod input;
pub use input::GraphSourceInput;
mod quota_projection;
pub use quota_projection::NativeGraphSourceQuotaProjection;

mod tree_profile;
use tree_profile::TreeProfile;
mod trace_admission;
pub use trace_admission::NativeGraphSourceTraceFootprint;
mod preissued;
pub use preissued::{NativeGraphSourceReservationPlan, PreissuedNativeGraphSourcePlan};
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
    census: GraphSourcePreparationPlan,
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
        .and_then(|n| n.checked_add(super::graph_source_recording::additional_host_bytes()))
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
    FixedNativeGraphSourceOclStorage::fixed()
        .map_err(|_| Error::Admission)?
        .required_host_bytes()
        .checked_add(2 * size_of::<NativeGraphSourcePhase>() + size_of::<Error>())
        .and_then(|bytes| bytes.checked_add(execution::additional_host_bytes()))
        .and_then(|bytes| bytes.checked_add(retirement::additional_wrapper_host_bytes()))
        .and_then(|bytes| bytes.checked_add(quota_projection::additional_host_bytes()))
        .and_then(|bytes| bytes.checked_add(preissued::additional_wrapper_host_bytes()))
        .ok_or(Error::Admission)
}

fn operation_host_budget(ledger: &Ledger) -> Result<usize> {
    let available = usize::try_from(ledger.remaining().host)
        .map_err(|_| Error::Admission)?
        .min(NATIVE_HOST);
    if available == 0 {
        return Err(Error::Admission);
    }
    Ok(available)
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
pub struct NativeGraphSourcePhase {
    tree_profile: TreeProfile,
    preparation: GraphSourcePreparationPlan,
    pcs: NativeGraphSourcePcsPlan,
    trace: NativeGraphSourceTraceFootprint,
    output: Option<PendingGraphSourceOutput>,
    attempted: bool,
    succeeded: bool,
    retirement_binding: Option<retirement::RuntimeBinding>,
    ledger: Ledger,
    // All dynamic phase payload/claims are destroyed before these backing
    // reservations. The research wrapper additionally orders runtime first.
    wrappers: Reservation,
    pcs_owner: Reservation,
}

impl NativeGraphSourcePhase {
    /// # Safety
    /// The source-closed caller must retain its original pending-runtime
    /// preflight while this method inspects environment/physical selection.
    /// Its serialized process guard must prevent environment mutation and
    /// unrelated GPU work through the eventual exact runtime retirement.
    /// Preparation, raw request, verifier and phase owners must survive that
    /// retirement. A numerical receipt or unrelated token is not a substitute.
    pub unsafe fn new(
        preparation: GraphSourcePreparationPlan,
        preparation_owner: &Reservation,
        pending_runtime_owner: &Reservation,
        output: PendingGraphSourceOutput,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<Self> {
        Self::with_tree_profile(
            TreeProfile::Device,
            preparation,
            preparation_owner,
            pending_runtime_owner,
            output,
            verifier,
            ledger,
        )
    }

    /// Explicit host-tree research profile. The original pending runtime must
    /// own StartupPlan::outer_host_v1's complete 8 GiB host-tree payload and
    /// quota wrapper inside the same 32 GiB worker ledger before this call.
    /// This is never selected as a fallback from the device profile.
    ///
    /// # Safety
    /// The same exact original-owner and immutable-process obligations as new
    /// apply, with the matching outer_host_v1 pending runtime. Keep that host
    /// runtime owner alive through destruction of every tree and exact runtime
    /// retirement, including all failures; no numeric receipt substitutes.
    pub unsafe fn new_outer_host_v1(
        preparation: GraphSourcePreparationPlan,
        preparation_owner: &Reservation,
        pending_runtime_owner: &Reservation,
        output: PendingGraphSourceOutput,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<Self> {
        Self::with_tree_profile(
            TreeProfile::OuterHostV1,
            preparation,
            preparation_owner,
            pending_runtime_owner,
            output,
            verifier,
            ledger,
        )
    }

    // Only the two source-fixed unsafe entrypoints can select a profile.
    // Existing device callers retain their exact constructor and behavior.
    fn with_tree_profile(
        tree_profile: TreeProfile,
        preparation: GraphSourcePreparationPlan,
        preparation_owner: &Reservation,
        pending_runtime_owner: &Reservation,
        output: PendingGraphSourceOutput,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<Self> {
        check_ledger(ledger)?;
        check_preparation(preparation, preparation_owner, ledger)?;
        check_verifier(verifier, ledger)?;
        output
            .check(preparation, ledger)
            .map_err(|_| Error::Output)?;
        let startup_device = tree_profile.check_startup(pending_runtime_owner, ledger)?;
        let wrappers = quota_projection::reserve_wrappers(tree_profile, ledger)?;
        let operation_host = operation_host_budget(ledger)?;
        // The original preparation planner partition owns this bounded
        // selection/model construction before the PCS reservation is issued.
        let limits =
            RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, MAX_ROWS)
                .map_err(|_| Error::Planner)?;
        let geometry = preparation.geometry();
        let pcs =
            NativeGraphSourcePcsPlan::new(geometry, operation_host, limits)
                .map_err(|_| Error::Planner)?;
        let footprint = pcs.footprint();
        tree_profile.check_plan(footprint)?;
        // pq_source_trace owns six matrices. The PCS phase model includes the
        // generated main trace; add all five other allocations to its complete
        // modeled peak without taking overlap credit. This
        // admission precedes runtime creation and the first private operation.
        let trace = NativeGraphSourceTraceFootprint::for_plan(preparation, footprint)?;
        if !footprint.maintained_device_plan_complete
            || footprint.fresh_runtime_baseline_bytes != startup_device
            || footprint.managed_phase_ceiling_bytes as u64 != MANAGED_DEVICE
            || footprint.required_pcs_host_bytes > operation_host
        {
            return Err(Error::Admission);
        }
        // Only this same original startup token owns the overlapping fixed
        // engine baseline. Reserve the rest of the full managed ceiling, not
        // a smaller observed peak or a copied external receipt.
        let pcs_owner = ledger
            .reserve(
                Category::PhaseScratch,
                quota_projection::pcs_request(startup_device, operation_host)?,
            )
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            tree_profile,
            preparation,
            pcs,
            trace,
            output: Some(output),
            attempted: false,
            succeeded: false,
            retirement_binding: None,
            ledger: ledger.clone(),
            wrappers,
            pcs_owner,
        })
    }

    /// A PCS component inventory only, not a complete-workflow qualification.
    pub fn footprint(&self) -> NativeGraphSourcePcsFootprint {
        self.pcs.footprint()
    }

    pub fn attempted(&self) -> bool {
        self.attempted
    }

    pub fn trace_footprint(&self) -> NativeGraphSourceTraceFootprint {
        self.trace
    }

    /// # Safety
    /// The caller must be the closed source orchestration: `prepared` and
    /// `key` must belong to its exact immutable reserved request/segment,
    /// and runtime/runtime_owner must be the original admitted runtime pair.
    /// Keep self, original preparation and verifier claims alive until this
    /// exact runtime has retired on both success and failure. This method never
    /// authorizes a retry or fallback; the first attempt consumes its state.
    pub unsafe fn produce(
        &mut self,
        prepared: PreparedGraphSource<'_>,
        input: GraphSourceInput<'_>,
        runtime: &Runtime,
        runtime_owner: &Reservation,
        verifier: &Reservation,
    ) -> Result<OwnedGraphSourceProof> {
        begin_attempt(&mut self.attempted)?;
        let result = execution::produce(self, prepared, input, runtime, runtime_owner, verifier);
        self.succeeded = result.is_ok();
        result
    }
}
