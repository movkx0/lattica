//! Source-built startup plan for the fixed RingCT research runtime.
//! This owns the bounded environment, physical selection and exact Engine epoch.
//! The research Session must reserve this plan in its original Ledger before
//! calling start and keep that token through retire, payload and error cleanup.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info"
))]
use super::super::{self as engine, *};
use crate::gpu_device::{bounded, sealed_environment::Captured};
use sha3::{Digest, Sha3_256};
use std::{ffi::CStr, mem::size_of};

const MANAGED: usize = 8 << 30;
const CONTEXT: usize = 4 << 30;
const OUTER_TREE_HOST: usize = 8 << 30;
const STAGING: usize = 64 << 20;
const REPLY: usize = 64 << 10;
const WRAPPER_DESCRIPTORS: usize = 64 << 10;
const DRIVER_TEXT_OVERLAP: usize = 8 * REPLY + 4096;
// Raw graph path: at most 8 supplied arguments and 1 builder+kernel pair.
// Reserve 2 pairs at 16 KiB each. Native AIR/registered proof phase storage is
// separately planned, and cannot infer its argument/cache bounds from this.
const RAW_KERNEL_WRAPPERS: usize = 2 * (16 << 10);

const SOURCES: &[&str] = &[
    crate::gpu::KERNEL_SRC,
    RETAINED_PATH_KERNEL,
    lde_execute::KERNEL_SRC,
    opening_reduce::KERNEL_SRC,
    fri_fold::KERNEL_SRC,
    query_reconstruct::KERNEL_SRC,
    device::TRANSFORM_KERNEL_SRC,
    device::QUOTIENT_KERNEL_SRC,
    device::QUOTIENT_COMMIT_KERNEL_SRC,
    device::LOOKUP_KERNEL_SRC,
    device::OPENING_KERNEL_SRC,
    device::QUADRATIC_OPENING_KERNEL_SRC,
    quotient::KERNEL_SRC,
    device::FRI_KERNEL_SRC,
    device::GENERAL_FRI_KERNEL_SRC,
    device::QUERY_KERNEL_SRC,
    device::TRACE_COMMIT_KERNEL_SRC,
    device::STORAGE_KERNEL_SRC,
    device::WITNESS_KERNEL_SRC,
    device::WALLET_KERNEL_SRC,
    device::PQ_POSEIDON_KERNEL_SRC,
    device::PQ_OPERATIONS_KERNEL_SRC,
    device::OPERATIONS_HASH_KERNEL_SRC,
    device::PQ_CRYPTO_KERNEL_SRC,
    device::PQ_RAW_CRYPTO_KERNEL_SRC,
    device::RESEARCH_ARITHMETIC_KERNEL_SRC,
    device::OPERATIONS_ARITHMETIC_KERNEL_SRC,
    device::PQ_SOURCES_KERNEL_SRC,
    device::PQ_SAMPLING_KERNEL_SRC,
    device::WALLET_BATCH_KERNEL_SRC,
    device::PERIODIC_KERNEL_SRC,
    device::HTLC_KERNEL_SRC,
    device::RANDOM_KERNEL_SRC,
    #[cfg(test)]
    device::RANDOM_REFERENCE_KERNEL_SRC,
    device::TRANSCRIPT_KERNEL_SRC,
    device::SCALARS_KERNEL_SRC,
    device::COMPILER_CONSTANTS_KERNEL_SRC,
    device::COMPILER_FOLDING_KERNEL_SRC,
    device::PUBLIC_HASH_KERNEL_SRC,
    device::EVALUATIONS_KERNEL_SRC,
];

const KEYS: [&CStr; 61] = [
    c"LATTICA_V2_GPU_HASH",
    c"LATTICA_V2_GPU_RETAIN_TREES",
    c"LATTICA_V2_GPU_QUERY_GATHER",
    c"LATTICA_V2_GPU_RESIDENT_LDE",
    c"LATTICA_V2_GPU_OPENINGS",
    c"LATTICA_V2_QUOTIENT_FUSION",
    c"LATTICA_V2_GPU_QUOTIENT_LDE",
    c"LATTICA_V2_GPU_QUOTIENT_EVAL",
    c"LATTICA_V2_GPU_QUOTIENT_RESIDENT",
    c"LATTICA_V2_GPU_LOOKUP",
    c"LATTICA_V2_GPU_OPENING_EVAL",
    c"LATTICA_V2_GPU_FRI_RESIDENT",
    c"LATTICA_V2_GPU_PCS_DEVICE_ONLY",
    c"LATTICA_V2_GPU_WITNESS",
    c"LATTICA_V2_GPU_RANDOMNESS",
    c"LATTICA_V2_GPU_TRANSCRIPT",
    c"LATTICA_V2_GPU_FRI_FOLD",
    c"LATTICA_PROVING_REPORT",
    c"LATTICA_PROVING_POLICY",
    c"LATTICA_V2_GPU_MANAGED_BYTES",
    c"LATTICA_V2_GPU_CONTEXT_BYTES",
    c"LATTICA_V2_HOST_OUTPUT_BYTES",
    c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE",
    c"LATTICA_V2_GPU_PUBLIC_HASH",
    c"RAYON_NUM_THREADS",
    c"LATTICA_V2_GPU_PIPELINE",
    c"LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE",
    c"LATTICA_V2_GPU_COMPACT_PROVER_DATA",
    c"LATTICA_V2_GPU_OPENING_COMPACT",
    c"LATTICA_PROFILE_TIMELINE",
    c"LATTICA_FFT_TRACE",
    c"LATTICA_V2_GPU_LDE_WORKSPACE_BYTES",
    c"LATTICA_V2_WORKER_BUDGET",
    c"LATTICA_WALLET_WORKER_BUDGET",
    c"LATTICA_V2_SHARED_PREPROCESSING_DIR",
    c"LATTICA_V2_PHASE_DIR",
    c"LATTICA_V2_LATE_PHASE_DIR",
    c"LATTICA_V2_QUERY_PHASE_DIR",
    c"LATTICA_V2_LDE_SCRATCH_BYTES",
    c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES",
    c"RUST_MIN_STACK",
    c"RAYON_RS_NUM_CPUS",
    c"LATTICA_GPU_DRAIN_FAILURE_TEST_CHILD",
    c"LATTICA_GPU_LEASE_DEATH_TEST_CHILD",
    c"LATTICA_V2_GPU_TUNING",
    c"LATTICA_V2_GPU_WORKERS",
    c"LATTICA_V2_GPU_DEVICE",
    c"LATTICA_GPU_DEVICE_UUID",
    c"LATTICA_SPILL_BACKING",
    c"LATTICA_SPILL_DIR",
    c"LATTICA_SPILL_MAX_BYTES",
    c"LATTICA_V2_COMPACT_SALTS",
    c"LATTICA_V2_GPU_DIRECT_READBACK",
    c"LATTICA_V2_GPU_OPENING_PINNED",
    c"LATTICA_V2_GPU_PARALLEL_READBACK",
    c"LATTICA_V2_LATE_PHASE_SLOTS",
    c"LATTICA_V2_MEMORY_RECLAIM",
    c"LATTICA_V2_OPENING_PROFILE",
    c"LATTICA_V2_PHASE_SLOTS",
    c"LATTICA_V2_QUERY_PHASE_SLOTS",
    c"LATTICA_V2_SHARED_PREPROCESSING_MAX_BYTES",
];
type Environment = Captured<61, 64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Device,
    Resource,
    Initialization,
    Lifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Footprint {
    pub requested_host_bytes: usize,
    pub managed_device_bytes: usize,
    pub mapped_staging_bytes: usize,
    pub source_bytes: usize,
    pub source_sha3: [u8; 32],
    pub driver_context_reserve: usize,
    /// Actual tree payload reserved by this original startup owner, not a
    /// numeric allowance accepted from a caller or a device-memory measurement.
    pub retained_tree_host_bytes: usize,
    pub retained_tree_quota_wrapper_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeProfile {
    Device,
    OuterHostV1,
}

/// Private source-derived fields; there is no numeric budget constructor.
pub struct StartupPlan {
    footprint: Footprint,
    tree_profile: TreeProfile,
}

/// Bounded, retained pre-context selection. It is not dispatch authority.
/// Keeping this owner permits outer admission while the Engine is still idle.
pub struct Selection {
    selected: bounded::Snapshot,
    scratch: bounded::Scratch,
    request: bounded::Request,
    environment: Environment,
    footprint: Footprint,
    tree_profile: TreeProfile,
    maximum_work_group_size: usize,
}

/// Epoch retires first. Selection/environment backing and the caller's actual
/// Ledger token remain live while the exact Engine is drained and destroyed.
pub struct Runtime {
    epoch: engine::owned_runtime::OwnedRuntime,
    selection: Selection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Retirement {
    pub managed_live_bytes: usize,
    /// Exact retired Engine's managed allocation peak; excludes opaque
    /// context/driver/process storage and does not measure total VRAM.
    pub managed_peak_bytes: usize,
    pub host_tree_live_bytes: usize,
    pub lease_released: bool,
}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Resource)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Resource)
}

fn tuning_fragments() -> &'static [&'static str] {
    #[cfg(feature = "gpu-tuning")]
    {
        &[
            include_str!("../commitment_shuffle.cl"),
            include_str!("../scale_shared.cl"),
            "\n#define LATTICA_TUNED_NTT 1\n#define ntt_tile_cached ntt_tile_cached_tuned\n",
            include_str!("../../../../gpu/ntt_cached.cl"),
            "\n#undef ntt_tile_cached\n#undef LATTICA_TUNED_NTT\n",
        ]
    }
    #[cfg(not(feature = "gpu-tuning"))]
    {
        &[]
    }
}

impl StartupPlan {
    /// Pure and allocation-free. Includes mapped staging in host and managed
    /// device charges; context reserve stays separate under the unchanged guard.
    pub fn new() -> Result<Self, Error> {
        Self::for_tree_profile(TreeProfile::Device)
    }

    /// Isolated outer backend profile. Its exact 8 GiB host-tree payload and
    /// HostQuota wrapper are additive to startup before any driver inspection.
    /// The enclosing original worker reservation must cover the full footprint.
    /// This constructor does not select an environment or authorize dispatch.
    pub fn outer_host_v1() -> Result<Self, Error> {
        Self::for_tree_profile(TreeProfile::OuterHostV1)
    }

    fn for_tree_profile(tree_profile: TreeProfile) -> Result<Self, Error> {
        if ocl::core::bounded_info::MAX_REPLY_BYTES != REPLY
            || ocl::core::bounded_info::MAX_KERNEL_ARGUMENTS != 128
            || engine::Limits::default().staging_bytes != STAGING
            || engine::Limits::default().tile_bytes != 128 << 20
        {
            return Err(Error::Configuration);
        }
        let prefix = "#define LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE 1\n";
        let mut digest = Sha3_256::new();
        digest.update(prefix.as_bytes());
        let mut source_bytes = prefix.len();
        for source in SOURCES {
            digest.update(b"\n");
            digest.update(source.as_bytes());
            source_bytes = add(source_bytes, add(1, source.len())?)?;
        }
        digest.update(b"\n");
        source_bytes = add(source_bytes, 1)?;
        let mut tuning_bytes = 0;
        for part in tuning_fragments() {
            digest.update(part.as_bytes());
            source_bytes = add(source_bytes, part.len())?;
            tuning_bytes = add(tuning_bytes, part.len())?;
        }
        let mut host = mul(add(source_bytes, 1)?, 4)?;
        if tuning_bytes != 0 {
            host = add(host, mul(add(tuning_bytes, 8)?, 4)?)?;
        }
        let physical = bounded::footprint();
        for bytes in [
            STAGING,
            WRAPPER_DESCRIPTORS,
            DRIVER_TEXT_OVERLAP,
            RAW_KERNEL_WRAPPERS,
            size_of::<Runtime>(),
            size_of::<Selection>(),
            size_of::<Self>(),
            size_of::<Engine>(),
            physical.fixed_selection_inline,
            physical.diagnostic_inline,
            bounded::fixed::inline_bytes(),
            mul(physical.maximum_string_requests, 3)?,
            Environment::inline_and_scratch_bytes(),
            mul(super::host_storage::session_bytes(), 2)?,
            mul(size_of::<super::ProofCapacity>(), 2)?,
        ] {
            host = add(host, bytes)?;
        }
        #[cfg(feature = "ringct-research-quota")]
        {
            host = add(host, retirement::additional_host_bytes())?;
        }
        let (retained_tree_host_bytes, retained_tree_quota_wrapper_bytes) = match tree_profile {
            TreeProfile::Device => (0, 0),
            TreeProfile::OuterHostV1 => (
                OUTER_TREE_HOST,
                crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<
                    engine::retained_storage::HostQuota,
                >(),
            ),
        };
        // The regular startup descriptor claim already covers its ordinary
        // engine metadata. Charge this additional host-tree wrapper explicitly;
        // no backend metadata overlap is credited to the new outer profile.
        host = add(
            host,
            add(retained_tree_host_bytes, retained_tree_quota_wrapper_bytes)?,
        )?;
        Ok(Self {
            footprint: Footprint {
                requested_host_bytes: host,
                managed_device_bytes: add(STAGING, CONSTANT_BYTES)?,
                mapped_staging_bytes: STAGING,
                source_bytes,
                source_sha3: digest.finalize().into(),
                driver_context_reserve: CONTEXT,
                retained_tree_host_bytes,
                retained_tree_quota_wrapper_bytes,
            },
            tree_profile,
        })
    }
    pub fn footprint(&self) -> Footprint {
        self.footprint
    }

    /// Read-only census precondition for an already-created, otherwise unused
    /// serial research context. This neither reserves storage nor grants an
    /// epoch, lease or operation permit. It performs no allocation, environment
    /// read, driver query, queue drain or GPU submission. The caller still owns
    /// the context and the external immutable-environment/process contract.
    pub fn check_current_engine(&self) -> Result<(), Error> {
        let slot = engine::ENGINE.get().ok_or(Error::Lifecycle)?;
        let guard = slot.lock().map_err(|_| Error::Lifecycle)?;
        let live = guard.as_ref().ok_or(Error::Lifecycle)?;
        check_engine_selection(self.tree_profile, true, live.limits, live.tree_storage.selection())?;
        // The ordinary Session does not retain Selection's bounded environment.
        // Check its actual selector and staging backing instead of assuming the
        // source-bounded constructor created this Engine. All other retained
        // wrapper owners are inline or included in WRAPPER_DESCRIPTORS.
        let mut variable_wrappers = mul(live.staging.capacity(), size_of::<Staging>())?;
        for selector in live.device_selection.iter().flatten() {
            variable_wrappers = add(variable_wrappers, selector.capacity())?;
        }
        for fixed in [
            size_of::<OnceLock<Mutex<Option<Engine>>>>()
                .checked_sub(size_of::<Engine>()).ok_or(Error::Resource)?,
            size_of::<Mutex<()>>(),
            crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<Mutex<Accounting>>(),
            crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<JobLease>(),
            crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<engine::retained_storage::HostQuota>(),
        ] {
            variable_wrappers = add(variable_wrappers, fixed)?;
        }
        if variable_wrappers > WRAPPER_DESCRIPTORS
            || live.staging.len() != live.mode.slots()
            || live.staging.capacity() > 4
            || live.timeline.events.capacity() != 0
            || live.timeline.dropped != 0
        {
            return Err(Error::Lifecycle);
        }
        let accounting = live.accounting.lock().map_err(|_| Error::Lifecycle)?;
        let startup_allocations = u64::try_from(4 + live.mode.slots())
            .map_err(|_| Error::Resource)?;
        if accounting.live != self.footprint.managed_device_bytes
            || accounting.peak != accounting.live
            || accounting.allocations != startup_allocations
            || accounting.retained_live != 0
            || accounting.retained_peak != 0
            || accounting.retained_trees != 0
            || accounting.device_live != 0
            || accounting.device_peak != 0
            || accounting.device_buffers != 0
            || accounting.memory_window.is_some()
            || accounting.proof_capacity.is_some()
            || accounting.capacity_generation != 0
            || live.tree_storage.live() != 0
            || live.workspace.is_some()
            || live.lde_workspace.is_some()
            || live.query.is_some()
            || live.native_private_spend_program.is_some()
            || live.stats.commits != 0
            || live.stats.uploaded_bytes != 0
            || live.stats.downloaded_bytes != 0
        {
            return Err(Error::Lifecycle);
        }
        Ok(())
    }

    /// # Safety
    /// The original shared worker Ledger reservation for this exact source-built
    /// footprint must already be live and must outlive Selection, Runtime and
    /// all errors. The guarded process environment is immutable until these
    /// owners retire. No other startup/shutdown/unreserved work may enter.
    /// This performs no context, queue, program or Engine construction.
    pub unsafe fn inspect(&self) -> Result<Selection, Error> {
        require_idle()?;
        // SAFETY: caller owns the immutable guarded process environment.
        let environment =
            unsafe { Environment::capture(&KEYS) }.map_err(|_| Error::Configuration)?;
        validate_environment(self.tree_profile, &environment)?;
        let request = bounded::Request::parse(
            environment
                .text(c"LATTICA_V2_GPU_DEVICE")
                .map_err(|_| Error::Configuration)?
                .ok_or(Error::Configuration)?,
            environment
                .text(c"LATTICA_GPU_DEVICE_UUID")
                .map_err(|_| Error::Configuration)?
                .ok_or(Error::Configuration)?,
        )
        .map_err(|_| Error::Configuration)?;
        let mut scratch = bounded::Scratch::new();
        let selected =
            bounded::Snapshot::capture(request, &mut scratch).map_err(|_| Error::Device)?;
        let identity = selected.identity();
        if identity.name != "NVIDIA GeForce RTX 5080"
            || identity.global_bytes < (MANAGED + CONTEXT) as u64
            || identity.max_allocation_bytes < STAGING as u64
            || device::public_hash::nvidia::source_prefix(selected.device()).is_empty()
        {
            return Err(Error::Device);
        }
        let maximum_work_group_size = selected.device().max_wg_size().map_err(|_| Error::Device)?;
        if maximum_work_group_size < 256 {
            return Err(Error::Device);
        }
        // SAFETY: same guard contract; refuse drift before creating Context/Program.
        unsafe { environment.recheck() }.map_err(|_| Error::Configuration)?;
        Ok(Selection {
            selected,
            scratch,
            request,
            environment,
            footprint: self.footprint,
            tree_profile: self.tree_profile,
            maximum_work_group_size,
        })
    }
}

fn require_idle() -> Result<(), Error> {
    let _initialize = INITIALIZE.lock().map_err(|_| Error::Lifecycle)?;
    if let Some(slot) = ENGINE.get() {
        if slot.lock().map_err(|_| Error::Lifecycle)?.is_some() {
            return Err(Error::Lifecycle);
        }
    }
    Ok(())
}

impl Selection {
    pub fn recheck_idle(&mut self) -> Result<(), Error> {
        require_idle()?;
        self.recheck()
    }

    fn recheck(&mut self) -> Result<(), Error> {
        // SAFETY: inspect's sealed-process contract persists until destruction.
        unsafe { self.environment.recheck() }.map_err(|_| Error::Configuration)?;
        validate_environment(self.tree_profile, &self.environment)?;
        self.selected
            .recheck(self.request, &mut self.scratch)
            .map_err(|_| Error::Device)
    }

    /// Consumes the already reserved, bounded selection. The immutable-process
    /// contract established by StartupPlan::inspect still applies. No caller
    /// supplied device, budget, metadata or environment replaces this owner.
    pub fn start(mut self) -> Result<Runtime, Error> {
        self.recheck_idle()?;
        let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env()
            .map_err(|_| Error::Configuration)?;
        if !fusion
            || !crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)
                .map_err(|_| Error::Configuration)?
        {
            return Err(Error::Configuration);
        }
        let epoch = engine::initialize_explicit(
            Limits {
                managed_bytes: MANAGED,
                ..Limits::default()
            },
            &self.selected,
        )
        .map_err(|_| Error::Initialization)?;
        let mut runtime = Runtime {
            epoch,
            selection: self,
        };
        if crate::block_v2::gpu_hash::initialize_tracked_from_env()
            .map_err(|_| Error::Initialization)?
            || !crate::block_v2::gpu_hash::initialize_resident_from_env()
                .map_err(|_| Error::Initialization)?
        {
            return Err(Error::Initialization);
        }
        runtime.recheck()?;
        Ok(runtime)
    }
}

impl Runtime {
    pub fn identity(&self) -> &crate::gpu_device::Identity {
        self.selection.selected.identity()
    }
    pub fn maximum_work_group_size(&self) -> usize {
        self.selection.maximum_work_group_size
    }
    pub fn footprint(&self) -> Footprint {
        self.selection.footprint
    }
    pub fn recheck(&mut self) -> Result<(), Error> {
        self.selection.recheck()?;
        self.epoch.check_live().map_err(|_| Error::Lifecycle)
    }
    /// The caller holds the actual Engine lock and retains this runtime's
    /// original ledger owner. This only checks identity; it grants no capacity.
    /// Environment/physical recheck must run before acquiring the Engine lock.
    pub(in crate::block_v2::gpu_hash::engine) fn check_engine(
        &self,
        live: &engine::Engine,
    ) -> Result<(), Error> {
        self.epoch
            .check_engine(live)
            .map_err(|_| Error::Lifecycle)?;
        check_engine_selection(
            self.selection.tree_profile,
            self.epoch.selected_device() == self.selection.selected.device(),
            live.limits,
            live.tree_storage.selection(),
        )
    }
    /// Aborts on any uncertain cleanup before the enclosing quota can release.
    pub fn retire(&mut self) -> Retirement {
        let receipt = self.epoch.retire();
        Retirement {
            managed_live_bytes: receipt.managed_live_bytes,
            managed_peak_bytes: receipt.managed_peak_bytes,
            host_tree_live_bytes: receipt.host_tree_live_bytes,
            lease_released: receipt.lease_released,
        }
    }
}

fn check_engine_selection(
    profile: TreeProfile,
    device_matches: bool,
    limits: engine::Limits,
    trees: engine::retained_storage::Selection,
) -> Result<(), Error> {
    let expected_trees = match profile {
        TreeProfile::Device => (engine::RetainedTreeStorageMode::Device, 0),
        TreeProfile::OuterHostV1 => (
            engine::RetainedTreeStorageMode::HostBacking,
            OUTER_TREE_HOST,
        ),
    };
    if !device_matches
        || limits.managed_bytes != MANAGED
        || limits.tile_bytes != 128 << 20
        || limits.staging_bytes != STAGING
        || (trees.mode, trees.host_bytes) != expected_trees
    {
        return Err(Error::Lifecycle);
    }
    Ok(())
}

fn validate_environment(tree_profile: TreeProfile, environment: &Environment) -> Result<(), Error> {
    validate_values(tree_profile, |key| {
        environment.value(key).map_err(|_| Error::Configuration)
    })
}

fn validate_values<'a>(
    tree_profile: TreeProfile,
    value: impl Fn(&CStr) -> Result<Option<&'a [u8]>, Error>,
) -> Result<(), Error> {
    if value(c"LATTICA_V2_GPU_HASH")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_RETAIN_TREES")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_QUERY_GATHER")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_RESIDENT_LDE")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_OPENINGS")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_QUOTIENT_FUSION")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_QUOTIENT_LDE")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_QUOTIENT_EVAL")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_QUOTIENT_RESIDENT")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_LOOKUP")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_OPENING_EVAL")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_FRI_RESIDENT")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_PCS_DEVICE_ONLY")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_WITNESS")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_RANDOMNESS")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_TRANSCRIPT")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_FRI_FOLD")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_PROVING_REPORT")? != Some(&b"1"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_PROVING_POLICY")? != Some(&b"gpu-required"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_MANAGED_BYTES")? != Some(&b"8589934592"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_GPU_CONTEXT_BYTES")? != Some(&b"4294967296"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_HOST_OUTPUT_BYTES")? != Some(&b"25769803776"[..]) {
        return Err(Error::Configuration);
    }
    match tree_profile {
        TreeProfile::Device => {
            if value(c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE")? != Some(&b"device"[..])
                || value(c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES")?.is_some()
            {
                return Err(Error::Configuration);
            }
        }
        TreeProfile::OuterHostV1 => {
            if value(c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE")? != Some(&b"host"[..])
                || value(c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES")? != Some(&b"8589934592"[..])
            {
                return Err(Error::Configuration);
            }
        }
    }
    if value(c"LATTICA_V2_GPU_PUBLIC_HASH")? != Some(&b"baseline"[..]) {
        return Err(Error::Configuration);
    }
    if value(c"RAYON_NUM_THREADS")? != Some(&b"8"[..]) {
        return Err(Error::Configuration);
    }
    if !matches!(value(c"LATTICA_V2_GPU_PIPELINE")?, None | Some(b"0")) {
        return Err(Error::Configuration);
    }
    if !matches!(
        value(c"LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE")?,
        None | Some(b"0")
    ) {
        return Err(Error::Configuration);
    }
    if !matches!(
        value(c"LATTICA_V2_GPU_COMPACT_PROVER_DATA")?,
        None | Some(b"0")
    ) {
        return Err(Error::Configuration);
    }
    if !matches!(value(c"LATTICA_V2_GPU_OPENING_COMPACT")?, None | Some(b"0")) {
        return Err(Error::Configuration);
    }
    if !matches!(value(c"LATTICA_PROFILE_TIMELINE")?, None | Some(b"0")) {
        return Err(Error::Configuration);
    }
    if !matches!(value(c"LATTICA_FFT_TRACE")?, None | Some(b"0")) {
        return Err(Error::Configuration);
    }
    if !matches!(
        value(c"LATTICA_V2_GPU_LDE_WORKSPACE_BYTES")?,
        None | Some(b"0")
    ) {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_WORKER_BUDGET")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_WALLET_WORKER_BUDGET")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_SHARED_PREPROCESSING_DIR")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_PHASE_DIR")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_LATE_PHASE_DIR")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_QUERY_PHASE_DIR")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_V2_LDE_SCRATCH_BYTES")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"RUST_MIN_STACK")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"RAYON_RS_NUM_CPUS")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_GPU_DRAIN_FAILURE_TEST_CHILD")?.is_some() {
        return Err(Error::Configuration);
    }
    if value(c"LATTICA_GPU_LEASE_DEATH_TEST_CHILD")?.is_some() {
        return Err(Error::Configuration);
    }
    if !matches!(value(c"LATTICA_V2_GPU_TUNING")?, None | Some(b""))
        || !matches!(value(c"LATTICA_V2_GPU_WORKERS")?, None | Some(b"1"))
    {
        return Err(Error::Configuration);
    }
    for key in &KEYS[48..] {
        if value(key)?.is_some() {
            return Err(Error::Configuration);
        }
    }
    Ok(())
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;

#[cfg(feature = "ringct-research-quota")]
mod retirement;
#[cfg(feature = "ringct-research-quota")]
pub use retirement::RetiredRuntime;
