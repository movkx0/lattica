//! Experimental device-owned intermediates for one proof attempt and context.
//! Operations drain commands before temporary buffers or host slices go away,
//! including on unwinding. No host matrix facade, implicit readback or fallback.
use super::{allocation, Allocation, Engine, JobLease, Lease, RetainedTree, ENGINE};
use crate::block_v2::compute;
use crate::config::Val;
use std::sync::{Arc, Mutex};

mod host_storage;
mod observation;
#[cfg(feature = "gpu")]
mod event_batch;
#[cfg(feature = "gpu")]
pub(super) use event_batch::EventReceipts;
pub(crate) use host_storage::HostScope;
pub(crate) use observation::ExecutionObservation;
mod commit_storage;
mod compiler_constants;
mod compiler_folding;
pub(crate) use commit_storage::{CommitInputStorage, SampleLocation};
mod evaluations;
pub(crate) mod public_hash;
mod random;
mod random_kernels;
mod scalars;
mod transcript;
mod transcript_kernels;
pub(super) use compiler_constants::KERNEL_SRC as COMPILER_CONSTANTS_KERNEL_SRC;
pub(super) use compiler_folding::KERNEL_SRC as COMPILER_FOLDING_KERNEL_SRC;
pub(super) use evaluations::KERNEL_SRC as EVALUATIONS_KERNEL_SRC;
pub(crate) use evaluations::{EvaluationInput, EvaluationShape};
pub(super) use public_hash::KERNEL_SRC as PUBLIC_HASH_KERNEL_SRC;
pub(crate) use scalars::DomainSpec;
pub(super) use scalars::KERNEL_SRC as SCALARS_KERNEL_SRC;
pub(crate) use transcript::{DeviceTranscript, TranscriptAttempt};
pub(super) use transcript_kernels::KERNEL_SRC as TRANSCRIPT_KERNEL_SRC;
mod htlc_kernels;
mod periodic;
pub(crate) use periodic::PeriodicShape;
mod trace_commit;
mod wallet;
#[cfg(feature = "gpu")]
mod wallet_batch_kernels;
mod wallet_kernels;
pub(super) use periodic::KERNEL_SRC as PERIODIC_KERNEL_SRC;
#[cfg(feature = "gpu")]
pub(super) use wallet_batch_kernels::KERNEL_SRC as WALLET_BATCH_KERNEL_SRC;
mod witness;
mod witness_kernels;
pub(super) use htlc_kernels::KERNEL_SRC as HTLC_KERNEL_SRC;
pub(crate) use random::salt_replay_workspace_bytes;
pub(crate) use random::PublicSaltStream;
pub use random::PublicSalts;
pub use random::ReplaySalts;
pub(crate) use random::{DeviceRandom, RandomWords};
pub(super) use random_kernels::KERNEL_SRC as RANDOM_KERNEL_SRC;
#[cfg(test)]
pub(super) use random_kernels::REFERENCE_KERNEL_SRC as RANDOM_REFERENCE_KERNEL_SRC;
pub(crate) use wallet::{WalletDevicePlan, WalletProofMinimum, WalletTrace};
pub(super) use wallet_kernels::KERNEL_SRC as WALLET_KERNEL_SRC;
pub(crate) use witness::{PreparedWitness, PreprocessingTrace, WitnessError};
pub(super) use witness_kernels::KERNEL_SRC as WITNESS_KERNEL_SRC;
mod transform;
pub(super) use trace_commit::KERNEL_SRC as TRACE_COMMIT_KERNEL_SRC;
pub(crate) use trace_commit::{TraceCommitInput, TraceCommitShape};
pub(super) use transform::KERNEL_SRC as TRANSFORM_KERNEL_SRC;
mod storage;
pub(crate) use storage::PublicMatrix;
pub(super) use storage::{capture_specs, KERNEL_SRC as STORAGE_KERNEL_SRC};
mod fri;
mod lookup;
mod lookup_kernels;
mod opening;
mod opening_kernels;
mod opening_quadratic_kernels;
mod query;
pub(super) use fri::GENERAL_KERNEL_SRC as GENERAL_FRI_KERNEL_SRC;
pub(super) use fri::KERNEL_SRC as FRI_KERNEL_SRC;
pub(crate) use opening::{DeviceOpening, OpeningAccumulator};
pub(super) use opening_kernels::KERNEL_SRC as OPENING_KERNEL_SRC;
pub(super) use opening_quadratic_kernels::KERNEL_SRC as QUADRATIC_OPENING_KERNEL_SRC;
pub(super) use query::KERNEL_SRC as QUERY_KERNEL_SRC;
mod quotient;
mod quotient_commit;
pub(crate) use lookup::PreparedLookup;
pub(super) use lookup_kernels::KERNEL_SRC as LOOKUP_KERNEL_SRC;
pub(crate) use quotient::PreparedQuotient;
pub(super) use quotient::KERNEL_SRC as QUOTIENT_KERNEL_SRC;
pub(super) use quotient_commit::KERNEL_SRC as QUOTIENT_COMMIT_KERNEL_SRC;
pub(crate) use quotient_commit::{QuotientCommitInput, QuotientCommitShape};

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extension {
    Base,
    Quadratic,
    Cubic,
}
impl Extension {
    pub fn degree(self) -> usize {
        match self {
            Self::Base => 1,
            Self::Quadratic => 2,
            Self::Cubic => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowOrder {
    Natural,
    BitReversed,
}

/// Contiguous row-major field elements, with adjacent extension coefficients.
/// `shift` is a canonical, nonzero Goldilocks coset multiplier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixSpec {
    log_rows: u32,
    columns: usize,
    extension: Extension,
    order: RowOrder,
    shift: u64,
    words: usize,
}

impl MatrixSpec {
    pub fn new(
        log_rows: u32,
        columns: usize,
        extension: Extension,
        order: RowOrder,
        shift: u64,
    ) -> Result<Self, String> {
        if log_rows > 32 || columns == 0 || columns > u32::MAX as usize {
            return Err("invalid device matrix dimensions".into());
        }
        if shift == 0 || shift >= GOLDILOCKS_MODULUS {
            return Err("device matrix coset shift must be canonical and nonzero".into());
        }
        let words = 1usize
            .checked_shl(log_rows)
            .and_then(|rows| rows.checked_mul(columns))
            .and_then(|elements| elements.checked_mul(extension.degree()))
            .filter(|words| words.checked_mul(8).is_some())
            .ok_or("device matrix storage overflow")?;
        Ok(Self {
            log_rows,
            columns,
            extension,
            order,
            shift,
            words,
        })
    }
    pub fn rows(self) -> usize {
        1usize << self.log_rows
    }
    pub fn columns(self) -> usize {
        self.columns
    }
    pub fn extension(self) -> Extension {
        self.extension
    }
    pub fn order(self) -> RowOrder {
        self.order
    }
    pub fn shift(self) -> u64 {
        self.shift
    }
    pub fn words(self) -> usize {
        self.words
    }
    pub fn bytes(self) -> usize {
        self.words * 8
    }

    fn cubic_fold_output(self) -> Result<Self, String> {
        if self.extension != Extension::Cubic
            || self.columns != 1
            || self.order != RowOrder::BitReversed
            || self.shift != 1
            || !(1..=25).contains(&self.log_rows)
        {
            return Err(
                "device FRI fold requires a bit-reversed cubic subgroup vector of 2..2^25 rows"
                    .into(),
            );
        }
        Self::new(self.log_rows - 1, 1, self.extension, self.order, 1)
    }
}

/// A snapshot, never a reservation. Execution replans under the engine lock;
/// allocation rechecks all live leases atomically, including retained trees.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct MemoryPlan {
    pub output_bytes: Vec<usize>,
    pub live_bytes: usize,
    pub peak_bytes: usize,
}
impl MemoryPlan {
    pub fn new(
        outputs: &[MatrixSpec],
        live_bytes: usize,
        managed_limit: usize,
        max_allocation: usize,
    ) -> Result<Self, String> {
        if outputs.is_empty() || outputs.len() > 256 || live_bytes > managed_limit {
            return Err("invalid device allocation plan".into());
        }
        let mut peak_bytes = live_bytes;
        let mut output_bytes = Vec::with_capacity(outputs.len());
        for output in outputs {
            let bytes = output.bytes();
            if bytes > max_allocation {
                return Err("device matrix exceeds per-allocation limit".into());
            }
            peak_bytes = peak_bytes
                .checked_add(bytes)
                .ok_or("device live-byte overflow")?;
            if peak_bytes > managed_limit {
                return Err("device matrix exceeds aggregate allocation budget".into());
            }
            output_bytes.push(bytes);
        }
        Ok(Self {
            output_bytes,
            live_bytes,
            peak_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub(crate) arithmetic: observation::ArithmeticStats,
    pub public_hash_calls: u64,
    pub public_hash_batches: u64,
    pub public_hash_fields: u64,
    pub public_hash_permutations: u64,
    pub public_hash_device_ns: u128,
    pub scalar_calls: u64,
    pub scalar_lookup_prefixes: u64,
    pub scalar_next_points: u64,
    pub scalar_cosets: u64,
    pub scalar_disjoint_domains: u64,
    pub scalar_input_bytes: u64,
    pub scalar_output_bytes: u64,
    pub scalar_device_ns: u128,
    pub transcript_creations: u64,
    pub transcript_snapshots: u64,
    pub transcript_observations: u64,
    pub transcript_observed_fields: u64,
    pub transcript_samples: u64,
    pub transcript_sampled_fields: u64,
    pub transcript_public_bytes: u64,
    pub transcript_device_ns: u128,
    pub grinding_calls: u64,
    pub grinding_batches: u64,
    pub grinding_candidates: u64,
    pub grinding_status_bytes: u64,
    pub grinding_device_ns: u128,
    pub random_streams: u64,
    pub random_calls: u64,
    pub random_fields: u64,
    pub random_draw_words: u64,
    pub random_status_bytes: u64,
    pub random_device_ns: u128,
    pub witness_programs: u64,
    pub witness_evaluations: u64,
    pub witness_waves: u64,
    pub witness_rows: u64,
    pub preprocessing_rows: u64,
    pub witness_status_bytes: u64,
    /// Completed transfers, including bounded control results (caps/status).
    /// Matrix readback requires an explicit `read` call.
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub cubic_folds: u64,
    pub general_fri_folds: u64,
    pub fold_device_ns: u128,
    pub commitments: u64,
    pub queries: u64,
    pub transforms: u64,
    pub transform_device_ns: u128,
    pub prepared_quotient_programs: u64,
    pub quotient_evaluations: u64,
    pub quotient_device_ns: u128,
    pub prepared_lookup_programs: u64,
    pub lookup_generations: u64,
    pub lookup_device_ns: u128,
    pub opening_evaluations: u64,
    pub opening_reductions: u64,
    pub opening_device_ns: u128,
    pub opening_value_bytes: u64,
    pub fri_mixes: u64,
    pub fri_mix_device_ns: u128,
    pub gathered_rows: u64,
    pub gathered_value_bytes: u64,
    pub query_reconstructions: u64,
    pub query_reconstruction_tiles: u64,
    pub query_value_bytes: u64,
    pub query_device_ns: u128,
}

impl Lease {
    fn mark_device(&mut self) -> Result<(), String> {
        if self.device || self.retained || self.bytes == 0 {
            return Err("invalid device matrix allocation lease".into());
        }
        let mut accounting = self.accounting.lock().unwrap();
        let next = accounting
            .device_live
            .checked_add(self.bytes)
            .ok_or("device matrix accounting overflow")?;
        let count = accounting
            .device_buffers
            .checked_add(1)
            .ok_or("device matrix count overflow")?;
        if next > accounting.live {
            return Err("device matrices exceed live reservations".into());
        }
        accounting.device_live = next;
        accounting.device_peak = accounting.device_peak.max(next);
        accounting.device_buffers = count;
        self.device = true;
        Ok(())
    }
}
struct Session {
    context: Arc<JobLease>,
    stats: Mutex<SessionStats>,
    observed_stages: std::sync::atomic::AtomicU32,
    transcript_host: Arc<host_storage::HostQuota>,
}

/// Clones refer to the same attempt. Create a fresh session for each new proof.
#[derive(Clone)]
pub struct DeviceSession {
    session: Arc<Session>,
}

/// Keeps managed capacity and the engine context through a serial proof.
/// The capacity lease drops first; actual allocations retain their own leases.
#[must_use = "retain managed capacity through all proving work and serialization"]
pub(crate) struct ProofCapacity {
    _capacity: super::capacity::Lease,
    _plan: Option<WalletDevicePlan>,
    _context: Arc<JobLease>,
}

/// Owns both the allocation reservation and the engine's exclusive device lease.
/// No `Clone`, host `Matrix`, or serialization implementation.
pub struct DeviceMatrix {
    storage: Arc<Allocation>,
    // Every alias of a generated random matrix retains its scrub owner.
    private_random: Option<Arc<random::SecretAllocation>>,
    session: Arc<Session>,
    spec: MatrixSpec,
}
impl DeviceMatrix {
    pub fn spec(&self) -> MatrixSpec {
        self.spec
    }

    /// Allocation/scrub-owner wrappers only. Session, shared engine/driver and
    /// device payloads have separate owners. Aliases may be charged repeatedly.
    pub(crate) fn retained_host_backing(&self) -> usize {
        matrix_host_backing(self.private_random.is_some())
    }
}

fn matrix_host_backing(has_scrub_owner: bool) -> usize {
    use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;
    arc_bytes::<Allocation>()
        + if has_scrub_owner {
            arc_bytes::<random::SecretAllocation>()
        } else {
            0
        }
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn retained_matrix_wrapper_backing_matches_allocator_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;
    let (_allocation, allocation) = measure(|| Arc::new(MaybeUninit::<Allocation>::uninit()));
    let (_scrub, scrub) = measure(|| Arc::new(MaybeUninit::<random::SecretAllocation>::uninit()));
    assert_eq!(matrix_host_backing(false), allocation.bytes);
    assert_eq!(matrix_host_backing(true), allocation.bytes + scrub.bytes);
    assert_eq!(allocation.calls + scrub.calls, 2);
    assert!(!allocation.overflow && !scrub.overflow);
}

/// The cap is the bounded transcript handoff. Tree nodes and the originating
/// context remain owned until this commitment is dropped.
pub struct DeviceCommitment {
    tree: RetainedTree,
    cap_height: usize,
    session: Arc<Session>,
}

impl DeviceCommitment {
    pub fn cap(&self) -> &[[Val; 4]] {
        self.tree.cap()
    }

    pub fn open(&self, index: usize) -> Result<Vec<[Val; 4]>, String> {
        let path = self.tree.open(index, self.cap_height)?;
        let mut stats = self.session.stats.lock().unwrap();
        stats.downloaded_bytes += (path.len() * 4 * 8) as u64;
        stats.queries += 1;
        Ok(path)
    }

    pub(crate) fn open_many(&self, indices: &[usize]) -> Result<Vec<Vec<[Val; 4]>>, String> {
        let paths = self.tree.open_many(indices, self.cap_height)?;
        let mut stats = self.session.stats.lock().unwrap();
        stats.downloaded_bytes += paths.iter().map(|p| p.len() as u64 * 32).sum::<u64>();
        stats.queries += indices.len() as u64;
        Ok(paths)
    }
}

impl DeviceSession {
    pub fn new() -> Result<Self, String> {
        let slot = ENGINE
            .get()
            .ok_or("GPU engine not initialized")?
            .lock()
            .map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_ref().ok_or("GPU engine shut down")?;
        Ok(Self {
            session: Arc::new(Session {
                context: engine._job_lease.clone(),
                stats: Mutex::new(SessionStats::default()),
                observed_stages: std::sync::atomic::AtomicU32::new(0),
                transcript_host: host_storage::new_quota(),
            }),
        })
    }

    /// Wallet proving uses the engine's existing managed ceiling, including
    /// retained allocations, rather than lending future phase capacity to a
    /// competing caller. Shape-derived peak admission remains a separate step.
    pub(crate) fn reserve_proof_capacity(&self) -> Result<ProofCapacity, String> {
        self.reserve_wallet_capacity(None)
    }

    /// Reject impossible wallet shapes under the same engine lock that grants
    /// the capacity owner. Existing reusable workspaces are already included
    /// in that owner's ceiling; the minimum is not added to live bytes again.
    pub(crate) fn reserve_wallet_proof_capacity(
        &self,
        minimum: WalletProofMinimum,
    ) -> Result<ProofCapacity, String> {
        self.reserve_wallet_capacity(Some(minimum))
    }

    fn reserve_wallet_capacity(
        &self,
        minimum: Option<WalletProofMinimum>,
    ) -> Result<ProofCapacity, String> {
        self.with_engine(|engine| {
            if let Some(minimum) = minimum {
                minimum.check(engine.limits.managed_bytes, engine.max_alloc)?;
            }
            let mut plan = None;
            let capacity = super::capacity::Lease::new_checked(
                engine.accounting.clone(),
                engine.limits.managed_bytes,
                engine.limits.managed_bytes,
                |live| {
                    plan = minimum
                        .map(|minimum| minimum.plan(engine, live))
                        .transpose()?;
                    Ok(())
                },
            )?;
            if let Some(plan) = &plan {
                plan.report();
            }
            Ok(ProofCapacity {
                _capacity: capacity,
                _plan: plan,
                _context: engine._job_lease.clone(),
            })
        })
    }
    fn with_engine<T>(
        &self,
        operation: impl FnOnce(&mut Engine) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut slot = ENGINE
            .get()
            .ok_or("GPU engine not initialized")?
            .lock()
            .map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_mut().ok_or("GPU engine shut down")?;
        if !Arc::ptr_eq(&self.session.context, &engine._job_lease) {
            return Err("device session belongs to another GPU context".into());
        }
        operation(engine)
    }
    fn check_owner(&self, matrix: &DeviceMatrix) -> Result<(), String> {
        if !Arc::ptr_eq(&self.session, &matrix.session) {
            return Err("device matrix belongs to another proof session".into());
        }
        Ok(())
    }
    fn plan(engine: &Engine, outputs: &[MatrixSpec]) -> Result<MemoryPlan, String> {
        MemoryPlan::new(
            outputs,
            engine.accounting.lock().unwrap().live,
            engine.limits.managed_bytes,
            engine.max_alloc,
        )
    }
    pub(super) fn allocate(
        &self,
        engine: &Engine,
        spec: MatrixSpec,
    ) -> Result<DeviceMatrix, String> {
        if !Arc::ptr_eq(&self.session.context, &engine._job_lease) {
            return Err("device allocation belongs to another context".into());
        }
        let _plan = Self::plan(engine, &[spec])?;
        let mut storage = allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            spec.words,
            compute::flags::MEM_READ_WRITE,
        )?;
        storage._lease.mark_device()?;
        Ok(DeviceMatrix {
            storage: Arc::new(storage),
            private_random: None,
            session: self.session.clone(),
            spec,
        })
    }
    pub fn plan_outputs(&self, outputs: &[MatrixSpec]) -> Result<MemoryPlan, String> {
        self.with_engine(|engine| Self::plan(engine, outputs))
    }
    pub fn stats(&self) -> SessionStats {
        *self.session.stats.lock().unwrap()
    }

    pub(crate) fn try_stats(&self) -> Option<SessionStats> {
        self.session.stats.lock().ok().map(|stats| *stats)
    }

    fn commit_plan(
        engine: &Engine,
        shape: MatrixSpec,
        cap_height: usize,
        pending_salt_bytes: usize,
    ) -> Result<(super::RetainedLayout, super::Plan), String> {
        let width = shape
            .columns
            .checked_mul(shape.extension.degree())
            .filter(|n| *n <= u32::MAX as usize - 4)
            .ok_or("device commitment row width overflow")?;
        if pending_salt_bytes > engine.max_alloc {
            return Err("device commitment salt allocation exceeds device limit".into());
        }
        if !engine.retain_trees {
            return Err("device commitments require retained trees".into());
        }
        let height = shape.rows();
        let layout = super::retained_layout(height, cap_height, engine.max_alloc)?;
        let plan = super::plan_slots(
            height,
            width + 4,
            engine.limits,
            engine.max_alloc,
            engine.mode.slots(),
        )?;
        let sponge_words = height.checked_mul(8).ok_or("device sponge size overflow")?;
        let sponge_bytes = sponge_words
            .checked_mul(8)
            .ok_or("device sponge size overflow")?;
        if sponge_bytes > engine.max_alloc {
            return Err("device sponge exceeds allocation limit".into());
        }
        // The transform cache is replaceable; input/session allocations and
        // all previous commitments stay live throughout this operation.
        let cached = engine.lde_workspace.as_ref().map_or(0, |w| w.bytes());
        let old_workspace = engine.workspace.as_ref().map_or(0, super::Workspace::bytes);
        let next_workspace = if engine
            .workspace
            .as_ref()
            .is_some_and(|w| w.fits(plan, engine.mode.slots()))
        {
            old_workspace
        } else {
            plan.bytes
                - super::CONSTANT_BYTES
                - engine.limits.staging_bytes
                - super::transport_bytes(engine.limits)
        };
        let live = engine
            .accounting
            .lock()
            .unwrap()
            .live
            .checked_sub(cached)
            .ok_or("device commitment accounting underflow")?;
        let tree_and_sponge = (layout.elements * 8)
            .checked_add(sponge_bytes)
            .ok_or("device commitment size overflow")?;
        super::retained_peak(
            live.checked_add(pending_salt_bytes)
                .ok_or("device commitment budget overflow")?,
            old_workspace,
            next_workspace,
            tree_and_sponge,
            if engine.query.is_none() {
                super::QUERY_ELEMENTS * 8
            } else {
                0
            },
            engine.limits.managed_bytes,
        )?;
        Ok((layout, plan))
    }

    /// Admission before salts are sampled. Execution rechecks under the engine
    /// lock after those salts have been uploaded; this is not a reservation.
    pub(crate) fn preflight_commit(
        &self,
        input: &DeviceMatrix,
        cap_height: usize,
    ) -> Result<(), String> {
        self.check_owner(input)?;
        let salt_bytes = input
            .spec
            .rows()
            .checked_mul(32)
            .ok_or("device salt size overflow")?;
        self.with_engine(|engine| {
            // Upload happens before commit() can replace its transform cache.
            // Admit that staging peak as well as the later hashing peak.
            let salt_spec = MatrixSpec::new(
                input.spec.log_rows,
                4,
                Extension::Base,
                input.spec.order,
                input.spec.shift,
            )?;
            Self::plan(engine, &[salt_spec])?;
            Self::commit_plan(engine, input.spec, cap_height, salt_bytes).map(|_| ())
        })
    }

    /// Commit one matrix plus its four explicit salt columns directly from
    /// device storage. Salts are per-attempt inputs, never cached or generated
    /// here. The only readback is the cap; authentication nodes stay on device.
    pub fn commit(
        &self,
        input: &DeviceMatrix,
        salts: &DeviceMatrix,
        cap_height: usize,
    ) -> Result<DeviceCommitment, String> {
        self.check_owner(input)?;
        self.check_owner(salts)?;
        let shape = input.spec;
        if salts.spec
            != MatrixSpec::new(shape.log_rows, 4, Extension::Base, shape.order, shape.shift)?
        {
            return Err(
                "device commitment requires four salt columns on the same row domain".into(),
            );
        }
        let width = shape
            .columns
            .checked_mul(shape.extension.degree())
            .filter(|n| *n <= u32::MAX as usize - 4)
            .ok_or("device commitment row width overflow")?;
        self.with_engine(|engine| {
            self.observe_engine(engine, |engine| {
                let (layout, plan) = Self::commit_plan(engine, shape, cap_height, 0)?;
                let height = shape.rows();
                let sponge_words = height * 8;
                engine.fence().finish()?;
                engine.lde_workspace = None;
                engine.workspace(plan)?;
                let sponge = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    sponge_words,
                    compute::flags::MEM_READ_WRITE,
                )?;
                let mut storage = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    layout.elements,
                    compute::flags::MEM_READ_WRITE,
                )?;
                storage._lease.mark_retained()?;
                let fence = engine.fence();
                sponge
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
                engine.lde_absorb(&input.storage.buffer, &sponge.buffer, 0, height, width, 0)?;
                engine.lde_absorb(
                    &salts.storage.buffer,
                    &sponge.buffer,
                    0,
                    height,
                    4,
                    width % 4,
                )?;
                let mut event = compute::Event::empty();
                // SAFETY: planner checked the height, eight-word states, four-word
                // leaves and all live allocations. Fence precedes buffer release.
                unsafe {
                    engine.commitment_builder("lde_leaf_finalize", height)?
                        .arg(&sponge.buffer)
                        .arg(&engine.workspace.as_ref().unwrap().a.buffer)
                        .arg(height as u32)
                        .arg((width % 4) as u32)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = engine.timeline.record("resident_commit_finalize", &event)?;
                engine.stats.leaf_kernel_ns += ns;
                let cap = engine.finish_retained_layers(&storage, height, layout)?;
                fence.finish()?;
                engine.stats.commits += 1;
                let mut stats = self.session.stats.lock().unwrap();
                stats.commitments += 1;
                stats.downloaded_bytes += (cap.len() * 4 * 8) as u64;
                Ok(DeviceCommitment {
                    tree: RetainedTree {
                        storage,
                        height,
                        layout,
                        cap,
                        _job_lease: engine._job_lease.clone(),
                    },
                    cap_height,
                    session: self.session.clone(),
                })
            })
        })
    }

    /// Explicit byte ingress. Validates canonical encoding without performing
    /// field arithmetic or normalizing field values on the host.
    pub fn upload(&self, spec: MatrixSpec, words: &[u64]) -> Result<DeviceMatrix, String> {
        if words.len() != spec.words || words.iter().any(|word| *word >= GOLDILOCKS_MODULUS) {
            return Err("device upload requires exact canonical matrix storage".into());
        }
        self.with_engine(|engine| {
            let output = self.allocate(engine, spec)?;
            let fence = engine.fence();
            output
                .storage
                .buffer
                .write(words)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += spec.bytes() as u64;
            self.session.stats.lock().unwrap().uploaded_bytes += spec.bytes() as u64;
            Ok(output)
        })
    }
    /// Explicit egress, with a host allowance separate from the device budget.
    pub fn read(&self, matrix: &DeviceMatrix, host_allowance: usize) -> Result<Vec<u64>, String> {
        self.check_owner(matrix)?;
        if matrix.spec.bytes() > host_allowance {
            return Err("device readback exceeds host allowance".into());
        }
        self.with_engine(|engine| {
            let mut words = vec![0u64; matrix.spec.words];
            let fence = engine.fence();
            matrix
                .storage
                .buffer
                .read(&mut words)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += matrix.spec.bytes() as u64;
            self.session.stats.lock().unwrap().downloaded_bytes += matrix.spec.bytes() as u64;
            Ok(words)
        })
    }
    /// One binary cubic fold with no transfers, not a complete FRI prover.
    /// Commitments, sampling and queries remain caller work. Metal rejects this
    /// operation until its matching kernel is implemented.
    pub fn fold_cubic(&self, input: &DeviceMatrix, beta: [u64; 3]) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        let spec = input.spec.cubic_fold_output()?;
        if beta.iter().any(|word| *word >= GOLDILOCKS_MODULUS) {
            return Err("device FRI challenge is not canonical".into());
        }
        #[cfg(feature = "gpu")]
        return self.with_engine(|engine| {
            fri::storage::vector_output(
                spec,
                engine.accounting.lock().unwrap().live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            let output = self.allocate(engine, spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: validated shapes bound every coefficient access. Both
            // allocations and the exclusive session outlive the queue fence.
            unsafe {
                engine
                    .pq
                    .kernel_builder("fri_fold_two")
                    .arg(&input.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(spec.rows() as u32)
                    .arg(0u32)
                    .arg(spec.log_rows)
                    .arg(super::fri_fold::inverse_root(input.spec.log_rows))
                    .arg(beta[0])
                    .arg(beta[1])
                    .arg(beta[2])
                    .global_work_size(spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let device_ns = self.session.record_event(
                engine,
                crate::proving::Stage::FriFold,
                "resident_fri_fold_two",
                &event,
            )?;
            fence.finish()?;
            let mut stats = self.session.stats.lock().unwrap();
            stats.cubic_folds += 1;
            stats.fold_device_ns += device_ns;
            Ok(output)
        });
        #[cfg(not(feature = "gpu"))]
        {
            let _ = spec;
            Err("resident cubic FRI fold is not implemented for Metal".into())
        }
    }
}

#[cfg(test)]
mod tests;
