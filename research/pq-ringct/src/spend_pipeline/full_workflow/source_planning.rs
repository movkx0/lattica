//! Allocation-free bootstrap for one complete N3 or N4 case.
//!
//! Source planning binds every transaction to one pristine context and ledger.
//! It neither certifies fresh generation nor authorizes proof execution. Native
//! generation/terminal receipts and complete graph closure remain driver duties.
use super::{InitialNativeSource, SourceClosurePlanningPlan, SourceGraphPlan, SourcePreparationError, SourcePreparationPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Requirements, Reservation},
        workflow_resources::{controller_bytes, WorkflowPlanning},
        ProvingContext,
    },
    graph_crypto::{Admission, Policy as CryptoPolicy, ShakeWrapperLayout},
    graph_proofs::ResourceLimits,
    spend_pipeline::{AesLayout, Budgets, CompositeLayout, TranscriptLayout},
};
use core::mem::size_of;
use lattica_prover_p3::proving::Policy;
use sha3::{Digest, Sha3_256};

const WORKER_HOST: u64 = 32 << 30;
const NATIVE_HOST: u64 = 24 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const REGISTRY_HOST: u64 = 64 << 20;
type Result<T> = core::result::Result<T, SourcePreparationError>;

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(SourcePreparationError::Resource)
}
fn host(bytes: u64) -> Bytes { Bytes { host: bytes, device: 0 } }
fn as_u64(bytes: usize) -> Result<u64> {
    u64::try_from(bytes).map_err(|_| SourcePreparationError::Resource)
}

#[cfg(not(debug_assertions))]
use crate::execution::generation_terminal::planning_startup::FreshPlanningContext;
#[cfg(not(debug_assertions))]
enum OriginalGeneration<'source> {
    N3(&'source super::fresh_generation::FreshGenerationBatch<3>),
    N4(&'source super::fresh_generation::FreshGenerationBatch<4>),
}
#[cfg(not(debug_assertions))]
impl OriginalGeneration<'_> {
    fn bytes(&self) -> Result<Bytes> {
        match self { Self::N3(b) => b.owned_generation_bytes(), Self::N4(b) => b.owned_generation_bytes() }
            .map_err(|_| SourcePreparationError::Resource)
    }
    fn current_bytes(&self) -> Result<Bytes> {
        match self { Self::N3(b) => b.current_original_bytes(), Self::N4(b) => b.current_original_bytes() }
            .map_err(|_| SourcePreparationError::Resource)
    }
    fn reserve_descriptor(&self, requirements: Requirements) -> Result<Reservation> {
        match self { Self::N3(b) => b.claim_source_descriptor(requirements),
            Self::N4(b) => b.claim_source_descriptor(requirements) }
            .map_err(|_| SourcePreparationError::Resource)
    }
    fn owns(&self, sources: &[InitialNativeSource<'_>]) -> bool {
        match self { Self::N3(b) => b.owns_sources(sources), Self::N4(b) => b.owns_sources(sources) }
    }
    fn validate(&self, context: &FreshPlanningContext<'_>) -> Result<()> {
        match self { Self::N3(b) => b.validate_planning_context(context), Self::N4(b) => b.validate_planning_context(context) }
            .map_err(|_| SourcePreparationError::Identity)
    }
}
/// Private descriptor of validated existing ownership, never admission authority.
struct SourceEnvironment<'source> {
    context: &'source ProvingContext,
    enclosing: u64,
    already_owned: u64,
    backend_device: u64,
    owned_inputs: bool,
    #[cfg(not(debug_assertions))]
    generation: Option<OriginalGeneration<'source>>,
    #[cfg(not(debug_assertions))]
    fresh_context: Option<&'source FreshPlanningContext<'source>>,
    #[cfg(test)]
    fixture_context: Option<&'source crate::execution::generation_terminal::planning_startup::FixturePlanningContext>,
}

/// The fixed array constructors make the complete retained native inventory
/// explicit; spare capacity in encoded/decoded owners is charged by each view.
/// The enclosing deduction persists for this whole case, through aggregation.
pub(crate) struct SourcePlanningPlan<'source> {
    #[cfg(not(debug_assertions))]
    verifiers: crate::graph_tree::metadata::verifier::VerifierCache,
    context: &'source ProvingContext,
    natives: &'source [InitialNativeSource<'source>],
    source: [u8; 32],
    compiled_source: [u8; 32],
    enclosing: Bytes,
    planning: Requirements,
    scratch: Requirements,
    backend: Bytes,
    layout: ShakeWrapperLayout,
    identity_limits: lattica_prover_p3::block_v2::machine::backend::identity_cpu::IdentityCpuOptions,
    budgets: Budgets,
    algebra_limits: ResourceLimits,
    #[cfg(not(debug_assertions))]
    original_generation: Option<OriginalGeneration<'source>>,
    #[cfg(not(debug_assertions))]
    fresh_context: Option<&'source FreshPlanningContext<'source>>,
    #[cfg(test)]
    fixture_context: Option<&'source crate::execution::generation_terminal::planning_startup::FixturePlanningContext>,
    #[cfg(not(debug_assertions))]
    descriptor_original: Option<Reservation>,
}

impl<'source> SourcePlanningPlan<'source> {
    #[cfg(not(debug_assertions))]
    pub(crate) fn fresh_n3(context: &'source FreshPlanningContext<'source>,
        natives: &'source [InitialNativeSource<'source>; 3], layout: ShakeWrapperLayout,
        generation: &'source super::fresh_generation::FreshGenerationBatch<3>,
    ) -> Result<Self> { Self::new_fresh(context, natives, layout, OriginalGeneration::N3(generation)) }
    #[cfg(not(debug_assertions))]
    pub(crate) fn fresh_n4(context: &'source FreshPlanningContext<'source>,
        natives: &'source [InitialNativeSource<'source>; 4], layout: ShakeWrapperLayout,
        generation: &'source super::fresh_generation::FreshGenerationBatch<4>,
    ) -> Result<Self> { Self::new_fresh(context, natives, layout, OriginalGeneration::N4(generation)) }
    #[cfg(not(debug_assertions))]
    fn new_fresh<const N: usize>(context: &'source FreshPlanningContext<'source>,
        natives: &'source [InitialNativeSource<'source>; N], layout: ShakeWrapperLayout,
        generation: OriginalGeneration<'source>,
    ) -> Result<Self> {
        generation.validate(context)?;
        if !generation.owns(natives) { return Err(SourcePreparationError::Identity); }
        let live = generation.bytes()?;
        let startup = context.original_requirements().map_err(|_| SourcePreparationError::Resource)?
            .total().map_err(|_| SourcePreparationError::Resource)?;
        let backend_device = context.source_backend_device_bytes().map_err(|_| SourcePreparationError::Resource)?;
        if live.device != 0 || add(startup.device, backend_device)? != MANAGED_DEVICE {
            return Err(SourcePreparationError::Resource);
        }
        Self::derive(natives, layout, SourceEnvironment { context: context.context(),
            enclosing: 0, already_owned: fresh_owned_host_with_limit(live, startup, generation.current_bytes()?, context.context().host_bytes())?, backend_device,
            owned_inputs: true, generation: Some(generation), fresh_context: Some(context), #[cfg(test)] fixture_context: None })
    }
    #[cfg(not(debug_assertions))]
    pub(crate) fn fresh_context(&self) -> Option<&'source FreshPlanningContext<'source>> {
        self.fresh_context
    }

    #[cfg(test)]
    pub(crate) fn fixture_n3(context: &'source crate::execution::generation_terminal::planning_startup::FixturePlanningContext,
        natives: &'source [InitialNativeSource<'source>; 3], layout: ShakeWrapperLayout) -> Result<Self> {
        let owned = context.ledger().snapshot().current;
        Self::derive(natives, layout, SourceEnvironment { context: context.context(), enclosing: 0,
            already_owned: owned.host, backend_device: context.source_backend_device_bytes().map_err(|_| SourcePreparationError::Resource)?,
            owned_inputs: true, generation: None, fresh_context: None, fixture_context: Some(context) })
    }
    #[cfg(test)]
    pub(crate) fn fixture_context(&self) -> Option<&'source crate::execution::generation_terminal::planning_startup::FixturePlanningContext> {
        self.fixture_context
    }
    pub(crate) fn n3(context: &'source ProvingContext,
        natives: &'source [InitialNativeSource<'source>; 3], layout: ShakeWrapperLayout,
    ) -> Result<Self> { Self::new(context, natives, layout) }

    pub(crate) fn n4(context: &'source ProvingContext,
        natives: &'source [InitialNativeSource<'source>; 4], layout: ShakeWrapperLayout,
    ) -> Result<Self> { Self::new(context, natives, layout) }

    fn new<const N: usize>(context: &'source ProvingContext,
        natives: &'source [InitialNativeSource<'source>; N], layout: ShakeWrapperLayout,
    ) -> Result<Self> {
        // The legacy descriptor is available only for a pristine unbound context.
        let footprint = context.workflow_enclosing_footprint().map_err(|_| SourcePreparationError::Resource)?;
        if footprint.managed_device_bytes != MANAGED_DEVICE { return Err(SourcePreparationError::Resource); }
        Self::derive(natives, layout, SourceEnvironment { context,
            enclosing: add(footprint.enclosing_host_bytes, REGISTRY_HOST)?, already_owned: 0,
            backend_device: MANAGED_DEVICE, owned_inputs: false,
            #[cfg(not(debug_assertions))] generation: None,
            #[cfg(not(debug_assertions))] fresh_context: None, #[cfg(test)] fixture_context: None })
    }
    fn derive<const N: usize>(natives: &'source [InitialNativeSource<'source>; N],
        layout: ShakeWrapperLayout, environment: SourceEnvironment<'source>,
    ) -> Result<Self> {
        let context = environment.context;
        if !matches!(N, 3 | 4)
            || !cfg!(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))
            || context.policy() != Policy::GpuRequired || context.host_bytes() != context.host_profile().worker_bytes() {
            return Err(SourcePreparationError::Source);
        }
        let compiled_source = crate::graph_proofs::compiled_source_fingerprint();
        let budgets = Budgets {
            native_bytes: NATIVE_HOST, outer_bytes: WORKER_HOST,
            cache_entry_bytes: REGISTRY_HOST,
            crypto_policy: CryptoPolicy { maximum_aes_blocks: 64,
                maximum_shake_permutations: 32, child_memory_budget_bytes: NATIVE_HOST,
                admission: Admission::Estimated },
            transcripts: TranscriptLayout::Serial, aes: AesLayout::Serial,
            composites: CompositeLayout::Branches,
        };
        // These maintained full-screen algebra limits are source geometry,
        // never a substitute for the later complete memory admission.
        let algebra_limits = ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: 32,
            max_mul_batch_count: 32,
            max_trace_cells: 1 << 27,
            max_estimated_prover_bytes: NATIVE_HOST,
        };
        let mut digest = Sha3_256::new();
        digest.update(b"lattica/ringct/owned-case-source/v1");
        digest.update(compiled_source);
        digest.update((N as u64).to_le_bytes());
        digest.update([match layout { ShakeWrapperLayout::Singleton => 0,
            ShakeWrapperLayout::PairedV1 => 1 }]);
        for value in [context.host_bytes(), NATIVE_HOST, MANAGED_DEVICE, REGISTRY_HOST,
            64, 32, algebra_limits.max_batch_count as u64,
            algebra_limits.max_ntt_batch_count as u64,
            algebra_limits.max_mul_batch_count as u64, algebra_limits.max_trace_cells,
            algebra_limits.max_estimated_prover_bytes] {
            digest.update(value.to_le_bytes());
        }
        let raw_host = as_u64(natives[0].footprint().raw_operation_host_bytes())?;
        if raw_host == 0 || raw_host > NATIVE_HOST {
            return Err(SourcePreparationError::Resource);
        }
        let closure_host = as_u64(SourceClosurePlanningPlan::enclosing_host_bytes()
            .map_err(|_| SourcePreparationError::Resource)?)?;
        let mut enclosing = environment.enclosing;
        if !environment.owned_inputs { enclosing = add(enclosing, closure_host)?; }
        if environment.owned_inputs {
            digest.update(b"same-generation-ledger/v1");
            digest.update(environment.already_owned.to_le_bytes());
            digest.update(environment.backend_device.to_le_bytes());
        }
        for (index, native) in natives.iter().enumerate() {
            if native.context() != natives[0].context()
                || native.setup_seed() != natives[0].setup_seed()
                || natives[..index].iter().any(|prior| prior.identity() == native.identity())
                || as_u64(native.footprint().raw_operation_host_bytes())? != raw_host {
                return Err(SourcePreparationError::Identity);
            }
            if !environment.owned_inputs { enclosing = add(enclosing, as_u64(native.retained_bytes())?)?; }
            digest.update(native.identity());
        }
        // No Vec, map, report JSON, compiler input, or proof is constructed by
        // this descriptor. Subsequent source phases reserve their own owners.
        // Fixed source descriptors may remain alive between those phases.
        let descriptors = size_of::<SourceGraphPlan<'source>>()
            .checked_add(size_of::<SourcePreparationPlan<'source>>())
            .and_then(|bytes| bytes.checked_mul(N))
            .ok_or(SourcePreparationError::Resource)?;
        let frames = size_of::<Self>().checked_add(size_of::<SourceEnvironment<'source>>())
            .and_then(|bytes| bytes.checked_add(descriptors))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<Self>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<WorkflowPlanning<'source>>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<Sha3_256>()))
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or(SourcePreparationError::Resource)?;
        if !environment.owned_inputs { enclosing = add(enclosing, as_u64(frames)?)?; }
        let scratch_bytes = InitialNativeSource::inspection_frame_bytes()
            .checked_add(4 * size_of::<Requirements>())
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or(SourcePreparationError::Resource)?;
        let mut scratch = Requirements::single(Category::PhaseScratch, host(as_u64(scratch_bytes)?));
        #[cfg(debug_assertions)]
        let inspection = SourceClosurePlanningPlan::inspection_requirements()
            .map_err(|_| SourcePreparationError::Resource)?;
        #[cfg(not(debug_assertions))]
        let inspection = super::metadata_planning::SourceMetadataPlanningPlan::inspection_requirements()
            .map_err(|_| SourcePreparationError::Resource)?;
        for category in Category::ALL {
            scratch.add(category, inspection.get(category))
                .map_err(|_| SourcePreparationError::Resource)?;
        }
        let mut planning = Requirements::single(Category::RegisteredMetadata,
            host(controller_bytes(2).map_err(|_| SourcePreparationError::Resource)?));
        for category in Category::ALL {
            planning.add(category, scratch.get(category))
                .map_err(|_| SourcePreparationError::Resource)?;
        }
        let descriptor_bytes = if environment.owned_inputs { add(closure_host, as_u64(frames)?)? } else { 0 };
        if add(add(add(enclosing, environment.already_owned)?, descriptor_bytes)?,
            planning.total().map_err(|_| SourcePreparationError::Resource)?.host)? >= context.host_bytes() {
            return Err(SourcePreparationError::Resource);
        }
        // These descriptor/closure frames remain live after WorkflowPlanning
        // replaces its bootstrap scratch. Retain a separate original here.
        #[cfg(not(debug_assertions))]
        let descriptor_original = match environment.generation.as_ref() {
            Some(generation) => Some(generation.reserve_descriptor(
                Requirements::single(Category::RegisteredMetadata, host(descriptor_bytes)))?),
            None => {
                #[cfg(test)]
                if let Some(fixture) = environment.fixture_context {
                    Some(fixture.ledger().admit_phase(Requirements::single(Category::RegisteredMetadata, host(descriptor_bytes)))
                        .map_err(|_| SourcePreparationError::Resource)?)
                } else { None }
                #[cfg(not(test))]
                { None }
            },
        };
        Ok(Self {
            #[cfg(not(debug_assertions))]
            verifiers: crate::graph_tree::metadata::verifier::VerifierCache::new(true),
            context, natives, source: digest.finalize().into(), compiled_source,
            enclosing: host(enclosing), planning, scratch,
            backend: Bytes { host: raw_host, device: environment.backend_device }, layout, budgets, algebra_limits,
            identity_limits: Default::default(),
            #[cfg(not(debug_assertions))] original_generation: environment.generation,
            #[cfg(not(debug_assertions))] fresh_context: environment.fresh_context,
            #[cfg(not(debug_assertions))] descriptor_original, #[cfg(test)] fixture_context: environment.fixture_context })
    }

    #[cfg(not(debug_assertions))]
    pub(crate) fn verifier_cache<'a>(&'a self, graph: &'a crate::graph_tree::metadata::GraphMetadata)
        -> &'a crate::graph_tree::metadata::verifier::VerifierCache {
        #[cfg(test)]
        if !crate::preparation_options::case_verifier_cache() { return &graph.verifiers; }
        let _ = graph;
        &self.verifiers
    }
    pub(crate) fn validate_initial_source(&self, native: &InitialNativeSource<'_>) -> Result<()> {
        if self.natives.iter().any(|original| core::ptr::eq(original, native)) {
            Ok(())
        } else { Err(SourcePreparationError::Identity) }
    }
    pub(crate) fn context(&self) -> &'source ProvingContext { self.context }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.source }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.compiled_source }
    pub(crate) fn enclosing_bytes(&self) -> Bytes { self.enclosing }
    pub(crate) fn planning_requirements(&self) -> Requirements { self.planning }
    pub(crate) fn planning_scratch_requirements(&self) -> Requirements { self.scratch }
    pub(crate) fn source_backend_allowance(&self) -> Bytes { self.backend }
    pub(crate) fn budgets(&self) -> Budgets { self.budgets }
    pub(crate) fn algebra_limits(&self) -> ResourceLimits { self.algebra_limits }
    pub(crate) fn layout(&self) -> ShakeWrapperLayout { self.layout }
    pub(crate) fn identity_limits(&self) -> lattica_prover_p3::block_v2::machine::backend::identity_cpu::IdentityCpuOptions {
        self.identity_limits
    }
    pub(crate) fn with_identity_limits(mut self,
        limits: lattica_prover_p3::block_v2::machine::backend::identity_cpu::IdentityCpuOptions) -> Result<Self> {

        if limits.parallel() {
            if !cfg!(feature = "full-workflow-experiment") { return Err(SourcePreparationError::Source); }
            let mut hash = Sha3_256::new();
            hash.update(b"lattica/workflow-identity-schedule/v1");
            hash.update(self.source);
            hash.update((limits.max_streams() as u64).to_le_bytes());
            self.source = hash.finalize().into();
        }
        self.identity_limits = limits;
        Ok(self)
    }
    pub(crate) fn natives(&self) -> &'source [InitialNativeSource<'source>] { self.natives }
}

// Include every existing original in this same ledger, including the case
// guard/container backing. This is a reservation census, never sampled GPU
// memory or permission to return/reissue a claim. Legacy pristine startup
// checks remain stricter and unchanged; this helper runs after named startup.
#[cfg(not(debug_assertions))]
fn fresh_owned_host(generation: Bytes, startup: Bytes, current: Bytes) -> Result<u64> {
    fresh_owned_host_with_limit(generation, startup, current, WORKER_HOST)
}
#[cfg(not(debug_assertions))]
fn fresh_owned_host_with_limit(generation: Bytes, startup: Bytes, current: Bytes, worker: u64) -> Result<u64> {
    let known = Bytes { host: add(generation.host, startup.host)?,
        device: add(generation.device, startup.device)? };
    if generation.device != 0 || known.host > current.host || known.device > current.device
        || current.device != startup.device || current.host > worker || crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(worker).is_err()
    { return Err(SourcePreparationError::Resource); }
    Ok(current.host)
}

#[cfg(all(test, not(debug_assertions)))]
#[path = "source_planning/fresh_storage_tests.rs"]
mod fresh_storage_tests;
