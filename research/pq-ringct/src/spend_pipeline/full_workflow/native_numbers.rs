//! Immutable bindings for private, admitted CPU metadata preparation.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::execution::workflow_resources::SourceRetained;
use crate::graph_tree::GraphContext;

/// Each worker checks the exact census before allocating within this sublimit.
pub(crate) const TRANSIENT_LIMIT: usize = 512 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) workflow: [u8; 32],
    pub(crate) compiled: [u8; 32],
    pub(crate) native: [u8; 32],
    pub(crate) label: [u8; 32],
    pub(crate) context: GraphContext,
}
impl Binding {
    pub(crate) fn new(scope: &SourcePlanningPlan<'_>, sources: &SourceRetained<PreparedWorkflowSources<'_>>) -> Self {
        Self { workflow: scope.source_fingerprint(), compiled: scope.compiled_source_fingerprint(),
            native: sources.get().native_identity(), label: sources.get().plan().label(),
            context: sources.get().context().clone() }
    }
}

use crate::graph_proofs::{self, ComponentKind};
use crate::graph_tree::metadata::verifier::{Key, VerifierCache, linear_map::Cache as LinearMapCache};

#[derive(Clone, Copy)]
pub(crate) enum Job<'a> {
    Affine(graph_proofs::owned_affine::metadata::View<'a>),
    Ntt(graph_proofs::owned_ntt::metadata::View<'a>),
    Mul(graph_proofs::owned_mul::metadata::View<'a>),
    GBound(graph_proofs::owned_g_bound::metadata::View<'a>),
    Permutation(graph_proofs::owned_permutation::metadata::View<'a>),
    LinearMap(graph_proofs::owned_linear_map::metadata::View<'a>),
}
pub(crate) enum Ready<'a> {
    Affine(super::affine_native::MetadataNumbers<'a>),
    Ntt(super::ntt_native::MetadataNumbers<'a>),
    Mul(super::mul_native::MetadataNumbers<'a>),
    GBound(super::g_bound_native::MetadataNumbers<'a>),
    Permutation(super::permutation_native::MetadataNumbers<'a>),
    LinearMap(Box<super::linear_map_native::MetadataNumbers<'a>>),
}
impl<'a> Job<'a> {
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, index: usize) -> Result<Option<Self>, ()> {
        let batch = sources.get().algebra().batches().get(index).ok_or(())?;
        Ok(Some(match batch.kind() {
            ComponentKind::Affine { .. } => Self::Affine(graph_proofs::owned_affine::AffineSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            ComponentKind::Ntt { .. } => Self::Ntt(graph_proofs::owned_ntt::NttSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            ComponentKind::Mul { .. } => Self::Mul(graph_proofs::owned_mul::MulSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            ComponentKind::GBound { .. } => Self::GBound(graph_proofs::owned_g_bound::GBoundSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            ComponentKind::Permutation { .. } => Self::Permutation(graph_proofs::owned_permutation::PermutationSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            ComponentKind::LinearMap { .. } => Self::LinearMap(graph_proofs::owned_linear_map::LinearMapSource::from_original(sources, index).map_err(|_| ())?.metadata_view()),
            _ => return Ok(None),
        }))
    }
    pub(crate) fn maximum_retained_bytes() -> usize {
        [graph_proofs::owned_affine::AffineProofPlan::metadata_worker_host_bytes(),
         graph_proofs::owned_ntt::NttProofPlan::metadata_worker_host_bytes(),
         graph_proofs::owned_mul::MulProofPlan::metadata_worker_host_bytes(),
         graph_proofs::owned_g_bound::GBoundProofPlan::metadata_worker_host_bytes(),
         graph_proofs::owned_permutation::PermutationProofPlan::metadata_worker_host_bytes(),
         (graph_proofs::owned_linear_map::LinearMapProofPlan::metadata_worker_host_bytes() + 8 * core::mem::size_of::<super::linear_map_native::MetadataNumbers<'static>>())]
            .into_iter().max().unwrap_or(0)
            + 8 * (core::mem::size_of::<Self>() + core::mem::size_of::<Ready<'static>>() + core::mem::size_of::<Binding>())
    }
    pub(crate) fn retained_bytes(self) -> usize {
        let data = match self {
            Self::Affine(_) => graph_proofs::owned_affine::AffineProofPlan::metadata_worker_host_bytes(),
            Self::Ntt(_) => graph_proofs::owned_ntt::NttProofPlan::metadata_worker_host_bytes(),
            Self::Mul(_) => graph_proofs::owned_mul::MulProofPlan::metadata_worker_host_bytes(),
            Self::GBound(_) => graph_proofs::owned_g_bound::GBoundProofPlan::metadata_worker_host_bytes(),
            Self::Permutation(_) => graph_proofs::owned_permutation::PermutationProofPlan::metadata_worker_host_bytes(),
            Self::LinearMap(_) => (graph_proofs::owned_linear_map::LinearMapProofPlan::metadata_worker_host_bytes() + 8 * core::mem::size_of::<super::linear_map_native::MetadataNumbers<'static>>()),
        };
        data + 8 * (core::mem::size_of::<Self>() + core::mem::size_of::<Ready<'static>>() + core::mem::size_of::<Binding>())
    }
    pub(crate) fn key(self) -> Option<Key> {
        match self {
            Self::Ntt(view) => Some(Key::Ntt(view.kind())),
            Self::Mul(view) => Some(Key::Mul(view.kind())),
            Self::Permutation(view) => Some(Key::Permutation(view.kind())),

            _ => None,
        }
    }
    pub(crate) fn transient_bytes(self) -> Result<usize, ()> {
        match self {
            Self::LinearMap(view) => graph_proofs::owned_linear_map::verification_memory::numeric_host_bytes(view.kind()).map_err(|_| ())?
                .checked_add(LinearMapCache::frame_bytes()).ok_or(()),
            _ => self.key().map_or(Ok(0), |key| key.numeric_host_bytes()),
        }
    }
    pub(crate) fn prepare_bounded(self, binding: Binding, cache: &VerifierCache,
        linear_maps: &LinearMapCache) -> Result<Option<Ready<'a>>, ()> {
        // Geometry inspection is covered by the separately admitted fixed
        // frames. Decline oversized work before any metadata is prepared.
        if self.transient_bytes()? > TRANSIENT_LIMIT { return Ok(None); }
        self.prepare(binding, cache, linear_maps).map(Some)
    }
    pub(crate) fn prepare(self, binding: Binding, cache: &VerifierCache, linear_maps: &LinearMapCache) -> Result<Ready<'a>, ()> {
        match self {
            Self::Affine(view) => {
                super::affine_native::MetadataNumbers::prepare(view, binding).map(Ready::Affine).map_err(|_| ())
            }
            Self::Ntt(view) => {
                let kind = view.kind();
                let verification = cache.verifier_ntt(kind, || {
                    let bytes = graph_proofs::owned_ntt::verification_memory::numeric_host_bytes(kind).map_err(|_| ())?;
                    graph_proofs::owned_ntt::verification_memory::numeric_plan(kind, bytes).map_err(|_| ())
                })?;
                if !crate::preparation_options::readiness_enabled("cpu") {
                    return super::ntt_native::MetadataNumbers::prepare(view, binding, verification).map(Ready::Ntt).map_err(|_| ());
                }
                let recording = cache.recording(Key::Ntt(kind), ||
                    super::ntt_native::NttNativeOperationPlan::verification_planning_requirements(kind).map_err(|_| ()))?;
                super::ntt_native::MetadataNumbers::prepare_recorded(view, binding, verification, recording).map(Ready::Ntt).map_err(|_| ())
            }
            Self::Mul(view) => {
                let kind = view.kind();
                let verification = cache.verifier_mul(kind, || {
                    let bytes = graph_proofs::owned_mul::verification_memory::numeric_host_bytes(kind).map_err(|_| ())?;
                    graph_proofs::owned_mul::verification_memory::numeric_plan(kind, bytes).map_err(|_| ())
                })?;
                if !crate::preparation_options::readiness_enabled("cpu") {
                    return super::mul_native::MetadataNumbers::prepare(view, binding, verification).map(Ready::Mul).map_err(|_| ());
                }
                let recording = cache.recording(Key::Mul(kind), ||
                    super::mul_native::MulNativeOperationPlan::verification_planning_requirements(kind).map_err(|_| ()))?;
                super::mul_native::MetadataNumbers::prepare_recorded(view, binding, verification, recording).map(Ready::Mul).map_err(|_| ())
            }
            Self::GBound(view) => {
                super::g_bound_native::MetadataNumbers::prepare(view, binding).map(Ready::GBound).map_err(|_| ())
            }
            Self::Permutation(view) => {
                let kind = view.kind();
                let verification = cache.verifier_permutation(kind, || {
                    let bytes = graph_proofs::owned_permutation::verification_memory::numeric_host_bytes(kind).map_err(|_| ())?;
                    graph_proofs::owned_permutation::verification_memory::numeric_plan(kind, bytes).map_err(|_| ())
                })?;
                if !crate::preparation_options::readiness_enabled("cpu") {
                    return super::permutation_native::MetadataNumbers::prepare(view, binding, verification).map(Ready::Permutation).map_err(|_| ());
                }
                let recording = cache.recording(Key::Permutation(kind), ||
                    super::permutation_native::PermutationNativeOperationPlan::verification_planning_requirements(kind).map_err(|_| ()))?;
                super::permutation_native::MetadataNumbers::prepare_recorded(view, binding, verification, recording).map(Ready::Permutation).map_err(|_| ())
            }
            Self::LinearMap(view) => {
                let kind = view.kind();
                let verification = linear_maps.resolve(kind, || {
                    let bytes = graph_proofs::owned_linear_map::verification_memory::numeric_host_bytes(kind).map_err(|_| ())?;
                    graph_proofs::owned_linear_map::verification_memory::numeric_plan(kind, bytes).map_err(|_| ())
                })?;
                if !crate::preparation_options::readiness_enabled("cpu") {
                    return super::linear_map_native::MetadataNumbers::prepare(view, binding, verification).map(|value| Ready::LinearMap(Box::new(value))).map_err(|_| ());
                }
                let recording = linear_maps.recording(kind, ||
                    super::linear_map_native::LinearMapNativeOperationPlan::verification_planning_requirements(kind).map_err(|_| ()))?;
                super::linear_map_native::MetadataNumbers::prepare_recorded(view, binding, verification, recording).map(|value| Ready::LinearMap(Box::new(value))).map_err(|_| ())
            }
        }
    }
}
