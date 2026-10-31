//! First source phase: lower the exact native relation only after its graph,
//! constructor temporaries, raw operations, reports and failure owner have all
//! received original claims from WorkflowPlanning's initial capability.
use super::{source_footprint::InitialNativeSource, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Requirements},
        workflow_resources::{
            source_retained_overhead_bytes, SourceFailure, SourcePhaseFailure,
            SourcePreparationAccess, SourceRetained,
        },
        ProvingContext,
    },
    rust_verify::committed_backend::{lower_unproved_on_gpu, UnprovedRelationGraph,
        source_graph::CheckedInitialGraph},
};
use core::mem::size_of;
use lattica_prover_p3::proving::operation_storage::RawPreparationReportStorage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourcePreparationError {
    Identity,
    Source,
    Resource,
    Geometry,
    Preparation,
    Cleanup,
}

type Result<T> = core::result::Result<T, SourcePreparationError>;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(SourcePreparationError::Resource)
}

fn host(bytes: usize) -> Result<Bytes> {
    Ok(Bytes {
        host: u64::try_from(bytes).map_err(|_| SourcePreparationError::Resource)?,
        device: 0,
    })
}

// The same complete original is required both before construction and by the
// narrow post-cleanup retention adapter. Every owner/continuation byte stays
// retained; only the checked immutable graph backing may later be reduced.
fn graph_output_requirements(graph_bytes: usize) -> Result<Requirements> {
    let mut output = Requirements::single(Category::SymbolicCompiler, host(graph_bytes)?);
    let metadata = [
        usize::try_from(source_retained_overhead_bytes().map_err(|_| SourcePreparationError::Resource)?)
            .map_err(|_| SourcePreparationError::Resource)?,
        size_of::<PreparedGraphSources>(),
        SourcePreparationAccess::completion_retained_bytes().map_err(|_| SourcePreparationError::Resource)?,
        SourcePreparationAccess::graph_retention_frame_bytes().map_err(|_| SourcePreparationError::Resource)?,
    ].into_iter().try_fold(0usize, add)?;
    output.add(Category::RegisteredMetadata, host(metadata)?)
        .map_err(|_| SourcePreparationError::Resource)?;
    Ok(output)
}

/// Only a source-closed initial workflow plan can derive this concrete phase.
/// Its reference remains stable through operation issuance and execution; the
/// numeric facts are observations of its private source derivation, not an
/// independently constructible budget or a claim about process RSS/stacks.
pub(crate) struct SourceGraphPlan<'source> {
    scope: &'source SourcePlanningPlan<'source>,
    native: &'source InitialNativeSource<'source>,
    output: Requirements,
    failure: Requirements,
    scratch: Requirements,
    backend: Bytes,
}

impl<'source> SourceGraphPlan<'source> {
    pub(crate) fn new(
        scope: &'source SourcePlanningPlan<'source>,
        native: &'source InitialNativeSource<'source>,
    ) -> Result<Self> {
        scope.validate_initial_source(native)?;
        if !cfg!(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64")) {
            return Err(SourcePreparationError::Source);
        }
        let footprint = native.footprint();
        let backend = scope.source_backend_allowance();
        if backend.host != footprint.raw_operation_host_bytes() as u64
            || backend.host == 0
            || backend.host > 24 << 30
            || backend.device == 0
            || backend.device > 8 << 30
        {
            return Err(SourcePreparationError::Resource);
        }
        let report = RawPreparationReportStorage::new()
            .map_err(|_| SourcePreparationError::Resource)?;
        let output = graph_output_requirements(footprint.graph_retained_bytes()
            .map_err(|_| SourcePreparationError::Resource)?)?;
        let failure = Requirements::single(
            Category::Report,
            host(add(
                size_of::<SourceFailure<PreparedGraphSources>>(),
                size_of::<SourcePhaseFailure<PreparedGraphSources>>(),
            )?)?,
        );
        let mut scratch = Requirements::single(
            Category::SymbolicCompiler,
            host(add(footprint.graph_growth_bytes(), footprint.symbolic_bytes())?)?,
        );
        scratch.add(Category::CompilerInputs, host(footprint.raw_host_bytes())?)
            .map_err(|_| SourcePreparationError::Resource)?;
        // The report plan follows the exact maintained with_operations entry,
        // including capability/observation/JSON/error overlap. Driver/runtime
        // metadata and bounded diagnostic retention are enclosing source-plan
        // obligations; compiled stack and allocator RSS remain external guards.
        let transport = [
            size_of::<Self>(),
            size_of::<SourceGraphOperation<'_, '_>>(),
            size_of::<PreparedGraphSources>(),
            size_of::<CheckedInitialGraph>(),
            size_of::<core::result::Result<CheckedInitialGraph, &'static str>>(),
            size_of::<SourceRetained<PreparedGraphSources>>(),
            size_of::<SourcePreparationAccess<'_>>(),
            size_of::<core::result::Result<UnprovedRelationGraph, String>>(),
            size_of::<Result<PreparedGraphSources>>(),
            4 * size_of::<String>(),
        ].into_iter().try_fold(0usize, add)?;
        scratch.add(
            Category::Report,
            host(add(report.required_host_bytes, transport)?)?,
        ).map_err(|_| SourcePreparationError::Resource)?;
        Ok(Self { scope, native, output, failure, scratch, backend })
    }

    pub(crate) fn context(&self) -> &'source ProvingContext {
        self.scope.context()
    }

    pub(crate) fn source_fingerprint(&self) -> [u8; 32] {
        self.scope.source_fingerprint()
    }

    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] {
        self.scope.compiled_source_fingerprint()
    }

    pub(crate) fn output_requirements(&self) -> Requirements {
        self.output
    }

    pub(crate) fn failure_requirements(&self) -> Requirements {
        self.failure
    }

    pub(crate) fn scratch_requirements(&self) -> Requirements {
        self.scratch
    }

    pub(crate) fn backend_allowance(&self) -> Bytes {
        self.backend
    }

    pub(crate) fn operation(&self) -> SourceGraphOperation<'_, 'source> {
        SourceGraphOperation { plan: self }
    }
}

// Issuing an operation borrows the descriptor only for this source phase. Its
// immutable source references remain valid independently in the owning table.
pub(crate) struct SourceGraphOperation<'plan, 'source> {
    plan: &'plan SourceGraphPlan<'source>,
}

impl<'source> SourceGraphOperation<'_, 'source> {
    pub(crate) fn plan(&self) -> &SourceGraphPlan<'source> {
        self.plan
    }

    pub(crate) fn execute(self, access: &SourcePreparationAccess<'_>) -> Result<PreparedGraphSources> {
        if !access.matches_graph(self.plan)
            || !core::ptr::eq(access.context(), self.plan.context())
            || access.source_fingerprint() != self.plan.source_fingerprint()
        {
            return Err(SourcePreparationError::Identity);
        }
        self.plan.scope.validate_initial_source(self.plan.native)?;
        let host = access.preparation_host_bytes()
            .map_err(|_| SourcePreparationError::Resource)?;
        if host != self.plan.backend.host {
            return Err(SourcePreparationError::Resource);
        }
        let graph = lower_unproved_on_gpu(
            self.plan.native.setup_seed(),
            self.plan.native.context(),
            self.plan.native.statement(),
            self.plan.native.proof(),
            access.context(),
            usize::try_from(host).map_err(|_| SourcePreparationError::Resource)?,
        ).map_err(|error| {
            // Destroy the maintained diagnostic while all preissued scratch
            // and failure claims remain live; only the fixed enum can escape.
            drop(error);
            SourcePreparationError::Preparation
        })?;
        if graph.setup_seed() != self.plan.native.setup_seed() {
            return Err(SourcePreparationError::Identity);
        }
        let graph = self.plan.native.footprint().check_graph(graph)
            .map_err(|_| SourcePreparationError::Geometry)?;
        Ok(PreparedGraphSources {
            graph,
            native_identity: self.plan.native.identity(),
        })
    }
}

/// Payload only; the execution-owned SourceRetained wrapper holds the original
/// output claim through this graph's final consumer and destruction.
pub(crate) struct PreparedGraphSources {
    graph: CheckedInitialGraph,
    native_identity: [u8; 32],
}

impl PreparedGraphSources {
    pub(crate) fn graph(&self) -> &UnprovedRelationGraph {
        self.graph.graph()
    }

    pub(crate) fn initial_output_requirements(&self) -> Result<Requirements> {
        graph_output_requirements(self.graph.initial_host_bytes())
    }

    pub(crate) fn retained_graph_host_bytes(&self) -> Result<u64> {
        u64::try_from(self.graph.retained_host_bytes()).map_err(|_| SourcePreparationError::Resource)
    }

    #[cfg(test)]
    pub(crate) fn retention_fixture() -> Self {
        Self { graph: CheckedInitialGraph::retention_fixture(), native_identity: [0; 32] }
    }

    pub(crate) fn native_identity(&self) -> [u8; 32] {
        self.native_identity
    }
}
