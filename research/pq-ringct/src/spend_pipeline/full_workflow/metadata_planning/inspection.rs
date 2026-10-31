//! Exact source census before any producer metadata table is allocated.
use super::*;
use crate::{graph_auxiliary::{Kind as AuxiliaryKind, Role}, graph_tree::owned_parent::*};
use lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind;

impl SourceMetadataPlanningPlan<'_> {
    pub(super) fn retained_requirements() -> Result<Requirements> {
        let frames = mul(8, [size_of::<Self>(), size_of::<Result<Self>>(),
            size_of::<ProducerCounts>(), size_of::<ProducerRequirements>(),
            size_of::<Result<ProducerRequirements>>(), size_of::<MetadataMember<'static, 'static>>(),
            size_of::<Result<MetadataMember<'static, 'static>>>(),
            size_of::<[&SourceRetained<PreparedWorkflowSources<'static>>; 4]>(),
            size_of::<[usize; LEVELS]>(), size_of::<[Requirements; 8]>(),
            size_of::<Ledger>(), size_of::<[Bytes; 4]>(), size_of::<[usize; 16]>(),
        ].into_iter().try_fold(0, add)?)?;
        Ok(Requirements::single(Category::RegisteredMetadata, host(frames)?))
    }

    /// The bootstrap source scope reserves this before any pure source view,
    /// blueprint construction, or constructor-bound query is entered.
    pub(crate) fn inspection_requirements() -> Result<Requirements> {
        use crate::{graph_proofs::{owned_affine::AffineSource, owned_ntt::NttSource,
                owned_mul::MulSource, owned_g_bound::GBoundSource,
                owned_permutation::PermutationSource, owned_linear_map::LinearMapSource},
            spend_pipeline::full_workflow::metadata_tables::{algebra, graph}};
        let view_frames = [AffineSource::planning_view_host_bytes(), NttSource::planning_view_host_bytes(),
            MulSource::planning_view_host_bytes(), GBoundSource::planning_view_host_bytes(),
            PermutationSource::planning_view_host_bytes(), LinearMapSource::planning_view_host_bytes()]
            .into_iter().try_fold(0, add)?;
        let blueprint_frames = mul(8, [
            size_of::<MetadataPlanningStage>(), size_of::<&mut MetadataPlanningStage>(),
            size_of::<graph::SourceBlueprintResult<'static, 'static>>(),
            size_of::<algebra::AffineBlueprintResult<'static, 'static>>(),
            size_of::<algebra::NttBlueprintResult<'static, 'static>>(),
            size_of::<algebra::MulBlueprintResult<'static, 'static>>(),
            size_of::<algebra::GBoundBlueprintResult<'static, 'static>>(),
            size_of::<algebra::PermutationBlueprintResult<'static, 'static>>(),
            size_of::<algebra::LinearMapBlueprintResult<'static, 'static>>(),
        ].into_iter().try_fold(0, add)?)?;
        // Blueprint construction calls the same pure footprint helpers before
        // returned compiler claims exist. Admit their exact forwarding frames
        // here as well as in each eventual compiler scratch original.
        let helper_frames = add(
            crate::graph_tree::ntt_sources::NttLeafBlueprint::source_requirement_frame_bytes()
                .map_err(|_| ClosureError::Resource)?,
            crate::graph_tree::mul_sources::MulLeafBlueprint::source_requirement_frame_bytes()
                .map_err(|_| ClosureError::Resource)?,
        )?;
        let retained = Self::retained_requirements()?.total().map_err(|_| ClosureError::Overflow)?;
        let own = Requirements::single(Category::PhaseScratch, Bytes {
            host: retained.host.checked_add(u64::try_from(add(add(view_frames, blueprint_frames)?, helper_frames)?)
                .map_err(|_| ClosureError::Overflow)?).ok_or(ClosureError::Overflow)?, device: 0,
        });
        sum(sum(sum(SourceClosurePlanningPlan::inspection_requirements()?, own)?,
            AuxiliaryPreparedInventory::inspection_requirements().map_err(|_| ClosureError::Resource)?)?,
            crate::execution::workflow_resources::producer_metadata_inspection_requirements()
                .map_err(|_| ClosureError::Resource)?)
    }

    pub(super) fn inspect_sources(&mut self, stage: &mut MetadataPlanningStage) -> Result<()> {
        use crate::spend_pipeline::full_workflow::{uniform_native::UniformNativeOperationPlan,
            sparse_native::SparseNativeOperationPlan, transcript_native::TranscriptNativeOperationPlan};
        // Record the fixed family before evaluating any fallible provider query.
        // This expands to a scalar write and the existing tuple expression.
        macro_rules! family {
            ($family:ident, $($value:expr),+) => {{
                *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::$family);
                (ProducerFamily::$family, $($value),+)
            }};
        }
        let members = self.members;
        for member in members {
            let member = *member;
            let prepared = member.get();
            *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Fixed);
            self.counts.add(ProducerFamily::Fixed, 1)?;
            *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Source);
            self.counts.add(ProducerFamily::Source, 2)?;
            *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Fixed);
            self.include(ProducerRequirements {
                original: FixedLeafOuterPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                construction: Requirements::default(),
            })?;
            for kind in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof] {
                *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Source);
                self.include(providers::source_native(member, kind)?)?;
            }
            // The maintained source-native PrivateProof owns Norm obligations.
            // Only actual retained algebra batches contribute extra producers.
            for (ordinal, batch) in prepared.algebra().batches().iter().enumerate() {
                let (family, requirements) = match batch.kind() {
                    ComponentKind::Affine { .. } => family!(Affine, providers::affine(member, ordinal)?),
                    ComponentKind::Ntt { .. } => family!(Ntt, providers::ntt(member, ordinal)?),
                    ComponentKind::Mul { .. } => family!(Mul, providers::mul(member, ordinal)?),
                    ComponentKind::GBound { .. } => family!(GBound, providers::g_bound(member, ordinal)?),
                    ComponentKind::Permutation { .. } => family!(Permutation, providers::permutation(member, ordinal)?),
                    ComponentKind::LinearMap { .. } => family!(LinearMap, providers::linear_map(member, ordinal)?),
                    ComponentKind::External => continue,
                };
                self.counts.add(family, 1)?;
                self.include(requirements)?;
            }
            for request in prepared.auxiliary_factory().requests() {
                *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Auxiliary);
                let (family, original) = match (request.kind(), request.role()) {
                    (AuxiliaryKind::Uniform(crate::uniform_air::Kind::SampleG4), Role::SampleGUniform)
                    | (AuxiliaryKind::Uniform(crate::uniform_air::Kind::ExpandAlpha2), Role::AlphaUniform) =>
                        family!(Uniform, UniformNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?),
                    (AuxiliaryKind::Sparse(crate::sparse_air::Kind::AlphaPrime39), Role::AlphaSparse)
                    | (AuxiliaryKind::Sparse(crate::sparse_air::Kind::ChallengeX44), Role::HashXSparse) =>
                        family!(Sparse, SparseNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?),
                    (AuxiliaryKind::Transcript, Role::HashAlphaTranscript | Role::HashXTranscript) =>
                        family!(Transcript, TranscriptNativeOperationPlan::metadata_requirements().map_err(|_| ClosureError::Resource)?),
                    _ => return Err(ClosureError::Source),
                };
                self.counts.add(family, 1)?;
                self.include(ProducerRequirements { original, construction: Requirements::default() })?;
            }
            for request in prepared.crypto().requests() {
                let (family, original, construction, native, recursive) = match request.descriptor() {
                    RequestDescriptor::Shake(_) => {
                        *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Shake);
                        let count = request.shake_wrapper_schedule(self.scope.layout()).map_err(|_| ClosureError::Source)?.counts();
                        (ProducerFamily::Shake,
                            PairedRequestPlan::planning_requirements(request, self.scope.layout()).map_err(|_| ClosureError::Resource)?,
                            PairedRequestPlan::planning_scratch_requirements(request, self.scope.layout()).map_err(|_| ClosureError::Resource)?,
                            count.native_proofs, add(count.recursive_leaves, count.recursive_parents)?)
                    }
                    RequestDescriptor::Aes(_) => {
                        *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Aes);
                        let native = request.segments().len();
                        if native == 0 { return Err(ClosureError::Coverage); }
                        (ProducerFamily::Aes,
                            OwnedAesRequestPlan::planning_requirements(request).map_err(|_| ClosureError::Resource)?,
                            OwnedAesRequestPlan::planning_scratch_requirements(request).map_err(|_| ClosureError::Resource)?,
                            native, mul(native, 2)?.checked_sub(1).ok_or(ClosureError::Overflow)?)
                    }
                };
                self.counts.add(family, 1)?;
                if family == ProducerFamily::Shake {
                    self.counts.shake_native = add(self.counts.shake_native, native)?;
                    self.counts.shake_recursive = add(self.counts.shake_recursive, recursive)?;
                } else {
                    self.counts.aes_native = add(self.counts.aes_native, native)?;
                    self.counts.aes_recursive = add(self.counts.aes_recursive, recursive)?;
                }
                self.include(ProducerRequirements { original, construction })?;
            }
            for (ordinal, leaf) in prepared.plan().leaves().iter().enumerate().skip(3) {
                *stage = MetadataPlanningStage::SourceInspection;
                let LeafKind::Operations(family) = leaf.kind() else { return Err(ClosureError::Coverage); };
                let (family, original, construction) = match family {
                    OperationFamily::Equality => family!(Equality,
                        EqualityGraphPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                        EqualityGraphPlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?),
                    OperationFamily::ParametersPp => family!(Parameters,
                        ParametersPpGraphPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                        ParametersPpGraphPlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?),
                    OperationFamily::SampleG | OperationFamily::ExpandAlpha | OperationFamily::HashAlpha | OperationFamily::HashX => {
                        *stage = MetadataPlanningStage::SourceFamily(ProducerFamily::Auxiliary);
                        let inventory = AuxiliaryPreparedInventory::new(member, ordinal).map_err(|_| ClosureError::Source)?;
                        (ProducerFamily::Auxiliary, AuxiliaryGraphPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                            inventory.planning_scratch_requirements().map_err(|_| ClosureError::Resource)?)
                    }
                    OperationFamily::Affine { .. } | OperationFamily::Ntt { .. } | OperationFamily::Mul { .. }
                    | OperationFamily::GBound | OperationFamily::Permutation | OperationFamily::LinearMap => continue,
                };
                self.counts.add(family, 1)?;
                self.include(ProducerRequirements { original, construction })?;
            }
            *stage = MetadataPlanningStage::SourceParents;
            let mut width = prepared.plan().leaves().len();
            let mut level = 0;
            while width > 1 {
                if level >= LEVELS { return Err(ClosureError::Overflow); }
                let pairs = width / 2;
                self.counts.parent_levels[level] = add(self.counts.parent_levels[level], pairs)?;
                for _ in 0..pairs {
                    self.include(ProducerRequirements {
                        original: GraphParentPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                        construction: GraphParentPlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?,
                    })?;
                }
                width = add(pairs, width % 2)?;
                level += 1;
            }
        }
        *stage = MetadataPlanningStage::SourceFinal;
        self.include(ProducerRequirements {
            original: sum(FinalAggregationPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
                FinalPhasePlan::planning_requirements().map_err(|_| ClosureError::Resource)?)?,
            construction: maximum(FinalAggregationPlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?,
                FinalPhasePlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?),
        })?;
        *stage = MetadataPlanningStage::SourceStepCounts;
        let c = self.counts;
        let mut steps = mul(c.family(ProducerFamily::Fixed), 2)?;
        for family in [ProducerFamily::Source, ProducerFamily::Affine, ProducerFamily::Ntt,
            ProducerFamily::Mul, ProducerFamily::GBound, ProducerFamily::Permutation, ProducerFamily::LinearMap] {
            steps = add(steps, mul(c.family(family), 3)?)?;
        }
        for family in [ProducerFamily::Uniform, ProducerFamily::Sparse, ProducerFamily::Transcript] {
            steps = add(steps, c.family(family))?;
        }
        for family in [ProducerFamily::Parameters, ProducerFamily::Auxiliary, ProducerFamily::Equality] {
            steps = add(steps, mul(c.family(family), 2)?)?;
        }
        steps = add(steps, add(c.family(ProducerFamily::Shake), c.family(ProducerFamily::Aes))?)?;
        steps = add(steps, add(c.shake_native, c.aes_native)?)?;
        steps = add(steps, mul(add(c.shake_recursive, c.aes_recursive)?, 2)?)?;
        for count in c.parent_levels { steps = add(steps, mul(count, 2)?)?; }
        self.counts.steps = add(steps, add(mul(self.members.len() - 1, 2)?, 1)?)?;
        Ok(())
    }
}
