use super::*;
use crate::{graph_auxiliary::{Kind as AuxiliaryKind, Role},
    graph_crypto::RequestDescriptor, graph_proofs::ComponentKind};
use lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind;

#[derive(Default)]
pub(super) struct Cursors {
    used: [usize; 16],
    crypto_native: [usize; 2],
    crypto_recursive: [usize; 2],
    parents: [usize; PARENT_LEVELS],
}
// Whole live cursor plus forwarding borrows, charged before the first leaf.
// Do not infer spare capacity from the previous inspection frame census.
pub(super) const PARENT_READY_STATE_BYTES: usize = size_of::<Cursors>()
    + size_of::<[&mut Cursors; 4]>() + size_of::<[&mut [usize; PARENT_LEVELS]; 4]>();
impl Cursors {
    fn next(&mut self, family: ProducerFamily) -> Result<usize> {
        let value = self.used[family as usize];
        self.used[family as usize] = add(value, 1)?;
        Ok(value)
    }
    fn finish(&self, tables: &CompleteProducerTables<'_>, stage: &mut CompleteStage) -> Result<()> {
        macro_rules! exact {
            ($family:ident, $($field:ident),+) => {
                *stage = CompleteStage::Member { member: None, family: Some(ProducerFamily::$family),
                    ordinal: None, action: "finish_cursors" };
                $(if self.used[ProducerFamily::$family as usize] != tables.$field.len() {
                    return Err(ClosureError::Coverage);
                })+
            };
        }
        exact!(Fixed, fixed, fixed_outer);
        exact!(Source, source_native, source_blueprint, source_compiler, source_outer);
        exact!(Uniform, uniform);
        exact!(Sparse, sparse);
        exact!(Transcript, transcript);
        exact!(Affine, affine, affine_blueprint, affine_compiler, affine_outer);
        exact!(Ntt, ntt, ntt_blueprint, ntt_compiler, ntt_outer);
        exact!(Mul, mul, mul_blueprint, mul_compiler, mul_outer);
        exact!(GBound, g_bound, g_bound_blueprint, g_bound_compiler, g_bound_outer);
        exact!(Permutation, permutation, permutation_blueprint, permutation_compiler, permutation_outer);
        exact!(LinearMap, linear_map, linear_map_blueprint, linear_map_compiler, linear_map_outer);
        exact!(Parameters, parameters);
        exact!(Auxiliary, auxiliary);
        exact!(Equality, equality);
        exact!(Shake, shake);
        exact!(Aes, aes);
        for level in 0..PARENT_LEVELS {
            *stage = CompleteStage::Parent { level, member: None,
                ordinal: Some(self.parents[level]), action: "finish_parent_cursors" };
            let expected = tables.parents.expected[level];
            let table = tables.parents.levels[level];
            if self.parents[level] != expected || table.is_some() != (expected != 0)
                || table.is_some_and(|table| table.len() != expected)
            { return Err(ClosureError::Coverage); }
        }
        Ok(())
    }
}

impl<'a> SupportedSchedule<'a> {
    pub(super) fn complete_members(&mut self, tables: &'a CompleteProducerTables<'a>, ledger: &Ledger,
        stage: &mut CompleteStage) -> Result<()> {
        *stage = CompleteStage::Gate("members_identity");
        let members = self.members;
        if !matches!(members.len(), 3 | 4) || members.len() != self.scope.natives().len()
            || self.final_source.graphs().len() != members.len()
            || !self.final_source.belongs_to(ledger)
            || self.final_source.compiled_source_fingerprint() != self.scope.compiled_source_fingerprint()
        { return Err(ClosureError::Identity); }
        let mut cursor = Cursors::default();
        for (transaction, owner) in members.iter().copied().enumerate() {
            *stage = CompleteStage::Member { member: Some(transaction), family: None,
                ordinal: None, action: "member_identity" };
            let prepared = owner.get();
            if !owner.belongs_to(ledger) || owner.source_fingerprint() != self.scope.source_fingerprint()
                || owner.compiled_source_fingerprint() != self.scope.compiled_source_fingerprint()
                || !core::ptr::eq(prepared.native_source(), &self.scope.natives()[transaction])
                || !core::ptr::eq(self.final_source.graphs()[transaction].plan, prepared.plan())
                || !core::ptr::eq(self.final_source.graphs()[transaction].context, prepared.context())
            { return Err(ClosureError::Identity); }

            // These macros accept only concrete typed plans returned by sealed
            // owning-table views. Pointer equality binds every dependent plan
            // to the exact original table entry, even for equal geometries.
            macro_rules! native {
                ($plan:expr, $factory:ident, $phase:ident, $family:ident, $ordinal:expr) => {{
                    let plan = $plan;
                    stage.action("native_binding");
                    let binding = PhaseBinding::$factory(plan, 0).map_err(|_| ClosureError::Source)?;
                    stage.action("native_identity");
                    if !plan.belongs_to(ledger) || !core::ptr::eq(plan.sources(), owner)
                        || !core::ptr::eq(plan.context(), self.scope.context())
                        || plan.workflow_source_fingerprint() != self.scope.source_fingerprint()
                        || plan.compiled_source_fingerprint() != self.scope.compiled_source_fingerprint()
                        || plan.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
                        || plan.phase_count() != 1 || binding.kind() != PhaseKind::$phase
                        || plan.backend_allowance().host == 0
                        || plan.backend_allowance().host > self.scope.budgets().native_bytes
                        || plan.backend_allowance().device != 8 << 30
                    { return Err(ClosureError::Identity); }
                    stage.action("native_record");
                    self.record_routed(binding, &[], 0, plan.backend_allowance(),
                        ProducerRoute::Native { family: NativeFamily::$family, ordinal: $ordinal })?
                }};
            }
            macro_rules! leaf_chain {
                ($native:expr, $compiler:expr, $outer:expr, $native_factory:ident,
                    $native_phase:ident, $compile_phase:ident, $family:ident, $ordinal:expr) => {{
                    let native = $native;
                    let compiler = $compiler;
                    let outer = $outer;
                    stage.action("compiler_identity");
                    if !core::ptr::eq(compiler.native_plan(), native)
                        || !core::ptr::eq(outer.compiler_plan(), compiler)
                        || !compiler.belongs_to(ledger) || !outer.belongs_to(ledger)
                        || compiler.phase_count() != 1 || compiler.backend_allowance() != Bytes::ZERO
                    { return Err(ClosureError::Identity); }
                    let input = native!(native, $native_factory, $native_phase, $family, $ordinal);
                    stage.action("compiler_binding");
                    let binding = compiler.binding().map_err(|_| ClosureError::Source)?;
                    if binding.kind() != PhaseKind::$compile_phase { return Err(ClosureError::Source); }
                    stage.action("compiler_record");
                    let compiled = self.record_routed(binding, &[input], 1, compiler.backend_allowance(),
                        ProducerRoute::Leaf { family: LeafFamily::$family, ordinal: $ordinal, phase: GraphPhase::Compile })?;
                    stage.action("outer_source");
                    let child = outer.child_source().map_err(|_| ClosureError::Source)?;
                    stage.action("outer_record");
                    self.record_routed(child.binding(), &[compiled], 1, Bytes::ZERO,
                        ProducerRoute::Leaf { family: LeafFamily::$family, ordinal: $ordinal, phase: GraphPhase::Outer })?;
                    stage.action("append_graph");
                    let leaf_end = add(child.source().span().interval().0, 1)?;
                    self.append_graph(transaction, child, None)?;
                    self.complete_ready_parents(tables, ledger, transaction, leaf_end,
                        &mut cursor.parents, stage)?;
                }};
            }

            *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Fixed),
                ordinal: None, action: "fixed_cursor" };
            let ordinal = cursor.next(ProducerFamily::Fixed)?;
            *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Fixed),
                ordinal: Some(ordinal), action: "fixed_plan" };
            let fixed = tables.fixed.plan(ordinal)?;
            stage.action("fixed_outer_plan");
            let fixed_outer = tables.fixed_outer.plan(ordinal)?;
            stage.action("fixed_identity");
            if ordinal != transaction || !core::ptr::eq(fixed.sources(), owner)
                || !core::ptr::eq(fixed.context(), self.scope.context())
                || fixed.workflow_source_fingerprint() != self.scope.source_fingerprint()
                || !core::ptr::eq(fixed_outer.compiler_plan(), fixed) || !fixed_outer.belongs_to(ledger)
                || fixed.phase_count() != 1 || fixed.backend_allowance() != Bytes::ZERO
                || prepared.plan().leaves().first().map(|leaf| leaf.kind()) != Some(&LeafKind::FixedSources)
            { return Err(ClosureError::Identity); }
            stage.action("fixed_binding");
            let binding = PhaseBinding::for_source(fixed, 0).map_err(|_| ClosureError::Source)?;
            if binding.kind() != PhaseKind::SourceCompile { return Err(ClosureError::Source); }
            stage.action("fixed_record");
            let compiled = self.record_routed(binding, &[], 0, Bytes::ZERO,
                ProducerRoute::Fixed { ordinal, phase: GraphPhase::Compile })?;
            stage.action("fixed_outer_source");
            let child = fixed_outer.child_source().map_err(|_| ClosureError::Source)?;
            stage.action("fixed_outer_record");
            self.record_routed(child.binding(), &[compiled], 1, Bytes::ZERO,
                ProducerRoute::Fixed { ordinal, phase: GraphPhase::Outer })?;
            stage.action("fixed_append_graph");
            self.append_graph(transaction, child, Some((0, 1)))?;
            self.complete_ready_parents(tables, ledger, transaction, 1,
                &mut cursor.parents, stage)?;

            for (local, kind) in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof].into_iter().enumerate() {
                *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Source),
                    ordinal: None, action: "source_cursor" };
                let ordinal = cursor.next(ProducerFamily::Source)?;
                *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Source),
                    ordinal: Some(ordinal), action: "source_native_plan" };
                let native = tables.source_native.plan(ordinal)?;
                stage.action("source_blueprint");
                let blueprint = tables.source_blueprint.plan(ordinal)?;
                stage.action("source_compiler");
                let compiler = tables.source_compiler.plan(ordinal)?;
                stage.action("source_outer");
                let outer = tables.source_outer.plan(ordinal)?;
                stage.action("source_coverage");
                let expected = if local == 0 { LeafKind::Statement } else { LeafKind::PrivateProof };
                if !core::ptr::eq(compiler.source_compile_plan().blueprint(), blueprint)
                    || native.kind() != kind || blueprint.kind() != kind
                    || blueprint.ordinal() != local + 1
                    || outer.source().span().interval() != (local + 1, 1)
                    || prepared.plan().leaves().get(local + 1).map(|leaf| leaf.kind()) != Some(&expected)
                { return Err(ClosureError::Coverage); }
                leaf_chain!(native, compiler, outer, for_source_native, SourceNative, SourceNativeCompile, Source, ordinal);
            }

            // Auxiliary request identity and source order are checked against
            // the original factory, not against the auxiliary counts.
            for request in prepared.auxiliary_factory().requests() {
                *stage = CompleteStage::Member { member: Some(transaction), family: None,
                    ordinal: Some(request.operation_index()), action: "auxiliary_kind" };
                macro_rules! auxiliary_native {
                    ($field:ident, $family:ident, $factory:ident, $phase:ident) => {{
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::$family),
                            ordinal: None, action: "auxiliary_native_cursor" };
                        let ordinal = cursor.next(ProducerFamily::$family)?;
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::$family),
                            ordinal: Some(ordinal), action: "auxiliary_native_plan" };
                        let plan = tables.$field.plan(ordinal)?;
                        stage.action("auxiliary_native_identity");
                        if !core::ptr::eq(plan.request(), request)
                            || plan.operation_index() != request.operation_index() || plan.role() != request.role()
                        { return Err(ClosureError::Identity); }
                        native!(plan, $factory, $phase, $family, ordinal);
                    }};
                }
                match (request.kind(), request.role()) {
                    (AuxiliaryKind::Uniform(crate::uniform_air::Kind::SampleG4), Role::SampleGUniform)
                    | (AuxiliaryKind::Uniform(crate::uniform_air::Kind::ExpandAlpha2), Role::AlphaUniform) =>
                        auxiliary_native!(uniform, Uniform, for_uniform_native, UniformNative),
                    (AuxiliaryKind::Sparse(crate::sparse_air::Kind::AlphaPrime39), Role::AlphaSparse)
                    | (AuxiliaryKind::Sparse(crate::sparse_air::Kind::ChallengeX44), Role::HashXSparse) =>
                        auxiliary_native!(sparse, Sparse, for_sparse_native, SparseNative),
                    (AuxiliaryKind::Transcript, Role::HashAlphaTranscript | Role::HashXTranscript) =>
                        auxiliary_native!(transcript, Transcript, for_transcript_native, TranscriptNative),
                    _ => return Err(ClosureError::Source),
                }
            }

            for (local, request) in prepared.crypto().requests().iter().enumerate() {
                let (typed_family, array, plan, ordinal, nodes) = match request.descriptor() {
                    RequestDescriptor::Shake(_) => {
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Shake),
                            ordinal: None, action: "crypto_cursor" };
                        let ordinal = cursor.next(ProducerFamily::Shake)?;
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Shake),
                            ordinal: Some(ordinal), action: "crypto_plan" };
                        let plan = tables.shake.plan(ordinal)?;
                        stage.action("crypto_layout");
                        if plan.layout() != self.scope.layout() { return Err(ClosureError::Identity); }
                        (CryptoFamily::Shake, 0, CryptoRequestPlan::Shake(plan), ordinal, plan.node_sources().len())
                    }
                    RequestDescriptor::Aes(_) => {
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Aes),
                            ordinal: None, action: "crypto_cursor" };
                        let ordinal = cursor.next(ProducerFamily::Aes)?;
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::Aes),
                            ordinal: Some(ordinal), action: "crypto_plan" };
                        let plan = tables.aes.plan(ordinal)?;
                        (CryptoFamily::Aes, 1, CryptoRequestPlan::Aes(plan), ordinal, plan.node_sources().len())
                    }
                };
                stage.action("crypto_identity");
                if !plan.belongs_to(ledger) || !core::ptr::eq(plan.request(), request)
                    || plan.context() != prepared.context() { return Err(ClosureError::Identity); }
                let route = dispatch::CryptoRoute { family: typed_family, request: ordinal,
                    native_offset: cursor.crypto_native[array], recursive_offset: cursor.crypto_recursive[array] };
                stage.action("crypto_request_schedule");
                let (root, endpoints) = self.request_routed(plan, Some(route))?;
                stage.action("crypto_cursor_totals");
                cursor.crypto_native[array] = add(cursor.crypto_native[array], request.segments().len())?;
                cursor.crypto_recursive[array] = add(cursor.crypto_recursive[array], nodes)?;
                stage.action("crypto_root_record");
                push(&mut self.roots, RequestRootSlots { transaction, request: local, root, endpoints })?;
            }

            // The registered graph adds exactly one leaf per immutable batch.
            // Visit native and direct leaves in that existing order. This
            // permits original parents to retire their children as soon as
            // their exact contiguous prefix exists, without changing topology.
            if prepared.plan().leaves().len() != add(prepared.algebra().batches().len(), 3)? {
                return Err(ClosureError::Coverage);
            }
            for (batch_ordinal, batch) in prepared.algebra().batches().iter().enumerate() {
                let expected_leaf = add(batch_ordinal, 3)?;
                macro_rules! algebra {
                    ($field:ident, $blueprint:ident, $compiler:ident, $outer:ident, $family:ident, $factory:ident, $phase:ident) => {{
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::$family),
                            ordinal: None, action: "algebra_cursor" };
                        let ordinal = cursor.next(ProducerFamily::$family)?;
                        *stage = CompleteStage::Member { member: Some(transaction), family: Some(ProducerFamily::$family),
                            ordinal: Some(ordinal), action: "algebra_native" };
                        let native = tables.$field.plan(ordinal)?;
                        stage.action("algebra_blueprint");
                        let blueprint = tables.$blueprint.plan(ordinal)?;
                        stage.action("algebra_compiler");
                        let compiler = tables.$compiler.plan(ordinal)?;
                        stage.action("algebra_outer");
                        let outer = tables.$outer.plan(ordinal)?;
                        stage.action("algebra_coverage");
                        let (leaf_ordinal, count) = outer.source().span().interval();
                        let leaf = prepared.plan().leaves().get(leaf_ordinal).ok_or(ClosureError::Coverage)?;
                        if !core::ptr::eq(compiler.source_compile_plan().blueprint(), blueprint)
                            || blueprint.ordinal() != leaf_ordinal
                            || !core::ptr::eq(native.batch(), batch) || native.batch_ordinal() != batch_ordinal
                            || count != 1 || native.operation_indices() != leaf.operation_indices()
                            || leaf_ordinal != expected_leaf
                        { return Err(ClosureError::Coverage); }
                        leaf_chain!(native, compiler, outer, $factory, $phase, AlgebraCompile, $family, ordinal);
                    }};
                }
                match batch.kind() {
                    ComponentKind::Affine { .. } => algebra!(affine, affine_blueprint, affine_compiler, affine_outer, Affine, for_affine_native, AffineNative),
                    ComponentKind::Ntt { .. } => algebra!(ntt, ntt_blueprint, ntt_compiler, ntt_outer, Ntt, for_ntt_native, NttNative),
                    ComponentKind::Mul { .. } => algebra!(mul, mul_blueprint, mul_compiler, mul_outer, Mul, for_mul_native, MulNative),
                    ComponentKind::GBound { .. } => algebra!(g_bound, g_bound_blueprint, g_bound_compiler, g_bound_outer, GBound, for_g_bound_native, GBoundNative),
                    ComponentKind::Permutation { .. } => algebra!(permutation, permutation_blueprint, permutation_compiler, permutation_outer, Permutation, for_permutation_native, PermutationNative),
                    ComponentKind::LinearMap { .. } => algebra!(linear_map, linear_map_blueprint, linear_map_compiler, linear_map_outer, LinearMap, for_linear_map_native, LinearMapNative),
                    ComponentKind::External => self.direct_leaf(transaction, expected_leaf,
                        tables, &mut cursor, ledger, stage)?,
                }
            }
            // Check every actual graph leaf, including all non-native families.
            // The coverage count is only accepted after exact plan/context/span
            // and unique concrete producer binding validation by append_graph.
            for ordinal in 0..prepared.plan().leaves().len() {
                *stage = CompleteStage::Member { member: Some(transaction), family: None,
                    ordinal: Some(ordinal), action: "graph_leaf_coverage" };
                self.graph_record(transaction, (ordinal, 1))?;
            }
        }
        cursor.finish(tables, stage)
    }

    fn direct_leaf(&mut self, member: usize, leaf_ordinal: usize,
        tables: &'a CompleteProducerTables<'a>, cursor: &mut Cursors,
        ledger: &Ledger, stage: &mut CompleteStage) -> Result<()> {
        let owner = *self.members.get(member).ok_or(ClosureError::Order)?;
        if leaf_ordinal < 3 { return Err(ClosureError::Coverage); }
        let leaf = owner.get().plan().leaves().get(leaf_ordinal).ok_or(ClosureError::Coverage)?;
            *stage = CompleteStage::Member { member: Some(member), family: None,
                ordinal: Some(leaf_ordinal), action: "direct_leaf_kind" };
            let LeafKind::Operations(family) = leaf.kind() else { return Err(ClosureError::Coverage); };
            macro_rules! direct {
                ($field:ident, $family:ident) => {{
                    *stage = CompleteStage::Member { member: Some(member), family: Some(ProducerFamily::$family),
                        ordinal: None, action: "direct_cursor" };
                    let ordinal = cursor.next(ProducerFamily::$family)?;
                    *stage = CompleteStage::Member { member: Some(member), family: Some(ProducerFamily::$family),
                        ordinal: Some(ordinal), action: "direct_plan" };
                    let plan = tables.$field.plan(ordinal)?;
                    stage.action("direct_identity");
                    if !plan.belongs_to(ledger) || !core::ptr::eq(plan.prepared(), owner)
                        || plan.source().span().interval() != (leaf_ordinal, 1)
                    { return Err(ClosureError::Identity); }
                    (ordinal, plan)
                }};
            }
            match family {
                OperationFamily::ParametersPp => {
                    let (ordinal, plan) = direct!(parameters, Parameters);
                    stage.action("parameters_root");
                    let request = CryptoRequestPlan::Shake(plan.request_plan());
                    let mut roots = (0..request.len()).filter(|index|
                        matches!(request.event(*index), Ok(Event::Outer(node)) if node == request.root()));
                    let root = roots.next().ok_or(ClosureError::Coverage)?;
                    if roots.next().is_some() { return Err(ClosureError::Coverage); }
                    let inputs = [Some(request.binding(root)?), Some(request.binding(0)?)];
                    stage.action("parameters_binding");
                    let binding = plan.binding(0).map_err(|_| ClosureError::Source)?;
                    if binding.kind() != PhaseKind::GraphLeafCompile { return Err(ClosureError::Source); }
                    stage.action("parameters_dependencies");
                    let compiled = self.record_dependencies(binding, &inputs, 2, 2, Bytes::ZERO,
                        ProducerRoute::Direct { family: DirectFamily::Parameters, ordinal, phase: GraphPhase::Compile })?;
                    stage.action("parameters_outer_source");
                    let child = plan.child_source().map_err(|_| ClosureError::Source)?;
                    stage.action("parameters_outer_record");
                    self.record_routed(child.binding(), &[compiled], 1, Bytes::ZERO,
                        ProducerRoute::Direct { family: DirectFamily::Parameters, ordinal, phase: GraphPhase::Outer })?;
                    stage.action("parameters_append_graph");
                    self.append_graph(member, child, Some((leaf_ordinal, 1)))?;
                }
                OperationFamily::SampleG | OperationFamily::ExpandAlpha | OperationFamily::HashAlpha | OperationFamily::HashX => {
                    let (ordinal, plan) = direct!(auxiliary, Auxiliary);
                    for phase in 0..2 {
                        stage.action(if phase == 0 { "auxiliary_compile_dependencies" } else { "auxiliary_outer_dependencies" });
                        let dependencies = plan.dependencies(phase).map_err(|_| ClosureError::Source)?;
                        stage.action(if phase == 0 { "auxiliary_compile_binding" } else { "auxiliary_outer_binding" });
                        let binding = plan.binding(phase).map_err(|_| ClosureError::Source)?;
                        let expected_kind = if phase == 0 { PhaseKind::GraphLeafCompile } else { PhaseKind::GraphOuter };
                        if binding.kind() != expected_kind {
                            return Err(ClosureError::Source);
                        }
                        stage.action(if phase == 0 { "auxiliary_compile_record" } else { "auxiliary_outer_record" });
                        self.record_dependencies(binding, &dependencies.bindings, dependencies.count, dependencies.consume,
                            Bytes::ZERO, ProducerRoute::Direct { family: DirectFamily::Auxiliary, ordinal,
                                phase: if phase == 0 { GraphPhase::Compile } else { GraphPhase::Outer } })?;
                    }
                    stage.action("auxiliary_append_graph");
                    self.append_graph(member, plan.child_source().map_err(|_| ClosureError::Source)?, Some((leaf_ordinal, 1)))?;
                }
                OperationFamily::Equality => {
                    let (ordinal, plan) = direct!(equality, Equality);
                    for phase in 0..2 {
                        stage.action(if phase == 0 { "equality_compile_dependencies" } else { "equality_outer_dependencies" });
                        let dependencies = plan.dependencies(phase).map_err(|_| ClosureError::Source)?;
                        stage.action(if phase == 0 { "equality_compile_binding" } else { "equality_outer_binding" });
                        let binding = plan.binding(phase).map_err(|_| ClosureError::Source)?;
                        let expected_kind = if phase == 0 { PhaseKind::GraphLeafCompile } else { PhaseKind::GraphOuter };
                        if binding.kind() != expected_kind {
                            return Err(ClosureError::Source);
                        }
                        stage.action(if phase == 0 { "equality_compile_record" } else { "equality_outer_record" });
                        self.record_dependencies(binding, &dependencies.bindings, dependencies.count, dependencies.consume,
                            Bytes::ZERO, ProducerRoute::Direct { family: DirectFamily::Equality, ordinal,
                                phase: if phase == 0 { GraphPhase::Compile } else { GraphPhase::Outer } })?;
                    }
                    stage.action("equality_append_graph");
                    self.append_graph(member, plan.child_source().map_err(|_| ClosureError::Source)?, Some((leaf_ordinal, 1)))?;
                }
                OperationFamily::Affine { .. } | OperationFamily::Ntt { .. } | OperationFamily::Mul { .. }
                | OperationFamily::GBound | OperationFamily::Permutation | OperationFamily::LinearMap => return Err(ClosureError::Source),
            }
        self.complete_ready_parents(tables, ledger, member, add(leaf_ordinal, 1)?,
            &mut cursor.parents, stage)?;
        Ok(())
    }
}
