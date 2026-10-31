use super::*;

impl<'tables, 'case, 'plans, 'source, 'native: 'a, 'a> NativeRuntime<'tables, 'case, 'plans, 'source, 'native, 'a> {
    /// The ordinal is only a lookup request. Exact admission/case validation and
    /// the existing independent native/outer preissue cursors confer authority.
    pub(crate) fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        let dispatch = inventory.closed_plan().dispatch().get(closed_ordinal)
            .ok_or(WorkflowError::Sequence)?;
        self.check_dispatch(inventory, case, closed_ordinal, dispatch)?;
        macro_rules! native {
            ($field:ident, $preissue:ident, $ordinal:expr) => {{
                let plan = original(self.plans.$field, $ordinal)?;
                let mut target = write(cell(self.native_packets.$field, $ordinal)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.$preissue(plan, 0));
                let _ = ready(&target)?;
            }};
        }
        macro_rules! outer {
            ($field:ident, $preissue:ident, $ordinal:expr) => {{
                let plan = original(self.outer_plans.$field, $ordinal)?;
                let mut target = write(cell(self.outer_packets.$field, $ordinal)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.$preissue(plan));
                let _ = ready(&target)?;
            }};
        }
        match dispatch.producer() {
            ProducerRoute::Native { family, ordinal } => match family {
                NativeFamily::Source => native!(source, preissue_source_native, ordinal),
                NativeFamily::Uniform => native!(uniform, preissue_uniform_native, ordinal),
                NativeFamily::Sparse => native!(sparse, preissue_sparse_native, ordinal),
                NativeFamily::Transcript => native!(transcript, preissue_transcript_native, ordinal),
                NativeFamily::Affine => native!(affine, preissue_affine_native, ordinal),
                NativeFamily::Ntt => native!(ntt, preissue_ntt_native, ordinal),
                NativeFamily::Mul => native!(mul, preissue_mul_native, ordinal),
                NativeFamily::GBound => native!(g_bound, preissue_g_bound_native, ordinal),
                NativeFamily::Permutation => native!(permutation, preissue_permutation_native, ordinal),
                NativeFamily::LinearMap => native!(linear_map, preissue_linear_map_native, ordinal),
            },
            ProducerRoute::Leaf { family, ordinal, phase: GraphPhase::Outer } => match family {
                LeafFamily::Source => outer!(source, preissue_native_leaf_outer, ordinal),
                LeafFamily::Affine => outer!(affine, preissue_affine_leaf_outer, ordinal),
                LeafFamily::Ntt => outer!(ntt, preissue_ntt_leaf_outer, ordinal),
                LeafFamily::Mul => outer!(mul, preissue_mul_leaf_outer, ordinal),
                LeafFamily::GBound => outer!(g_bound, preissue_g_bound_leaf_outer, ordinal),
                LeafFamily::Permutation => outer!(permutation, preissue_permutation_leaf_outer, ordinal),
                LeafFamily::LinearMap => outer!(linear_map, preissue_linear_map_leaf_outer, ordinal),
            },
            _ => return Err(WorkflowError::Sequence),
        }
        guard.completed = true;
        Ok(())
    }

    /// Dispatch exactly one sealed producer, retaining whole phase Results in
    /// their concrete original-backed cells before success/failure inspection.
    pub(crate) fn execute(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        let dispatch = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        self.check_dispatch(inventory, case, closed_ordinal, &dispatch)?;
        let binding = step(inventory, closed_ordinal)?.binding;
        macro_rules! native {
            ($field:ident, $produce:ident, $ordinal:expr) => {{
                let plan = original(self.plans.$field, $ordinal)?;
                let mut target = write(cell(self.native.$field, $ordinal)?)?;
                let mut packet = write(cell(self.native_packets.$field, $ordinal)?)?;
                empty(&target)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let operation = plan.operation().map_err(|_| WorkflowError::Source)?;
                same_binding(operation.binding(), binding)?;
                // The packet is still in its stable cell when admission checks
                // the exact phase. No input lookup occurs after extraction.
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take_ready(&mut packet)?;
                *target = Some(phase.$produce(operation, packet_owner));
                let _ = ready(&target)?;
            }};
        }
        macro_rules! compile {
            ($field:ident, $family:ident, $produce:ident, $ordinal:expr) => {{
                let plan = original(self.compilers.$field, $ordinal)?;
                let producer = ProducerRoute::Native { family: NativeFamily::$family, ordinal: $ordinal };
                let (input_binding, input_slot) = prior_input(inventory, closed_ordinal, 0, producer)?;
                let mut input = write(cell(self.native.$field, $ordinal)?)?;
                let mut target = write(cell(self.compiled.$field, $ordinal)?)?;
                empty(&target)?;
                same_binding(ready(&input)?.binding(), input_binding)?;
                if ready(&input)?.slot_id() != input_slot { return Err(WorkflowError::SlotAuthority); }
                let phase = guard.workflow.next_phase(binding)?;
                let operation = match plan.operation(take_ready(&mut input)?) {
                    Ok(operation) => operation,
                    Err((_bounded_error, owner)) => {
                        // The rejected constructor returns the exact original
                        // native owner. Restore it before phase/guard teardown.
                        *input = Some(Ok(owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.$produce(operation));
                let _ = ready(&target)?;
            }};
        }
        macro_rules! outer {
            ($field:ident, $family:ident, $produce:ident, $ordinal:expr) => {{
                let plan = original(self.outer_plans.$field, $ordinal)?;
                let producer = ProducerRoute::Leaf { family: LeafFamily::$family,
                    ordinal: $ordinal, phase: GraphPhase::Compile };
                let (input_binding, input_slot) = prior_input(inventory, closed_ordinal, 0, producer)?;
                let mut input = write(cell(self.compiled.$field, $ordinal)?)?;
                let mut packet = write(cell(self.outer_packets.$field, $ordinal)?)?;
                let mut target = write(cell(self.outer.$field, $ordinal)?)?;
                empty(&target)?;
                same_binding(ready(&input)?.binding(), input_binding)?;
                if ready(&input)?.slot_id() != input_slot { return Err(WorkflowError::SlotAuthority); }
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take_ready(&mut packet)?;
                let input_owner = match take_ready(&mut input) {
                    Ok(owner) => owner,
                    Err(error) => {
                        *packet = Some(Ok(packet_owner));
                        return Err(error);
                    }
                };
                let operation = match plan.outer_operation_retaining(input_owner) {
                    Ok(operation) => operation,
                    Err((_bounded_error, owner)) => {
                        *input = Some(Ok(owner));
                        *packet = Some(Ok(packet_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                // Named producer retirement guards retain uncertain compiled
                // input/output claims. Authenticated cleanup may consume them.
                *target = Some(phase.$produce(operation, packet_owner));
                let _ = ready(&target)?;
            }};
        }
        match dispatch.producer() {
            ProducerRoute::Native { family, ordinal } => match family {
                NativeFamily::Source => native!(source, produce_source_native, ordinal),
                NativeFamily::Uniform => native!(uniform, produce_uniform_native, ordinal),
                NativeFamily::Sparse => native!(sparse, produce_sparse_native, ordinal),
                NativeFamily::Transcript => native!(transcript, produce_transcript_native, ordinal),
                NativeFamily::Affine => native!(affine, produce_affine_native, ordinal),
                NativeFamily::Ntt => native!(ntt, produce_ntt_native, ordinal),
                NativeFamily::Mul => native!(mul, produce_mul_native, ordinal),
                NativeFamily::GBound => native!(g_bound, produce_g_bound_native, ordinal),
                NativeFamily::Permutation => native!(permutation, produce_permutation_native, ordinal),
                NativeFamily::LinearMap => native!(linear_map, produce_linear_map_native, ordinal),
            },
            ProducerRoute::Leaf { family, ordinal, phase: GraphPhase::Compile } => match family {
                LeafFamily::Source => compile!(source, Source, compile_source_native, ordinal),
                LeafFamily::Affine => compile!(affine, Affine, compile_affine_native, ordinal),
                LeafFamily::Ntt => compile!(ntt, Ntt, compile_ntt_native, ordinal),
                LeafFamily::Mul => compile!(mul, Mul, compile_mul_native, ordinal),
                LeafFamily::GBound => compile!(g_bound, GBound, compile_g_bound_native, ordinal),
                LeafFamily::Permutation => compile!(permutation, Permutation, compile_permutation_native, ordinal),
                LeafFamily::LinearMap => compile!(linear_map, LinearMap, compile_linear_map_native, ordinal),
            },
            ProducerRoute::Leaf { family, ordinal, phase: GraphPhase::Outer } => match family {
                LeafFamily::Source => outer!(source, Source, prove_owned_native_leaf_outer, ordinal),
                LeafFamily::Affine => outer!(affine, Affine, prove_owned_affine_leaf_outer, ordinal),
                LeafFamily::Ntt => outer!(ntt, Ntt, prove_owned_ntt_leaf_outer, ordinal),
                LeafFamily::Mul => outer!(mul, Mul, prove_owned_mul_leaf_outer, ordinal),
                LeafFamily::GBound => outer!(g_bound, GBound, prove_owned_g_bound_leaf_outer, ordinal),
                LeafFamily::Permutation => outer!(permutation, Permutation, prove_owned_permutation_leaf_outer, ordinal),
                LeafFamily::LinearMap => outer!(linear_map, LinearMap, prove_owned_linear_map_leaf_outer, ordinal),
            },
            _ => return Err(WorkflowError::Identity),
        }
        guard.completed = true;
        Ok(())
    }
}
