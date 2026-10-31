use super::*;

impl<'tables, 'case, 'plans, 'source, 'native: 'a, 'a> NativeRuntime<'tables, 'case, 'plans, 'source, 'native, 'a> {
    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let counts = metadata.counts();
        self.outer.distinct()?;
        macro_rules! native {
            ($field:ident, $family:ident) => {{
                let count = counts.family(ProducerFamily::$family);
                populated(self.plans.$field, case, count)?;
                uninitialized_table(self.native.$field, case, count)?;
                uninitialized_table(self.native_packets.$field, case, count)?;
            }};
        }
        macro_rules! leaf {
            ($field:ident, $family:ident) => {{
                let count = counts.family(ProducerFamily::$family);
                populated(self.compilers.$field, case, count)?;
                populated(self.outer_plans.$field, case, count)?;
                uninitialized_table(self.compiled.$field, case, count)?;
                uninitialized_table(self.outer.$field, case, count)?;
                uninitialized_table(self.outer_packets.$field, case, count)?;
            }};
        }
        native!(source, Source); native!(uniform, Uniform); native!(sparse, Sparse);
        native!(transcript, Transcript); native!(affine, Affine); native!(ntt, Ntt);
        native!(mul, Mul); native!(g_bound, GBound); native!(permutation, Permutation);
        native!(linear_map, LinearMap);
        leaf!(source, Source); leaf!(affine, Affine); leaf!(ntt, Ntt); leaf!(mul, Mul);
        leaf!(g_bound, GBound); leaf!(permutation, Permutation); leaf!(linear_map, LinearMap);

        // All plan/result/packet tables pass ownership/count/occupancy checks
        // before this first mutation. None of these installations owns a proof.
        macro_rules! native_cells {
            ($field:ident) => {{
                initialize_table(self.native.$field)?;
                initialize_table(self.native_packets.$field)?;
            }};
        }
        macro_rules! leaf_cells {
            ($field:ident) => {{
                initialize_table(self.compiled.$field)?;
                initialize_table(self.outer.$field)?;
                initialize_table(self.outer_packets.$field)?;
            }};
        }
        native_cells!(source); native_cells!(uniform); native_cells!(sparse);
        native_cells!(transcript); native_cells!(affine); native_cells!(ntt);
        native_cells!(mul); native_cells!(g_bound); native_cells!(permutation);
        native_cells!(linear_map);
        leaf_cells!(source); leaf_cells!(affine); leaf_cells!(ntt); leaf_cells!(mul);
        leaf_cells!(g_bound); leaf_cells!(permutation); leaf_cells!(linear_map);
        guard.planning.validate_metadata_driver(metadata, case)?;
        guard.completed = true;
        Ok(())
    }

    /// Called after seal and before any preissue or producer. It authenticates
    /// the entire native/leaf portion, including all still-empty concrete cells.
    pub(crate) fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        let closed = inventory.closed_plan();
        if closed.dispatch().len() != closed.steps().len() { return Err(WorkflowError::Sequence); }
        self.outer.distinct()?;
        let mut natives = [0usize; 10];
        let mut compilers = [0usize; 7];
        let mut outers = [0usize; 7];
        for (closed_ordinal, dispatch) in closed.dispatch().iter().enumerate() {
            match dispatch.producer() {
                ProducerRoute::Native { family, ordinal } => {
                    next_count(&mut natives[native_index(family)], ordinal)?;
                }
                ProducerRoute::Leaf { family, ordinal, phase: GraphPhase::Compile } => {
                    next_count(&mut compilers[leaf_index(family)], ordinal)?;
                }
                ProducerRoute::Leaf { family, ordinal, phase: GraphPhase::Outer } => {
                    next_count(&mut outers[leaf_index(family)], ordinal)?;
                }
                _ => continue,
            }
            self.check_dispatch(inventory, case, closed_ordinal, dispatch)?;
        }
        macro_rules! native {
            ($field:ident, $index:expr) => {{
                let count = natives[$index];
                populated(self.plans.$field, case, count)?;
                empty_table(self.native.$field, case, count)?;
                empty_table(self.native_packets.$field, case, count)?;
            }};
        }
        macro_rules! leaf {
            ($field:ident, $native:expr, $leaf:expr) => {{
                let count = natives[$native];
                if compilers[$leaf] != count || outers[$leaf] != count {
                    return Err(WorkflowError::Sequence);
                }
                populated(self.compilers.$field, case, count)?;
                populated(self.outer_plans.$field, case, count)?;
                empty_table(self.compiled.$field, case, count)?;
                empty_table(self.outer.$field, case, count)?;
                empty_table(self.outer_packets.$field, case, count)?;
            }};
        }
        native!(source, 0); native!(uniform, 1); native!(sparse, 2); native!(transcript, 3);
        native!(affine, 4); native!(ntt, 5); native!(mul, 6); native!(g_bound, 7);
        native!(permutation, 8); native!(linear_map, 9);
        leaf!(source, 0, 0); leaf!(affine, 4, 1); leaf!(ntt, 5, 2); leaf!(mul, 6, 3);
        leaf!(g_bound, 7, 4); leaf!(permutation, 8, 5); leaf!(linear_map, 9, 6);
        guard.completed = true;
        Ok(())
    }

    /// Authentication is performed by the entry point before passing this
    /// borrowed dispatch. This helper issues no phase, packet, or reservation.
    pub(super) fn check_dispatch(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState, closed_ordinal: usize, dispatch: &StepDispatch) -> Result<()>
    {
        let scheduled = step(inventory, closed_ordinal)?;
        self.outer.distinct()?;
        macro_rules! native {
            ($field:ident, $family:ident, $factory:ident, $ordinal:expr) => {{
                shape(dispatch, scheduled, &[])?;
                let count = inventory.producer_counts().family(ProducerFamily::$family);
                original_table(self.plans.$field, case, count)?;
                original_table(self.native.$field, case, count)?;
                original_table(self.native_packets.$field, case, count)?;
                let plan = original(self.plans.$field, $ordinal)?;
                same_binding(PhaseBinding::$factory(plan, 0)?, scheduled.binding)?;
                if scheduled.backend != plan.backend_allowance() { return Err(WorkflowError::BackendAllowance); }
            }};
        }
        macro_rules! leaf {
            ($field:ident, $family:ident, $factory:ident, $ordinal:expr, $phase:expr) => {{
                let count = inventory.producer_counts().family(ProducerFamily::$family);
                original_table(self.plans.$field, case, count)?;
                original_table(self.compilers.$field, case, count)?;
                original_table(self.outer_plans.$field, case, count)?;
                original_table(self.native.$field, case, count)?;
                original_table(self.compiled.$field, case, count)?;
                original_table(self.outer.$field, case, count)?;
                original_table(self.outer_packets.$field, case, count)?;
                let native = original(self.plans.$field, $ordinal)?;
                let compiler = original(self.compilers.$field, $ordinal)?;
                let outer = original(self.outer_plans.$field, $ordinal)?;
                if !core::ptr::eq(compiler.native_plan(), native)
                    || !core::ptr::eq(outer.compiler_plan(), compiler)
                { return Err(WorkflowError::Identity); }
                let (producer, input_binding, binding) = match $phase {
                    GraphPhase::Compile => (
                        ProducerRoute::Native { family: NativeFamily::$family, ordinal: $ordinal },
                        PhaseBinding::$factory(native, 0)?,
                        compiler.binding().map_err(|_| WorkflowError::Source)?),
                    GraphPhase::Outer => (
                        ProducerRoute::Leaf { family: LeafFamily::$family, ordinal: $ordinal, phase: GraphPhase::Compile },
                        compiler.binding().map_err(|_| WorkflowError::Source)?,
                        outer.binding().map_err(|_| WorkflowError::Source)?),
                };
                shape(dispatch, scheduled, &[producer])?;
                same_binding(binding, scheduled.binding)?;
                same_binding(prior_input(inventory, closed_ordinal, 0, producer)?.0, input_binding)?;
                check_leaf_backend($phase, scheduled.backend)?;
            }};
        }
        match dispatch.producer() {
            ProducerRoute::Native { family, ordinal } => match family {
                NativeFamily::Source => native!(source, Source, for_source_native, ordinal),
                NativeFamily::Uniform => native!(uniform, Uniform, for_uniform_native, ordinal),
                NativeFamily::Sparse => native!(sparse, Sparse, for_sparse_native, ordinal),
                NativeFamily::Transcript => native!(transcript, Transcript, for_transcript_native, ordinal),
                NativeFamily::Affine => native!(affine, Affine, for_affine_native, ordinal),
                NativeFamily::Ntt => native!(ntt, Ntt, for_ntt_native, ordinal),
                NativeFamily::Mul => native!(mul, Mul, for_mul_native, ordinal),
                NativeFamily::GBound => native!(g_bound, GBound, for_g_bound_native, ordinal),
                NativeFamily::Permutation => native!(permutation, Permutation, for_permutation_native, ordinal),
                NativeFamily::LinearMap => native!(linear_map, LinearMap, for_linear_map_native, ordinal),
            },
            ProducerRoute::Leaf { family, ordinal, phase } => match family {
                LeafFamily::Source => leaf!(source, Source, for_source_native, ordinal, phase),
                LeafFamily::Affine => leaf!(affine, Affine, for_affine_native, ordinal, phase),
                LeafFamily::Ntt => leaf!(ntt, Ntt, for_ntt_native, ordinal, phase),
                LeafFamily::Mul => leaf!(mul, Mul, for_mul_native, ordinal, phase),
                LeafFamily::GBound => leaf!(g_bound, GBound, for_g_bound_native, ordinal, phase),
                LeafFamily::Permutation => leaf!(permutation, Permutation, for_permutation_native, ordinal, phase),
                LeafFamily::LinearMap => leaf!(linear_map, LinearMap, for_linear_map_native, ordinal, phase),
            },
            _ => return Err(WorkflowError::Identity),
        }
        Ok(())
    }
}
