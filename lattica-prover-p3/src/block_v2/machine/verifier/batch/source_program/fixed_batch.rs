//! Bounded public-source reconstruction for an explicitly selected fixed batch.
//! No synthetic proof or its values leave this module, and no values are evaluated.
//! This helper grants no trust: the enclosing caller independently authenticates
//! each shape/cap/public tuple and the complete ordered batch binding.
use super::*;
use super::super::shape::{OperationCounts, MAX_CHILDREN};

#[derive(Clone, Copy)]
pub struct Child<'a> {
    pub shape: RegisteredChildShape,
    pub preprocessing_cap: &'a [[Val; 4]],
    pub public: [Val; PUBLICS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Storage {
    planning: PlanningStorage,
    required_bytes: usize,
}

impl Storage {
    pub fn new(children: &[RegisteredChildShape], limits: ConstructionLimits) -> Result<Self, CompileError> {
        if children.iter().any(|c| c.public_values != PUBLICS || c.preprocessing_cap_roots != ROOTS) {
            return Err(CompileError::Shape("fixed batch child geometry"));
        }
        let planning = PlanningStorage::for_children(PUBLICS, children, limits)?;
        let helper_bytes = [
            4 * size_of::<Self>(),
            4 * size_of::<Result<Self, CompileError>>(),
            4 * size_of::<ProgramBuilder>(),
            4 * size_of::<Program>(),
            4 * size_of::<ProofInputs>(),
            4 * size_of::<Result<Program, CompileError>>(),
            4 * size_of::<MachineAir>(),
            4 * size_of::<[RegisteredChildShape; MAX_CHILDREN]>(),
            4 * size_of::<[Child<'static>; MAX_CHILDREN]>(),
            4 * size_of::<ConstructionLimits>(),
            4 * size_of::<[[Wire; 4]; ROOTS]>(),
            8 * size_of::<[Wire; PUBLICS]>(),
            8 * size_of::<[Val; PUBLICS]>(),
            4 * size_of::<OperationCounts>(),
            128 * size_of::<usize>(),
        ].into_iter().try_fold(0usize, |a, b| a.checked_add(b))
            .ok_or(CompileError::ResourceAdmission("fixed batch helper overflow"))?;
        let required_bytes = planning.total_requested_bytes.checked_add(helper_bytes)
            .ok_or(CompileError::ResourceAdmission("fixed batch storage overflow"))?;
        Ok(Self { planning, required_bytes })
    }

    pub fn required_bytes(self) -> usize { self.required_bytes }
}

/// Source-derived extra operations around the opaque-cap verifier core. Each
/// root public and each child-public input has one Constant and one Equal.
/// Child publics remain fresh inputs, so only the existing cap-specialization
/// argument is needed. Constant interning may remove work but cannot add it.
pub fn binding_overhead(children: usize) -> Result<OperationCounts, CompileError> {
    if !(1..=MAX_CHILDREN).contains(&children) {
        return Err(CompileError::Shape("fixed batch child count"));
    }
    Ok(OperationCounts { scalar: 2 * PUBLICS * (children + 1), cubic: 0, poseidon: 0 })
}

/// Reconstruct exactly the ordered fixed-child verifier program. Claimed keys
/// from an artifact must never reach this API. Complete storage is checked
/// before a builder, template, symbolic graph or proof input is allocated.
pub fn reconstruct(
    expected_public: [Val; PUBLICS],
    children: &[Child<'_>],
    limits: ConstructionLimits,
    admitted_host_bytes: usize,
) -> Result<Program, CompileError> {
    if children.is_empty() || children.len() > MAX_CHILDREN {
        return Err(CompileError::Shape("fixed batch child count"));
    }
    let mut shapes = [children[0].shape; MAX_CHILDREN];
    for (slot, child) in shapes.iter_mut().zip(children) {
        *slot = child.shape;
        if child.preprocessing_cap.len() != child.shape.preprocessing_cap_roots {
            return Err(CompileError::Shape("fixed batch cap geometry"));
        }
    }
    let storage = Storage::new(&shapes[..children.len()], limits)?;
    if storage.required_bytes > admitted_host_bytes {
        return Err(CompileError::ResourceAdmission("fixed batch source admission"));
    }
    let mut builder = ProgramBuilder::new_with_construction_limits(PUBLICS, limits)
        .map_err(|e| CompileError::from_builder_admission(e, "fixed batch builder"))?;
    for (index, value) in expected_public.into_iter().enumerate() {
        let public = builder.public(index)
            .map_err(|e| CompileError::from_builder_admission(e, "fixed batch public"))?;
        let expected = builder.constant(value);
        builder.assert_equal(public, expected);
    }
    let mut inputs = ProofInputs::default();
    for child in children {
        let public = inputs.bases(&mut builder, &child.public)?;
        for (&wire, value) in public.iter().zip(child.public) {
            let expected = builder.constant(value);
            builder.assert_equal(wire, expected);
        }
        let mut cap = [[Wire(0); 4]; ROOTS];
        for (destination, digest) in cap.iter_mut().zip(child.preprocessing_cap) {
            *destination = digest.map(|word| builder.constant(word));
        }
        if let Some(error) = builder.resource_failure() {
            return Err(CompileError::from_builder_admission(error, "fixed batch binding"));
        }
        let empty = ProgramBuilder::new(PUBLICS).and_then(|b| b.finish(Some(child.shape.height)))
            .map_err(|_| CompileError::Shape("fixed batch child AIR"))?;
        let air = MachineAir::new(empty);
        let template = super::super::super::template::batch_bounded_shape(&air)?;
        retained_proof_capacity_bytes(&template, storage.planning.template_retained_bytes)
            .map_err(|_| CompileError::Shape("fixed batch template drift"))?;
        super::super::verify_bounded_shape(&mut builder, &mut inputs, &air, &public, &cap, &template)?;
        // One template at a time; cumulative inputs and builder remain bounded.
        drop(template);
        drop(air);
    }
    let program = builder.finish(None)
        .map_err(|e| CompileError::from_builder_admission(e, "fixed batch finalization"))?;
    if program.witness_values() != inputs.values.len() {
        return Err(CompileError::Shape("fixed batch input geometry"));
    }
    drop(inputs);
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn fixed_batch_binds_each_public_without_specializing_unknown_inputs() {
        for n in 1..=MAX_CHILDREN {
            assert_eq!(binding_overhead(n).unwrap(), OperationCounts {
                scalar: 8 * (n + 1), cubic: 0, poseidon: 0,
            });
        }
        assert!(binding_overhead(0).is_err());
        assert!(binding_overhead(MAX_CHILDREN + 1).is_err());
    }

    #[test]
    fn all_fixed_children_and_full_storage_are_admitted_before_compilation() {
        if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) { return; }
        let limits = ConstructionLimits {
            max_requested_program_bytes: 2 << 30, max_wires: 1 << 26, max_input_values: 1 << 20,
        };
        let shape = RegisteredChildShape { public_values: 4, height: 8, preprocessing_cap_roots: ROOTS };
        let cap = [[Val::ZERO; 4]; ROOTS];
        for n in [3, 4] {
            let storage = Storage::new(&[shape; MAX_CHILDREN][..n], limits).unwrap();
            let mut children = [Child { shape, preprocessing_cap: &cap, public: [Val::ZERO; 4] }; MAX_CHILDREN];
            assert!(reconstruct([Val::ZERO; 4], &children[..n], limits, storage.required_bytes() - 1).is_err());
            children[n - 1].preprocessing_cap = &cap[..ROOTS - 1];
            assert!(reconstruct([Val::ZERO; 4], &children[..n], limits, storage.required_bytes()).is_err());
        }
    }

    #[test]
    #[ignore = "coordinator-only serialized wide-profile source screen; no GPU execution"]
    fn direct_ring_flat_n3_n4_source_geometry() {
        assert!(cfg!(all(not(debug_assertions), target_arch = "x86_64")));
        assert_eq!(crate::block_v2::machine::program::LANES, 23);
        let limits = ConstructionLimits {
            max_requested_program_bytes: 2 << 30, max_wires: 1 << 26, max_input_values: 1 << 20,
        };
        // The qualified wide direct-ring leaf is2^19 rows. The complete driver
        // still derives and checks each real compiled leaf before any setup.
        let child = RegisteredChildShape { public_values: 4, height: 1 << 19, preprocessing_cap_roots: ROOTS };
        let mut closed = true;
        for n in [3, 4] {
            let shapes = [child; MAX_CHILDREN];
            let storage = PlanningStorage::for_children(4, &shapes[..n], limits).unwrap();
            let core = super::super::super::shape::verifier_core_bound(4, &shapes[..n], limits, storage.auxiliary_peak_bytes).unwrap();
            let counts = core.operations.with_overhead(binding_overhead(n).unwrap()).unwrap();
            let active = counts.active_rows(4).unwrap();
            let padded = counts.padded_rows(4).unwrap();
            let wires = core.wire_upper_bound + 4 * (n + 1);
            let fits = padded <= 1 << 20 && wires <= limits.max_wires && core.input_values_upper_bound <= limits.max_input_values;
            eprintln!("direct_ring_flat_source n={n} leaf_height={} active_rows={active} padded_rows={padded} wires={wires} inputs={} requested_program_peak={} auxiliary_bytes={} source_closed={fits} native_proofs=0", child.height, core.input_values_upper_bound, core.planner_requested_program_bytes_peak, storage.auxiliary_peak_bytes);
            closed &= fits;
        }
        assert!(closed, "flat source does not close; choose a separate fixed topology before native0");
    }
}
