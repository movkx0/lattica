//! Exact fixed merge adapter. It emits no verifier and confers no acceptance;
//! child predicates must be authenticated by the genuine registration caps.
use crate::component_tree::{self, Spec, HEADER};
use lattica_prover_p3::block_v2::machine::{
    program::{ProgramBuilder, Wire},
    verifier::batch::shape::OperationCounts,
};

pub(super) const fn operations() -> OperationCounts {
    // public_wires: eight bounded32 contexts at162 scalar each, then eight
    // profile + six contract/span + four descriptor Constant/Equal pairs.
    let header = 8 * 162 + (8 + 6 + 4) * 2;
    // bind_merge: shared header equalities; first/adjacent/count; three sets
    // of four endpoint equalities. The actual registered child predicates
    // fix child spec levels; the parent spec level is max(left,right)+1.
    let binding = 2 * (HEADER - 3) + 5 + 3 * 4;
    OperationCounts {
        scalar: header + binding,
        cubic: 0,
        poseidon: 0,
    }
}

/// Fixed-array call to the maintained predicate. This private primitive must
/// only run inside an already-admitted bounded builder/input phase. Neither
/// a naked builder nor this function issues a complete parent compile permit.
pub(super) fn emit(
    builder: &mut ProgramBuilder,
    spec: &Spec,
    outer: &[Wire; HEADER + 8],
    left: &[Wire; HEADER + 8],
    right: &[Wire; HEADER + 8],
) -> super::Result<()> {
    // The fixed 46-public profile makes index zero valid. This public,
    // allocation-free accessor also rejects a latched construction failure.
    builder.public(0).map_err(|_| super::Error::Capacity)?;
    component_tree::bind_merge(builder, spec, outer, left, right);
    builder.public(0).map_err(|_| super::Error::Capacity)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tree::{Contract, EndpointContext, Val};
    use lattica_prover_p3::block_v2::machine::program::{ConstructionLimits, ProofInputs};
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn exact_merge_framing_rejects_shared_header_span_and_every_interior_root_mutation() {
        let contract = Contract::shake(
            [7; 32],
            9,
            crate::shake_air::Descriptor {
                input_len: 16_416,
                output_len: 137,
            },
        )
        .unwrap();
        let mut left_spec = contract.span(0, 120).unwrap();
        left_spec.level = 2;
        let right_spec = contract.span(120, 2).unwrap();
        let spec = Spec::merge(&left_spec, &right_spec).unwrap();
        let context = EndpointContext {
            context: [11; 32],
            statement: [Val::from_u64(13); 4],
            input: [Val::from_u64(17); 4],
            output: [Val::from_u64(19); 4],
        };
        let mut left = component_tree::header(&left_spec, &context).unwrap();
        let mut right = component_tree::header(&right_spec, &context).unwrap();
        let mut public = component_tree::header(&spec, &context).unwrap();
        for i in 0..4 {
            left[HEADER + i] = Val::from_usize(31 + i);
            left[HEADER + 4 + i] = Val::from_usize(41 + i);
            right[HEADER + i] = left[HEADER + 4 + i];
            right[HEADER + 4 + i] = Val::from_usize(51 + i);
            public[HEADER + i] = left[HEADER + i];
            public[HEADER + 4 + i] = right[HEADER + 4 + i];
        }
        // External fixture storage is distinct from source-planner admission.
        // This is a bounded framing program, with no child verifier or proof.
        let mut builder = ProgramBuilder::new_with_construction_limits(
            HEADER + 8,
            ConstructionLimits {
                max_requested_program_bytes: 1 << 20,
                max_wires: 1 << 14,
                max_input_values: 2 * (HEADER + 8),
            },
        )
        .unwrap();
        let outer: [Wire; HEADER + 8] = component_tree::public_wires(&mut builder, &spec)
            .unwrap()
            .try_into()
            .unwrap();
        let mut inputs = ProofInputs::default();
        let left_wires: [Wire; HEADER + 8] = inputs
            .bases(&mut builder, &left)
            .unwrap()
            .try_into()
            .unwrap();
        let right_wires: [Wire; HEADER + 8] = inputs
            .bases(&mut builder, &right)
            .unwrap()
            .try_into()
            .unwrap();
        emit(&mut builder, &spec, &outer, &left_wires, &right_wires).unwrap();
        let program = builder.finish(None).unwrap();
        let actual = OperationCounts::from_program(&program);
        assert!(actual.scalar <= operations().scalar + 2 * (HEADER + 8));
        assert_eq!((actual.cubic, actual.poseidon), (0, 0));
        assert!(program
            .check_host_constraints(&public, &inputs.values)
            .is_ok());
        for child in 0..2 {
            for field in 0..HEADER + 8 {
                // Child level belongs to its authenticated registered
                // predicate, not to this framing-only program.
                if field == component_tree::LEVEL {
                    continue;
                }
                let index = child * (HEADER + 8) + field;
                inputs.values[index] += Val::ONE;
                assert!(
                    program
                        .check_host_constraints(&public, &inputs.values)
                        .is_err(),
                    "child={child} field={field}"
                );
                inputs.values[index] -= Val::ONE;
            }
        }
        for field in 0..HEADER + 8 {
            public[field] += Val::ONE;
            assert!(
                program
                    .check_host_constraints(&public, &inputs.values)
                    .is_err(),
                "outer field={field}"
            );
            public[field] -= Val::ONE;
        }
        assert!(program
            .check_host_constraints(&public, &inputs.values)
            .is_ok());
    }
}
