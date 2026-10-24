use super::*;
use crate::block_v2::machine::program::Val;

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
fn child(public_values: usize, height: usize) -> RegisteredChildShape {
    RegisteredChildShape {
        public_values,
        height,
        preprocessing_cap_roots: 64,
    }
}

#[test]
fn public_geometry_and_overflow_refuse_before_templates() {
    let valid = child(32, 1 << 18);
    for bad in [
        child(65, 8),
        child(0, 0),
        child(1, 7),
        child(1, 9),
        child(1, 1 << 25),
        RegisteredChildShape {
            preprocessing_cap_roots: 0,
            ..valid
        },
        RegisteredChildShape {
            preprocessing_cap_roots: 63,
            ..valid
        },
        RegisteredChildShape {
            preprocessing_cap_roots: 128,
            ..valid
        },
    ] {
        assert!(matches!(
            PlanningStorage::for_children(32, &[valid, bad], limits()),
            Err(CompileError::Shape(_))
        ));
    }
    for shapes in [&[][..], &[valid; 5][..]] {
        assert!(matches!(
            PlanningStorage::for_children(32, shapes, limits()),
            Err(CompileError::Shape(_))
        ));
    }
    assert!(matches!(
        PlanningStorage::for_children(65, &[valid], limits()),
        Err(CompileError::Shape(_))
    ));
    for construction in [
        ConstructionLimits {
            max_requested_program_bytes: 0,
            ..limits()
        },
        ConstructionLimits {
            max_wires: 0,
            ..limits()
        },
        ConstructionLimits {
            max_wires: MAX_WIRES + 1,
            ..limits()
        },
        ConstructionLimits {
            max_input_values: MAX_WIRES,
            ..limits()
        },
    ] {
        assert!(matches!(
            PlanningStorage::for_children(32, &[valid], construction),
            Err(CompileError::Shape(_))
        ));
    }
    if cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        assert!(matches!(
            PlanningStorage::for_children(
                32,
                &[valid],
                ConstructionLimits {
                    max_requested_program_bytes: usize::MAX,
                    ..limits()
                }
            ),
            Err(CompileError::ResourceAdmission(_))
        ));
        assert_eq!(
            verifier_core_bound(32, &[valid], limits(), 0),
            Err(CompileError::ResourceAdmission(
                "registered shape auxiliary allowance"
            ))
        );
    } else {
        assert!(matches!(
            PlanningStorage::for_children(32, &[valid], limits()),
            Err(CompileError::Unsupported(_))
        ));
    }
}

#[test]
fn operation_classes_pack_separately_and_check_overflow() {
    let counts = OperationCounts {
        scalar: LANES + 1,
        cubic: EXT_LANES + 1,
        poseidon: 7,
    };
    assert_eq!(counts.active_rows(33).unwrap(), 13);
    assert_eq!(counts.padded_rows(33).unwrap(), 16);
    assert_eq!(
        counts
            .with_overhead(OperationCounts {
                scalar: LANES - 1,
                cubic: EXT_LANES - 1,
                poseidon: 0
            })
            .unwrap()
            .active_rows(33)
            .unwrap(),
        13
    );
    let overflow = OperationCounts {
        scalar: usize::MAX,
        cubic: usize::MAX,
        poseidon: usize::MAX,
    };
    assert!(overflow.active_rows(64).is_err());
    assert!(overflow.with_overhead(counts).is_err());
    assert!(counts.active_rows(65).is_err());
    assert!(OperationCounts {
        scalar: 0,
        cubic: 0,
        poseidon: 1 << 24
    }
    .padded_rows(1)
    .is_err());
}

#[test]
fn template_bound_uses_source_geometry_and_one_child_lifetime() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let a = child(0, 8);
    let b = child(64, 1 << 24);
    let small = PlanningStorage::for_children(0, &[a], limits()).unwrap();
    let large = PlanningStorage::for_children(0, &[b], limits()).unwrap();
    let combined = PlanningStorage::for_children(0, &[a, b, b, a], limits()).unwrap();
    assert!(large.template_retained_bytes > small.template_retained_bytes);
    assert_eq!(combined, large);
    assert!(large.template_retained_bytes < 64 << 20);
    assert_eq!(large.symbolic_workspace_bytes, 192 << 20);
    assert_eq!(large.symbolic_retained_bytes, 128 << 20);
    assert_eq!(
        large.input_backing_bytes,
        2 * (1 << 20) * core::mem::size_of::<Val>()
    );
    assert_eq!(
        large.total_requested_bytes,
        large.auxiliary_peak_bytes + limits().max_requested_program_bytes
    );
}

fn qualified() {
    assert!(cfg!(all(not(debug_assertions), target_arch = "x86_64")));
    assert_eq!(
        std::env::var("LATTICA_BOUNDED_BATCH_SHAPE_QUALIFICATION").as_deref(),
        Ok("1"),
        "run only in the coordinator's serialized release memory guard"
    );
}

// Test-only concrete programs. No such authority escapes the public planner.
fn concrete_core(
    outer: usize,
    shapes: &[RegisteredChildShape],
    pattern: usize,
    bounded: bool,
) -> (Program, Vec<Val>) {
    let mut b = ProgramBuilder::new_with_construction_limits(outer, limits()).unwrap();
    let mut inputs = ProofInputs::default();
    for (index, &shape) in shapes.iter().enumerate() {
        let air = empty_air(shape).unwrap();
        let template = if bounded {
            super::super::super::template::batch_bounded_shape(&air)
        } else {
            super::super::super::template::batch(&air)
        }
        .unwrap();
        let public = inputs
            .bases(&mut b, &vec![Val::ZERO; shape.public_values])
            .unwrap();
        let cap: Vec<_> = (0..shape.preprocessing_cap_roots)
            .map(|i| {
                core::array::from_fn(|j| {
                    b.constant(match pattern {
                        0 => Val::ZERO,
                        1 => Val::from_usize((i + j) % 2),
                        _ => Val::from_usize(1000 + index * 4096 + i * 4 + j),
                    })
                })
            })
            .collect();
        if bounded {
            super::super::verify_bounded_shape(&mut b, &mut inputs, &air, &public, &cap, &template)
        } else {
            super::super::verify(&mut b, &mut inputs, &air, &public, &cap, &template)
        }
        .unwrap();
    }
    (b.finish(None).unwrap(), inputs.values)
}

#[test]
#[ignore = "serialized release memory guard and explicit qualification env required"]
fn opaque_cap_dominates_and_bounded_concrete_manifest_matches_reference() {
    qualified();
    for shapes in [
        vec![child(0, 8)],
        vec![child(32, 1 << 18)],
        vec![child(64, 8), child(24, 256)],
    ] {
        let bound = verifier_core_bound(32, &shapes, limits(), 512 << 20).unwrap();
        for pattern in 0..3 {
            let (bounded, bounded_values) = concrete_core(32, &shapes, pattern, true);
            let counts = OperationCounts::from_program(&bounded);
            assert!(
                counts.scalar <= bound.operations.scalar,
                "scalar cap pattern {pattern}"
            );
            assert!(
                counts.cubic <= bound.operations.cubic,
                "cubic cap pattern {pattern}"
            );
            assert!(
                counts.poseidon <= bound.operations.poseidon,
                "hash cap pattern {pattern}"
            );
            assert!(bounded.wire_count() <= bound.wire_upper_bound);
            assert!(bounded.witness_values() <= bound.input_values_upper_bound);
            assert!(bounded.active_rows() <= bound.active_rows_upper_bound);
            assert!(bounded.height() <= bound.padded_rows_upper_bound);
            let (reference, reference_values) = concrete_core(32, &shapes, pattern, false);
            assert!(bounded_values == reference_values, "concrete proof input order changed");
            // Program equality compares operations, rows, references, publics,
            // witnesses and height; excludes construction provenance only.
            assert!(bounded == reference, "concrete registered verifier program changed");
            // Stream manifests to avoid a second program-sized Vec.
            let mut fields = 0usize;
            bounded
                .visit_manifest_fields(&mut |_| {
                    fields += 1;
                    Ok(())
                })
                .unwrap();
            assert!(fields > 0);
        }
        eprintln!("opaque_batch_shape children={} rows={} padded={} scalar={} cubic={} poseidon={} wires={} inputs={} planner_requested_peak={} auxiliary_reservation={}",
            shapes.len(), bound.active_rows_upper_bound, bound.padded_rows_upper_bound,
            bound.operations.scalar, bound.operations.cubic, bound.operations.poseidon,
            bound.wire_upper_bound, bound.input_values_upper_bound,
            bound.planner_requested_program_bytes_peak, bound.storage.auxiliary_peak_bytes);
    }
}

#[test]
#[ignore = "serialized release memory guard and explicit qualification env required"]
fn opaque_core_four_child_shape_and_late_builder_refusal_are_closed() {
    qualified();
    let shapes = [child(32, 1 << 18); 4];
    let bound = verifier_core_bound(32, &shapes, limits(), 512 << 20).unwrap();
    assert!(bound.active_rows_upper_bound > 0);
    assert!(bound.padded_rows_upper_bound <= 1 << 24);
    let refused = ConstructionLimits {
        max_input_values: 1,
        ..limits()
    };
    assert!(matches!(
        verifier_core_bound(32, &shapes, refused, 512 << 20),
        Err(CompileError::ResourceAdmission(_))
    ));
    // A fresh call has no surviving sticky builder or symbolic state.
    assert!(verifier_core_bound(0, &[child(0, 8)], limits(), 512 << 20).is_ok());
}
