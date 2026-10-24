use super::*;
use crate::{
    affine_air::AffineKind,
    linear_map_air::LinearMapDescriptor,
    permutation_air::PermutationKind,
    rust_verify::{committed_backend::PolynomialKind, D, Q, QHAT},
};
use lattica_prover_p3::block_v2::machine::{
    program::{ProgramBuilder, MAX_WIRES},
    verifier::{batch::shape::OperationCounts, uni, ProofInputs},
};
use p3_air::{symbolic::SymbolicAirBuilder, Air};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}

fn canonical_map(inputs: usize, modulus: u64, coefficient: i64) -> LinearMapDescriptor {
    let kind = PolynomialKind::Canonical { modulus };
    LinearMapDescriptor::new(
        vec![kind; inputs],
        kind,
        vec![[coefficient; D]; inputs],
        [0; D],
    )
    .unwrap()
}

fn signed_map(inputs: usize) -> LinearMapDescriptor {
    LinearMapDescriptor::new(
        (1..=inputs)
            .map(|bound| PolynomialKind::Signed {
                bound: bound as u32,
            })
            .collect(),
        PolynomialKind::Signed {
            bound: i32::MAX as u32,
        },
        vec![[0; D]; inputs],
        [0; D],
    )
    .unwrap()
}

fn algebra_cases() -> Vec<(ComponentKind, usize)> {
    let mut cases = Vec::new();
    for modulus in [Q, QHAT] {
        for count in [1, 64] {
            for kind in [
                AffineKind::Add,
                AffineKind::Sub,
                AffineKind::SignedToCanonical { bound: 565 },
            ] {
                cases.push((ComponentKind::Affine { kind, modulus }, count));
            }
        }
        for count in [1, 3, 32] {
            cases.push((ComponentKind::Ntt { modulus }, count));
            cases.push((ComponentKind::Mul { modulus }, count));
        }
        for count in [1, 16] {
            cases.push((
                ComponentKind::LinearMap {
                    descriptor: canonical_map(count, modulus, 1),
                },
                1,
            ));
        }
    }
    for bound in [6_825_771, 1_137_628] {
        cases.push((ComponentKind::GBound { bound }, 1));
    }
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        cases.push((ComponentKind::Permutation { kind }, 1));
    }
    for count in [1, 16] {
        cases.push((
            ComponentKind::LinearMap {
                descriptor: signed_map(count),
            },
            1,
        ));
    }
    cases.push((
        ComponentKind::LinearMap {
            descriptor: canonical_map(1, QHAT, 1 << 28),
        },
        1,
    ));
    cases
}

fn assert_geometry<A: BaseAir<Val>>(descriptor: OtherNativeDescriptor<'_>, air: &A, height: usize) {
    let g = descriptor.geometry().unwrap();
    assert_eq!(
        (g.width, g.height, g.public_values, g.periodic_columns),
        (
            air.width(),
            height,
            air.num_public_values(),
            air.num_periodic_columns()
        )
    );
    let columns = air.periodic_columns();
    assert_eq!(columns.len(), g.periodic_columns);
    assert!(columns
        .iter()
        .all(|c| c.len().is_power_of_two() && c.len() <= g.maximum_period));
    // Compressed columns may retain the full source-table capacity; charge
    // that original maximum period rather than their shorter logical length.
    let actual = columns.capacity() * size_of::<Vec<Val>>()
        + columns
            .iter()
            .map(|c| c.capacity() * size_of::<Val>())
            .sum::<usize>();
    let source = 4
        * (g.periodic_columns * g.maximum_period * size_of::<Val>()
            + g.periodic_columns * size_of::<Vec<Val>>());
    assert!(actual <= source);
}

#[test]
fn closed_geometry_and_periodic_backing_match_every_family() {
    let statement = OtherNativeDescriptor::Statement {
        setup_seed: [23; 32],
    };
    assert_geometry(
        statement,
        &StatementAir {
            setup_seed: [23; 32],
        },
        statement_air::HEIGHT,
    );
    assert_geometry(
        OtherNativeDescriptor::PrivateProof,
        &ProofAir,
        proof_air::HEIGHT,
    );
    for (kind, count) in algebra_cases() {
        let d = OtherNativeDescriptor::Algebra { kind: &kind, count };
        match &kind {
            ComponentKind::Affine { kind, modulus } => {
                let air = AffineAir::new(*kind, *modulus, count).unwrap();
                assert_geometry(d, &air, air.height());
            }
            ComponentKind::Ntt { modulus } => {
                let air = NttAir::new(*modulus, count).unwrap();
                assert_geometry(d, &air, air.height);
            }
            ComponentKind::Mul { modulus } => {
                let air = MulAir::new(*modulus, count).unwrap();
                assert_geometry(d, &air, air.height);
            }
            ComponentKind::GBound { bound } => {
                assert_geometry(d, &GBoundAir::new(*bound).unwrap(), g_bound_air::HEIGHT)
            }
            ComponentKind::Permutation { kind } => {
                assert_geometry(d, &PermutationAir::new(*kind), permutation_air::HEIGHT)
            }
            ComponentKind::LinearMap { descriptor } => {
                let air = LinearMapAir::new(descriptor.clone());
                assert_geometry(d, &air, air.height());
            }
            ComponentKind::External => unreachable!(),
        }
    }
}

#[test]
fn selected_caps_and_invalid_parameters_refuse_before_compilation() {
    let invalid = [
        (
            ComponentKind::Affine {
                kind: AffineKind::Add,
                modulus: Q,
            },
            0,
        ),
        (
            ComponentKind::Affine {
                kind: AffineKind::Add,
                modulus: Q,
            },
            3,
        ),
        (
            ComponentKind::Affine {
                kind: AffineKind::Add,
                modulus: Q,
            },
            128,
        ),
        (
            ComponentKind::Affine {
                kind: AffineKind::SignedToCanonical { bound: 0 },
                modulus: Q,
            },
            1,
        ),
        (
            ComponentKind::Affine {
                kind: AffineKind::Add,
                modulus: 17,
            },
            1,
        ),
        (ComponentKind::Ntt { modulus: Q }, 0),
        (ComponentKind::Ntt { modulus: Q }, 33),
        (ComponentKind::Ntt { modulus: 17 }, 1),
        (ComponentKind::Mul { modulus: Q }, 0),
        (ComponentKind::Mul { modulus: Q }, 33),
        (ComponentKind::Mul { modulus: 17 }, 1),
        (ComponentKind::GBound { bound: 1 }, 1),
        (ComponentKind::GBound { bound: 6_825_771 }, 2),
        (
            ComponentKind::Permutation {
                kind: PermutationKind::AutomorphismQ,
            },
            2,
        ),
        (
            ComponentKind::LinearMap {
                descriptor: canonical_map(1, Q, 1),
            },
            2,
        ),
        (ComponentKind::External, 1),
    ];
    for (kind, count) in invalid {
        let d = OtherNativeDescriptor::Algebra { kind: &kind, count };
        assert!(d.geometry().is_err());
        assert!(other_native_core_bound(d, limits(), usize::MAX).is_err());
    }
}

fn check_refusal(d: OtherNativeDescriptor<'_>) {
    let storage = d.storage(limits()).unwrap();
    assert!(storage.auxiliary_peak_bytes < 512 << 20);
    assert!(matches!(
        other_native_core_bound(d, limits(), storage.auxiliary_peak_bytes - 1),
        Err(CompileError::ResourceAdmission(
            "unchanged native auxiliary allowance"
        ))
    ));
    assert!(d
        .storage(ConstructionLimits {
            max_requested_program_bytes: usize::MAX,
            ..limits()
        })
        .is_err());
}

#[test]
fn preallocation_budget_boundary_covers_every_closed_family() {
    check_refusal(OtherNativeDescriptor::Statement {
        setup_seed: [0; 32],
    });
    check_refusal(OtherNativeDescriptor::PrivateProof);
    for (kind, count) in algebra_cases() {
        check_refusal(OtherNativeDescriptor::Algebra { kind: &kind, count });
    }
}

#[test]
fn ntt_step_storage_and_linear_map_owned_backing_are_separate() {
    let (_, statement) = OtherNativeDescriptor::Statement {
        setup_seed: [0; 32],
    }
    .source()
    .unwrap();
    let scalar_constants = 86 * size_of::<Val>() + 3 * size_of::<Vec<Val>>();
    assert_eq!(statement.construction_extra_bytes, 2 * scalar_constants);
    let affine = ComponentKind::Affine {
        kind: AffineKind::Add,
        modulus: Q,
    };
    let (_, source) = OtherNativeDescriptor::Algebra {
        kind: &affine,
        count: 1,
    }
    .source()
    .unwrap();
    assert_eq!(source.construction_extra_bytes, scalar_constants);
    let kind = ComponentKind::Ntt { modulus: QHAT };
    let (g, source) = OtherNativeDescriptor::Algebra {
        kind: &kind,
        count: 32,
    }
    .source()
    .unwrap();
    assert_eq!(
        (g.public_values, g.periodic_columns, g.maximum_period),
        (256, 73, 32768)
    );
    assert_eq!(source.construction_extra_bytes, 768 * 32);
    assert_eq!(source.owned_backing_bytes, 0);
    let linear = signed_map(16);
    let layout = linear.planning_layout().unwrap();
    assert_eq!(
        (layout.height, layout.public_values, layout.periodic_columns),
        (2048, 68, 104)
    );
    let expected =
        16 * size_of::<PolynomialKind>() + 16 * size_of::<[i64; D]>() + 18 * size_of::<u32>();
    assert_eq!(layout.clone_backing_bytes, expected);
    let kind = ComponentKind::LinearMap { descriptor: linear };
    let (_, source) = OtherNativeDescriptor::Algebra {
        kind: &kind,
        count: 1,
    }
    .source()
    .unwrap();
    assert_eq!(source.owned_backing_bytes, expected);
    assert_eq!(source.construction_extra_bytes, 0);
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "serial allocation audit without core stream allocator; coordinator guard required"]
fn geometry_refusal_and_cloned_descriptor_obey_allocation_bounds() {
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    let cases = algebra_cases();
    // Every input, including excessive caller-owned Vec capacity, exists before
    // observation. A derived Vec::clone retains logical lengths, not capacities.
    let kind = PolynomialKind::Canonical { modulus: Q };
    let mut inputs = Vec::with_capacity(1024);
    inputs.push(kind);
    let mut coefficients = Vec::with_capacity(1024);
    coefficients.push([1; D]);
    let large_caller = LinearMapDescriptor::new(inputs, kind, coefficients, [0; D]).unwrap();
    observe_planner_allocations(0, || {
        check_refusal(OtherNativeDescriptor::Statement {
            setup_seed: [0; 32],
        });
        check_refusal(OtherNativeDescriptor::PrivateProof);
        for (kind, count) in &cases {
            let d = OtherNativeDescriptor::Algebra {
                kind,
                count: *count,
            };
            d.geometry().unwrap();
            check_refusal(d);
        }
        let bad = ComponentKind::Ntt { modulus: 17 };
        assert!(OtherNativeDescriptor::Algebra {
            kind: &bad,
            count: 1
        }
        .geometry()
        .is_err());
        large_caller.planning_layout().unwrap();
    });
    let backing = large_caller.planning_layout().unwrap().clone_backing_bytes;
    observe_planner_allocations(4 * backing, || drop(large_caller.clone()));
}

fn reference<A>(air: &A, height: usize) -> (OperationCounts, usize, usize, [u8; 32])
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let template = crate::component_tree::shape_diagnostic::invalid_native_template(air, height);
    let mut builder = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    let public = inputs
        .bases(&mut builder, &vec![Val::ZERO; air.num_public_values()])
        .unwrap();
    uni::verify(&mut builder, &mut inputs, air, height, &public, &template).unwrap();
    let program = builder.finish(None).unwrap();
    let mut digest = Sha3_256::new();
    program
        .visit_manifest_fields(&mut |word| {
            digest.update(word.to_le_bytes());
            Ok(())
        })
        .unwrap();
    (
        OperationCounts::from_program(&program),
        program.wire_count(),
        program.witness_values(),
        digest.finalize().into(),
    )
}

fn qualify<A>(name: &str, descriptor: OtherNativeDescriptor<'_>, air: &A)
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let g = descriptor.geometry().unwrap();
    // All reference objects are destroyed before the bounded planner begins.
    let expected = reference(air, g.height);
    let bound = other_native_core_bound(descriptor, limits(), 512 << 20).unwrap();
    assert_eq!(
        (
            bound.counts.operations,
            bound.counts.wires,
            bound.counts.input_values,
            bound.counts.manifest_sha3_256
        ),
        expected,
        "bounded/reference native core drift: {name}"
    );
    eprintln!("unchanged_native_core kind={name} width={} height={} publics={} periodic={} quotient_chunks={} scalar={} cubic={} poseidon={} active_rows={} padded_rows={} auxiliary_reservation={} planner_requested_peak={} proof_produced=false dispatch_admitted=false",
        g.width, g.height, g.public_values, g.periodic_columns, bound.counts.quotient_chunks,
        expected.0.scalar, expected.0.cubic, expected.0.poseidon,
        expected.0.active_rows(0).unwrap(), expected.0.padded_rows(0).unwrap(),
        bound.storage.auxiliary_peak_bytes, bound.counts.planner_requested_program_bytes_peak);
}

#[test]
#[ignore = "native compiler parity; coordinator serialized production-compatible release guard required"]
fn statement_and_private_cores_match_reference() {
    assert_eq!(
        std::env::var("LATTICA_NATIVE_CORE_SHAPE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    for setup_seed in [[0; 32], [19; 32]] {
        qualify(
            "statement",
            OtherNativeDescriptor::Statement { setup_seed },
            &StatementAir { setup_seed },
        );
    }
    qualify(
        "private-proof",
        OtherNativeDescriptor::PrivateProof,
        &ProofAir,
    );
}

#[test]
#[ignore = "native compiler parity; coordinator serialized production-compatible release guard required"]
fn algebra_cores_match_reference_and_late_refusal_stays_fail_closed() {
    assert_eq!(
        std::env::var("LATTICA_NATIVE_CORE_SHAPE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    for modulus in [Q, QHAT] {
        for kind in [
            AffineKind::Add,
            AffineKind::Sub,
            AffineKind::SignedToCanonical { bound: 565 },
        ] {
            let k = ComponentKind::Affine { kind, modulus };
            qualify(
                "affine64",
                OtherNativeDescriptor::Algebra {
                    kind: &k,
                    count: 64,
                },
                &AffineAir::new(kind, modulus, 64).unwrap(),
            );
        }
        let k = ComponentKind::Ntt { modulus };
        qualify(
            "ntt32",
            OtherNativeDescriptor::Algebra {
                kind: &k,
                count: 32,
            },
            &NttAir::new(modulus, 32).unwrap(),
        );
        let k = ComponentKind::Mul { modulus };
        qualify(
            "multiply32",
            OtherNativeDescriptor::Algebra {
                kind: &k,
                count: 32,
            },
            &MulAir::new(modulus, 32).unwrap(),
        );
    }
    for bound in [6_825_771, 1_137_628] {
        let k = ComponentKind::GBound { bound };
        qualify(
            "g-bound",
            OtherNativeDescriptor::Algebra { kind: &k, count: 1 },
            &GBoundAir::new(bound).unwrap(),
        );
    }
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        let k = ComponentKind::Permutation { kind };
        qualify(
            "permutation",
            OtherNativeDescriptor::Algebra { kind: &k, count: 1 },
            &PermutationAir::new(kind),
        );
    }
    for descriptor in [
        canonical_map(1, Q, 1),
        canonical_map(1, QHAT, 1 << 28),
        canonical_map(16, QHAT, 1),
        signed_map(1),
        signed_map(16),
    ] {
        let air = LinearMapAir::new(descriptor.clone());
        let k = ComponentKind::LinearMap { descriptor };
        qualify(
            "linear-map",
            OtherNativeDescriptor::Algebra { kind: &k, count: 1 },
            &air,
        );
    }
    let k = ComponentKind::Permutation {
        kind: PermutationKind::InverseChallenge,
    };
    let d = OtherNativeDescriptor::Algebra { kind: &k, count: 1 };
    assert!(matches!(
        other_native_core_bound(
            d,
            ConstructionLimits {
                max_input_values: 1,
                ..limits()
            },
            512 << 20
        ),
        Err(CompileError::ResourceAdmission(_))
    ));
    // No result or registration is cached after late refusal.
    qualify(
        "permutation-after-refusal",
        d,
        &PermutationAir::new(PermutationKind::InverseChallenge),
    );
}
