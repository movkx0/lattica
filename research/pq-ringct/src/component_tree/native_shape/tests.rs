use super::*;
use lattica_prover_p3::block_v2::machine::{
    program::ProgramBuilder,
    verifier::{batch::shape::OperationCounts, ProofInputs},
};
use p3_air::symbolic::SymbolicAirBuilder;
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}

#[test]
fn descriptor_geometry_is_exact_before_owned_construction() {
    for parts in [
        vec![PartKind::Bytes32],
        vec![
            PartKind::Bytes32,
            PartKind::PolynomialQ,
            PartKind::PolynomialQhat,
        ],
        vec![PartKind::PolynomialQ; 256],
    ] {
        let g = NativeDescriptor::Transcript(&parts).geometry().unwrap();
        let air = TranscriptAir::new(parts).unwrap();
        assert_eq!(g.width, air.width());
        assert_eq!(g.height, air.height());
        assert_eq!(g.periodic_columns, air.num_periodic_columns());
    }
    for kind in [
        sparse_air::Kind::AlphaPrime39,
        sparse_air::Kind::ChallengeX44,
    ] {
        let g = NativeDescriptor::Sparse(kind).geometry().unwrap();
        let air = SparseAir::new(kind);
        assert_eq!(g.width, air.width());
        assert_eq!(g.periodic_columns, air.num_periodic_columns());
    }
    assert!(NativeDescriptor::Transcript(&[]).geometry().is_err());
    assert!(NativeDescriptor::Transcript(&[PartKind::Bytes32; 257])
        .geometry()
        .is_err());
    assert!(NativeDescriptor::Shake {
        descriptor: shake_air::Descriptor {
            input_len: 1,
            output_len: 1
        },
        first: 0,
        count: 3
    }
    .geometry()
    .is_err());
}

#[test]
fn source_storage_preflight_refuses_before_native_compilation() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let descriptor = NativeDescriptor::Transcript(&[PartKind::Bytes32]);
    let storage = NativePlanningStorage::for_descriptor(descriptor, limits()).unwrap();
    assert!(storage.auxiliary_peak_bytes < 512 << 20);
    assert_eq!(
        native_core_bound(descriptor, limits(), storage.auxiliary_peak_bytes - 1),
        Err(CompileError::ResourceAdmission(
            "native planner auxiliary allowance"
        ))
    );
    assert!(NativePlanningStorage::for_descriptor(
        descriptor,
        ConstructionLimits {
            max_requested_program_bytes: usize::MAX,
            ..limits()
        }
    )
    .is_err());
    assert!(NativePlanningStorage::for_descriptor(
        descriptor,
        ConstructionLimits {
            max_input_values: usize::MAX,
            ..limits()
        }
    )
    .is_err());
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

fn qualify<A>(name: &str, descriptor: NativeDescriptor<'_>, air: &A, height: usize)
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    // Reference objects are fully dropped before the bounded planner begins.
    let expected = reference(air, height);
    let bound = native_core_bound(descriptor, limits(), 512 << 20).unwrap();
    assert_eq!(
        (
            bound.counts.operations,
            bound.counts.wires,
            bound.counts.input_values,
            bound.counts.manifest_sha3_256
        ),
        expected,
        "native core bounded/reference primitive or input geometry drift: {name}"
    );
    eprintln!("native_core_shape kind={name} width={} height={} publics={} quotient_chunks={} scalar={} cubic={} poseidon={} active_rows={} padded_rows={} auxiliary_reservation={} planner_requested_peak={} proof_produced=false ownership_admitted=false",
        bound.storage.geometry.width, height, air.num_public_values(), bound.counts.quotient_chunks,
        expected.0.scalar, expected.0.cubic, expected.0.poseidon,
        expected.0.active_rows(0).unwrap(), expected.0.padded_rows(0).unwrap(),
        bound.storage.auxiliary_peak_bytes, bound.counts.planner_requested_program_bytes_peak);
}

#[test]
#[ignore = "bounded native-core source qualification; coordinator serialized release guard required"]
fn exact_native_cores_match_reference_and_late_refusal_releases_state() {
    assert!(cfg!(all(not(debug_assertions), target_arch = "x86_64")));
    assert_eq!(
        std::env::var("LATTICA_NATIVE_CORE_SHAPE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    for (name, input_len, output_len, first, count) in [
        ("shake-batch-absorb", 136 * 9 + 1, 32, 0, 8),
        ("shake-padding", 136 * 2, 32, 2, 1),
        ("shake-partial-squeeze", 1, 137, 1, 1),
        ("shake-batch-squeeze", 1, 136 * 10, 1, 8),
    ] {
        let d = NativeDescriptor::Shake {
            descriptor: shake_air::Descriptor {
                input_len,
                output_len,
            },
            first,
            count,
        };
        let air = d.shake().unwrap();
        qualify(name, d, &air, air.height());
    }
    let parts = [
        PartKind::Bytes32,
        PartKind::PolynomialQ,
        PartKind::PolynomialQhat,
    ];
    let air = TranscriptAir::new(parts.to_vec()).unwrap();
    qualify(
        "transcript-mixed",
        NativeDescriptor::Transcript(&parts),
        &air,
        air.height(),
    );
    let all_parts: Vec<_> = (0..256).map(|i| parts[i % parts.len()]).collect();
    let air = TranscriptAir::new(all_parts.clone()).unwrap();
    qualify(
        "transcript-maximum-events",
        NativeDescriptor::Transcript(&all_parts),
        &air,
        air.height(),
    );
    for (name, kind) in [
        ("sparse-alpha39", sparse_air::Kind::AlphaPrime39),
        ("sparse-x44", sparse_air::Kind::ChallengeX44),
    ] {
        qualify(
            name,
            NativeDescriptor::Sparse(kind),
            &SparseAir::new(kind),
            sparse_air::HEIGHT,
        );
    }
    let d = NativeDescriptor::Sparse(sparse_air::Kind::ChallengeX44);
    assert!(matches!(
        native_core_bound(
            d,
            ConstructionLimits {
                max_input_values: 1,
                ..limits()
            },
            512 << 20
        ),
        Err(CompileError::ResourceAdmission(_))
    ));
    assert!(native_core_bound(d, limits(), 512 << 20).is_ok());
}
