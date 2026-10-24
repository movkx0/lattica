//! Authored source qualification, not executed during the benchmark freeze.
//! Shape fixtures are deliberately invalid; no native or outer proof is created.
use super::*;
use lattica_prover_p3::block_v2::machine::program::MAX_WIRES;
use sha3::{Digest, Sha3_256};

#[test]
fn bounded_group_rejects_each_interior_boundary_mutation_before_compilation() {
    let left = [Val::ZERO; shake_air::PUBLIC_VALUES];
    let right = [Val::ZERO; shake_air::PUBLIC_VALUES];
    check_shake_boundary(&left, &right).unwrap();
    let indices = shake_indices();
    assert_eq!(indices[0].len(), 108);
    assert_eq!(indices[1].len(), 108);
    for (&start, &end) in indices[0].iter().zip(&indices[1]) {
        let mut mutated_left = left;
        mutated_left[end] = Val::ONE;
        assert!(check_shake_boundary(&mutated_left, &right).is_err());
        let mut mutated_right = right;
        mutated_right[start] = Val::ONE;
        assert!(check_shake_boundary(&left, &mutated_right).is_err());
        // Matching values are accepted by this cheap check only. Both native
        // proofs and all recursive equality constraints are still required.
        check_shake_boundary(&mutated_left, &mutated_right).unwrap();
    }
}

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
fn auxiliary() -> usize {
    512 << 20
}

#[test]
fn symbolic_and_auxiliary_footprints_are_separate_and_checked() {
    use ShakeGroupFootprintError::*;
    assert_eq!(
        ShakeGroupCompileFootprint::for_group(0, limits()),
        Err(Empty)
    );
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        assert_eq!(
            ShakeGroupCompileFootprint::for_group(1, limits()),
            Err(UnsupportedProfile)
        );
        return;
    }
    let one = ShakeGroupCompileFootprint::for_group(1, limits()).unwrap();
    let two = ShakeGroupCompileFootprint::for_group(2, limits()).unwrap();
    assert_eq!(two.symbolic.workspace_bytes, 192 << 20);
    assert_eq!(two.symbolic.retained_graph_bytes, 64 << 20);
    assert_eq!(
        two.input_backing_bytes,
        limits().max_input_values * 2 * core::mem::size_of::<Val>()
    );
    assert_eq!(
        two.returned_wire_bytes,
        limits().max_input_values * core::mem::size_of::<Wire>()
    );
    assert!(two.helper_bytes > one.helper_bytes);
    assert!(two.auxiliary_peak_bytes < auxiliary());
    assert_eq!(
        ShakeGroupCompileFootprint::for_group(usize::MAX, limits()),
        Err(Overflow)
    );
    for limits in [
        ConstructionLimits {
            max_input_values: usize::MAX,
            ..limits()
        },
        ConstructionLimits {
            max_requested_program_bytes: usize::MAX,
            ..limits()
        },
    ] {
        assert_eq!(
            ShakeGroupCompileFootprint::for_group(2, limits),
            Err(Overflow)
        );
    }
}
fn context() -> EndpointContext {
    EndpointContext {
        context: [7; 32],
        statement: [Val::from_u64(11); 4],
        input: [Val::from_u64(13); 4],
        output: [Val::from_u64(17); 4],
    }
}
fn counters(failed: bool) -> ConstructionCounters {
    ConstructionCounters {
        wires: 46,
        witnesses: 0,
        operations: 0,
        wire_limit: 1024,
        input_limit: 32,
        requested_bytes_peak: 0,
        resource_failed: failed,
    }
}

#[test]
fn only_typed_resource_errors_with_sticky_admission_allow_refusal() {
    let phase = ShakeGroupCompilePhase::NativeVerifier { member: 1 };
    assert!(matches!(
        shake_group_compile_error(
            verifier::CompileError::ResourceAdmission("fixture"),
            limits(),
            phase,
            counters(true),
        ),
        Ok(ShakeGroupCompileOutcome::ResourceRefused(
            ShakeGroupResourceRefusal {
                phase: ShakeGroupCompilePhase::NativeVerifier { member: 1 },
                ..
            }
        )),
    ));
    for error in [
        verifier::CompileError::Shape("proof input storage allowance"),
        verifier::CompileError::Shape("uni proof shape"),
        verifier::CompileError::Unsupported("relation"),
        verifier::CompileError::Backend("TooLarge".into()),
        verifier::CompileError::Backend("GPU failure".into()),
    ] {
        let expected = err(error.clone());
        match shake_group_compile_error(error, limits(), phase, counters(true)) {
            Err(actual) => assert_eq!(actual, expected),
            _ => panic!("a non-resource compile error became retryable"),
        }
    }
    assert!(shake_group_compile_error(
        verifier::CompileError::ResourceAdmission("fixture"),
        limits(),
        phase,
        counters(false),
    )
    .is_err());
}

#[test]
fn empty_groups_remain_errors_even_with_refusing_limits() {
    let contract = Contract::shake(
        [1; 32],
        3,
        shake_air::Descriptor {
            input_len: 0,
            output_len: 32,
        },
    )
    .unwrap();
    let bounded = ConstructionLimits {
        max_requested_program_bytes: 0,
        ..limits()
    };
    let before = compile_shake_group_with_context(&contract, &[], &context(), None);
    let after =
        compile_shake_group_bounded_with_context(&contract, &[], &context(), None, bounded, 0);
    match (before, after) {
        (Err(before), Err(after)) => assert_eq!(before, after),
        _ => panic!("empty group shape failure was hidden by resource refusal"),
    }
}

fn admitted() {
    assert_eq!(
        std::env::var("LATTICA_BOUNDED_SHAKE_QUALIFICATION").as_deref(),
        Ok("1"),
        "explicit serialized process-guarded shape qualification required"
    );
}
fn fixture(input_len: usize) -> (Contract, Vec<shake_air::lane::LaneShakeProof>) {
    let descriptor = shake_air::Descriptor {
        input_len,
        output_len: 32,
    };
    let contract = Contract::shake([1; 32], 3, descriptor).unwrap();
    let proofs = (0..contract.total)
        .map(|first| {
            let air = shake_air::lane::LaneShakeAir::new(descriptor, first as usize).unwrap();
            shake_air::lane::LaneShakeProof {
                public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
                proof: shape_diagnostic::invalid_native_template(&air, shake_air::lane::HEIGHT),
            }
        })
        .collect();
    (contract, proofs)
}
fn members(proofs: &[shake_air::lane::LaneShakeProof]) -> Vec<ShakeGroupMember<'_>> {
    proofs
        .iter()
        .enumerate()
        .map(|(first, proof)| ShakeGroupMember {
            first: first as u32,
            count: 1,
            proof,
        })
        .collect()
}
fn program_digest(program: &Program) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    program
        .visit_manifest_fields(&mut |word| {
            digest.update(word.to_le_bytes());
            Ok(())
        })
        .unwrap();
    digest.finalize().into()
}
fn values_digest(values: &[Val]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    for value in values {
        digest.update(value.as_canonical_u64().to_le_bytes());
    }
    digest.finalize().into()
}

#[test]
#[ignore = "compile-only invalid templates; requires serialized post-freeze process admission"]
fn bounded_group_one_and_two_preserve_program_identity_and_input_order() {
    admitted();
    // Exact manifest/input parity across absorption, padding, squeezing, and
    // homogeneous 8-permutation native segments. These remain invalid shape
    // templates: no proof acceptance or recursive closure is inferred.
    for (input_len, output_len, intervals) in [
        (0, 32, vec![(0, 1)]),
        (137, 32, vec![(0, 1), (1, 1)]),
        (0, 2 * shake_air::RATE + 7, vec![(0, 1), (1, 1)]),
        (8 * shake_air::RATE + 7, 32, vec![(0, 8), (8, 1)]),
        (0, 10 * shake_air::RATE, vec![(1, 8), (9, 1)]),
    ] {
        let descriptor = shake_air::Descriptor {
            input_len,
            output_len,
        };
        let contract = Contract::shake([1; 32], 3, descriptor).unwrap();
        let airs: Vec<_> = intervals
            .iter()
            .map(|&(first, count)| {
                use shake_air::lane::batch::{BatchShakeAir, ShakeSegmentAir};
                if count == 1 {
                    ShakeSegmentAir::Single(
                        shake_air::lane::LaneShakeAir::new(descriptor, first).unwrap(),
                    )
                } else {
                    ShakeSegmentAir::Batch(
                        BatchShakeAir::full_absorb(descriptor, first, count)
                            .or_else(|_| BatchShakeAir::full_squeeze(descriptor, first, count))
                            .unwrap(),
                    )
                }
            })
            .collect();
        let proofs: Vec<_> = airs
            .iter()
            .map(|air| shake_air::lane::LaneShakeProof {
                public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
                proof: shape_diagnostic::invalid_native_template(air, air.height()),
            })
            .collect();
        let members: Vec<_> = intervals
            .iter()
            .zip(&proofs)
            .map(|(&(first, count), proof)| ShakeGroupMember {
                first: first as u32,
                count: count as u32,
                proof,
            })
            .collect();
        let old = compile_shake_group_with_context(&contract, &members, &context(), None).unwrap();
        let identity = program_digest(&old.program);
        let witness = values_digest(&old.witness);
        let public = old.public.clone();
        let spec = old.spec.clone();
        let shape = (
            old.program.height(),
            old.program.wire_count(),
            old.program.witness_values(),
        );
        drop(old); // Do not retain two large compiled wrapper programs together.
        let bounded = match compile_shake_group_bounded_with_context(
            &contract,
            &members,
            &context(),
            None,
            limits(),
            auxiliary(),
        )
        .unwrap()
        {
            ShakeGroupCompileOutcome::Compiled(node) => node,
            ShakeGroupCompileOutcome::ResourceRefused(_) => {
                panic!("shape qualification allowance refused")
            }
        };
        assert_eq!(program_digest(&bounded.program), identity);
        assert_eq!(values_digest(&bounded.witness), witness);
        assert_eq!(bounded.public, public);
        assert_eq!(bounded.spec, spec);
        assert_eq!(
            (
                bounded.program.height(),
                bounded.program.wire_count(),
                bounded.program.witness_values()
            ),
            shape
        );
        eprintln!("bounded_shake_parity input_len={input_len} output_len={output_len} intervals={intervals:?} height={} wires={} inputs={} matched=true", shape.0, shape.1, shape.2);
        for boundary in shake_indices() {
            assert_eq!(boundary.len(), 108);
        }
        // No evaluate/prepare/register/prove: matching invalid-template circuit
        // identity is construction evidence, never proof acceptance or closure.
    }
}

#[test]
#[ignore = "compile-only invalid templates; requires serialized post-freeze process admission"]
fn wrapper_resource_refusals_do_not_hide_member_or_proof_shape_errors() {
    admitted();
    let (contract, mut proofs) = fixture(137);
    {
        let members = members(&proofs);
        for (bounded, phase) in [
            (
                ConstructionLimits {
                    max_requested_program_bytes: 0,
                    ..limits()
                },
                ShakeGroupCompilePhase::Initialize,
            ),
            (
                ConstructionLimits {
                    max_input_values: 0,
                    ..limits()
                },
                ShakeGroupCompilePhase::Inputs { member: 0 },
            ),
            (
                ConstructionLimits {
                    max_requested_program_bytes: 1,
                    ..limits()
                },
                ShakeGroupCompilePhase::Inputs { member: 0 },
            ),
        ] {
            match compile_shake_group_bounded_with_context(
                &contract,
                &members,
                &context(),
                None,
                bounded,
                auxiliary(),
            )
            .unwrap()
            {
                ShakeGroupCompileOutcome::ResourceRefused(refusal) => {
                    assert_eq!(refusal.phase, phase)
                }
                _ => panic!("bounded compile did not return typed admission refusal"),
            }
        }
        let duplicated = [
            ShakeGroupMember {
                first: 0,
                count: 1,
                proof: &proofs[0],
            },
            ShakeGroupMember {
                first: 0,
                count: 1,
                proof: &proofs[1],
            },
        ];
        assert!(compile_shake_group_bounded_with_context(
            &contract,
            &duplicated,
            &context(),
            None,
            ConstructionLimits {
                max_requested_program_bytes: 0,
                ..limits()
            },
            auxiliary(),
        )
        .is_err());
    }
    proofs[0].proof.degree_bits = 0;
    assert!(compile_shake_group_bounded_with_context(
        &contract,
        &members(&proofs),
        &context(),
        None,
        limits(),
        auxiliary(),
    )
    .is_err());
}

#[test]
fn auxiliary_refusal_happens_before_compiler_and_endpoint_session() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let (contract, proofs) = fixture(0);
    let members = members(&proofs);
    let needed = ShakeGroupCompileFootprint::for_group(1, limits())
        .unwrap()
        .auxiliary_peak_bytes;
    for allowance in [0, needed - 1] {
        match compile_shake_group_bounded_with_context(
            &contract,
            &members,
            &context(),
            None,
            limits(),
            allowance,
        )
        .unwrap()
        {
            ShakeGroupCompileOutcome::ResourceRefused(refusal) => {
                assert_eq!(refusal.phase, ShakeGroupCompilePhase::AuxiliaryAdmission);
                assert_eq!(refusal.counters, None);
            }
            _ => panic!("auxiliary reservation was not enforced"),
        }
    }
}
