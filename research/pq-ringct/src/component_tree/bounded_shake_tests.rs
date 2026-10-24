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
fn context() -> EndpointContext {
    EndpointContext {
        context: [7; 32], statement: [Val::from_u64(11); 4],
        input: [Val::from_u64(13); 4], output: [Val::from_u64(17); 4],
    }
}
fn counters(failed: bool) -> ConstructionCounters {
    ConstructionCounters {
        wires: 46, witnesses: 0, operations: 0, wire_limit: 1024,
        input_limit: 32, requested_bytes_peak: 0, resource_failed: failed,
    }
}

#[test]
fn only_typed_resource_errors_with_sticky_admission_allow_refusal() {
    let phase = ShakeGroupCompilePhase::NativeVerifier { member: 1 };
    assert!(matches!(
        shake_group_compile_error(
            verifier::CompileError::ResourceAdmission("fixture"), limits(), phase, counters(true),
        ),
        Ok(ShakeGroupCompileOutcome::ResourceRefused(ShakeGroupResourceRefusal {
            phase: ShakeGroupCompilePhase::NativeVerifier { member: 1 }, ..
        })),
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
        verifier::CompileError::ResourceAdmission("fixture"), limits(), phase, counters(false),
    ).is_err());
}

#[test]
fn empty_groups_remain_errors_even_with_refusing_limits() {
    let contract = Contract::shake([1; 32], 3, shake_air::Descriptor { input_len: 0, output_len: 32 }).unwrap();
    let bounded = ConstructionLimits { max_requested_program_bytes: 0, ..limits() };
    let before = compile_shake_group_with_context(&contract, &[], &context(), None);
    let after = compile_shake_group_bounded_with_context(&contract, &[], &context(), None, bounded);
    match (before, after) {
        (Err(before), Err(after)) => assert_eq!(before, after),
        _ => panic!("empty group shape failure was hidden by resource refusal"),
    }
}

fn admitted() {
    assert_eq!(std::env::var("LATTICA_BOUNDED_SHAKE_QUALIFICATION").as_deref(), Ok("1"),
        "explicit serialized process-guarded shape qualification required");
}
fn fixture(input_len: usize) -> (Contract, Vec<shake_air::lane::LaneShakeProof>) {
    let descriptor = shake_air::Descriptor { input_len, output_len: 32 };
    let contract = Contract::shake([1; 32], 3, descriptor).unwrap();
    let proofs = (0..contract.total).map(|first| {
        let air = shake_air::lane::LaneShakeAir::new(descriptor, first as usize).unwrap();
        shake_air::lane::LaneShakeProof {
            public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
            proof: shape_diagnostic::invalid_native_template(&air, shake_air::lane::HEIGHT),
        }
    }).collect();
    (contract, proofs)
}
fn members(proofs: &[shake_air::lane::LaneShakeProof]) -> Vec<ShakeGroupMember<'_>> {
    proofs.iter().enumerate().map(|(first, proof)| ShakeGroupMember { first: first as u32, count: 1, proof }).collect()
}
fn program_digest(program: &Program) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    program.visit_manifest_fields(&mut |word| { digest.update(word.to_le_bytes()); Ok(()) }).unwrap();
    digest.finalize().into()
}
fn values_digest(values: &[Val]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    for value in values { digest.update(value.as_canonical_u64().to_le_bytes()); }
    digest.finalize().into()
}

#[test]
#[ignore = "compile-only invalid templates; requires serialized post-freeze process admission"]
fn bounded_group_one_and_two_preserve_program_identity_and_input_order() {
    admitted();
    // Group two crosses full-absorb/final-padding AIR phases while preserving
    // their original separate native verifiers and all 108 boundary equalities.
    for input_len in [0, 137] {
        let (contract, proofs) = fixture(input_len);
        let members = members(&proofs);
        let old = compile_shake_group_with_context(&contract, &members, &context(), None).unwrap();
        let identity = program_digest(&old.program);
        let witness = values_digest(&old.witness);
        let public = old.public.clone();
        let spec = old.spec.clone();
        let shape = (old.program.height(), old.program.wire_count(), old.program.witness_values());
        drop(old); // Do not retain two large compiled wrapper programs together.
        let bounded = match compile_shake_group_bounded_with_context(
            &contract, &members, &context(), None, limits(),
        ).unwrap() {
            ShakeGroupCompileOutcome::Compiled(node) => node,
            ShakeGroupCompileOutcome::ResourceRefused(_) => panic!("shape qualification allowance refused"),
        };
        assert_eq!(program_digest(&bounded.program), identity);
        assert_eq!(values_digest(&bounded.witness), witness);
        assert_eq!(bounded.public, public);
        assert_eq!(bounded.spec, spec);
        assert_eq!((bounded.program.height(), bounded.program.wire_count(), bounded.program.witness_values()), shape);
        for boundary in shake_indices() { assert_eq!(boundary.len(), 108); }
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
            (ConstructionLimits { max_requested_program_bytes: 0, ..limits() }, ShakeGroupCompilePhase::Initialize),
            (ConstructionLimits { max_input_values: 0, ..limits() }, ShakeGroupCompilePhase::Inputs { member: 0 }),
            (ConstructionLimits { max_requested_program_bytes: 1, ..limits() }, ShakeGroupCompilePhase::Inputs { member: 0 }),
        ] {
            match compile_shake_group_bounded_with_context(&contract, &members, &context(), None, bounded).unwrap() {
                ShakeGroupCompileOutcome::ResourceRefused(refusal) => assert_eq!(refusal.phase, phase),
                _ => panic!("bounded compile did not return typed admission refusal"),
            }
        }
        let duplicated = [
            ShakeGroupMember { first: 0, count: 1, proof: &proofs[0] },
            ShakeGroupMember { first: 0, count: 1, proof: &proofs[1] },
        ];
        assert!(compile_shake_group_bounded_with_context(
            &contract, &duplicated, &context(), None,
            ConstructionLimits { max_requested_program_bytes: 0, ..limits() },
        ).is_err());
    }
    proofs[0].proof.degree_bits = 0;
    assert!(compile_shake_group_bounded_with_context(
        &contract, &members(&proofs), &context(), None, limits(),
    ).is_err());
}
