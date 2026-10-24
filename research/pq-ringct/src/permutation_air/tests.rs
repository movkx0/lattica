use super::*;
use crate::rust_verify::constraints_ntt::{commit_signed_values, commit_values};
use p3_air::check_all_constraints;
fn accepts(air: &PermutationAir, witness: &PermutationWitness) -> bool {
    check_all_constraints(air, &witness.trace, &witness.public_values, Some(4))
        .failures
        .is_empty()
}
fn fixture(kind: PermutationKind) -> PermutationInput {
    match kind {
        PermutationKind::AutomorphismQ => PermutationInput::Canonical(core::array::from_fn(|i| {
            if i % 5 == 0 {
                Q - 1
            } else {
                i as u64 * 7919
            }
        })),
        PermutationKind::InverseChallenge => {
            PermutationInput::Signed(core::array::from_fn(|i| (i % 3) as i64 - 1))
        }
    }
}
fn root(input: &PermutationInput) -> [Val; 4] {
    match input {
        PermutationInput::Canonical(values) => commit_values(POLYNOMIAL_DOMAIN, Q, values),
        PermutationInput::Signed(values) => commit_signed_values(values),
    }
}
#[test]
fn fixed_permutations_match_native_and_universal_roots() {
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        let air = PermutationAir::new(kind);
        let input = fixture(kind);
        let witness = air.generate(&input).unwrap();
        assert!(accepts(&air, &witness), "kind={kind:?}");
        assert_eq!(&witness.public_values[..4], &root(&input));
        assert_eq!(&witness.public_values[4..], &root(&witness.output));
        let mut indices: Vec<_> = (0..D).map(|i| air.source_index(i)).collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..D).collect::<Vec<_>>());
    }
}
#[test]
fn fixed_permutations_reject_bank_range_scale_and_root_mutations() {
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        let air = PermutationAir::new(kind);
        let mut witness = air.generate(&fixture(kind)).unwrap();
        let mut mutations = vec![
            (0, BANK),
            (80, BANK + 201),
            (255, BANK + 9),
            (7, READ + 1),
            (64, air.range(0)),
            (64, air.range(1) + 1),
            (64, SIGN),
            (128, ACC + 4),
            (0, ACC),
            (0, air.poseidon()),
            (127, air.poseidon() + 5),
        ];
        if kind == PermutationKind::AutomorphismQ {
            mutations.push((64, air.quotient(1)));
        }
        for (row, column) in mutations {
            let index = row * air.width() + column;
            witness.trace.values[index] += Val::ONE;
            assert!(
                !accepts(&air, &witness),
                "kind={kind:?} row={row} column={column}"
            );
            witness.trace.values[index] -= Val::ONE;
        }
        for index in 0..PUBLIC_VALUES {
            witness.public_values[index] += Val::ONE;
            assert!(!accepts(&air, &witness));
            witness.public_values[index] -= Val::ONE;
        }
    }
}
#[test]
fn fixed_permutation_shapes_and_bounds_fail_closed() {
    let canonical = PermutationAir::new(PermutationKind::AutomorphismQ);
    let challenge = PermutationAir::new(PermutationKind::InverseChallenge);
    assert!(canonical
        .generate(&PermutationInput::Canonical([Q; D]))
        .is_err());
    assert!(challenge
        .generate(&PermutationInput::Signed([-2; D]))
        .is_err());
    assert!(canonical
        .generate(&fixture(PermutationKind::InverseChallenge))
        .is_err());
    assert!(challenge
        .generate(&fixture(PermutationKind::AutomorphismQ))
        .is_err());
}
#[test]
#[ignore = "actual permutation child proofs and typed recursive traces; memory-coordinated release run"]
fn fixed_permutation_actual_proofs_and_typed_joins() {
    use lattica_prover_p3::block_v2::machine::{verifier::ProofInputs, MachineAir, ProgramBuilder};
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        let registration = RegisteredPermutationAir::new(kind);
        let input = fixture(kind);
        let witness = registration.air().generate(&input).unwrap();
        let started = std::time::Instant::now();
        let mut artifact = registration.prove(&input).unwrap();
        eprintln!(
            "permutation child kind={kind:?} height={HEIGHT} width={} elapsed_ms={}",
            registration.air().width(),
            started.elapsed().as_millis()
        );
        let mut builder = ProgramBuilder::new(0).unwrap();
        let request = PendingPermutation {
            kind,
            input_commitment: root(&input).map(|value| builder.constant(value)),
            output_commitment: root(&witness.output).map(|value| builder.constant(value)),
        };
        let mut inputs = ProofInputs::default();
        let mut wrong = request.clone();
        wrong.kind = if kind == PermutationKind::AutomorphismQ {
            PermutationKind::InverseChallenge
        } else {
            PermutationKind::AutomorphismQ
        };
        assert!(registration
            .compile_join(&mut builder, &mut inputs, &wrong, &artifact)
            .is_err());
        registration
            .compile_join(&mut builder, &mut inputs, &request, &artifact)
            .unwrap();
        let machine = MachineAir::new(builder.finish(None).unwrap());
        machine.trace(&[], &inputs.values).unwrap();
        eprintln!(
            "permutation typed join kind={kind:?} wires={} active_rows={} height={}",
            machine.program().wire_count(),
            machine.program().active_rows(),
            machine.program().height()
        );
        for index in [0, 7, inputs.values.len() / 2, inputs.values.len() - 1] {
            inputs.values[index] += Val::ONE;
            assert!(machine.trace(&[], &inputs.values).is_err());
            inputs.values[index] -= Val::ONE;
        }
        artifact.public_values[4] += Val::ONE;
        assert!(registration.verify(&artifact).is_err());
        artifact.public_values[4] -= Val::ONE;
        artifact.proof.opened_values.trace_local[0] +=
            lattica_prover_p3::block_v2::profile::Challenge::ONE;
        assert!(registration.verify(&artifact).is_err());
    }
}
