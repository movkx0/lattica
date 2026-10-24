use super::*;
use p3_air::check_all_constraints;

fn accepts(air: &AffineAir, witness: &AffineWitness) -> bool {
    check_all_constraints(air, &witness.trace, &witness.public_values, Some(4))
        .failures
        .is_empty()
}
fn binary(q: u64) -> AffineInput {
    AffineInput::Binary {
        left: core::array::from_fn(|i| {
            if i % 3 == 0 {
                q - 1
            } else {
                (i as u64 * 104729) % q
            }
        }),
        right: core::array::from_fn(|i| {
            if i % 5 == 0 {
                q - 1
            } else {
                (i as u64 * 7919) % q
            }
        }),
    }
}
fn signed(bound: u32) -> AffineInput {
    AffineInput::Signed(core::array::from_fn(|i| match i % 5 {
        0 => -i64::from(bound),
        1 => i64::from(bound),
        2 => 0,
        3 => -1,
        _ => 1,
    }))
}

#[test]
fn affine_both_moduli_operations_and_batched_roots_are_constrained() {
    for q in [Q, QHAT] {
        for kind in [
            AffineKind::Add,
            AffineKind::Sub,
            AffineKind::SignedToCanonical { bound: 1 },
            AffineKind::SignedToCanonical { bound: 38346 },
            AffineKind::SignedToCanonical { bound: 6212586 },
        ] {
            let air = AffineAir::new(kind, q, 2).unwrap();
            let first = if kind.is_conversion() {
                signed(kind.bound())
            } else {
                binary(q)
            };
            let second = if kind.is_conversion() {
                AffineInput::Signed([0; D])
            } else {
                AffineInput::Binary {
                    left: [0; D],
                    right: [q - 1; D],
                }
            };
            let witness = air.generate(&[first.clone(), second]).unwrap();
            assert!(accepts(&air, &witness), "kind={kind:?} q={q}");
            assert_eq!(
                witness.public_values,
                air.bundle_roots(&witness.roots).unwrap()
            );
            let mut reversed = witness.roots.clone();
            reversed.reverse();
            assert_ne!(witness.public_values, air.bundle_roots(&reversed).unwrap());
            assert_eq!(air.height(), 1024);
            assert!(air.width() < 500);
            assert!(air.metadata().iter().all(|column| column.len() == 512));
            if let AffineInput::Signed(signed) = first {
                for (i, value) in signed.into_iter().enumerate() {
                    assert_eq!(
                        witness.output[0][i],
                        if value < 0 {
                            q - value.unsigned_abs()
                        } else {
                            value as u64
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn affine_rejects_range_arithmetic_reset_bundle_and_root_mutations() {
    for kind in [
        AffineKind::Add,
        AffineKind::Sub,
        AffineKind::SignedToCanonical { bound: 38346 },
    ] {
        let air = AffineAir::new(kind, QHAT, 2).unwrap();
        let input = if kind.is_conversion() {
            signed(kind.bound())
        } else {
            binary(QHAT)
        };
        let mut witness = air.generate(&[input.clone(), input]).unwrap();
        assert!(accepts(&air, &witness));
        let mut changes = vec![
            (0, LEFT),
            (1, RIGHT),
            (1, LEFT),
            (2, air.range(0)),
            (2, air.range(0) + 1),
            (2, air.range(0) + 1 + air.bits()),
            (2, CARRY),
            (2, SIGN),
            (256, ACC),
            (258, BUNDLE),
            (511, ACC),
            (512, ACC),
            (700, BUNDLE),
            (0, air.poseidon()),
            (258, air.poseidon() + 4),
        ];
        if kind.is_conversion() {
            changes.extend([(0, air.magnitude(0)), (0, air.magnitude(0) + 1), (0, SIGN)]);
        }
        for (row, column) in changes {
            let index = row * air.width() + column;
            witness.trace.values[index] += Val::ONE;
            assert!(
                !accepts(&air, &witness),
                "unbound {kind:?} row={row} column={column}"
            );
            witness.trace.values[index] -= Val::ONE;
        }
        for lane in 0..4 {
            witness.public_values[lane] += Val::ONE;
            assert!(!accepts(&air, &witness));
            witness.public_values[lane] -= Val::ONE;
        }
    }
}

#[test]
fn affine_descriptor_input_and_signed_bounds_fail_closed() {
    for count in [0, 3, 129, usize::MAX] {
        assert!(AffineAir::new(AffineKind::Add, Q, count).is_err());
    }
    assert!(AffineAir::new(AffineKind::Add, Q + 1, 1).is_err());
    for bound in [0, Q as u32, u32::MAX] {
        assert!(AffineAir::new(AffineKind::SignedToCanonical { bound }, Q, 1).is_err());
    }
    let conversion = AffineAir::new(AffineKind::SignedToCanonical { bound: 1 }, Q, 1).unwrap();
    assert!(conversion
        .generate(&[AffineInput::Signed([-2; D])])
        .is_err());
    assert!(conversion.generate(&[binary(Q)]).is_err());
    assert!(conversion.generate(&[]).is_err());
    let addition = AffineAir::new(AffineKind::Add, Q, 1).unwrap();
    assert!(addition
        .generate(&[AffineInput::Binary {
            left: [Q; D],
            right: [0; D]
        }])
        .is_err());
    assert!(addition.generate(&[signed(1)]).is_err());
}

#[test]
#[ignore = "actual component STARKs and typed recursive traces; run release with memory guard"]
fn affine_actual_proofs_and_typed_recursive_joins() {
    use lattica_prover_p3::block_v2::machine::{
        program::ScopedProgramBuilder, verifier::ProofInputs, MachineAir, ProgramBuilder,
    };
    fn request(
        b: &mut ScopedProgramBuilder<'_>,
        registration: &RegisteredAffineAir,
        roots: &AffineRoots,
    ) -> PendingAffine {
        PendingAffine {
            kind: registration.air().kind(),
            modulus: registration.air().modulus(),
            left_commitment: roots.left.map(|v| b.constant(v)),
            right_commitment: roots.right.map(|r| r.map(|v| b.constant(v))),
            output_commitment: roots.output.map(|v| b.constant(v)),
        }
    }
    for kind in [
        AffineKind::Add,
        AffineKind::Sub,
        AffineKind::SignedToCanonical { bound: 6212586 },
    ] {
        let registration = RegisteredAffineAir::new(kind, QHAT, 2).unwrap();
        let first = if kind.is_conversion() {
            signed(kind.bound())
        } else {
            binary(QHAT)
        };
        let second = if kind.is_conversion() {
            AffineInput::Signed([0; D])
        } else {
            AffineInput::Binary {
                left: [0; D],
                right: [QHAT - 1; D],
            }
        };
        let roots = registration
            .air()
            .generate(&[first.clone(), second.clone()])
            .unwrap()
            .roots;
        let started = std::time::Instant::now();
        let mut artifact = registration.prove(&[first, second]).unwrap();
        eprintln!(
            "affine actual proof kind={kind:?} count=2 height={} width={} elapsed_ms={}",
            registration.air().height(),
            registration.air().width(),
            started.elapsed().as_millis()
        );
        let mut b = ProgramBuilder::new(0).unwrap();
        let requests: Vec<_> = roots
            .iter()
            .map(|roots| request(&mut b, &registration, roots))
            .collect();
        let mut inputs = ProofInputs::default();
        assert!(registration
            .compile_join(&mut b, &mut inputs, &requests[..1], &artifact)
            .is_err());
        let mut wrong_kind = requests.clone();
        wrong_kind[0].kind = if kind == AffineKind::Add {
            AffineKind::Sub
        } else {
            AffineKind::Add
        };
        assert!(registration
            .compile_join(&mut b, &mut inputs, &wrong_kind, &artifact)
            .is_err());
        registration
            .compile_join(&mut b, &mut inputs, &requests, &artifact)
            .unwrap();
        let machine = MachineAir::new(b.finish(None).unwrap());
        machine.trace(&[], &inputs.values).unwrap();
        eprintln!(
            "affine typed join kind={kind:?} wires={} active_rows={} height={}",
            machine.program().wire_count(),
            machine.program().active_rows(),
            machine.program().height()
        );
        for index in [0, inputs.values.len() / 2, inputs.values.len() - 1] {
            inputs.values[index] += Val::ONE;
            assert!(machine.trace(&[], &inputs.values).is_err());
            inputs.values[index] -= Val::ONE;
        }
        let mut b = ProgramBuilder::new(0).unwrap();
        let mut swapped: Vec<_> = roots
            .iter()
            .rev()
            .map(|roots| request(&mut b, &registration, roots))
            .collect();
        let mut wrong_inputs = ProofInputs::default();
        registration
            .compile_join(&mut b, &mut wrong_inputs, &swapped, &artifact)
            .unwrap();
        assert!(MachineAir::new(b.finish(None).unwrap())
            .trace(&[], &wrong_inputs.values)
            .is_err());
        swapped.clear();
        artifact.public_values[0] += Val::ONE;
        assert!(registration.verify(&artifact).is_err());
        artifact.public_values[0] -= Val::ONE;
        artifact.proof.opened_values.trace_local[0] +=
            lattica_prover_p3::block_v2::profile::Challenge::ONE;
        assert!(registration.verify(&artifact).is_err());
    }
}
