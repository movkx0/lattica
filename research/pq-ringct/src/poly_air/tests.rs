use super::*;
use crate::rust_verify::constraints_ntt::commit_values;
use p3_air::check_all_constraints;
fn accepts(air: &MulAir, witness: &MulWitness) -> bool {
    check_all_constraints(air, &witness.trace, &witness.public_values, Some(4))
        .failures
        .is_empty()
}
#[test]
fn serial_ring_products_match_native_both_moduli_and_shared_roots() {
    for q in [Q, QHAT] {
        let left = [
            core::array::from_fn(|i| {
                if i % 3 == 0 {
                    q - 1
                } else {
                    (i as u64 * 7919) % q
                }
            }),
            [0; D],
        ];
        let right = [
            core::array::from_fn(|i| {
                if i % 5 == 0 {
                    q - 1
                } else {
                    (i as u64 * 104729) % q
                }
            }),
            [q - 1; D],
        ];
        let air = MulAir::new(q, 2).unwrap();
        let witness = air.generate(&left, &right).unwrap();
        assert!(accepts(&air, &witness));
        for polynomial in 0..2 {
            assert_eq!(
                witness.output[polynomial],
                arithmetic::mul(&left[polynomial], &right[polynomial], q)
            );
            for (which, values) in [
                &left[polynomial],
                &right[polynomial],
                &witness.output[polynomial],
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    &witness.public_values
                        [12 * polynomial + 4 * which..12 * polynomial + 4 * which + 4],
                    &commit_values(POLYNOMIAL_DOMAIN, q, values)
                );
            }
        }
        assert!(air.width() < 330);
        assert_eq!(air.height, 4096);
    }
}
#[test]
fn serial_ring_product_rejects_operand_arithmetic_reset_and_commitment_mutations() {
    let air = MulAir::new(QHAT, 1).unwrap();
    let input = core::array::from_fn(|i| {
        if i % 2 == 0 {
            QHAT - 1
        } else {
            i as u64 * 34567
        }
    });
    let mut witness = air.generate(&[input], &[input]).unwrap();
    assert!(accepts(&air, &witness));
    for (row, column) in [
        (0, LEFT),
        (1, RIGHT + 1),
        (2, STATE),
        (2, READS),
        (2, air.range(0)),
        (2, air.range(1)),
        (2, air.range(2)),
        (2, air.range(3)),
        (2, air.range(4)),
        (2, air.range(3) + 1),
        (2, air.range(4) + 1 + air.bits()),
        (2, air.carry()),
        (3, STATE),
        (18, STATE),
        (19, STATE),
        (19, air.acc()),
        (18, air.poseidon()),
    ] {
        let index = row * air.width() + column;
        witness.trace.values[index] += Val::ONE;
        assert!(
            !accepts(&air, &witness),
            "unbound product row={row} column={column}"
        );
        witness.trace.values[index] -= Val::ONE;
    }
    for i in 0..12 {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
}
#[test]
fn product_descriptor_and_witness_shapes_are_fixed() {
    assert!(MulAir::new(17, 1).is_err());
    assert!(MulAir::new(Q, 0).is_err());
    assert!(MulAir::new(Q, 129).is_err());
    let air = MulAir::new(Q, 1).unwrap();
    assert!(air.generate(&[], &[[0; D]]).is_err());
    assert!(air.generate(&[[Q; D]], &[[0; D]]).is_err());
}
#[test]
#[ignore = "actual serial product component STARK; coordinated proof window"]
fn serial_ring_product_actual_proof_rejects_public_and_opening_mutations() {
    use lattica_prover_p3::block_v2::profile;
    let air = MulAir::new(QHAT, 1).unwrap();
    let left = core::array::from_fn(|i| {
        if i % 2 == 0 {
            QHAT - 1
        } else {
            i as u64 * 34567
        }
    });
    let right = core::array::from_fn(|i| {
        if i % 3 == 0 {
            QHAT - 1
        } else {
            i as u64 * 34543
        }
    });
    let witness = air.generate(&[left], &[right]).unwrap();
    assert!(accepts(&air, &witness));
    let start = std::time::Instant::now();
    let config = profile::make_config();
    let mut proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    eprintln!(
        "serial product actual proof q={} height={} width={} elapsed_ms={}",
        air.modulus,
        air.height,
        air.width(),
        start.elapsed().as_millis()
    );
    let mut wrong = witness.public_values.clone();
    wrong[8] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &wrong).is_err());
    proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).is_err());
}

#[test]
#[ignore = "actual serial product proof and pinned recursive verifier trace; coordinated window"]
fn serial_ring_product_typed_join_rejects_missing_modulus_and_witness_mutations() {
    use crate::rust_verify::{
        constraints::ConstraintContext, constraints_crypto::CryptoObligations,
        constraints_poly::request_mul,
    };
    use lattica_prover_p3::block_v2::machine::{verifier::ProofInputs, MachineAir, ProgramBuilder};
    let left = core::array::from_fn(|i| (i as u64 * 7919) % QHAT);
    let registration = RegisteredMulAir::new(QHAT, 1).unwrap();
    let artifact = registration.prove(&[left], &[left]).unwrap();
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut hints = Vec::new();
    let mut obligations = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut hints,
            crypto: &mut obligations,
        };
        let left = left.map(|value| c.constant_residue(value, QHAT));
        request_mul(&mut c, &left, &left, QHAT);
    }
    assert_eq!(
        obligations.polynomial_commitments.len(),
        2,
        "identical operand wires must reuse one root"
    );
    let request = &obligations.mul[0];
    assert_eq!(request.left_commitment, request.right_commitment);
    let mut inputs = ProofInputs::default();
    inputs.values = hints;
    let public_start = inputs.values.len();
    assert!(registration
        .compile_join(&mut b, &mut inputs, &[], &artifact)
        .is_err());
    let wrong = RegisteredMulAir::new(Q, 1).unwrap();
    assert!(wrong
        .compile_join(&mut b, &mut inputs, &[request], &artifact)
        .is_err());
    registration
        .compile_join(&mut b, &mut inputs, &[request], &artifact)
        .unwrap();
    let air = MachineAir::new(b.finish(None).unwrap());
    let started = std::time::Instant::now();
    air.trace(&[], &inputs.values).unwrap();
    eprintln!(
        "serial product recursive join wires={} height={} trace_ms={}",
        air.program().wire_count(),
        air.program().height(),
        started.elapsed().as_millis()
    );
    for index in [
        0,
        public_start,
        public_start + 4,
        public_start + 8,
        inputs.values.len() - 1,
    ] {
        let mut changed = inputs.values.clone();
        changed[index] += Val::ONE;
        assert!(
            air.trace(&[], &changed).is_err(),
            "unbound product join witness {index}"
        );
    }
}
