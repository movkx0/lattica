use super::*;
use crate::rust_verify::constraints_ntt::commit_values;
use p3_air::check_all_constraints;

fn accepts(air: &NttAir, witness: &NttWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(4));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

#[test]
fn nibble_equality_and_greater_truth_tables_are_exact() {
    for value in 0..16_u8 {
        let bits: Vec<_> = (0..4).map(|bit| Val::from_u8((value >> bit) & 1)).collect();
        for bound in 0..16_u8 {
            assert_eq!(nibble_eq(&bits, bound), Val::from_bool(value == bound));
            let greater = ((bound + 1)..16)
                .map(|candidate| nibble_eq(&bits, candidate))
                .fold(Val::ZERO, |sum, item| sum + item);
            assert_eq!(greater, Val::from_bool(value > bound));
        }
    }
}

#[test]
fn serial_ntt_batch_matches_both_moduli_and_ordered_commitments() {
    for q in [Q, QHAT] {
        let inputs = vec![
            core::array::from_fn(|i| {
                if i % 3 == 0 {
                    q - 1
                } else {
                    (i as u64 * 53) % q
                }
            }),
            [0; D],
        ];
        let air = NttAir::new(q, inputs.len()).unwrap();
        let witness = air.generate(&inputs).unwrap();
        assert!(accepts(&air, &witness));
        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(
                &witness.public_values[i * 8..i * 8 + 4],
                &commit_values(INPUT_DOMAIN, q, input)
            );
            assert_eq!(
                &witness.public_values[i * 8 + 4..i * 8 + 8],
                &commit_values(OUTPUT_DOMAIN, q, &witness.output[i])
            );
        }
        assert!(air.width() < 700);
        assert_eq!(air.height, 2048);
    }
}

#[test]
fn serial_ntt_rejects_state_index_range_quotient_and_commitment_changes() {
    let air = NttAir::new(QHAT, 1).unwrap();
    let input = core::array::from_fn(|i| if i % 5 == 0 { QHAT - 1 } else { i as u64 });
    let mut witness = air.generate(&[input]).unwrap();
    assert!(accepts(&air, &witness));
    let width = air.width();
    for (row, column) in [
        (0, STATE),
        (64, STATE + 128),
        (64, INDEX_BITS),
        (64, PREFIX),
        (64, READS),
        (64, air.range(0)),
        (64, air.range(2)),
        (64, air.range(3) + 1),
        (64, air.range(4) + 1 + air.bits()),
        (64, air.carries()),
        (65, STATE),
        (832, READS),
        (832, air.acc()),
        (832, air.poseidon()),
    ] {
        let index = row * width + column;
        witness.trace.values[index] += Val::ONE;
        assert!(
            !accepts(&air, &witness),
            "unbound NTT row={row} column={column}"
        );
        witness.trace.values[index] -= Val::ONE;
    }
    for i in 0..8 {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
}

#[test]
#[ignore = "actual serial NTT component STARK; coordinated proof window"]
fn serial_ntt_actual_proof_rejects_public_and_opening_mutations() {
    use lattica_prover_p3::block_v2::profile;
    let air = NttAir::new(QHAT, 1).unwrap();
    let input = core::array::from_fn(|i| if i % 5 == 0 { QHAT - 1 } else { i as u64 });
    let witness = air.generate(&[input]).unwrap();
    assert!(accepts(&air, &witness));
    let start = std::time::Instant::now();
    let config = profile::make_config();
    let mut proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    eprintln!(
        "Serial NTT AIR actual proof: q={} height={} width={} elapsed_ms={}",
        air.modulus,
        air.height,
        air.width(),
        start.elapsed().as_millis()
    );
    let mut wrong = witness.public_values.clone();
    wrong[4] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &wrong).is_err());
    proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).is_err());
}

#[test]
#[ignore = "actual serial NTT proof and pinned recursive verifier trace; coordinated window"]
fn serial_ntt_typed_join_rejects_missing_modulus_and_witness_mutations() {
    use crate::rust_verify::{
        constraints::ConstraintContext, constraints_crypto::CryptoObligations,
        constraints_ntt::request_ntt,
    };
    use lattica_prover_p3::block_v2::machine::{verifier::ProofInputs, MachineAir, ProgramBuilder};
    let input = core::array::from_fn(|i| (i as u64 * 7919) % QHAT);
    let registration = RegisteredNttAir::new(QHAT, 1).unwrap();
    let artifact = registration.prove(&[input]).unwrap();
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut hints = Vec::new();
    let mut obligations = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut hints,
            crypto: &mut obligations,
        };
        let signed = input.map(|value| c.constant_signed(value as i64, 3_000_000));
        request_ntt(&mut c, &signed, QHAT);
    }
    let request = &obligations.ntt[0];
    let mut inputs = ProofInputs::default();
    inputs.values = hints;
    let public_start = inputs.values.len();
    assert!(registration
        .compile_join(&mut b, &mut inputs, &[], &artifact)
        .is_err());
    let wrong = RegisteredNttAir::new(Q, 1).unwrap();
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
        "serial NTT recursive join wires={} height={} trace_ms={}",
        air.program().wire_count(),
        air.program().height(),
        started.elapsed().as_millis()
    );
    for index in [0, public_start, public_start + 4, inputs.values.len() - 1] {
        let mut changed = inputs.values.clone();
        changed[index] += Val::ONE;
        assert!(
            air.trace(&[], &changed).is_err(),
            "unbound NTT join witness {index}"
        );
    }
}
