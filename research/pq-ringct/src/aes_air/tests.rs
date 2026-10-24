use super::*;
use crate::shake_air::commit_bytes;
use p3_air::check_all_constraints;

fn accepts(air: &AesAir, witness: &AesWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(4));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

#[test]
fn aes_round_air_matches_rustcrypto_and_exact_counter_commitments() {
    for (descriptor, key) in [
        (
            Descriptor {
                domain: 0,
                start_counter: 0,
                output_len: 16,
            },
            [0; 32],
        ),
        (
            Descriptor {
                domain: 0x4368,
                start_counter: 161,
                output_len: 1,
            },
            core::array::from_fn(|i| i as u8),
        ),
        (
            Descriptor {
                domain: 0x0123_4567_89ab_cdef,
                start_counter: u32::MAX,
                output_len: 31,
            },
            [0x9b; 32],
        ),
        (
            Descriptor {
                domain: 0,
                start_counter: 0,
                output_len: 17,
            },
            [0xff; 32],
        ),
    ] {
        let air = AesAir::new(descriptor).unwrap();
        let witness = air.generate(key).unwrap();
        assert!(accepts(&air, &witness), "{descriptor:?}");
        assert_eq!(
            &witness.public_values[..4],
            &commit_bytes(AES_INPUT_DOMAIN, &descriptor.input_bytes(&key))
        );
        assert_eq!(
            &witness.public_values[4..],
            &commit_bytes(AES_OUTPUT_DOMAIN, &witness.output)
        );
        assert_eq!(witness.output.len(), descriptor.output_len);
    }
}

#[test]
fn aes_air_rejects_changed_key_rounds_ciphertext_and_commitments() {
    let air = AesAir::new(Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 31,
    })
    .unwrap();
    let mut witness = air.generate([17; 32]).unwrap();
    assert!(accepts(&air, &witness));
    for (row, column) in [
        (0, ROOT_KEY),
        (0, KEY),
        (0, STATE),
        (0, CIPHER),
        (2, STATE_SBOX + INV),
        (2, STATE_SBOX + GF_CARRY),
        (2, STATE_SBOX + ZERO),
        (2, STATE_SBOX + FIELD_INV),
        (2, STATE_SBOX + SBOX_OUT),
        (2, NEXT_KEY),
        (2, KEY_CARRY),
        (2, STATE_OUT),
        (2, STATE_CARRY),
        (0, INPUT_ACC),
        (0, OUTPUT_ACC),
        (0, INPUT_POSEIDON),
        (0, OUTPUT_POSEIDON),
    ] {
        let index = row * WIDTH + column;
        witness.trace.values[index] += Val::ONE;
        assert!(
            !accepts(&air, &witness),
            "unbound AES trace row={row} col={column}"
        );
        witness.trace.values[index] -= Val::ONE;
    }
    for i in 0..PUBLIC_VALUES {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
}

#[test]
#[ignore = "actual AES component STARK; run in coordinated proof window"]
fn aes_air_actual_proof_rejects_public_and_opening_mutations() {
    use lattica_prover_p3::block_v2::profile;
    let air=AesAir::new(Descriptor{domain:0x4368,start_counter:161,output_len:31}).unwrap();
    let witness=air.generate([17;32]).unwrap();assert!(accepts(&air,&witness));
    let config=profile::make_config();let start=std::time::Instant::now();
    let mut proof=p3_uni_stark::prove(&config,&air,witness.trace,&witness.public_values);
    p3_uni_stark::verify(&config,&air,&proof,&witness.public_values).unwrap();
    eprintln!("AES AIR actual proof: height={} width={} elapsed_ms={}",air.height,WIDTH,start.elapsed().as_millis());
    let mut wrong=witness.public_values;wrong[4]+=Val::ONE;assert!(p3_uni_stark::verify(&config,&air,&proof,&wrong).is_err());
    proof.opened_values.trace_local[0]+=profile::Challenge::ONE;assert!(p3_uni_stark::verify(&config,&air,&proof,&witness.public_values).is_err());
}
