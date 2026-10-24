use super::*;
use crate::recursive_aggregation::LeafStatement;
use p3_air::check_all_constraints;
use p3_field::PrimeField64;

fn fixture() -> (StatementAir, Vec<u8>) {
    let air = StatementAir {
        setup_seed: [29; 32],
    };
    let mut bytes = vec![0; STATEMENT_BYTES];
    bytes[..32].copy_from_slice(&air.setup_seed);
    for (i, word) in bytes[32..STATEMENT_BYTES - 64]
        .chunks_exact_mut(4)
        .enumerate()
    {
        let value = (i as u64)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
            % Q;
        word.copy_from_slice(&(value as u32).to_le_bytes());
    }
    bytes[32..36].copy_from_slice(&((Q - 1) as u32).to_le_bytes());
    bytes[STATEMENT_BYTES - 1] = 1;
    (air, bytes)
}
fn accepts(air: &StatementAir, w: &StatementWitness) -> bool {
    check_all_constraints(air, &w.trace, &w.public_values, Some(2))
        .failures
        .is_empty()
}

#[test]
fn statement_air_matches_exact_leaf_digest_and_enforces_packet_semantics() {
    let (air, bytes) = fixture();
    let witness = air.generate(&bytes).unwrap();
    let expected = LeafStatement::from_bytes([0; 32], [0; 32], &bytes).unwrap();
    assert_eq!(
        witness.public_values[..4]
            .iter()
            .map(|x| x.as_canonical_u64())
            .collect::<Vec<_>>(),
        expected.digest.to_vec()
    );
    assert!(accepts(&air, &witness));
    let bundle = bundle::StatementBundle::from_bytes(&bytes).unwrap();
    assert_eq!(witness.public_values[4..], bundle.commitment());
    for changed in [0, 32, STATEMENT_BYTES - 1] {
        let mut malformed = bytes.clone();
        match changed {
            0 => malformed[0] ^= 1,
            32 => malformed[32..36].copy_from_slice(&(Q as u32).to_le_bytes()),
            _ => malformed[STATEMENT_BYTES - 1] = 0,
        }
        // Regenerate every internal witness and the matching digest. Only the
        // range/setup/serial relation can reject these internally consistent rows.
        assert!(!accepts(&air, &air.generate(&malformed).unwrap()));
    }
    assert!(air.generate(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn statement_air_rejects_bits_delay_registers_and_commitment_mutations() {
    let (air, bytes) = fixture();
    let mut witness = air.generate(&bytes).unwrap();
    for (row, column) in [
        (3, BITS),
        (3, PREFIX),
        (3, ACC),
        (3, ROW_INDEX),
        (3, SELECTOR),
        (3, SELECTOR_INVERSE),
        (3, ACTIVE_FLAG),
        (3, COEFFICIENT_FLAG),
        (3, SERIAL_FLAG),
        (66, POLY_ACC),
        (67, BUNDLE_ACC),
        (67, POLY_POSEIDON),
        (66, BUNDLE_POSEIDON),
        (SELECTED_ROWS[4], COEFFICIENT_FLAG),
        (ACTIVE_ROWS, ACTIVE_FLAG),
        (ACTIVE_ROWS - 1, OLDER),
        (ACTIVE_ROWS - 1, DIFFERENCES),
    ] {
        let index = row * WIDTH + column;
        witness.trace.values[index] += Val::ONE;
        assert!(!accepts(&air, &witness), "row={row}, column={column}");
        witness.trace.values[index] -= Val::ONE;
    }
    for i in [0, 4] {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
}

#[test]
fn statement_bundle_binds_setup_order_every_polynomial_and_serial_words() {
    let (air, bytes) = fixture();
    let bundle = bundle::StatementBundle::from_bytes(&bytes).unwrap();
    let expected = air.generate(&bytes).unwrap().public_values[4..].to_vec();
    assert_eq!(expected, bundle.commitment());
    for i in 0..POLYNOMIALS {
        let mut changed = bundle.clone();
        changed.polynomial_roots[i][i % 4] += Val::ONE;
        assert_ne!(expected, changed.commitment());
    }
    let mut reordered = bundle.clone();
    reordered.polynomial_roots.swap(0, POLYNOMIALS - 1);
    assert_ne!(expected, reordered.commitment());
    let mut changed_setup = bundle.clone();
    changed_setup.setup_seed[0] ^= 1;
    assert_ne!(expected, changed_setup.commitment());
    for i in 0..16 {
        let mut changed = bundle.clone();
        changed.serial_words[i] ^= 1;
        assert_ne!(expected, changed.commitment());
    }
    let mut malformed = bytes;
    malformed[32..36].copy_from_slice(&(Q as u32).to_le_bytes());
    assert!(bundle::StatementBundle::from_bytes(&malformed).is_err());
}

#[test]
fn statement_schedule_binds_each_setup_word_and_each_serial_pair() {
    let (mut air, mut bytes) = fixture();
    air.setup_seed = core::array::from_fn(|i| (17 * i + 29) as u8);
    bytes[..32].copy_from_slice(&air.setup_seed);
    let witness = air.generate(&bytes).unwrap();
    assert!(accepts(&air, &witness));
    assert_eq!(
        witness.public_values[4..],
        bundle::StatementBundle::from_bytes(&bytes)
            .unwrap()
            .commitment()
    );
    for word in 0..8 {
        bytes[4 * word] ^= 1;
        assert!(!accepts(&air, &air.generate(&bytes).unwrap()));
        bytes[4 * word] ^= 1;
    }
    let serial: [u8; 32] = core::array::from_fn(|i| (31 * i + 7) as u8);
    bytes[STATEMENT_BYTES - 64..STATEMENT_BYTES - 32].copy_from_slice(&serial);
    bytes[STATEMENT_BYTES - 32..].copy_from_slice(&serial);
    assert!(!accepts(&air, &air.generate(&bytes).unwrap()));
    for word in 0..8 {
        bytes[STATEMENT_BYTES - 32 + 4 * word] ^= 1;
        assert!(accepts(&air, &air.generate(&bytes).unwrap()));
        bytes[STATEMENT_BYTES - 32 + 4 * word] ^= 1;
    }
}

#[test]
#[ignore = "full statement component STARK: run with a memory limit"]
fn statement_air_actual_proof_and_recursive_geometry() {
    use lattica_prover_p3::block_v2::{
        machine::{program::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    let (air, bytes) = fixture();
    let witness = air.generate(&bytes).unwrap();
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    let mut bad = witness.public_values;
    bad[0] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &bad).is_err());
    let artifact = bundle::StatementProof {
        public_values: witness.public_values,
        proof,
    };
    let values = bundle::StatementBundle::from_bytes(&bytes).unwrap();
    let mut builder = ProgramBuilder::new(4).unwrap();
    let public = core::array::from_fn(|i| builder.public(i).unwrap());
    let mut inputs = ProofInputs::default();
    let roots: [[_; 4]; POLYNOMIALS] = inputs
        .bases(
            &mut builder,
            &values
                .polynomial_roots
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .chunks_exact(4)
        .map(|chunk| chunk.try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let serials: [_; 16] = inputs
        .bases(&mut builder, &values.serial_words.map(Val::from_u32))
        .unwrap()
        .try_into()
        .unwrap();
    bundle::verify_bundle(
        &mut builder,
        &mut inputs,
        air.setup_seed,
        public,
        &roots,
        &serials,
        &artifact,
    )
    .unwrap();
    let program = builder.finish(None).unwrap();
    eprintln!("statement component width={WIDTH} height={HEIGHT}; recursive active_rows={} height={} wires={}", program.active_rows(), program.height(), program.wire_count());
    let machine = MachineAir::new(program);
    machine
        .trace(&witness.public_values[..4], &inputs.values)
        .unwrap();
    assert!(machine.trace(&bad[..4], &inputs.values).is_err());
    // Coordinator inputs must match this child proof's exact data, even if
    // substituted roots come from another independently valid component.
    for index in [
        0,
        4 * (POLYNOMIALS - 1),
        4 * POLYNOMIALS,
        4 * POLYNOMIALS + 15,
    ] {
        inputs.values[index] += Val::ONE;
        assert!(machine
            .trace(&witness.public_values[..4], &inputs.values)
            .is_err());
        inputs.values[index] -= Val::ONE;
    }
    for i in 0..4 {
        inputs.values.swap(i, 4 * (POLYNOMIALS - 1) + i);
    }
    assert!(machine
        .trace(&witness.public_values[..4], &inputs.values)
        .is_err());
}
