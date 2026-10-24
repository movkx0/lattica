use super::*;
use p3_air::check_all_constraints;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn xof(input: &[u8], count: usize) -> Vec<u8> {
    let mut hash = Shake256::default();
    hash.update(input);
    let mut output = vec![0; count];
    hash.finalize_xof().read(&mut output);
    output
}

fn check(air: &ShakeAir, witness: &SegmentWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(8));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

#[test]
fn shake_air_padding_squeeze_and_commitments_match_rustcrypto() {
    for (input_len, output_len) in [
        (0, 0),
        (0, 32),
        (3, 1),
        (135, 137),
        (136, 32),
        (137, 137),
        (300, 173),
    ] {
        let input: Vec<_> = (0..input_len).map(|i| (i * 17 + 3) as u8).collect();
        let air = ShakeAir::whole(Descriptor {
            input_len,
            output_len,
        })
        .unwrap();
        let witness = air.generate(&input).unwrap();
        assert_eq!(
            air.expected_public_values(&input).unwrap(),
            witness.public_values
        );
        assert!(
            check(&air, &witness),
            "input={input_len} output={output_len}"
        );
        assert_eq!(
            &witness.public_values[INPUT_END..OUTPUT_START],
            &commit_bytes(SHAKE_INPUT_DOMAIN, &input)
        );
        assert_eq!(
            &witness.public_values[OUTPUT_END..],
            &commit_bytes(SHAKE_OUTPUT_DOMAIN, &xof(&input, output_len))
        );
    }
}

#[test]
fn shake_air_segments_share_exact_state_and_accumulator_boundaries() {
    let descriptor = Descriptor {
        input_len: 300,
        output_len: 173,
    };
    let input: Vec<_> = (0..300).map(|i| i as u8).collect();
    let mut previous: Option<[Val; PUBLIC_VALUES]> = None;
    for i in 0..descriptor.permutations().unwrap() {
        let air = ShakeAir::new(descriptor, i, 1).unwrap();
        let witness = air.generate(&input).unwrap();
        assert_eq!(
            air.expected_public_values(&input).unwrap(),
            witness.public_values
        );
        assert!(check(&air, &witness));
        if let Some(prior) = previous {
            assert_eq!(
                &prior[END_STATE..INPUT_START],
                &witness.public_values[START_STATE..END_STATE]
            );
            assert_eq!(
                &prior[INPUT_END..OUTPUT_START],
                &witness.public_values[INPUT_START..INPUT_END]
            );
            assert_eq!(
                &prior[OUTPUT_END..],
                &witness.public_values[OUTPUT_START..OUTPUT_END]
            );
        }
        previous = Some(witness.public_values);
    }
    let final_public = previous.unwrap();
    assert_eq!(
        &final_public[INPUT_END..OUTPUT_START],
        &commit_bytes(SHAKE_INPUT_DOMAIN, &input)
    );
    assert_eq!(
        &final_public[OUTPUT_END..],
        &commit_bytes(SHAKE_OUTPUT_DOMAIN, &xof(&input, 173))
    );
}

#[test]
fn shake_air_rejects_padding_chain_commitment_and_output_mutations() {
    let air = ShakeAir::whole(Descriptor {
        input_len: 137,
        output_len: 137,
    })
    .unwrap();
    let input = vec![0x5a; 137];
    for (row, column) in [
        (24, MESSAGE + 8),       // suffix bit in final absorption block
        (24, MESSAGE),           // second block message bit; corrupt within-block hold/commit
        (23, OUTPUT),            // actual permutation end state
        (24, INPUT_ACC),         // input commitment chain across permutations
        (48, OUTPUT_ACC),        // output commitment chain into squeeze block
        (48, ODD_BITS),          // odd final output-byte decomposition
        (0, INPUT_POSEIDON + 4), // input byte order/packing in Poseidon
    ] {
        let mut witness = air.generate(&input).unwrap();
        witness.trace.values[row * WIDTH + column] += Val::ONE;
        assert!(
            !check(&air, &witness),
            "accepted mutated row={row} column={column}"
        );
    }
    for index in [
        START_STATE,
        END_STATE,
        INPUT_START,
        INPUT_END,
        OUTPUT_START,
        OUTPUT_END,
    ] {
        let mut witness = air.generate(&input).unwrap();
        witness.public_values[index] += Val::ONE;
        assert!(!check(&air, &witness), "accepted mutated public={index}");
    }
}

#[test]
fn shake_air_trusted_descriptor_cannot_be_substituted() {
    let input = vec![0x72; 137];
    let air = ShakeAir::whole(Descriptor {
        input_len: 137,
        output_len: 137,
    })
    .unwrap();
    let witness = air.generate(&input).unwrap();
    for descriptor in [
        Descriptor {
            input_len: 138,
            output_len: 137,
        },
        Descriptor {
            input_len: 137,
            output_len: 138,
        },
    ] {
        let changed = ShakeAir::whole(descriptor).unwrap();
        assert_eq!(changed.height, air.height);
        assert!(!check(&changed, &witness));
    }
    assert!(ShakeAir::new(air.descriptor, 0, 0).is_err());
    assert!(ShakeAir::new(air.descriptor, 2, 2).is_err());
}

#[test]
fn byte_commitment_matches_machine_circuit() {
    use lattica_prover_p3::block_v2::machine::{
        pq_bytes::{poseidon_commit_bytes, Byte},
        ProgramBuilder,
    };
    for length in [0, 1, 7, 8, 9, 136, 137] {
        let input: Vec<_> = (0..length).map(|i| (i * 13) as u8).collect();
        let mut b = ProgramBuilder::new(4).unwrap();
        let bytes: Vec<_> = input.iter().map(|_| Byte::input(&mut b)).collect();
        let result = poseidon_commit_bytes(&mut b, SHAKE_INPUT_DOMAIN, &bytes);
        let expected = commit_bytes(SHAKE_INPUT_DOMAIN, &input);
        for i in 0..4 {
            let actual = result[i];
            let expected = b.public(i).unwrap();
            b.assert_equal(actual, expected);
        }
        let air = lattica_prover_p3::block_v2::machine::MachineAir::new(b.finish(None).unwrap());
        let witness: Vec<_> = input.into_iter().map(Val::from_u8).collect();
        air.trace(&expected, &witness).unwrap();
    }
}

#[test]
#[ignore = "actual SHAKE component STARK; run in coordinated proof window"]
fn shake_air_actual_proof_rejects_public_and_opening_mutations() {
    use lattica_prover_p3::block_v2::profile;
    let descriptor = Descriptor {
        input_len: 3,
        output_len: 32,
    };
    let air = ShakeAir::whole(descriptor).unwrap();
    let witness = air.generate(b"abc").unwrap();
    assert!(check(&air, &witness));
    let config = profile::make_config();
    let mut proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    let mut wrong = witness.public_values;
    wrong[OUTPUT_END] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &wrong).is_err());
    proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).is_err());
}

#[test]
#[ignore = "three actual component proofs plus full constrained recursive verifiers"]
fn shake_air_three_segment_recursive_join() {
    use crate::crypto_join::{verify_shake_request, ShakePartition, ShakeSegmentProof};
    use crate::rust_verify::{constraints::ByteValue, constraints_crypto::PendingShake};
    use lattica_prover_p3::block_v2::{
        machine::{
            pq_bytes::{poseidon_commit_bytes, Byte},
            program::ProofInputs,
            MachineAir, ProgramBuilder,
        },
        profile,
    };
    let input: Vec<_> = (0..137).map(|i| (i * 13 + 7) as u8).collect();
    let output = xof(&input, 137);
    let partition = ShakePartition::new(
        Descriptor {
            input_len: 137,
            output_len: 137,
        },
        1,
    )
    .unwrap();
    let config = profile::make_config();
    let mut proofs = Vec::new();
    for air in partition.segments() {
        let witness = air.generate(&input).unwrap();
        let proof = p3_uni_stark::prove(&config, air, witness.trace, &witness.public_values);
        p3_uni_stark::verify(&config, air, &proof, &witness.public_values).unwrap();
        proofs.push(ShakeSegmentProof {
            public_values: witness.public_values,
            proof,
        });
    }
    let compile_join = |proofs: &[ShakeSegmentProof]| {
        let mut builder = ProgramBuilder::new(8).unwrap();
        let mut witness = Vec::new();
        let mut allocate = |values: &[u8]| {
            values
                .iter()
                .map(|&value| {
                    witness.push(Val::from_u8(value));
                    ByteValue {
                        value,
                        constrained: Byte::input(&mut builder),
                    }
                })
                .collect::<Vec<_>>()
        };
        let input_bytes = allocate(&input);
        let output_bytes = allocate(&output);
        let input_commitment = poseidon_commit_bytes(
            &mut builder,
            SHAKE_INPUT_DOMAIN,
            &input_bytes
                .iter()
                .map(|v| v.constrained)
                .collect::<Vec<_>>(),
        );
        let output_commitment = poseidon_commit_bytes(
            &mut builder,
            SHAKE_OUTPUT_DOMAIN,
            &output_bytes
                .iter()
                .map(|v| v.constrained)
                .collect::<Vec<_>>(),
        );
        for (i, value) in input_commitment
            .into_iter()
            .chain(output_commitment)
            .enumerate()
        {
            let public = builder.public(i).unwrap();
            builder.assert_equal(value, public);
        }
        let request = PendingShake {
            input: input_bytes,
            output: output_bytes,
            input_commitment,
            output_commitment,
        };
        let first_component_public = witness.len();
        let mut proof_inputs = ProofInputs::default();
        verify_shake_request(
            &mut builder,
            &mut proof_inputs,
            &request,
            &partition,
            proofs,
        )
        .unwrap();
        witness.extend(proof_inputs.values);
        let program = builder.finish(None).unwrap();
        eprintln!(
            "SHAKE 3segment recursive join wires={} active_rows={} height={} witness_fields={}",
            program.wire_count(),
            program.active_rows(),
            program.height(),
            witness.len()
        );
        let machine = MachineAir::new(program);
        let analysis = lattica_prover_p3::block_v2::machine::analysis::analyze(&machine).unwrap();
        eprintln!(
            "SHAKE 3segment retained_lde_bytes={}",
            analysis.retained_lde_bytes
        );
        (machine, witness, first_component_public)
    };
    let (machine, mut witness, first_component_public) = compile_join(&proofs);
    let public: Vec<_> = commit_bytes(SHAKE_INPUT_DOMAIN, &input)
        .into_iter()
        .chain(commit_bytes(SHAKE_OUTPUT_DOMAIN, &output))
        .collect();
    machine.trace(&public, &witness).unwrap();
    let mut changed_public = public.clone();
    changed_public[7] += Val::ONE;
    assert!(machine.trace(&changed_public, &witness).is_err());
    witness[first_component_public + END_STATE] += Val::ONE;
    assert!(machine.trace(&public, &witness).is_err());

    // A separately valid child proof must still fail the recursive join when
    // its prior Keccak state and rolling commitments belong to another input.
    // Free the first machine before compiling the second to bound test memory.
    drop(machine);
    drop(witness);
    let mut other_input = input.clone();
    other_input[0] ^= 1;
    let middle_air = &partition.segments()[1];
    let other_witness = middle_air.generate(&other_input).unwrap();
    assert_ne!(
        other_witness.public_values[START_STATE..START_STATE + 100],
        proofs[1].public_values[START_STATE..START_STATE + 100]
    );
    let other_proof = p3_uni_stark::prove(
        &config,
        middle_air,
        other_witness.trace,
        &other_witness.public_values,
    );
    p3_uni_stark::verify(
        &config,
        middle_air,
        &other_proof,
        &other_witness.public_values,
    )
    .unwrap();
    proofs[1] = ShakeSegmentProof {
        public_values: other_witness.public_values,
        proof: other_proof,
    };
    let (machine, witness, _) = compile_join(&proofs);
    assert!(machine.trace(&public, &witness).is_err());
}
