use super::*;
use p3_air::check_all_constraints;

fn check(air: &BatchShakeAir, witness: &SegmentWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(8));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

#[test]
fn lane_batch_absorb_eight_and_squeeze_eight_match_wide_endpoints() {
    let cases = [
        (
            Descriptor {
                input_len: RATE * 8 + 3,
                output_len: 137,
            },
            0,
            Kind::FullAbsorb,
        ),
        (
            Descriptor {
                input_len: 3,
                output_len: RATE * 10 + 1,
            },
            1,
            Kind::FullSqueeze,
        ),
    ];
    for (descriptor, first, kind) in cases {
        let input: Vec<_> = (0..descriptor.input_len)
            .map(|i| (i * 17 + 3) as u8)
            .collect();
        let air = BatchShakeAir::new(descriptor, first, 8, kind).unwrap();
        assert_eq!(air.width(), 518);
        assert_eq!(air.height(), 32768);
        assert!(air.periodic_columns().iter().all(|p| p.len() == 128));
        let witness = air.generate(&input).unwrap();
        assert!(check(&air, &witness));
        let wide = ShakeAir::new(descriptor, first, 8)
            .unwrap()
            .generate(&input)
            .unwrap();
        assert_eq!(witness.public_values, wide.public_values);
    }
}

#[test]
fn lane_batch_preserves_all_boundary_registers_and_exact_count() {
    let descriptor = Descriptor {
        input_len: RATE * 2 + 3,
        output_len: 32,
    };
    let input: Vec<_> = (0..descriptor.input_len)
        .map(|i| (i * 7 + 9) as u8)
        .collect();
    let air = BatchShakeAir::full_absorb(descriptor, 0, 2).unwrap();
    let mut witness = air.generate(&input).unwrap();
    assert!(check(&air, &witness));
    for (row, column) in [
        (HEIGHT, STATE + 99),
        (HEIGHT, SCRATCH + 99),
        (HEIGHT, INPUT_ACC),
        (HEIGHT, OUTPUT_ACC),
        (HEIGHT, RC),
        (HEIGHT, PERMUTATION),
        (air.height() - 1, COUNTER),
    ] {
        let index = row * WIDTH + column;
        let old = witness.trace.values[index];
        witness.trace.values[index] += Val::ONE;
        assert!(!check(&air, &witness), "row={row} column={column}");
        witness.trace.values[index] = old;
    }
    let wrong_count = BatchShakeAir::full_absorb(descriptor, 0, 1).unwrap();
    assert!(!check(&wrong_count, &witness));
}

#[test]
fn lane_batch_rejects_partial_or_cross_phase_ranges() {
    let descriptor = Descriptor {
        input_len: RATE * 8 + 3,
        output_len: RATE * 10 + 1,
    };
    assert!(BatchShakeAir::full_absorb(descriptor, 0, 0).is_err());
    assert!(BatchShakeAir::full_absorb(descriptor, 0, 3).is_err());
    assert!(BatchShakeAir::full_absorb(descriptor, 1, 8).is_err());
    assert!(BatchShakeAir::full_absorb(descriptor, 8, 1).is_err());
    assert!(BatchShakeAir::full_squeeze(descriptor, 8, 1).is_err());
    assert!(BatchShakeAir::full_squeeze(descriptor, 10, 8).is_ok());
    assert!(BatchShakeAir::full_squeeze(descriptor, 11, 8).is_err());
}

#[test]
#[ignore = "actual eight-permutation SHAKE proof; coordinate >=8GiB memory window"]
fn lane_batch_absorb_eight_actual_proof_and_recursive_geometry() {
    use lattica_prover_p3::block_v2::{
        machine::{analysis, verifier, MachineAir, ProgramBuilder},
        profile,
    };
    let descriptor = Descriptor {
        input_len: RATE * 8 + 3,
        output_len: 32,
    };
    let input: Vec<_> = (0..descriptor.input_len)
        .map(|i| (i * 17 + 3) as u8)
        .collect();
    let air = BatchShakeAir::full_absorb(descriptor, 0, 8).unwrap();
    let witness = air.generate(&input).unwrap();
    let config = profile::make_config();
    let mut proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    let mut changed = witness.public_values;
    changed[END_STATE] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &changed).is_err());
    let mut builder = ProgramBuilder::new(4).unwrap();
    let mut inputs = verifier::ProofInputs::default();
    let publics = inputs.bases(&mut builder, &witness.public_values).unwrap();
    verifier::uni::verify(
        &mut builder,
        &mut inputs,
        &air,
        air.height(),
        &publics,
        &proof,
    )
    .unwrap();
    for i in 0..4 {
        let expected = builder.public(i).unwrap();
        builder.assert_equal(publics[INPUT_END + i], expected);
    }
    let machine = MachineAir::new(builder.finish(None).unwrap());
    let geometry = analysis::analyze(&machine).unwrap();
    eprintln!("batch SHAKE permutations=8 width={WIDTH} child_height={} recursive_rows={} recursive_height={} retained_lde_bytes={}", air.height(), machine.program().active_rows(), machine.program().height(), geometry.retained_lde_bytes);
    machine
        .trace(
            &witness.public_values[INPUT_END..INPUT_END + 4],
            &inputs.values,
        )
        .unwrap();
    let mut wrong = inputs.values.clone();
    wrong[END_STATE] += Val::ONE;
    assert!(machine
        .trace(&witness.public_values[INPUT_END..INPUT_END + 4], &wrong)
        .is_err());
    proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).is_err());
    proof.opened_values.trace_local[0] -= profile::Challenge::ONE;
    drop(machine);

    // Exercise the canonical mixed partition end to end: eight full input
    // blocks plus the final padded block, with the actual byte commitments.
    let final_air = LaneShakeAir::new(descriptor, 8).unwrap();
    let final_witness = final_air.generate(&input).unwrap();
    let final_proof = p3_uni_stark::prove(
        &config,
        &final_air,
        final_witness.trace,
        &final_witness.public_values,
    );
    p3_uni_stark::verify(
        &config,
        &final_air,
        &final_proof,
        &final_witness.public_values,
    )
    .unwrap();
    let proofs = [
        LaneShakeProof {
            public_values: witness.public_values,
            proof,
        },
        LaneShakeProof {
            public_values: final_witness.public_values,
            proof: final_proof,
        },
    ];
    let contract = crate::component_tree::Contract::shake([0x42; 32], 0, descriptor).unwrap();
    let context = crate::component_tree::EndpointContext {
        context: [7; 32],
        statement: [Val::from_u8(9); 4],
        input: commit_bytes(SHAKE_INPUT_DOMAIN, &input),
        output: final_witness.public_values[OUTPUT_END..]
            .try_into()
            .unwrap(),
    };
    for (first, count, proof) in [(0, 8, &proofs[0]), (8, 1, &proofs[1])] {
        let node =
            crate::component_tree::compile_shake_batch(&contract, first, count, &context, proof)
                .unwrap();
        let geometry = node.geometry().unwrap();
        eprintln!("batch SHAKE endpointleaf first={first} count={count} public_fields={} active_rows={} height={} retained_lde_bytes={}", node.public_values().len(), geometry.active_rows, geometry.padded_rows, geometry.retained_lde_bytes);
        node.evaluate().unwrap();
    }
    let partition = ShakeBatchPartition::new(descriptor, 8).unwrap();
    let (machine, values, public) = compile_byte_join(&input, &partition, &proofs);
    let geometry = analysis::analyze(&machine).unwrap();
    eprintln!("batch SHAKE mixedrequest proofs=2 permutations=9 recursive_rows={} recursive_height={} retained_lde_bytes={}", machine.program().active_rows(), machine.program().height(), geometry.retained_lde_bytes);
    machine.trace(&public, &values).unwrap();
    let mut changed = public;
    changed[7] += Val::ONE;
    assert!(machine.trace(&changed, &values).is_err());
}

fn compile_byte_join(
    input: &[u8],
    partition: &ShakeBatchPartition,
    proofs: &[LaneShakeProof],
) -> (
    lattica_prover_p3::block_v2::machine::MachineAir,
    Vec<Val>,
    Vec<Val>,
) {
    use crate::rust_verify::{constraints::ByteValue, constraints_crypto::PendingShake};
    use lattica_prover_p3::block_v2::machine::{
        pq_bytes::{poseidon_commit_bytes, Byte},
        verifier::ProofInputs,
        MachineAir, ProgramBuilder,
    };
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut output = vec![0u8; partition.descriptor().output_len];
    hasher.finalize_xof().read(&mut output);
    let mut builder = ProgramBuilder::new(8).unwrap();
    let mut values = Vec::new();
    let mut allocate = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|&value| {
                values.push(Val::from_u8(value));
                ByteValue {
                    value,
                    constrained: Byte::input(&mut builder),
                }
            })
            .collect::<Vec<_>>()
    };
    let input_bytes = allocate(input);
    let output_bytes = allocate(&output);
    let input_commitment = poseidon_commit_bytes(
        &mut builder,
        SHAKE_INPUT_DOMAIN,
        &input_bytes
            .iter()
            .map(|x| x.constrained)
            .collect::<Vec<_>>(),
    );
    let output_commitment = poseidon_commit_bytes(
        &mut builder,
        SHAKE_OUTPUT_DOMAIN,
        &output_bytes
            .iter()
            .map(|x| x.constrained)
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
    let mut proof_inputs = ProofInputs::default();
    verify_batched_request(&mut builder, &mut proof_inputs, &request, partition, proofs).unwrap();
    values.extend(proof_inputs.values);
    let machine = MachineAir::new(builder.finish(None).unwrap());
    let public = commit_bytes(SHAKE_INPUT_DOMAIN, input)
        .into_iter()
        .chain(commit_bytes(SHAKE_OUTPUT_DOMAIN, &output))
        .collect();
    (machine, values, public)
}
