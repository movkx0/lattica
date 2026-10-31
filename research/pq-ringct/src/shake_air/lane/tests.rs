use super::*;
use p3_air::check_all_constraints;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn check(air: &LaneShakeAir, witness: &SegmentWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(8));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

fn xof(input: &[u8], count: usize) -> Vec<u8> {
    let mut hash = Shake256::default();
    hash.update(input);
    let mut output = vec![0; count];
    hash.finalize_xof().read(&mut output);
    output
}

fn compile_join(
    input: &[u8],
    output: &[u8],
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
    let input_bytes = allocate(input);
    let output_bytes = allocate(output);
    let input_commitment = poseidon_commit_bytes(
        &mut builder,
        SHAKE_INPUT_DOMAIN,
        &input_bytes
            .iter()
            .map(|b| b.constrained)
            .collect::<Vec<_>>(),
    );
    let output_commitment = poseidon_commit_bytes(
        &mut builder,
        SHAKE_OUTPUT_DOMAIN,
        &output_bytes
            .iter()
            .map(|b| b.constrained)
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
    verify_request(&mut builder, &mut proof_inputs, &request, proofs).unwrap();
    witness.extend(proof_inputs.values);
    let machine = MachineAir::new(builder.finish(None).unwrap());
    let public = commit_bytes(SHAKE_INPUT_DOMAIN, input)
        .into_iter()
        .chain(commit_bytes(SHAKE_OUTPUT_DOMAIN, output))
        .collect();
    (machine, witness, public)
}

#[test]
#[ignore = "four actual lane component proofs and two constrained three-component joins"]
fn lane_shake_three_segment_recursive_join_rejects_valid_substitution() {
    use lattica_prover_p3::block_v2::{machine::analysis, profile};
    let input: Vec<_> = (0..137).map(|i| (i * 13 + 7) as u8).collect();
    let output = xof(&input, 137);
    let descriptor = Descriptor {
        input_len: input.len(),
        output_len: output.len(),
    };
    let config = profile::make_config();
    let mut proofs = Vec::new();
    for permutation in 0..descriptor.permutations().unwrap() {
        let air = LaneShakeAir::new(descriptor, permutation).unwrap();
        let witness = air.generate(&input).unwrap();
        let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
        proofs.push(LaneShakeProof {
            public_values: witness.public_values,
            proof,
        });
    }
    let (machine, witness, public) = compile_join(&input, &output, &proofs);
    let geometry = analysis::analyze(&machine).unwrap();
    eprintln!(
        "lane SHAKE3join recursive_rows={} recursive_height={} retained_lde_bytes={}",
        machine.program().active_rows(),
        machine.program().height(),
        geometry.retained_lde_bytes
    );
    machine.trace(&public, &witness).unwrap();
    let mut changed = public.clone();
    changed[7] += Val::ONE;
    assert!(machine.trace(&changed, &witness).is_err());
    drop(machine);
    drop(witness);

    let mut other_input = input.clone();
    other_input[0] ^= 1;
    let air = LaneShakeAir::new(descriptor, 1).unwrap();
    let witness = air.generate(&other_input).unwrap();
    assert_ne!(
        witness.public_values[START_STATE..END_STATE],
        proofs[1].public_values[START_STATE..END_STATE]
    );
    let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    proofs[1] = LaneShakeProof {
        public_values: witness.public_values,
        proof,
    };
    let (machine, witness, public) = compile_join(&input, &output, &proofs);
    assert!(machine.trace(&public, &witness).is_err());
}

#[test]
fn lane_shake_matches_wide_and_rustcrypto_at_rate_boundaries() {
    assert_eq!(WIDTH, 517);
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
        let descriptor = Descriptor {
            input_len,
            output_len,
        };
        let mut previous: Option<[Val; PUBLIC_VALUES]> = None;
        for permutation in 0..descriptor.permutations().unwrap() {
            let air = LaneShakeAir::new(descriptor, permutation).unwrap();
            assert!(air.periodic_columns().iter().all(|p| p.len() == 128));
            let witness = air.generate(&input).unwrap();
            assert!(
                check(&air, &witness),
                "input={input_len} output={output_len} permutation={permutation}"
            );
            let wide = ShakeAir::new(descriptor, permutation, 1)
                .unwrap()
                .generate(&input)
                .unwrap();
            assert_eq!(witness.public_values, wide.public_values);
            if let Some(previous) = previous {
                assert_eq!(
                    previous[END_STATE..INPUT_START],
                    witness.public_values[START_STATE..END_STATE]
                );
                assert_eq!(
                    previous[INPUT_END..OUTPUT_START],
                    witness.public_values[INPUT_START..INPUT_END]
                );
                assert_eq!(
                    previous[OUTPUT_END..],
                    witness.public_values[OUTPUT_START..OUTPUT_END]
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
            &commit_bytes(SHAKE_OUTPUT_DOMAIN, &xof(&input, output_len))
        );
    }
}

#[test]
fn lane_shake_rejects_register_counter_round_constant_and_padding_mutations() {
    let air = LaneShakeAir::new(
        Descriptor {
            input_len: 3,
            output_len: 1,
        },
        0,
    )
    .unwrap();
    let mut witness = air.generate(b"abc").unwrap();
    assert!(check(&air, &witness));
    for (row, column) in [
        (10, STATE + 99), // An otherwise idle register must still be carried.
        (128, SCRATCH + 80),
        (256, COUNTER + 1),
        (256, ROUNDS),
        (128 + 100, RC),
        (101, BITS + 64 + 24),      // SHAKE suffix immediately after abc.
        (24 * 128 + 101, BITS + 7), // Odd-byte squeeze must remain linked.
        (HEIGHT - 1, INPUT_ACC),
    ] {
        let index = row * WIDTH + column;
        let old = witness.trace.values[index];
        witness.trace.values[index] += Val::ONE;
        assert!(!check(&air, &witness), "row={row} column={column}");
        witness.trace.values[index] = old;
    }
    witness.public_values[OUTPUT_END] += Val::ONE;
    assert!(!check(&air, &witness));
}

#[test]
fn lane_shake_rejects_trusted_descriptor_substitution() {
    let air = LaneShakeAir::new(
        Descriptor {
            input_len: 3,
            output_len: 1,
        },
        0,
    )
    .unwrap();
    let witness = air.generate(b"abc").unwrap();
    for descriptor in [
        Descriptor {
            input_len: 4,
            output_len: 1,
        },
        Descriptor {
            input_len: 3,
            output_len: 2,
        },
    ] {
        assert!(!check(&LaneShakeAir::new(descriptor, 0).unwrap(), &witness));
    }
}

#[test]
#[ignore = "actual 4096-row component STARK and full recursive verifier geometry"]
fn lane_shake_real_proof_and_recursive_verifier_geometry() {
    use lattica_prover_p3::block_v2::{machine::analysis, profile};
    let air = LaneShakeAir::new(
        Descriptor {
            input_len: 3,
            output_len: 32,
        },
        0,
    )
    .unwrap();
    let witness = air.generate(b"abc").unwrap();
    assert!(check(&air, &witness));
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    let mut changed = witness.public_values;
    changed[OUTPUT_END] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &changed).is_err());
    let proofs = [LaneShakeProof {
        public_values: witness.public_values,
        proof,
    }];
    let (machine, inputs, public) = compile_join(b"abc", &xof(b"abc", 32), &proofs);
    let geometry = analysis::analyze(&machine).unwrap();
    eprintln!("lane SHAKE width={WIDTH} child_height={HEIGHT} recursive_wires={} recursive_rows={} recursive_height={} retained_lde_bytes={}", machine.program().wire_count(), machine.program().active_rows(), machine.program().height(), geometry.retained_lde_bytes);
    machine.trace(&public, &inputs).unwrap();
    let mut changed_public = public.clone();
    changed_public[7] += Val::ONE;
    assert!(machine.trace(&changed_public, &inputs).is_err());
    let [LaneShakeProof { mut proof, .. }] = proofs;
    proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).is_err());
}

#[test]
#[ignore = "actual recursive STARK; exclusive coordinated 32GiB proving window"]
fn lane_shake_actual_recursive_stark_rejects_mutations() {
    use lattica_prover_p3::{
        block_v2::{
            machine::{analysis, backend::RegisteredProgram},
            profile,
        },
        proving::Request,
    };
    let air = LaneShakeAir::new(
        Descriptor {
            input_len: 3,
            output_len: 32,
        },
        0,
    )
    .unwrap();
    let witness = air.generate(b"abc").unwrap();
    let config = profile::make_config();
    let child = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &child, &witness.public_values).unwrap();
    let children = [LaneShakeProof {
        public_values: witness.public_values,
        proof: child,
    }];
    let (machine, inputs, public) = compile_join(b"abc", &xof(b"abc", 32), &children);
    let geometry = analysis::analyze(&machine).unwrap();
    eprintln!(
        "lane SHAKE actual recursion rows={} height={} retained_lde_bytes={}",
        machine.program().active_rows(),
        machine.program().height(),
        geometry.retained_lde_bytes
    );
    let registered =
        RegisteredProgram::new_with_request(machine, 32_u64 << 30, Request::compatible()).unwrap();
    let mut proof = registered
        .prove_with_request(&public, &inputs, Request::compatible())
        .unwrap();
    let verifier = registered.verifier();
    verifier.verify(&proof, &public).unwrap();
    let mut changed = public.clone();
    changed[7] += Val::ONE;
    assert!(verifier.verify(&proof, &changed).is_err());
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(verifier.verify(&proof, &public).is_err());
}
