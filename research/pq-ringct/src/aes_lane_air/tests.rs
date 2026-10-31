use super::*;
use crate::shake_air::commit_bytes;
use p3_air::check_all_constraints;

fn accepts(air: &AesLaneAir, witness: &SegmentWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(4));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}

fn compile_join(
    key: [u8; 32],
    output: &[u8],
    partition: &join::AesLanePartition,
    proofs: &[join::AesLaneSegmentProof],
) -> (
    lattica_prover_p3::block_v2::machine::MachineAir,
    Vec<Val>,
    Vec<Val>,
) {
    use crate::rust_verify::constraints::{ByteValue, ConstraintContext};
    use crate::rust_verify::constraints_crypto::{CryptoObligations, PendingAes};
    use lattica_prover_p3::block_v2::machine::{
        pq_bytes, verifier::ProofInputs, MachineAir, ProgramBuilder,
    };
    let descriptor = partition.descriptor();
    let mut builder = ProgramBuilder::new(8).unwrap();
    let mut witness = Vec::new();
    let mut obligations = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut builder,
        witness: &mut witness,
        crypto: &mut obligations,
    };
    let key_bytes = key.map(|byte| c.byte(byte));
    let output_bytes: Vec<_> = output.iter().map(|&byte| c.byte(byte)).collect();
    let mut header: Vec<ByteValue> = key_bytes.to_vec();
    header.extend(
        descriptor.input_bytes(&key)[32..]
            .iter()
            .map(|&byte| c.constant_byte(byte)),
    );
    let input_commitment = pq_bytes::poseidon_commit_bytes(
        c.builder,
        AES_INPUT_DOMAIN,
        &header.iter().map(|b| b.constrained).collect::<Vec<_>>(),
    );
    let output_commitment = pq_bytes::poseidon_commit_bytes(
        c.builder,
        AES_OUTPUT_DOMAIN,
        &output_bytes
            .iter()
            .map(|b| b.constrained)
            .collect::<Vec<_>>(),
    );
    let request = PendingAes {
        key: key_bytes,
        domain: descriptor.domain,
        start_counter: descriptor.start_counter,
        output: output_bytes,
        input_commitment,
        output_commitment,
    };
    for (i, value) in input_commitment
        .into_iter()
        .chain(output_commitment)
        .enumerate()
    {
        let public = builder.public(i).unwrap();
        builder.assert_equal(value, public);
    }
    let mut inputs = ProofInputs::default();
    join::verify_request(&mut builder, &mut inputs, &request, partition, proofs).unwrap();
    witness.extend(inputs.values);
    let public = commit_bytes(AES_INPUT_DOMAIN, &descriptor.input_bytes(&key))
        .into_iter()
        .chain(commit_bytes(AES_OUTPUT_DOMAIN, output))
        .collect();
    (
        MachineAir::new(builder.finish(None).unwrap()),
        witness,
        public,
    )
}
#[test]
fn serial_aes_matches_wide_rustcrypto_and_segment_commitments() {
    for (descriptor, key) in [
        (
            Descriptor {
                domain: 0,
                start_counter: 0,
                output_len: 1,
            },
            [0; 32],
        ),
        (
            Descriptor {
                domain: 0x4368,
                start_counter: 161,
                output_len: 16,
            },
            core::array::from_fn(|i| i as u8),
        ),
        (
            Descriptor {
                domain: 0x0123456789abcdef,
                start_counter: u32::MAX,
                output_len: 31,
            },
            [0x9b; 32],
        ),
        (
            Descriptor {
                domain: 1,
                start_counter: 0,
                output_len: 40,
            },
            [0xff; 32],
        ),
    ] {
        let wide = crate::aes_air::AesAir::new(descriptor)
            .unwrap()
            .generate(key)
            .unwrap();
        let air = AesLaneAir::new(descriptor).unwrap();
        let witness = air.generate(key).unwrap();
        assert!(accepts(&air, &witness), "{descriptor:?}");
        assert_eq!(witness.output, wide.output);
        assert_eq!(
            &witness.public_values[..4],
            &commit_bytes(AES_INPUT_DOMAIN, &descriptor.input_bytes(&key))
        );
        assert_eq!(
            &witness.public_values[OUTPUT_END..],
            &commit_bytes(AES_OUTPUT_DOMAIN, &witness.output)
        );
        let mut previous = [
            Val::from_u64(AES_OUTPUT_DOMAIN),
            Val::from_usize(descriptor.output_len),
            Val::ZERO,
            Val::ZERO,
        ];
        for block in 0..descriptor.blocks() {
            let segment = AesLaneAir::segment(descriptor, block, 1).unwrap();
            let part = segment.generate(key).unwrap();
            assert!(accepts(&segment, &part));
            assert_eq!(&part.public_values[..4], &witness.public_values[..4]);
            assert_eq!(
                &part.public_values[OUTPUT_START..OUTPUT_START + 4],
                &previous
            );
            previous.copy_from_slice(&part.public_values[OUTPUT_END..]);
        }
        assert_eq!(&previous, &witness.public_values[OUTPUT_END..]);
    }
}

#[test]
fn serial_aes_rejects_key_state_schedule_counter_and_commitment_mutations() {
    let air = AesLaneAir::new(Descriptor {
        domain: 0x4368,
        start_counter: u32::MAX,
        output_len: 40,
    })
    .unwrap();
    let mut witness = air.generate([17; 32]).unwrap();
    assert!(accepts(&air, &witness));
    for (row, column) in [
        (0, ROOT_KEY),
        (0, KEY),
        (17, STATE),
        (65, SCRATCH),
        (65, SBOX),
        (81, READ),
        (97, RESULT),
        (111, KEY),
        (960, STATE),
        (961, READ),
        (1023, COUNTER_CARRY),
        (1024, COUNTER_BITS),
        (1024, KEY),
        (64, PHASE_BITS),
        (128, RCON_BITS),
        (960, OUTPUT_PHASE),
        (2048, REMAINING),
        (3072, ACTIVE),
        (3072, BLOCK_INDEX),
        (0, INPUT_ACC),
        (0, OUTPUT_ACC),
        (960, POSEIDON),
    ] {
        let i = row * WIDTH + column;
        witness.trace.values[i] += Val::ONE;
        assert!(
            !accepts(&air, &witness),
            "mutation accepted at {row}:{column}"
        );
        witness.trace.values[i] -= Val::ONE;
    }
    for i in 0..PUBLIC_VALUES {
        witness.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &witness));
        witness.public_values[i] -= Val::ONE;
    }
    let different = AesLaneAir::new(Descriptor {
        domain: 0x4369,
        ..air.descriptor
    })
    .unwrap();
    assert!(!accepts(&different, &witness));
    let different = AesLaneAir::segment(air.descriptor, 1, 2).unwrap();
    assert!(!accepts(&different, &witness));
}

#[test]
#[ignore = "actual serial AES STARK and recursive geometry; coordinate memory window"]
fn serial_aes_actual_stark_and_recursive_verifier_geometry() {
    use lattica_prover_p3::block_v2::profile;
    let air = AesLaneAir::new(Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 31,
    })
    .unwrap();
    let witness = air.generate([17; 32]).unwrap();
    assert!(accepts(&air, &witness));
    let config = profile::make_config();
    let start = std::time::Instant::now();
    let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
    eprintln!(
        "serial AES native height={} width={WIDTH} elapsed_ms={}",
        air.height,
        start.elapsed().as_millis()
    );
    let mut wrong = witness.public_values;
    wrong[OUTPUT_END] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &proof, &wrong).is_err());
    let partition = join::AesLanePartition::new(air.descriptor, 2).unwrap();
    let receipt = join::AesLaneSegmentProof {
        public_values: witness.public_values,
        proof,
    };
    let (machine, mut inputs, public) =
        compile_join([17; 32], &witness.output, &partition, &[receipt]);
    let program = machine.program();
    eprintln!(
        "serial AES recursive active_rows={} height={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    eprintln!(
        "serial AES recursive retained_lde={}",
        lattica_prover_p3::block_v2::machine::analysis::analyze(&machine)
            .unwrap()
            .retained_lde_bytes
    );
    machine.trace(&public, &inputs).unwrap();
    for index in [0, 32, 32 + witness.output.len() + OUTPUT_END] {
        inputs[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs).is_err());
        inputs[index] -= Val::ONE;
    }
    let mut wrong = public.clone();
    wrong[7] += Val::ONE;
    assert!(machine.trace(&wrong, &inputs).is_err());
}
