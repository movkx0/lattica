use super::*;
use lattica_prover_p3::block_v2::{
    commitment,
    machine::{MachineAir, ProgramBuilder},
};

#[test]
fn manifest_plan_rejects_missing_duplicate_reordered_and_unsupported_shapes() {
    let s = CryptoShape::Shake {
        index: 0,
        input_len: 1,
        output_len: 32,
    };
    let a = CryptoShape::Aes {
        index: 0,
        domain: u64::MAX,
        start_counter: u32::MAX,
        output_len: 17,
    };
    let n = CryptoShape::Ntt {
        index: 0,
        modulus: crate::rust_verify::Q,
    };
    assert!(CryptoPlan::new(vec![s.clone(), a.clone(), n.clone()]).is_ok());
    for values in [
        vec![s.clone(), s.clone()],
        vec![a.clone(), s.clone()],
        vec![CryptoShape::Ntt {
            index: 1,
            modulus: crate::rust_verify::Q,
        }],
        vec![CryptoShape::Mul {
            index: 0,
            modulus: 17,
        }],
    ] {
        assert!(CryptoPlan::new(values).is_err());
    }
    let plan = CryptoPlan::new(vec![s.clone(), a.clone()]).unwrap();
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    let session = ComponentManifest::new(&mut b, &mut inputs, &plan);
    assert!(session.expect(&[a]).is_err());
    assert!(session.expect(&[s]).is_ok());
    assert!(session.finish().is_err());
}

#[test]
fn canonical_manifest_binds_order_descriptors_and_every_operand_root() {
    let q = crate::rust_verify::Q;
    let plan = CryptoPlan::new(vec![
        CryptoShape::Shake {
            index: 0,
            input_len: 1,
            output_len: 32,
        },
        CryptoShape::Aes {
            index: 0,
            domain: u64::MAX,
            start_counter: 161,
            output_len: 31,
        },
        CryptoShape::Mul {
            index: 0,
            modulus: q,
        },
    ])
    .unwrap();
    let mut b = ProgramBuilder::new(4).unwrap();
    let mut inputs = ProofInputs::default();
    let values: Vec<_> = (1..=28).map(Val::from_u64).collect();
    let wires = inputs.bases(&mut b, &values).unwrap();
    let roots = vec![
        vec![
            wires[0..4].try_into().unwrap(),
            wires[4..8].try_into().unwrap(),
        ],
        vec![
            wires[8..12].try_into().unwrap(),
            wires[12..16].try_into().unwrap(),
        ],
        vec![
            wires[16..20].try_into().unwrap(),
            wires[20..24].try_into().unwrap(),
            wires[24..28].try_into().unwrap(),
        ],
    ];
    let root = commit(&mut b, &plan, &roots).unwrap();
    for i in 0..4 {
        let public = b.public(i).unwrap();
        b.assert_equal(public, root.0[i]);
    }
    let mut fields = vec![1, 3, 0, 1, 0, 2, 1, 32, 2];
    fields.extend(1..=8);
    fields.extend([1, 2, 0, 4, u32::MAX as u64, u32::MAX as u64, 161, 31, 2]);
    fields.extend(9..=16);
    fields.extend([2, 4, 0, 1, q, 3]);
    fields.extend(17..=28);
    let public = commitment::hash_fields(DOMAIN, &fields)
        .unwrap()
        .map(Val::from_u64);
    let machine = MachineAir::new(b.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for i in 0..inputs.values.len() {
        inputs.values[i] += Val::ONE;
        assert!(
            machine.trace(&public, &inputs.values).is_err(),
            "unbound operand root field{i}"
        );
        inputs.values[i] -= Val::ONE;
    }
    let mut swapped = inputs.values.clone();
    for i in 0..4 {
        swapped.swap(16 + i, 20 + i);
    }
    assert!(machine.trace(&public, &swapped).is_err());
    let mut wrong = public;
    wrong[0] += Val::ONE;
    assert!(machine.trace(&wrong, &inputs.values).is_err());
}

#[test]
#[ignore = "actual AES proof + complete typed manifest verifier; coordinate4GiB window"]
fn actual_aes_component_manifest_matches_arithmetic_and_rejects_substitution() {
    use crate::{
        aes_lane_air::{
            self,
            join::{AesLanePartition, AesLaneSegmentProof},
        },
        rust_verify::constraints::ConstraintContext,
        shake_air::commit_bytes,
    };
    use lattica_prover_p3::block_v2::{machine::pq_bytes, profile};
    use p3_field::PrimeField64;
    let descriptor = aes_lane_air::Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 31,
    };
    let key = [17; 32];
    let air = aes_lane_air::AesLaneAir::new(descriptor).unwrap();
    let child = air.generate(key).unwrap();
    let proof = p3_uni_stark::prove(
        &profile::make_config(),
        &air,
        child.trace,
        &child.public_values,
    );
    let receipt = AesLaneSegmentProof {
        public_values: child.public_values,
        proof,
    };
    let partition = AesLanePartition::new(descriptor, 2).unwrap();
    let mut b = ProgramBuilder::new(4).unwrap();
    let mut witness = Vec::new();
    let mut obligations = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut b,
        witness: &mut witness,
        crypto: &mut obligations,
    };
    let key_bytes = key.map(|x| c.byte(x));
    let output: Vec<_> = child.output.iter().map(|&x| c.byte(x)).collect();
    let mut header = key_bytes.to_vec();
    header.extend(
        descriptor.input_bytes(&key)[32..]
            .iter()
            .map(|&x| c.constant_byte(x)),
    );
    let input_commitment = pq_bytes::poseidon_commit_bytes(
        c.builder,
        aes_lane_air::AES_INPUT_DOMAIN,
        &header.iter().map(|x| x.constrained).collect::<Vec<_>>(),
    );
    let output_commitment = pq_bytes::poseidon_commit_bytes(
        c.builder,
        aes_lane_air::AES_OUTPUT_DOMAIN,
        &output.iter().map(|x| x.constrained).collect::<Vec<_>>(),
    );
    obligations.aes.push(PendingAes {
        key: key_bytes,
        domain: descriptor.domain,
        start_counter: descriptor.start_counter,
        output,
        input_commitment,
        output_commitment,
    });
    let (plan, arithmetic_root) = arithmetic_crypto_manifest(&mut b, &obligations).unwrap();
    for i in 0..4 {
        let public = b.public(i).unwrap();
        b.assert_equal(public, arithmetic_root.0[i]);
    }
    let mut inputs = ProofInputs::default();
    let mut session = ComponentManifest::new(&mut b, &mut inputs, &plan);
    session
        .verify_aes(0, &obligations.aes[0], &partition, &[receipt])
        .unwrap();
    session.finish_equal(arithmetic_root.wires()).unwrap();
    let proof_start = witness.len();
    witness.extend(inputs.values);
    let machine = MachineAir::new(b.finish(None).unwrap());
    let mut fields = vec![
        1,
        1,
        0,
        2,
        0,
        4,
        descriptor.domain & 0xffff_ffff,
        descriptor.domain >> 32,
        u64::from(descriptor.start_counter),
        descriptor.output_len as u64,
        2,
    ];
    fields.extend(
        commit_bytes(
            aes_lane_air::AES_INPUT_DOMAIN,
            &descriptor.input_bytes(&key),
        )
        .into_iter()
        .map(|x| x.as_canonical_u64()),
    );
    fields.extend(
        commit_bytes(aes_lane_air::AES_OUTPUT_DOMAIN, &child.output)
            .into_iter()
            .map(|x| x.as_canonical_u64()),
    );
    let public = commitment::hash_fields(DOMAIN, &fields)
        .unwrap()
        .map(Val::from_u64);
    machine.trace(&public, &witness).unwrap();
    eprintln!(
        "typed crypto manifest rows={} height={} wires={}",
        machine.program().active_rows(),
        machine.program().height(),
        machine.program().wire_count()
    );
    for i in [0, 32, proof_start + aes_lane_air::OUTPUT_END] {
        witness[i] += Val::ONE;
        assert!(machine.trace(&public, &witness).is_err());
        witness[i] -= Val::ONE;
    }
    let mut wrong = public;
    wrong[2] += Val::ONE;
    assert!(machine.trace(&wrong, &witness).is_err());
}
