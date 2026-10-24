use super::*;
use crate::{
    rust_verify::{constraints_ntt::commit_signed_values, primitives},
    shake_air::commit_bytes,
    sparse_air::{Kind, SparseAir},
};
use lattica_prover_p3::block_v2::{
    machine::{MachineAir, ProgramBuilder},
    profile,
};
#[test]
fn key_bridge_binds_byte_range_domain_counter_length_and_seed_root() {
    let key = core::array::from_fn(|i| (7 * i + 19) as u8);
    let descriptor = Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 127,
    };
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut inputs = ProofInputs::default();
    let expected = core::array::from_fn(|i| b.public(i).unwrap());
    let request = bind_key_request(&mut b, &mut inputs, &expected, &key, descriptor).unwrap();
    for i in 0..4 {
        let value = b.public(4 + i).unwrap();
        b.assert_equal(request[i], value);
    }
    let machine = MachineAir::new(b.finish(None).unwrap());
    let mut public = commit_bytes(BYTES32_DOMAIN, &key).to_vec();
    public.extend(commit_bytes(
        AES_INPUT_DOMAIN,
        &descriptor.input_bytes(&key),
    ));
    machine.trace(&public, &inputs.values).unwrap();
    let mut bad = inputs.values.clone();
    bad[0] = Val::from_u16(256);
    assert!(machine.trace(&public, &bad).is_err());
    bad = inputs.values.clone();
    bad[1] += Val::ONE;
    assert!(machine.trace(&public, &bad).is_err());
    for changed in [
        Descriptor {
            start_counter: 160,
            ..descriptor
        },
        Descriptor {
            domain: 0,
            ..descriptor
        },
        Descriptor {
            output_len: 128,
            ..descriptor
        },
    ] {
        let mut altered = public.clone();
        altered[4..].copy_from_slice(&commit_bytes(AES_INPUT_DOMAIN, &changed.input_bytes(&key)));
        assert!(machine.trace(&altered, &inputs.values).is_err());
    }
    public[0] += Val::ONE;
    assert!(machine.trace(&public, &inputs.values).is_err());
}
#[test]
fn paired_key_requests_share_one_opening_and_bind_both_descriptors() {
    let key = core::array::from_fn(|i| (7 * i + 19) as u8);
    let descriptors = [
        Descriptor {
            domain: 0x4368,
            start_counter: 0,
            output_len: 2572,
        },
        Descriptor {
            domain: 0x4368,
            start_counter: 161,
            output_len: 127,
        },
    ];
    let build = |shared: bool| {
        let mut b = ProgramBuilder::new(12).unwrap();
        let mut inputs = ProofInputs::default();
        let key_root = core::array::from_fn(|i| b.public(i).unwrap());
        let roots = if shared {
            bind_key_request_pair(&mut b, &mut inputs, &key_root, &key, descriptors).unwrap()
        } else {
            descriptors.map(|descriptor| {
                bind_key_request(&mut b, &mut inputs, &key_root, &key, descriptor).unwrap()
            })
        };
        for (request, root) in roots.iter().enumerate() {
            for (lane, &wire) in root.iter().enumerate() {
                let expected = b.public(4 + 4 * request + lane).unwrap();
                b.assert_equal(wire, expected);
            }
        }
        (b.finish(None).unwrap(), inputs.values)
    };
    let (program, inputs) = build(true);
    let (separate, separate_inputs) = build(false);
    assert_eq!(inputs.len(), 32);
    assert_eq!(separate_inputs.len(), 64);
    assert!(program.active_rows() < separate.active_rows());
    eprintln!(
        "paired seed opening active_rows={} separate_active_rows={}",
        program.active_rows(),
        separate.active_rows()
    );
    let machine = MachineAir::new(program);
    let mut public = commit_bytes(BYTES32_DOMAIN, &key).to_vec();
    for descriptor in descriptors {
        public.extend(commit_bytes(
            AES_INPUT_DOMAIN,
            &descriptor.input_bytes(&key),
        ));
    }
    machine.trace(&public, &inputs).unwrap();
    MachineAir::new(separate)
        .trace(&public, &separate_inputs)
        .unwrap();

    for request in 0..2 {
        let descriptor = descriptors[request];
        for changed in [
            Descriptor {
                domain: descriptor.domain + 1,
                ..descriptor
            },
            Descriptor {
                start_counter: descriptor.start_counter + 1,
                ..descriptor
            },
            Descriptor {
                output_len: descriptor.output_len + 1,
                ..descriptor
            },
        ] {
            let mut altered = public.clone();
            let start = 4 + request * 4;
            altered[start..start + 4]
                .copy_from_slice(&commit_bytes(AES_INPUT_DOMAIN, &changed.input_bytes(&key)));
            assert!(machine.trace(&altered, &inputs).is_err());
        }
    }
    let mut reordered = public.clone();
    reordered[4..8].copy_from_slice(&public[8..12]);
    reordered[8..12].copy_from_slice(&public[4..8]);
    assert!(machine.trace(&reordered, &inputs).is_err());
    for lane in 0..public.len() {
        let mut altered = public.clone();
        altered[lane] += Val::ONE;
        assert!(machine.trace(&altered, &inputs).is_err());
    }
    for index in [0, 31] {
        let mut altered = inputs.clone();
        altered[index] += Val::ONE;
        assert!(machine.trace(&public, &altered).is_err());
        altered[index] = Val::from_u16(256);
        assert!(machine.trace(&public, &altered).is_err());
    }
}

#[test]
#[ignore = "actual eight-block AES + sparse sampler proofs and recursive join; memory guard required"]
fn actual_alpha_prime_aes_and_sampler_join() {
    let key = [37u8; 32];
    let descriptor = Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 127,
    };
    let partition = AesLanePartition::new(descriptor, 8).unwrap();
    let config = profile::make_config();
    let aes: Vec<_> = partition
        .segments()
        .iter()
        .map(|air| {
            let w = air.generate(key).unwrap();
            let proof = p3_uni_stark::prove(&config, air, w.trace, &w.public_values);
            p3_uni_stark::verify(&config, air, &proof, &w.public_values).unwrap();
            AesLaneSegmentProof {
                public_values: w.public_values,
                proof,
            }
        })
        .collect();
    let mut stream = primitives::AesStream::new(&key, 0x4368);
    let _ = stream.bytes(161 * 16);
    let bytes = stream.bytes(127);
    let air = SparseAir::new(Kind::AlphaPrime39);
    let w = air.generate(&bytes).unwrap();
    let output = commit_signed_values(&w.polynomial);
    assert_eq!(w.polynomial, primitives::expand_alpha(&key).unwrap().1);
    let proof = p3_uni_stark::prove(&config, &air, w.trace, &w.public_values);
    let sparse = SparseArtifact {
        public_values: w.public_values,
        proof,
    };
    sparse_air::join::verify_native(Kind::AlphaPrime39, &sparse).unwrap();
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut inputs = ProofInputs::default();
    let seed_root = core::array::from_fn(|i| b.public(i).unwrap());
    let output_root = core::array::from_fn(|i| b.public(4 + i).unwrap());
    verify_alpha_prime(
        &mut b,
        &mut inputs,
        &seed_root,
        &key,
        &output_root,
        AesArtifacts {
            partition: &partition,
            proofs: &aes,
        },
        &sparse,
    )
    .unwrap();
    let program = b.finish(None).unwrap();
    eprintln!(
        "alpha-prime AES+sampler: active_rows={} height={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    let machine = MachineAir::new(program);
    let mut public = commit_bytes(BYTES32_DOMAIN, &key).to_vec();
    public.extend(output);
    machine.trace(&public, &inputs.values).unwrap();
    public[0] += Val::ONE;
    assert!(machine.trace(&public, &inputs.values).is_err());
    public[0] -= Val::ONE;
    public[4] += Val::ONE;
    assert!(machine.trace(&public, &inputs.values).is_err());
    let wrong = AesLanePartition::new(
        Descriptor {
            start_counter: 160,
            ..descriptor
        },
        8,
    )
    .unwrap();
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut inputs = ProofInputs::default();
    let seed_root = core::array::from_fn(|i| b.public(i).unwrap());
    let output_root = core::array::from_fn(|i| b.public(4 + i).unwrap());
    assert!(verify_alpha_prime(
        &mut b,
        &mut inputs,
        &seed_root,
        &key,
        &output_root,
        AesArtifacts {
            partition: &wrong,
            proofs: &aes
        },
        &sparse
    )
    .is_err());
}
