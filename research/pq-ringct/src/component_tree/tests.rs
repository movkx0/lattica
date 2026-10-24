use super::*;

fn context() -> EndpointContext {
    EndpointContext {
        context: [7; 32],
        statement: [Val::from_u64(11); 4],
        input: [Val::from_u64(13); 4],
        output: [Val::from_u64(17); 4],
    }
}

#[test]
fn typed_intervals_reject_missing_duplicate_reordered_and_foreign_requests() {
    let contract = Contract::shake(
        [1; 32],
        3,
        shake_air::Descriptor {
            input_len: 137,
            output_len: 137,
        },
    )
    .unwrap();
    assert_eq!(contract.total, 3);
    let a = contract.span(0, 1).unwrap();
    let b = contract.span(1, 1).unwrap();
    let c = contract.span(2, 1).unwrap();
    let ab = Spec::merge(&a, &b).unwrap();
    assert_eq!(ab.count, 2);
    assert_eq!(Spec::merge(&ab, &c).unwrap().count, 3);
    for (left, right) in [(&a, &a), (&a, &c), (&b, &a), (&ab, &b)] {
        assert!(Spec::merge(left, right).is_err());
    }
    assert!(contract.span(3, 1).is_err());
    assert!(contract.span(0, 0).is_err());
    assert!(contract.span(u32::MAX, 2).is_err());
    let mut foreign = b.clone();
    foreign.contract.request += 1;
    assert!(Spec::merge(&a, &foreign).is_err());
    foreign = b.clone();
    foreign.contract.profile[0] ^= 1;
    assert!(Spec::merge(&a, &foreign).is_err());
    let aes = Contract::aes(
        [1; 32],
        3,
        aes_lane_air::Descriptor {
            domain: 1,
            start_counter: 0,
            output_len: 48,
        },
    )
    .unwrap();
    assert!(Spec::merge(&a, &aes.span(1, 1).unwrap()).is_err());
}

/// Tests only the merge relation, separately from the full child verifiers
/// which the production constructor always emits.
#[test]
fn constrained_merge_rejects_context_endpoint_order_and_interval_substitution() {
    let contract = Contract::aes(
        [1; 32],
        3,
        aes_lane_air::Descriptor {
            domain: 1,
            start_counter: 0,
            output_len: 32,
        },
    )
    .unwrap();
    let left = contract.span(0, 1).unwrap();
    let right = contract.span(1, 1).unwrap();
    let spec = Spec::merge(&left, &right).unwrap();
    let mut a = header(&left, &context()).unwrap();
    let mut c = header(&right, &context()).unwrap();
    a[HEADER..HEADER + 4].fill(Val::from_u64(19));
    a[HEADER + 4..].fill(Val::from_u64(23));
    c[HEADER..HEADER + 4].fill(Val::from_u64(23));
    c[HEADER + 4..].fill(Val::from_u64(29));
    let mut public = header(&spec, &context()).unwrap();
    public[HEADER..HEADER + 4].copy_from_slice(&a[HEADER..HEADER + 4]);
    public[HEADER + 4..].copy_from_slice(&c[HEADER + 4..]);
    let mut b = ProgramBuilder::new(spec.width()).unwrap();
    let outer = public_wires(&mut b, &spec).unwrap();
    let mut inputs = ProofInputs::default();
    let aw = inputs.bases(&mut b, &a).unwrap();
    let cw = inputs.bases(&mut b, &c).unwrap();
    bind_merge(&mut b, &spec, &outer, &aw, &cw);
    let machine = MachineAir::new(b.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for index in [
        CONTEXT,
        STATEMENT,
        EXPECTED_INPUT,
        EXPECTED_OUTPUT,
        KIND,
        REQUEST,
        FIRST,
        COUNT,
        TOTAL,
        DESCRIPTOR,
        HEADER,
        HEADER + 4,
        spec.width() + HEADER,
        spec.width() + COUNT,
    ] {
        inputs.values[index] += Val::ONE;
        assert!(
            machine.trace(&public, &inputs.values).is_err(),
            "accepted child mutation {index}"
        );
        inputs.values[index] -= Val::ONE;
    }
    let mut swapped = c;
    swapped.extend(a);
    assert!(machine.trace(&public, &swapped).is_err());
    for index in [CONTEXT, STATEMENT, EXPECTED_OUTPUT, HEADER, HEADER + 4] {
        public[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[index] -= Val::ONE;
    }
}

#[test]
fn endpoint_hash_binds_all_capacity_state_and_accumulator_fields() {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let input = b"exact endpoint tree";
    let mut h = Shake256::default();
    h.update(input);
    let mut output = [0; 32];
    h.finalize_xof().read(&mut output);
    let descriptor = shake_air::Descriptor {
        input_len: input.len(),
        output_len: output.len(),
    };
    let contract = Contract::shake([9; 32], 0, descriptor).unwrap();
    let spec = contract.span(0, 1).unwrap();
    let child = shake_air::lane::LaneShakeAir::new(descriptor, 0)
        .unwrap()
        .generate(input)
        .unwrap();
    let endpoints = shake_indices().map(|indices| {
        indices
            .iter()
            .map(|&i| child.public_values[i])
            .collect::<Vec<_>>()
    });
    let mut context = context();
    context.input = shake_air::commit_bytes(shake_air::SHAKE_INPUT_DOMAIN, input);
    context.output = shake_air::commit_bytes(shake_air::SHAKE_OUTPUT_DOMAIN, &output);
    let mut public = header(&spec, &context).unwrap();
    for (offset, values) in [(HEADER, &endpoints[0]), (HEADER + 4, &endpoints[1])] {
        public[offset..offset + 4].copy_from_slice(&endpoint_root(&contract, values).unwrap());
    }
    let mut b = ProgramBuilder::new(spec.width()).unwrap();
    let outer = public_wires(&mut b, &spec).unwrap();
    let mut inputs = ProofInputs::default();
    let start = inputs.bases(&mut b, &endpoints[0]).unwrap();
    let end = inputs.bases(&mut b, &endpoints[1]).unwrap();
    bind_endpoints(&mut b, &spec, &outer, &start, &end);
    let machine = MachineAir::new(b.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for index in 0..216 {
        inputs.values[index] += Val::ONE;
        assert!(
            machine.trace(&public, &inputs.values).is_err(),
            "unbound full endpoint field {index}"
        );
        inputs.values[index] -= Val::ONE;
    }
    for index in [EXPECTED_INPUT, EXPECTED_OUTPUT, HEADER, HEADER + 4] {
        public[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[index] -= Val::ONE;
    }
    assert_eq!(spec.width(), 46);
    assert!(spec.width() <= 64);
}

#[test]
#[ignore = "actual AES component proofs and source-cap registration; coordinate32GiB geometry window"]
fn actual_typed_aes_leaves_and_next_level_geometry() {
    use lattica_prover_p3::block_v2::profile;
    let descriptor = aes_lane_air::Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 31,
    };
    let key = [17; 32];
    let whole = aes_lane_air::AesLaneAir::new(descriptor)
        .unwrap()
        .generate(key)
        .unwrap();
    let contract = Contract::aes([1; 32], 3, descriptor).unwrap();
    let mut context = context();
    context.input = shake_air::commit_bytes(
        aes_lane_air::AES_INPUT_DOMAIN,
        &descriptor.input_bytes(&key),
    );
    context.output = shake_air::commit_bytes(aes_lane_air::AES_OUTPUT_DOMAIN, &whole.output);
    let config = profile::make_config();
    let mut keys = Vec::new();
    for first in 0..2 {
        let air = aes_lane_air::AesLaneAir::segment(descriptor, first, 1).unwrap();
        let witness = air.generate(key).unwrap();
        let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        let artifact = aes_lane_air::join::AesLaneSegmentProof {
            public_values: witness.public_values,
            proof,
        };
        let compiled = compile_aes(&contract, first as u32, 1, &context, &artifact).unwrap();
        compiled.evaluate().unwrap();
        eprintln!("typed AES leaf {first}: {:?}", compiled.geometry().unwrap());
        let registered = compiled.prepare(32_u64 << 30).unwrap();
        keys.push(registered.key());
        drop(registered);
    }
    let geometry = merge_geometry(&keys[0], &keys[1]).unwrap();
    eprintln!("typed AES actual source-cap next-level geometry: {geometry:?}");
    assert!(merge_geometry(&keys[0], &keys[0]).is_err());
    assert!(merge_geometry(&keys[1], &keys[0]).is_err());
}

#[test]
#[cfg(feature = "recursive-wide")]
#[ignore = "actual four AES children and parent source-cap registration; reserve16GiB geometry-only window"]
fn actual_wide_parent_source_caps_and_next_level_closure_geometry() {
    use lattica_prover_p3::block_v2::profile;
    let descriptor = aes_lane_air::Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 63,
    };
    let key = [17; 32];
    let whole = aes_lane_air::AesLaneAir::new(descriptor)
        .unwrap()
        .generate(key)
        .unwrap();
    let contract = Contract::aes([1; 32], 3, descriptor).unwrap();
    let mut context = context();
    context.input = shake_air::commit_bytes(
        aes_lane_air::AES_INPUT_DOMAIN,
        &descriptor.input_bytes(&key),
    );
    context.output = shake_air::commit_bytes(aes_lane_air::AES_OUTPUT_DOMAIN, &whole.output);
    let config = profile::make_config();
    let mut leaves = Vec::new();
    for first in 0..4 {
        let air = aes_lane_air::AesLaneAir::segment(descriptor, first, 1).unwrap();
        let witness = air.generate(key).unwrap();
        let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        let artifact = aes_lane_air::join::AesLaneSegmentProof {
            public_values: witness.public_values,
            proof,
        };
        let compiled = compile_aes(&contract, first as u32, 1, &context, &artifact).unwrap();
        compiled.evaluate().unwrap();
        eprintln!(
            "wide closure real leaf {first}: {:?}",
            compiled.geometry().unwrap()
        );
        let prepared = compiled.prepare(32_u64 << 30).unwrap();
        leaves.push(prepared.key());
        drop(prepared);
    }
    let template = |key: &NodeKey| NodeProof {
        public: vec![Val::ZERO; key.spec.width()],
        proof: verifier::template::batch(&key.air().unwrap()).unwrap(),
    };
    let mut parents = Vec::new();
    for (index, children) in leaves.chunks_exact(2).enumerate() {
        let left = template(&children[0]);
        let right = template(&children[1]);
        // Invalid proof templates are used only to compile the exact verifier
        // shape. They are never evaluated, accepted, or proved. Registration
        // computes a real preprocessing cap for that actual verifier program.
        let compiled = merge_impl(&children[0], &children[1], [&left, &right]).unwrap();
        drop(left);
        drop(right);
        let geometry = compiled.geometry().unwrap();
        eprintln!("wide closure registered parent {index}: {geometry:?}");
        let preprocessing_bytes = geometry.padded_rows as u64
            * (2_u64 << profile::LOG_BLOWUP)
            * geometry.preprocessed_width as u64
            * 8;
        assert!(
            preprocessing_bytes <= 16_u64 << 30,
            "preprocessing payload exceeds registration guard"
        );
        let prepared = compiled.prepare(32_u64 << 30).unwrap();
        parents.push(prepared.key());
        drop(prepared);
    }
    let geometry = merge_geometry(&parents[0], &parents[1]).unwrap();
    eprintln!("wide closure actual-parent-source-cap next-level geometry: {geometry:?}");
    eprintln!(
        "wide closure height_stable={}",
        parents.iter().all(|key| key.height == geometry.padded_rows)
    );
    assert!(merge_geometry(&parents[0], &parents[0]).is_err());
    assert!(merge_geometry(&parents[1], &parents[0]).is_err());
}

#[test]
#[ignore = "actual three unchanged N8 SHAKE children and grouped recursive traces; reserve8GiB"]
fn actual_two_and_three_native_shake_batch_group_geometry() {
    use lattica_prover_p3::block_v2::{
        machine::pq_bytes::{SHAKE_INPUT_DOMAIN, SHAKE_OUTPUT_DOMAIN},
        profile,
    };
    use shake_air::lane::batch::{BatchShakeAir, ShakeSegmentAir};
    let descriptor = shake_air::Descriptor {
        input_len: 24 * 136 + 1,
        output_len: 32,
    };
    let input: Vec<_> = (0..descriptor.input_len)
        .map(|index| (index % 251) as u8)
        .collect();
    let output = crate::rust_verify::primitives::shake(&input, descriptor.output_len);
    let contract = Contract::shake([1; 32], 3, descriptor).unwrap();
    let mut context = context();
    context.input = shake_air::commit_bytes(SHAKE_INPUT_DOMAIN, &input);
    context.output = shake_air::commit_bytes(SHAKE_OUTPUT_DOMAIN, &output);
    let config = profile::make_config();
    let mut proofs = Vec::new();
    for first in [0, 8, 16] {
        let air = ShakeSegmentAir::Batch(BatchShakeAir::full_absorb(descriptor, first, 8).unwrap());
        let witness = air.generate(&input).unwrap();
        let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
        proofs.push(shake_air::lane::LaneShakeProof {
            public_values: witness.public_values,
            proof,
        });
    }
    for count in 1..=3 {
        let members: Vec<_> = proofs[..count]
            .iter()
            .enumerate()
            .map(|(index, proof)| ShakeGroupMember {
                first: (index * 8) as u32,
                count: 8,
                proof,
            })
            .collect();
        let mut compiled = compile_shake_group(&contract, &members, &context).unwrap();
        compiled.evaluate().unwrap();
        eprintln!(
            "grouped native SHAKE children={count} native_batch=8 geometry={:?}",
            compiled.geometry().unwrap()
        );
        compiled.public[HEADER] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.public[HEADER] -= Val::ONE;
        compiled.public[COUNT] += Val::ONE;
        assert!(compiled.evaluate().is_err());
    }
    assert!(compile_shake_group(&contract, &[], &context).is_err());
    for positions in [[0, 0], [8, 0], [0, 16]] {
        let members = positions.map(|first| ShakeGroupMember {
            first,
            count: 8,
            proof: &proofs[(first / 8) as usize],
        });
        assert!(compile_shake_group(&contract, &members, &context).is_err());
    }
    let wrong_count = [ShakeGroupMember {
        first: 0,
        count: 16,
        proof: &proofs[0],
    }];
    assert!(compile_shake_group(&contract, &wrong_count, &context).is_err());
    let saved = proofs[1].public_values[shake_air::START_STATE];
    proofs[1].public_values[shake_air::START_STATE] += Val::ONE;
    let members: Vec<_> = proofs[..2]
        .iter()
        .enumerate()
        .map(|(index, proof)| ShakeGroupMember {
            first: (index * 8) as u32,
            count: 8,
            proof,
        })
        .collect();
    let forged = compile_shake_group(&contract, &members, &context).unwrap();
    assert!(forged.evaluate().is_err());
    proofs[1].public_values[shake_air::START_STATE] = saved;
}
