use super::*;
use crate::shake_air::commit_bytes;
use lattica_prover_p3::block_v2::{
    machine::{MachineAir, ProgramBuilder},
    profile,
};
#[test]
fn digest_bridge_and_fixed_pp_framing_match_native_and_reject_mutations() {
    let setup = [43; 32];
    let context = [53; 32];
    let expected = primitives::parameters(&setup, &context).unwrap().pp;
    assert_eq!(
        primitives::shake(&pp_input_bytes(&setup, &context), 32),
        expected
    );
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut inputs = ProofInputs::default();
    let root = core::array::from_fn(|i| b.public(i).unwrap());
    let output = bridge_digest32(&mut b, &mut inputs, &expected, &root).unwrap();
    for i in 0..4 {
        let public = b.public(4 + i).unwrap();
        b.assert_equal(output[i], public);
    }
    let air = MachineAir::new(b.finish(None).unwrap());
    let mut public = commit_bytes(BYTES32_DOMAIN, &expected).to_vec();
    public.extend(commit_bytes(SHAKE_OUTPUT_DOMAIN, &expected));
    air.trace(&public, &inputs.values).unwrap();
    let mut bad = inputs.values.clone();
    bad[0] = Val::from_u16(256);
    assert!(air.trace(&public, &bad).is_err());
    for i in 0..8 {
        public[i] += Val::ONE;
        assert!(air.trace(&public, &inputs.values).is_err());
        public[i] -= Val::ONE;
    }
}
#[test]
#[ignore = "actual pp SHAKE proof with context/digest bridges and typed recursive trace; memory guard required"]
fn actual_parameters_pp_shake_and_graph_byte_roots() {
    let setup = [43; 32];
    let context = [61; 32];
    let data = pp_input_bytes(&setup, &context);
    let pp: [u8; 32] = primitives::shake(&data, 32).try_into().unwrap();
    let partition = ShakeBatchPartition::new(
        Descriptor {
            input_len: data.len(),
            output_len: 32,
        },
        8,
    )
    .unwrap();
    assert_eq!(partition.segments().len(), 1);
    let config = profile::make_config();
    let proofs: Vec<_> = partition
        .segments()
        .iter()
        .map(|air| {
            let w = air.generate(&data).unwrap();
            let proof = p3_uni_stark::prove(&config, air, w.trace, &w.public_values);
            p3_uni_stark::verify(&config, air, &proof, &w.public_values).unwrap();
            LaneShakeProof {
                public_values: w.public_values,
                proof,
            }
        })
        .collect();
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut inputs = ProofInputs::default();
    let context_root = core::array::from_fn(|i| b.public(i).unwrap());
    let pp_root = core::array::from_fn(|i| b.public(4 + i).unwrap());
    verify_parameters_pp(
        &mut b,
        &mut inputs,
        &setup,
        &context_root,
        &context,
        &pp_root,
        &pp,
        ShakeArtifacts {
            partition: &partition,
            proofs: &proofs,
        },
    )
    .unwrap();
    let program = b.finish(None).unwrap();
    eprintln!(
        "parameters pp bridge: active_rows={} height={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    let machine = MachineAir::new(program);
    let mut public = commit_bytes(BYTES32_DOMAIN, &context).to_vec();
    public.extend(commit_bytes(BYTES32_DOMAIN, &pp));
    machine.trace(&public, &inputs.values).unwrap();
    for i in [0, 4] {
        public[i] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[i] -= Val::ONE;
    }
    let mut bad = inputs.values.clone();
    bad[0] += Val::ONE;
    assert!(machine.trace(&public, &bad).is_err());
}
