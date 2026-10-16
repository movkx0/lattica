//! Compile the selected profile against full-size public proof shapes.
//! Source template proofs are deliberately not authenticated: this diagnostic
//! measures allocation bounds and never registers keys, proves, or admits work.
use super::*;
use crate::block_v2::{codec, gpu_hash, machine::gpu_backend::resources::Bounds};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires full-size public wallet templates; CPU compilation only"]
fn capacity_profile_resource_geometry() {
    assert!(!gpu_hash::is_enabled());
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let output = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_OUTPUT").unwrap());
    let load = |index| {
        let bytes = fs::read(directory.join(format!("wallet.{index}"))).unwrap();
        assert!(bytes.len() <= profile::MAX_PROOF_BYTES && bytes.starts_with(b"LBV2TW01"));
        codec::decode::<WalletProof>(&bytes[8..]).unwrap()
    };
    let wallets = [load(0), load(1), load(3)];
    let height = 1 << 18;
    let mut modes = Vec::new();
    for mode in 1..=12 {
        let compiled = crate::block_v2::statements::compile(height, 12, |prefix| {
            Ok(typed_pairs::compile_registration_with_registry(
                height,
                mode,
                paired_templates(mode, [&wallets[0], &wallets[1], &wallets[2]]),
                Some(prefix),
            )?)
        })
        .unwrap();
        let required_height = compiled.program.height();
        assert!(required_height <= height);
        let program = compiled.program.pad_to(height).unwrap();
        let bounds = Bounds::for_program_with_device_salts(&program, true).unwrap();
        let reservation = bounds.reservation(1).unwrap();
        let descriptor: serde_json::Value = serde_json::from_str(include_str!(
            "../../scripts/block-v2-typed-owned-gpu-workload-128.json"
        ))
        .unwrap();
        for (key, actual) in serde_json::to_value(&bounds).unwrap().as_object().unwrap() {
            assert!(
                descriptor["witness_bounds"][key].as_u64().unwrap() >= actual.as_u64().unwrap(),
                "insufficient workload bound: {key}"
            );
        }
        modes.push(
            serde_json::json!({"mode":mode, "required_height":required_height,
            "witness_bounds":bounds, "witness_reservation":reservation}),
        );
    }
    fs::write(output, serde_json::to_vec_pretty(&serde_json::json!({
        "schema":"lattica-capacity-resource-geometry-v1", "block_capacity":profile::MAX_TRANSACTIONS,
        "depth":profile::TREE_DEPTH, "height":height, "modes":modes,
        "device_salts":true, "template_proofs_verified":false, "gpu_initialized":false, "proof_completed":false,
    })).unwrap()).unwrap();
}

#[test]
fn capacity_profile_top_merge_checks_real_depth_six_children() {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
    use p3_field::PrimeCharacteristicRing;

    let height = 2048;
    let mut caps: programs::Caps<12> =
        core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    let empty = programs::empty(height, &caps).unwrap();
    let registered =
        RegisteredProgram::new(MachineAir::new(empty.program.pad_to(height).unwrap())).unwrap();
    caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
    let empty = programs::empty(height, &caps).unwrap();
    let context = commitment::Context {
        profile_id: programs::profile_id(height, &caps).unwrap(),
        chain_id: [0x51; 32],
    };
    let child = commitment::empty_subtree(context, commitment::DEPTH - 1).unwrap();
    let child_public = programs::statement(child, programs::EMPTY);
    let proof = registered.prove(&child_public, &empty.witness).unwrap();
    registered.verify(&proof, &child_public).unwrap();
    let root = commitment::merge_nodes(child, child).unwrap();
    assert_eq!(root.level, 7);
    let public = programs::statement(root, programs::MERGE);
    let merge = programs::merge(height, &caps, [&child_public; 2], [&proof; 2]).unwrap();
    merge.program.evaluate(&public, &merge.witness).unwrap();
    for index in [programs::LEVEL, programs::COUNT, programs::ROOT] {
        let mut forged = public;
        forged[index] += Val::ONE;
        assert!(merge.program.evaluate(&forged, &merge.witness).is_err());
    }
}
