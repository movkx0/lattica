use super::*;
use crate::proving::{CoverageScope, Policy};

#[test]
fn tree_output_admission_is_bounded_by_count_and_container_cap() {
    assert!(output_bound(0).is_err());
    assert!(output_bound(crate::MAX_TREE_TX + 1).is_err());
    assert_eq!(
        output_bound(1).unwrap(),
        crate::TREE_MAGIC.len() + 4 + 32 + crate::JS_PUBLIC_INPUTS_LEN + 4 + crate::MAX_PROOF_LEN
    );
    assert_eq!(
        output_bound(crate::MAX_TREE_TX).unwrap(),
        crate::MAX_TREE_PROOF_LEN
    );
}

#[test]
#[ignore = "requires release native GPU startup in a 1 GiB managed bounded service"]
fn gpu_tree_container_preserves_cpu_verifier_and_statement_order() {
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 0);
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let mut witnesses = vec![crate::joinsplit_air::demo_witness(); 3];
    for (i, witness) in witnesses.iter_mut().enumerate() {
        witness.tx_binding[0] = Val::from_u64((17 + i) as u64);
    }
    let output = prove_joinsplit_tree(&witnesses, request).unwrap();
    assert_eq!(output.report.capabilities.scope(), CoverageScope::Operation);
    assert!(output.report.succeeded && output.report.stage_coverage_complete);
    assert_eq!(
        output.root,
        crate::batch_joinsplit_air::batch_root(&witnesses)
    );
    let encoded: Vec<u8> = witnesses
        .iter()
        .flat_map(crate::encode_joinsplit_witness)
        .collect();
    let mut abi_proof = vec![0; output_bound(witnesses.len()).unwrap()];
    let mut abi_root = [0; 32];
    let (mut proof_len, mut root_len) = (0, 0);
    let probe = crate::block_v2::wallet_worker::admission_tests::PrivateInputProbe::start();
    // SAFETY: live disjoint buffers of the advertised bounded sizes.
    assert_eq!(
        unsafe {
            crate::lattica_joinsplit_tree_prove(
                encoded.as_ptr(),
                encoded.len(),
                witnesses.len(),
                abi_proof.as_mut_ptr(),
                abi_proof.len(),
                &mut proof_len,
                abi_root.as_mut_ptr(),
                abi_root.len(),
                &mut root_len,
            )
        },
        0
    );
    probe.finish(3);
    assert_eq!(root_len, 32);
    assert_eq!(abi_root.as_slice(), crate::encode_digest(&output.root));
    abi_proof.truncate(proof_len);
    assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 0);
    let root = output.root;
    assert!(crate::verify_joinsplit_tree_bytes(&output.proof, &root, 3));
    assert!(crate::verify_joinsplit_tree_bytes(&abi_proof, &root, 3));
    assert!(!crate::verify_joinsplit_tree_bytes(&output.proof, &root, 2));
    let mut changed_root = root.clone();
    changed_root[0] += Val::ONE;
    assert!(!crate::verify_joinsplit_tree_bytes(
        &output.proof,
        &changed_root,
        3
    ));
    assert!(!crate::verify_joinsplit_tree_bytes(
        &output.proof[..output.proof.len() - 1],
        &root,
        3
    ));
    let mut forged = output.proof.clone();
    let first_public = crate::TREE_MAGIC.len() + 4 + 32;
    forged[first_public] ^= 1;
    assert!(!crate::verify_joinsplit_tree_bytes(&forged, &root, 3));
    // Move the first two complete encoded leaves, preserving each proof/public
    // pair. The unchanged verifier must still reject the reordered root chain.
    let first_len = u32::from_le_bytes(
        output.proof[first_public + crate::JS_PUBLIC_INPUTS_LEN
            ..first_public + crate::JS_PUBLIC_INPUTS_LEN + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let second = first_public + crate::JS_PUBLIC_INPUTS_LEN + 4 + first_len;
    let second_len = u32::from_le_bytes(
        output.proof
            [second + crate::JS_PUBLIC_INPUTS_LEN..second + crate::JS_PUBLIC_INPUTS_LEN + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let third = second + crate::JS_PUBLIC_INPUTS_LEN + 4 + second_len;
    let mut reordered = output.proof[..first_public].to_vec();
    reordered.extend_from_slice(&output.proof[second..third]);
    reordered.extend_from_slice(&output.proof[first_public..second]);
    reordered.extend_from_slice(&output.proof[third..]);
    assert!(!crate::verify_joinsplit_tree_bytes(&reordered, &root, 3));
    eprintln!(
        "legacy_gpu_tree_container_verified leaves=3 cpu_after_shutdown=true tamper_checks=5"
    );
}
