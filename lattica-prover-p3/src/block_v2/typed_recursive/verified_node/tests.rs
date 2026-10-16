use super::*;
use crate::block_v2::codec;
use crate::spill_alloc::allocation_requests::measure;
use std::{fs, path::PathBuf, time::Instant};

fn fixture() -> (CheckedRegistry, Vec<Vec<u8>>) {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let registry = Registry {
        height: serde_json::from_slice(&fs::read(directory.join("height.json")).unwrap()).unwrap(),
        caps: std::array::from_fn(|i| {
            let bytes = fs::read(directory.join(format!("key.{}", i + 1))).unwrap();
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    let seeds = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_NODES").unwrap());
    let mut paths: Vec<_> = fs::read_dir(seeds)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 2);
    let bytes = paths
        .iter()
        .map(|path| {
            assert!(fs::symlink_metadata(path).unwrap().is_file());
            assert!(fs::metadata(path).unwrap().len() <= profile::MAX_PROOF_BYTES as u64);
            fs::read(path).unwrap()
        })
        .collect();
    (CheckedRegistry::new(registry).unwrap(), bytes)
}

fn decode(bytes: &[u8]) -> NodeProof {
    codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT)
        .node(bytes)
        .unwrap()
}

fn approve(registry: &CheckedRegistry, bytes: &[u8]) -> VerifiedNodeInput {
    let node = decode(bytes);
    let expected = node.public;
    VerifiedNodeInput::verify(&registry.as_ref(), node, &expected).unwrap()
}

#[test]
#[ignore = "independent CPU checks of archived count-32 inputs; no GPU initialization"]
fn owned_inputs_bind_statement_registry_and_numerical_proof() {
    let (registry, bytes) = fixture();
    let mut session = Session::from_checked(registry.clone(), 512 << 20).unwrap();
    let mut other = registry.as_registry().clone();
    other.caps[0][0][0] += Val::ONE;
    let other = CheckedRegistry::new(other).unwrap();
    let mut other_session = Session::from_checked(other.clone(), 512 << 20).unwrap();
    let mut negative_cases = 0;
    for bytes in &bytes {
        let node = decode(bytes);
        let expected = node.public;
        let backing = node.proof.opened_values.instances.as_ptr();
        let verified = VerifiedNodeInput::verify(&registry.as_ref(), node, &expected).unwrap();
        assert_eq!(
            verified.node.proof.opened_values.instances.as_ptr(),
            backing
        );
        let (result, allocations) = measure(|| verified.check_session(&session));
        result.unwrap();
        assert_eq!(
            (allocations.calls, allocations.bytes, allocations.overflow),
            (0, 0, false)
        );

        // Every expected public field is bound, including mode, chain, profile,
        // count, level and roots. No changed statement can receive an approval.
        for field in 0..PUBLIC_VALUES {
            let mut changed = expected;
            changed[field] += Val::ONE;
            assert!(
                VerifiedNodeInput::verify(&registry.as_ref(), decode(bytes), &changed).is_err()
            );
            negative_cases += 1;
        }
        let mut changed = decode(bytes);
        changed.public[programs::ROOT] += Val::ONE;
        assert!(VerifiedNodeInput::verify(&registry.as_ref(), changed, &expected).is_err());
        assert!(VerifiedNodeInput::verify(&other.as_ref(), decode(bytes), &expected).is_err());
        negative_cases += 2;

        let mut changed = decode(bytes);
        changed.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
        let expected_error = session
            .verify_registered(&changed, &expected)
            .unwrap_err()
            .to_string();
        assert_eq!(
            session.merge(&changed, &changed).err().unwrap().to_string(),
            expected_error
        );
        assert_eq!(
            session.finalize(&changed).err().unwrap().to_string(),
            expected_error
        );
        assert_eq!(
            VerifiedNodeInput::verify(&registry.as_ref(), changed, &expected)
                .err()
                .unwrap()
                .to_string(),
            expected_error
        );
        negative_cases += 3;

        // The second caller cannot consume an approval under different caps.
        // Both positions in a merge and the finalizer are checked before proving.
        assert!(other_session.finalize_verified(verified).is_err());
        assert!(other_session
            .merge_verified(approve(&registry, bytes), approve(&registry, bytes))
            .is_err());
        let wrong_profile = VerifiedNodeInput {
            node: decode(bytes),
            profile: other.profile(),
        };
        // Private test-only construction exercises the right-position guard;
        // no constructor outside this module can forge an approval this way.
        assert!(session
            .merge_verified(approve(&registry, bytes), wrong_profile)
            .is_err());
        negative_cases += 3;
        assert_eq!(session.stats(), recursive::CacheStats::default());
        assert_eq!(other_session.stats(), recursive::CacheStats::default());
    }
    println!(
        "verified_node_inputs {}",
        serde_json::json!({
            "nodes": bytes.len(), "negative_cases": negative_cases,
            "backing_moved": true, "handoff_allocations": 0,
            "ordinary_entrypoints_verify": true, "gpu_initialized": false,
        })
    );
}

#[test]
#[ignore = "measure original numerical verification and immutable handoff on archived inputs"]
fn owned_input_handoff_cost_and_inline_storage() {
    let (registry, bytes) = fixture();
    let session = Session::from_checked(registry.clone(), 512 << 20).unwrap();
    let mut observations = Vec::new();
    for (index, bytes) in bytes.iter().enumerate() {
        for round in 0..5 {
            let node = decode(bytes);
            let expected = node.public;
            let start = Instant::now();
            registry.verify(&node, &expected).unwrap();
            let first_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            session.verify_registered(&node, &expected).unwrap();
            let duplicate_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            let input = VerifiedNodeInput::verify(&registry.as_ref(), node, &expected).unwrap();
            let approved_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            input.check_session(&session).unwrap();
            let handoff_ns = start.elapsed().as_nanos();
            observations.push(serde_json::json!({
                "node": index, "round": round, "original_verifier_ns": first_ns,
                "duplicate_verifier_ns": duplicate_ns, "approval_verifier_ns": approved_ns,
                "handoff_ns": handoff_ns,
            }));
        }
    }
    assert_eq!(
        std::mem::size_of::<VerifiedNodeInput>(),
        std::mem::size_of::<NodeProof>() + 32
    );
    println!(
        "verified_node_cost {}",
        serde_json::json!({
            "observations": observations, "extra_inline_bytes_per_input": 32,
            "added_heap_buffers": 0, "workflow_measurement": false,
        })
    );
}
