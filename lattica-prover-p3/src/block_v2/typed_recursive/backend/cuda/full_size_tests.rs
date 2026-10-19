//! Uses an independently approved registry, never a CUDA-produced key. The
//! controller pins every fixture input and CPU audit executable before launch.
use super::*;
use crate::{
    block_v2::{
        codec,
        commitment::{Context as StatementContext, NodeSummary},
    },
    cuda_compute::Limits as DeviceLimits,
};
use serde::de::DeserializeOwned;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

fn read(path: &Path) -> Vec<u8> {
    assert!(fs::symlink_metadata(path).unwrap().is_file());
    assert!(fs::metadata(path).unwrap().len() <= profile::MAX_PROOF_BYTES as u64);
    let bytes = fs::read(path).unwrap();
    assert!(bytes.len() <= profile::MAX_PROOF_BYTES);
    bytes
}
fn artifact<T: DeserializeOwned + serde::Serialize>(path: &Path, magic: &[u8; 8]) -> T {
    let bytes = read(path);
    assert!(bytes.starts_with(magic));
    codec::decode(&bytes[8..]).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "full-size CUDA typed requests; independently pinned fixture and bounded service required"]
fn cuda_typed_full_size_requests_against_pinned_registry() {
    full_size(false);
}

#[test]
#[ignore = "full-size CUDA cached bindings; independently pinned fixture and bounded service required"]
fn cuda_typed_full_size_cached_bindings_against_pinned_registry() {
    full_size(true);
}

fn phase(
    output: &Path,
    name: &str,
    repetitions: usize,
    mut prove: impl FnMut(usize) -> NodeProof,
) -> (Vec<NodeProof>, Vec<f64>) {
    let mut nodes: Vec<NodeProof> = Vec::with_capacity(repetitions);
    let mut seconds = Vec::with_capacity(repetitions);
    let mut previous = Vec::new();
    for index in 0..repetitions {
        let start = Instant::now();
        let node = prove(index);
        seconds.push(start.elapsed().as_secs_f64());
        let encoded = codec::encode_node(&node).unwrap();
        if let Some(original) = nodes.first() {
            assert_eq!(node.public, original.public);
            assert_ne!(
                encoded, previous,
                "cached bindings must use fresh randomness"
            );
        }
        let suffix = if index == 0 { "" } else { "-cached" };
        write(&output.join(format!("{name}{suffix}.bin")), &encoded);
        previous = encoded;
        nodes.push(node);
    }
    (nodes, seconds)
}

fn full_size(cached_bindings: bool) {
    let directory: PathBuf = std::env::var_os("LATTICA_CUDA_TYPED_FIXTURE")
        .unwrap()
        .into();
    let output: PathBuf = std::env::var_os("LATTICA_CUDA_TYPED_OUTPUT")
        .unwrap()
        .into();
    let expected: serde_json::Value =
        serde_json::from_slice(&read(&directory.join("expected.json"))).unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&read(&directory.join("body.json"))).unwrap();
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&directory.join("height.json"))).unwrap(),
        caps: std::array::from_fn(|i| {
            artifact(&directory.join(format!("key.{}", i + 1)), b"LBV2TP01")
        }),
    };
    let profile: [u8; 32] = serde_json::from_value(expected["profile"].clone()).unwrap();
    assert_eq!(
        registry.id().unwrap(),
        profile,
        "fixture profile differs from this build"
    );
    assert_eq!(registry.height, 1 << 18);
    let chain: [u8; 32] = serde_json::from_value(expected["chain"].clone()).unwrap();
    let height = expected["block_height"].as_u64().unwrap();
    let mint = expected["authorized_issuance"]["3"].as_u64().unwrap();
    let policies = [
        Policy::JoinSplit,
        Policy::Htlc {
            expected_height: height,
        },
        Policy::Htlc {
            expected_height: height,
        },
        Policy::Issuance {
            authorized_mint: mint,
        },
    ];
    let wallets: [WalletProof; 4] = std::array::from_fn(|i| {
        let wallet: WalletProof = artifact(&directory.join(format!("wallet.{i}")), b"LBV2TW01");
        let fields: Vec<u64> =
            serde_json::from_value(body["transactions"][i]["statement"].clone()).unwrap();
        assert_eq!(wallet.chain, chain);
        assert_eq!(
            wallet
                .public
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
            fields
        );
        verify_wallet(&wallet, policies[i]).unwrap();
        wallet
    });
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        DeviceLimits {
            managed_bytes: 7 << 30,
            max_allocation_bytes: 1 << 30,
            ..DeviceLimits::default()
        },
    )
    .unwrap();
    let baseline = crate::proving::cpu_witness_oracle_calls();
    let start = Instant::now();
    let mut session = Session::new_cuda(
        registry.clone(),
        profile,
        3 << 30,
        &runtime,
        Limits {
            construction: ConstructionLimits {
                program_host_bytes: 1 << 30,
                wires: 1 << 24,
                input_values: 1 << 20,
            },
        },
    )
    .unwrap();
    let preparation = start.elapsed().as_secs_f64();
    let repetitions = if cached_bindings { 2 } else { 1 };
    let (left, left_seconds) = phase(&output, "left", repetitions, |_| {
        session
            .wrap_pair([&wallets[0], &wallets[1]], [policies[0], policies[1]], 2)
            .unwrap()
    });
    let (right, right_seconds) = phase(&output, "right", repetitions, |_| {
        session
            .wrap_pair([&wallets[2], &wallets[3]], [policies[2], policies[3]], 2)
            .unwrap()
    });
    // Cached merges/finalizers bind different child proof bytes to the same
    // approved program. Retaining the original witness would fail verification.
    let (merged, merge_seconds) = phase(&output, "merge", repetitions, |index| {
        session.merge(&left[index], &right[index]).unwrap()
    });
    let (roots, finalize_seconds) = phase(&output, "root", repetitions, |index| {
        session.finalize(&merged[index]).unwrap()
    });
    let stats = session.stats();
    assert_eq!(stats.setups, 4);
    assert_eq!(stats.hits, if cached_bindings { 4 } else { 0 });
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), baseline);
    let expected_public = programs::statement(
        NodeSummary {
            context: StatementContext {
                profile_id: profile,
                chain_id: chain,
            },
            level: crate::block_v2::commitment::DEPTH,
            count: u8::try_from(expected["count"].as_u64().unwrap()).unwrap(),
            root: serde_json::from_value(expected["root"].clone()).unwrap(),
        },
        typed_pairs::FINALIZE,
    );
    for root in &roots {
        assert_eq!(root.public, expected_public);
    }
    drop(session);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    let snapshot = runtime.snapshot();
    drop(runtime);
    for root in &roots {
        registry.verify(profile, root, &expected_public).unwrap();
    }
    let mut changed = expected_public;
    changed[programs::ROOT] += Val::ONE;
    assert!(registry
        .verify(profile, roots.last().unwrap(), &changed)
        .is_err());
    let receipt = serde_json::json!({"profile":profile,"height":registry.height,
        "preparation_seconds":preparation,"left_seconds":left_seconds[0],"right_seconds":right_seconds[0],
        "merge_seconds":merge_seconds[0],"finalize_seconds":finalize_seconds[0],
        "phase_seconds":{"left":left_seconds,"right":right_seconds,"merge":merge_seconds,"finalize":finalize_seconds},
        "cached_bindings":cached_bindings,
        "setups":stats.setups,"cache_hits":stats.hits,"snapshot":snapshot,
        "cpu_witness_oracle_calls":0,"cpu_verified_after_cuda_shutdown":true,
        "changed_statement_rejected":true,"independent_cpu_audit_pending":true});
    write(
        &output.join("receipt.json"),
        &serde_json::to_vec_pretty(&receipt).unwrap(),
    );
    println!("cuda_typed_full_size_receipt {receipt}");
}
