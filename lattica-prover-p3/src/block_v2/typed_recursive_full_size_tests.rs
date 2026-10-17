//! Qualification against separately pinned, transaction-bearing public fixtures.
//! The controller verifies archived file hashes before launching these tests.
use super::*;
use crate::block_v2::{
    codec,
    execution::job::{Job, RegistryPin, VerifiedWallet},
    gpu_hash,
    machine::{self, gpu_backend::resources::Bounds},
    typed_fixture,
};
use crate::native_gpu::{lattica_gpu_public_worker_initialize_from_env, lattica_gpu_shutdown};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::de::DeserializeOwned;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[path = "typed_recursive_full_size_tests/nonempty.rs"]
mod nonempty;
#[path = "typed_recursive_full_size_tests/mixed_pairs.rs"]
mod mixed_pairs;

fn directory() -> PathBuf {
    std::env::var_os("LATTICA_FULL_SIZE_FIXTURE")
        .unwrap()
        .into()
}

fn output() -> PathBuf {
    std::env::var_os("LATTICA_FULL_SIZE_OUTPUT").unwrap().into()
}

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

fn registry() -> Registry<12> {
    let path = directory();
    let height: usize = serde_json::from_slice(&read(&path.join("height.json"))).unwrap();
    assert_eq!(height, 1 << 18);
    let registry = Registry {
        height,
        caps: std::array::from_fn(|index| {
            artifact(&path.join(format!("key.{}", index + 1)), b"LBV2TP01")
        }),
    };
    RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    registry
}

fn wallet(index: usize, policy: Policy, kind: &str) -> WalletProof {
    let path = directory();
    let body: serde_json::Value = serde_json::from_slice(&read(&path.join("body.json"))).unwrap();
    let chain: [u8; 32] = serde_json::from_value(body["chain"].clone()).unwrap();
    assert_eq!(chain, typed_fixture::CHAIN);
    assert_eq!(body["transactions"][index]["kind"], kind);
    let expected: Vec<u64> =
        serde_json::from_value(body["transactions"][index]["statement"].clone()).unwrap();
    let wallet: WalletProof = artifact(&path.join(format!("wallet.{index}")), b"LBV2TW01");
    assert_eq!(wallet.chain, chain);
    assert_eq!(
        wallet
            .public
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect::<Vec<_>>(),
        expected
    );
    verify_wallet(&wallet, policy).unwrap();
    wallet
}

fn program_storage(program: &machine::Program) -> serde_json::Value {
    use machine::program::{Op, Row, Wire};
    let hints = |op: &Op| match op {
        Op::SelectHint { entries, bits, .. } => {
            (entries.capacity() + bits.capacity()) * std::mem::size_of::<Wire>()
        }
        _ => 0,
    };
    let mut row_operations = 0;
    for row in &program.rows {
        if let Row::Alu(ops) | Row::Cubic(ops) = row {
            row_operations += ops.capacity();
        }
    }
    serde_json::json!({
        "operation_bytes": std::mem::size_of::<Op>(),
        "row_bytes": std::mem::size_of::<Row>(),
        "operation_count": program.operations.len(),
        "operation_capacity": program.operations.capacity(),
        "operation_storage_bytes": program.operations.capacity() * std::mem::size_of::<Op>(),
        "operation_hint_bytes": program.operations.iter().map(hints).sum::<usize>(),
        "row_capacity": program.rows.capacity(),
        "row_storage_bytes": program.rows.capacity() * std::mem::size_of::<Row>(),
        "row_operation_capacity": row_operations,
        "row_operation_storage_bytes": row_operations * std::mem::size_of::<u32>(),
        "row_hint_bytes": 0,
        "reference_storage_bytes": program.references.capacity() * std::mem::size_of::<u32>(),
        "construction_peak_bytes": program.construction_host_bytes(),
        "is_rss_bound": false,
    })
}

#[test]
#[ignore = "bounded CPU compilation of a real full-size registry mode; does not prove or admit GPU work"]
fn full_size_mode_resource_geometry() {
    assert!(!gpu_hash::is_enabled());
    let registry = registry();
    let wallets = [
        wallet(0, Policy::JoinSplit, "joinsplit"),
        wallet(
            1,
            Policy::Htlc {
                expected_height: typed_fixture::HEIGHT,
            },
            "htlc_redeem",
        ),
        wallet(
            3,
            Policy::Issuance {
                authorized_mint: typed_fixture::MINT,
            },
            "issuance",
        ),
    ];
    let mode: u64 = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=12).contains(&mode));
    let compiled = typed_pairs::compile_registration(
        registry.height,
        mode,
        paired_templates(mode, [&wallets[0], &wallets[1], &wallets[2]]),
    )
    .unwrap();
    let required_height = compiled.program.height();
    let program = compiled.program.pad_to(registry.height).unwrap();
    let bounds = Bounds::for_program(&program).unwrap();
    let reservation = bounds.reservation(1).unwrap();
    let report = serde_json::json!({
        "version": 1, "height": registry.height, "mode": mode,
        "required_height": required_height, "profile": registry.id().unwrap(),
        "witness_bounds": bounds, "witness_reservation": reservation,
        "program_storage": program_storage(&program),
        "public_wallets_cpu_verified": true, "gpu_initialized": false,
        "proof_completed": false,
    });
    fs::write(output(), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("full_size_mode_geometry {report}");
    assert!(!gpu_hash::is_enabled());
}

#[test]
#[ignore = "full-size two-wallet paired proof under exact owned GPU admission and resource caps"]
fn full_size_pair_gpu_proof_matches_archived_registry() {
    assert!(!gpu_hash::is_enabled());
    // Public wallet verification uses Rayon too. Native worker admission
    // must initialize the assigned pool before any verifier runs.
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    let registry = registry();
    let profile = registry.id().unwrap();
    let pin = RegistryPin::new_typed(&registry, profile).unwrap();
    let wallets = [
        wallet(0, Policy::JoinSplit, "joinsplit"),
        wallet(4, Policy::JoinSplit, "joinsplit"),
    ];
    let verified = [0, 4].map(|index| {
        VerifiedWallet::verify_typed(
            pin,
            &registry,
            typed_fixture::CHAIN,
            Policy::JoinSplit,
            &read(&directory().join(format!("wallet.{index}"))),
        )
        .unwrap()
    });
    let expected = Job::typed_pair(0, verified[0], Some(verified[1]))
        .unwrap()
        .expected_public();
    let mut session = Session::new(registry.clone(), profile, 3 << 30).unwrap();
    let proof = session
        .wrap_pair([&wallets[0], &wallets[1]], [Policy::JoinSplit; 2], 2)
        .unwrap();
    assert_eq!(proof.public, expected);
    let bytes = codec::encode_node(&proof).unwrap();
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 0 }
    );
    assert!(gpu_hash::report("full-size pair complete").is_some());
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    // Backend selection is immutable for this process; shutdown removes the
    // context and allocations, not the selected-backend flag.
    assert!(gpu_hash::report("full-size pair after shutdown").is_none());
    registry.verify(profile, &proof, &expected).unwrap();
    let mut altered = expected;
    altered[programs::COUNT] += Val::ONE;
    assert!(registry.verify(profile, &proof, &altered).is_err());
    assert!(gpu_hash::report("full-size pair after CPU verification").is_none());
    fs::write(output(), bytes).unwrap();
    println!("full_size_pair_gpu_verified rows={} transactions=2 mode=1 archived_registry=true cpu_verified_after_shutdown=true altered_statement_rejected=true", registry.height);
}

#[test]
#[ignore = "full-size Empty/merge/finalizer qualification with pinned public inputs and resource caps"]
fn full_size_recursive_gpu_proof_matches_archived_registry() {
    assert!(!gpu_hash::is_enabled());
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    let registry = registry();
    let profile = registry.id().unwrap();
    let mode: u64 = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    assert!([programs::EMPTY, programs::MERGE, typed_pairs::FINALIZE].contains(&mode));
    let context = Context {
        profile_id: profile,
        chain_id: typed_fixture::CHAIN,
    };
    let empty = commitment::empty_subtree(context, 1).unwrap();
    let empty_public = programs::statement(empty, programs::EMPTY);
    let mut pair = None;
    let mut right = None;
    let mut child = None;
    let mut expected_node = empty;
    if mode != programs::EMPTY {
        let pin = RegistryPin::new_typed(&registry, profile).unwrap();
        let verified = [0, 4].map(|index| {
            let _ = wallet(index, Policy::JoinSplit, "joinsplit");
            VerifiedWallet::verify_typed(
                pin,
                &registry,
                typed_fixture::CHAIN,
                Policy::JoinSplit,
                &read(&directory().join(format!("wallet.{index}"))),
            )
            .unwrap()
        });
        let pair_public = Job::typed_pair(0, verified[0], Some(verified[1]))
            .unwrap()
            .expected_public();
        let load = |name: &str, expected: &[Val; programs::PUBLIC_VALUES]| {
            let path = PathBuf::from(std::env::var_os(name).unwrap());
            let node = codec::decode_node(&read(&path)).unwrap();
            registry.verify(profile, &node, expected).unwrap();
            node
        };
        pair = Some(load("LATTICA_FULL_SIZE_PAIR", &pair_public));
        expected_node = commitment::merge_nodes(
            recursive::summary_with_modes(&pair_public, 12).unwrap(),
            empty,
        )
        .unwrap();
        if mode == programs::MERGE {
            right = Some(load("LATTICA_FULL_SIZE_EMPTY", &empty_public));
        } else {
            child = Some(load(
                "LATTICA_FULL_SIZE_MERGE",
                &programs::statement(expected_node, programs::MERGE),
            ));
            while expected_node.level < commitment::DEPTH {
                expected_node = commitment::merge_nodes(
                    expected_node,
                    commitment::empty_subtree(context, expected_node.level).unwrap(),
                )
                .unwrap();
            }
        }
    }
    let expected = programs::statement(expected_node, mode);
    let mut session = Session::new(registry.clone(), profile, 3 << 30).unwrap();
    let proof = match mode {
        programs::EMPTY => session.empty(typed_fixture::CHAIN, 1),
        programs::MERGE => session.merge(pair.as_ref().unwrap(), right.as_ref().unwrap()),
        typed_pairs::FINALIZE => session.finalize(child.as_ref().unwrap()),
        _ => unreachable!(),
    }
    .unwrap();
    assert_eq!(proof.public, expected);
    let bytes = codec::encode_node(&proof).unwrap();
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 0 }
    );
    assert!(gpu_hash::report("full-size recursive proof complete").is_some());
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    assert!(gpu_hash::report("full-size recursion after shutdown").is_none());
    let decoded = codec::decode_node(&bytes).unwrap();
    registry.verify(profile, &decoded, &expected).unwrap();
    let mut altered = expected;
    altered[programs::ROOT] += Val::ONE;
    assert!(registry.verify(profile, &decoded, &altered).is_err());
    assert!(gpu_hash::report("full-size recursion after CPU verification").is_none());
    fs::write(output(), bytes).unwrap();
    println!("full_size_recursive_gpu_verified rows={} transactions={} mode={mode} level={} archived_registry=true cpu_verified_after_shutdown=true altered_statement_rejected=true",
        registry.height, expected_node.count, expected_node.level);
}
