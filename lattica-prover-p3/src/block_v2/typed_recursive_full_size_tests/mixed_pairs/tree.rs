//! Cold and cached recursion over four distinct archived wallet policies.

use super::*;

fn jobs(registry: &Registry<12>) -> [Job; 4] {
    // The qualified parent pairs use wallet indices [0, 5] and [2, 7].
    // Their public statements are independent of scheduler range positions.
    let (_, _, left) = fixture_at(registry, 4, false, 0);
    let (_, _, right) = fixture_at(registry, 8, true, 2);
    assert_ne!(left.expected().root, right.expected().root);
    let merged = Job::merge(&left, &right).unwrap();
    let finalized = Job::finalize(&merged).unwrap();
    assert_eq!((merged.expected().count, merged.expected().level), (4, 2));
    assert_eq!(
        (finalized.expected().count, finalized.expected().level),
        (4, commitment::DEPTH)
    );
    [left, right, merged, finalized]
}

fn tree_mode() -> (u64, usize) {
    let mode = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    let index = match mode {
        programs::MERGE => 2,
        typed_pairs::FINALIZE => 3,
        _ => panic!("unsupported mixed tree mode"),
    };
    (mode, index)
}

fn warm_output() -> PathBuf {
    output().with_file_name("node-proof-warm.bin")
}

#[test]
#[ignore = "full-size mixed-policy merge/finalizer with cold setup and warm cache reuse"]
fn full_size_mixed_tree_gpu_proofs_reuse_cache() {
    assert!(!gpu_hash::is_enabled());
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    let registry = registry();
    let profile = registry.id().unwrap();
    let jobs = jobs(&registry);
    let (mode, index) = tree_mode();
    let load = |name: &str, job: &Job| {
        let path = PathBuf::from(std::env::var_os(name).unwrap());
        let proof = codec::decode_node(&read(&path)).unwrap();
        registry
            .verify(profile, &proof, &job.expected_public())
            .unwrap();
        proof
    };
    let dependencies = if mode == programs::MERGE {
        vec![
            load("LATTICA_FULL_SIZE_PAIR", &jobs[0]),
            load("LATTICA_FULL_SIZE_RIGHT_PAIR", &jobs[1]),
        ]
    } else {
        vec![load("LATTICA_FULL_SIZE_MERGE", &jobs[2])]
    };
    let mut session = Session::new(registry.clone(), profile, 3 << 30).unwrap();
    let outputs: [_; 2] = std::array::from_fn(|iteration| {
        let proof = if mode == programs::MERGE {
            session.merge(&dependencies[0], &dependencies[1])
        } else {
            session.finalize(&dependencies[0])
        }
        .unwrap();
        assert_eq!(proof.public, jobs[index].expected_public());
        assert_eq!(
            session.stats(),
            recursive::CacheStats {
                setups: 1,
                hits: iteration as u64,
            }
        );
        codec::encode_node(&proof).unwrap()
    });
    assert_ne!(outputs[0], outputs[1]);
    assert!(gpu_hash::report("mixed tree GPU proofs complete").is_some());
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    for bytes in &outputs {
        verify(&registry, &jobs[index], bytes);
    }
    fs::write(output(), &outputs[0]).unwrap();
    fs::write(warm_output(), &outputs[1]).unwrap();
    println!("full_size_mixed_tree_verified proofs=2 rows={} transactions=4 mode={mode} level={} wallets=0,5,2,7 setups=1 hits=1 fresh_bytes=true cpu_verified_after_shutdown=true altered_statements_rejected=8", registry.height, jobs[index].expected().level);
}

#[test]
#[ignore = "independent CPU verification of both persisted mixed-tree proofs after GPU exit"]
fn full_size_mixed_tree_saved_proofs_verify_without_gpu() {
    assert!(!gpu_hash::is_enabled());
    let registry = registry();
    let jobs = jobs(&registry);
    let (mode, index) = tree_mode();
    let outputs = [read(&output()), read(&warm_output())];
    assert_ne!(outputs[0], outputs[1]);
    for bytes in &outputs {
        verify(&registry, &jobs[index], bytes);
    }
    println!("full_size_mixed_tree_cpu_verified proofs=2 rows={} transactions=4 mode={mode} level={} gpu_initialized=false altered_statements_rejected=8", registry.height, jobs[index].expected().level);
}
