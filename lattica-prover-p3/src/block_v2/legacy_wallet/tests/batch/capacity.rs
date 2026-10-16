//! Complete large legacy batches, with public artifacts audited in another process.
use super::*;
use std::{fs, io::Write, path::PathBuf, time::Instant};

const PROOF_BYTES: usize = 4 << 20;

struct Case {
    count: usize,
    htlc: bool,
    abi: bool,
    directory: PathBuf,
}

fn case() -> Case {
    assert!(
        !cfg!(debug_assertions),
        "capacity qualification requires release proving"
    );
    let count = std::env::var("LATTICA_BATCH_CAPACITY_COUNT")
        .unwrap()
        .parse()
        .unwrap();
    assert!([8, 16, 32, 64].contains(&count));
    let htlc = match std::env::var("LATTICA_BATCH_CAPACITY_KIND")
        .unwrap()
        .as_str()
    {
        "joinsplit" => false,
        "htlc" => true,
        _ => panic!("unknown capacity proof kind"),
    };
    let abi = match std::env::var("LATTICA_BATCH_CAPACITY_ROUTE")
        .unwrap()
        .as_str()
    {
        "rust" => false,
        "abi" => true,
        _ => panic!("unknown capacity entry point"),
    };
    Case {
        count,
        htlc,
        abi,
        directory: PathBuf::from(std::env::var_os("LATTICA_BATCH_CAPACITY_DIR").unwrap()),
    }
}

fn fixtures(count: usize) -> (Vec<js::Witness>, Vec<htlc::Witness>) {
    let (js, htlc) = witnesses();
    // Exercise spend/mint and redeem/refund branches. These repeated fixtures
    // qualify proof capacity, not unique, durably applied user transactions.
    (
        (0..count).map(|i| js[i % js.len()].clone()).collect(),
        (0..count).map(|i| htlc[i % htlc.len()].clone()).collect(),
    )
}

fn save(c: &Case, name: &str, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(c.directory.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "prepare trusted synthetic inputs for a separate native C wallet process"]
fn prepare_native_large_batch_inputs_without_gpu() {
    let c = case();
    assert!(c.abi);
    assert!(!gpu_hash::is_enabled());
    let (js, htlc) = fixtures(c.count);
    let (encoded, expected) = if c.htlc {
        (
            htlc.iter()
                .flat_map(crate::encode_htlc_witness)
                .collect::<Vec<_>>(),
            bh::batch_root(&htlc),
        )
    } else {
        (
            js.iter()
                .flat_map(crate::encode_joinsplit_witness)
                .collect::<Vec<_>>(),
            bj::batch_root(&js),
        )
    };
    save(&c, "witness.bin", &encoded);
    save(&c, "expected-root.bin", &crate::encode_digest(&expected));
    assert!(!gpu_hash::is_enabled());
    println!(
        "native_large_batch_inputs_prepared count={} htlc={} gpu_initialized=false synthetic=true",
        c.count, c.htlc
    );
}

#[test]
#[ignore = "one complete large batch in a capped OpenCL service; separate CPU audit required"]
fn gpu_large_batch_is_saved_for_independent_cpu_verification() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let c = case();
    let (js, htlc) = fixtures(c.count);
    assert!(!gpu_hash::is_enabled());
    // The CPU test oracle runs before GPU initialization and outside proving.
    let expected = if c.htlc {
        bh::batch_root(&htlc)
    } else {
        bj::batch_root(&js)
    };
    let expected_bytes = crate::encode_digest(&expected);
    assert_eq!(expected_bytes.len(), 32);
    let _policy = Env::set("LATTICA_PROVING_POLICY", "gpu-required");
    initialize();
    let started = Instant::now();
    let proof = if c.abi {
        let encoded = if c.htlc {
            htlc.iter()
                .flat_map(crate::encode_htlc_witness)
                .collect::<Vec<_>>()
        } else {
            js.iter()
                .flat_map(crate::encode_joinsplit_witness)
                .collect::<Vec<_>>()
        };
        let prove: BatchAbi = if c.htlc {
            crate::lattica_htlc_batch_prove
        } else {
            crate::lattica_batch_prove
        };
        let mut proof = vec![0xa5; PROOF_BYTES];
        let mut root = [0x5a; 32];
        let (mut proof_len, mut root_len) = (0, 0);
        assert_eq!(
            unsafe {
                prove(
                    encoded.as_ptr(),
                    encoded.len(),
                    c.count,
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut proof_len,
                    root.as_mut_ptr(),
                    root.len(),
                    &mut root_len,
                )
            },
            0
        );
        assert_eq!(root_len, 32);
        assert_eq!(root.as_slice(), expected_bytes.as_slice());
        assert!((1..=PROOF_BYTES).contains(&proof_len));
        proof.truncate(proof_len);
        proof
    } else {
        let (proof, report) = if c.htlc {
            bh::prove_batch_to_bytes_with_request(&htlc, request(Policy::GpuRequired)).unwrap()
        } else {
            bj::prove_batch_to_bytes_with_request(&js, request(Policy::GpuRequired)).unwrap()
        };
        check_report(&report);
        proof
    };
    let elapsed_ms = started.elapsed().as_millis();
    assert!((1..=PROOF_BYTES).contains(&proof.len()));
    let memory = gpu_hash::report("legacy_large_batch_complete").unwrap();
    assert_eq!(memory.device_matrices, 0);
    gpu_hash::shutdown().unwrap();
    assert!(gpu_hash::report("legacy_large_batch_after_shutdown").is_none());
    save(&c, "proof.bin", &proof);
    save(&c, "expected-root.bin", &expected_bytes);
    save(
        &c,
        "summary.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "count": c.count, "htlc": c.htlc, "abi": c.abi,
            "proof_bytes": proof.len(), "proof_elapsed_ms": elapsed_ms,
            "managed_peak_bytes": memory.managed_peak_bytes,
            "device_matrices_after_proof": memory.device_matrices,
            "gpu_shutdown": true, "cpu_verified": false,
            "repeated_test_witnesses": true, "delivered_throughput_qualification": false,
        }))
        .unwrap(),
    );
    println!(
        "legacy_large_batch_saved count={} htlc={} abi={} gpu_shutdown=true",
        c.count, c.htlc, c.abi
    );
}

#[test]
#[ignore = "independent CPU audit of a complete saved large legacy batch"]
fn saved_large_batch_verifies_without_gpu() {
    let c = case();
    assert!(!gpu_hash::is_enabled());
    let (js, htlc) = fixtures(c.count);
    let expected = if c.htlc {
        bh::batch_root(&htlc)
    } else {
        bj::batch_root(&js)
    };
    let root = crate::encode_digest(&expected);
    assert_eq!(
        fs::read(c.directory.join("expected-root.bin")).unwrap(),
        root
    );
    let path = c.directory.join("proof.bin");
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
    assert!((1..=PROOF_BYTES as u64).contains(&fs::metadata(&path).unwrap().len()));
    let proof = fs::read(path).unwrap();
    let verify = if c.htlc {
        bh::verify_batch_bytes
    } else {
        bj::verify_batch_bytes
    };
    let abi: VerifyAbi = if c.htlc {
        crate::lattica_htlc_batch_verify
    } else {
        crate::lattica_batch_verify
    };
    let verify_abi = |bytes: &[u8], public: &[Val]| {
        let root = crate::encode_digest(public);
        unsafe { abi(bytes.as_ptr(), bytes.len(), root.as_ptr(), root.len()) == 0 }
    };
    assert!(verify(&proof, &expected));
    assert!(verify_abi(&proof, &expected));
    for index in 0..4 {
        let mut wrong = expected;
        wrong[index] += Val::ONE;
        assert!(!verify(&proof, &wrong));
        assert!(!verify_abi(&proof, &wrong));
    }
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(!verify(&trailing, &expected));
    assert!(!verify_abi(&trailing, &expected));
    let mut decoded: p3_uni_stark::Proof<crate::config::MyConfig> =
        postcard::from_bytes(&proof).unwrap();
    decoded.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
    let damaged = postcard::to_allocvec(&decoded).unwrap();
    assert!(!verify(&damaged, &expected));
    assert!(!verify_abi(&damaged, &expected));
    assert!(!gpu_hash::is_enabled());
    println!("legacy_large_batch_cpu_verified count={} htlc={} abi={} verifier_routes=2 mutations_per_route=6 gpu_initialized=false", c.count, c.htlc, c.abi);
}
