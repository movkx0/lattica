use super::*;
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};

extern "C" {
    fn lattica_cpu_generation_test_seed(owner: *mut c_void, seed: *const u8) -> i32;
    fn lattica_cpu_generation_test_failure(owner: *mut c_void, failure: u32);
    fn lattica_cpu_generation_test_clean(owner: *mut c_void) -> i32;
    fn lattica_cpu_generation_test_rng(
        seed: *const u8,
        counter: u64,
        lanes: u32,
        output: *mut u8,
        bytes: usize,
        next: *mut u64,
    ) -> i32;
}
fn seeded(config: Configuration, seed: u8) -> Generator {
    let mut owner = Generator::new([17; 32], [34; 32], config).unwrap();
    set_seed(&mut owner, seed);
    owner
}
fn set_seed(owner: &mut Generator, seed: u8) {
    let _guard = NATIVE_LOCK.lock().unwrap();
    assert_eq!(
        unsafe { lattica_cpu_generation_test_seed(owner.owner.as_ptr(), [seed; 32].as_ptr()) },
        1
    );
}
fn clean(owner: &Generator) {
    let _guard = NATIVE_LOCK.lock().unwrap();
    assert_eq!(
        unsafe { lattica_cpu_generation_test_clean(owner.owner.as_ptr()) },
        1
    );
}
fn amounts() -> FixtureAmounts {
    FixtureAmounts {
        input: [7, 11],
        output: [5, 13],
    }
}

#[test]
fn aes_interleaving_matches_independent_ctr_and_refuses_wrap() {
    let _guard = NATIVE_LOCK.lock().unwrap();
    let seed = [91u8; 32];
    let cipher = Aes256::new_from_slice(&seed).unwrap();
    for lanes in [1, 4, 8] {
        for counter in [0, (1u64 << 32) - 256, (1u64 << 32) - 1, 1u64 << 32] {
            for bytes in [0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1024, 4097] {
                let blocks = bytes.div_ceil(16) as u64;
                let mut output = vec![0xa5; bytes.max(1)];
                let mut next = u64::MAX;
                let result = unsafe {
                    lattica_cpu_generation_test_rng(
                        seed.as_ptr(),
                        counter,
                        lanes,
                        output.as_mut_ptr(),
                        bytes,
                        &mut next,
                    )
                };
                if blocks > (1u64 << 32) - counter {
                    assert_eq!(result, 0);
                    assert_eq!(next, u64::MAX);
                    assert!(output.iter().all(|&v| v == 0xa5));
                    continue;
                }
                assert_eq!(result, 1);
                assert_eq!(next, counter + blocks);
                let mut expected = Vec::new();
                for i in 0..blocks {
                    let mut block = aes::Block::default();
                    block[..4].copy_from_slice(&((counter + i) as u32).to_le_bytes());
                    cipher.encrypt_block(&mut block);
                    expected.extend_from_slice(&block);
                }
                assert_eq!(
                    &output[..bytes],
                    &expected[..bytes],
                    "lanes={lanes}, counter={counter}, bytes={bytes}"
                );
            }
        }
    }
}

#[test]
fn cpu_generation_variants_match_verify_and_clear() {
    for seed in [3, 19] {
        let mut baseline = seeded(Configuration::default(), seed);
        let expected = baseline.generate(3, amounts()).unwrap();
        clean(&baseline);
        assert!(super::super::verify(&[34; 32], &expected.statement, &expected.proof).unwrap());
        let mut mutated = expected.proof.clone();
        mutated[32] ^= 1;
        assert!(!super::super::verify(&[34; 32], &expected.statement, &mutated).unwrap());
        assert!(!super::super::verify(&[35; 32], &expected.statement, &expected.proof).unwrap());
        for lanes in [1, 4, 8] {
            let mut owner = seeded(
                Configuration {
                    aes_lanes: lanes,
                    cache_public_parameters: true,
                    ..Configuration::default()
                },
                seed,
            );
            for hit in [0, 1] {
                let actual = owner.generate(3, amounts()).unwrap();
                clean(&owner);
                assert_eq!(actual.statement, expected.statement);
                assert_eq!(actual.proof, expected.proof);
                assert_eq!(actual.statistics.attempts, expected.statistics.attempts);
                assert_eq!(
                    actual.statistics.random_calls,
                    expected.statistics.random_calls
                );
                assert_eq!(
                    actual.statistics.random_blocks,
                    expected.statistics.random_blocks
                );
                assert_eq!(actual.statistics.proposals, expected.statistics.proposals);
                assert_eq!(actual.statistics.parameter_cache_hits, hit);
            }
        }
    }
}

#[test]
fn cpu_generation_refusals_clear_and_recover() {
    let mut owner = seeded(
        Configuration {
            cache_public_parameters: true,
            ..Configuration::default()
        },
        7,
    );
    let limits = Limits::default();
    for (limited, expected) in [
        (
            Limits {
                random_call_limit: 1,
                ..limits
            },
            3,
        ),
        (
            Limits {
                proposal_limit: 1,
                ..limits
            },
            4,
        ),
    ] {
        owner.config.limits = limited;
        match owner.generate(3, amounts()).unwrap_err() {
            Error::Refused(stats) => assert_eq!(stats.status, expected),
            error => panic!("{error}"),
        }
        clean(&owner);
    }
    owner.config.limits = limits;
    {
        let _guard = NATIVE_LOCK.lock().unwrap();
        unsafe { lattica_cpu_generation_test_failure(owner.owner.as_ptr(), 1) };
    }
    match owner.generate(3, amounts()).unwrap_err() {
        Error::Refused(stats) => assert_eq!(stats.status, 5),
        error => panic!("{error}"),
    }
    clean(&owner);
    {
        let _guard = NATIVE_LOCK.lock().unwrap();
        unsafe { lattica_cpu_generation_test_failure(owner.owner.as_ptr(), 0) };
    }
    // Bound attempts independently of RNG/proposal limits. Find a deterministic
    // retrying transaction instead of making a probabilistic test assertion.
    owner.config.limits.max_attempts = 1;
    let mut refused = false;
    for seed in 1..=32 {
        set_seed(&mut owner, seed);
        if let Err(Error::Refused(stats)) = owner.generate(3, amounts()) {
            assert_eq!(stats.status, 2);
            assert_eq!(stats.attempts, 1);
            refused = true;
            break;
        }
    }
    assert!(refused);
    clean(&owner);
    owner.config.limits = limits;
    set_seed(&mut owner, 7);
    let recovered = owner.generate(3, amounts()).unwrap();
    let mut fresh = seeded(Configuration::default(), 7);
    let expected = fresh.generate(3, amounts()).unwrap();
    assert_eq!(recovered.statement, expected.statement);
    assert_eq!(recovered.proof, expected.proof);
    clean(&owner);
    clean(&fresh);
    assert!(super::super::verify(&[34; 32], &recovered.statement, &recovered.proof).unwrap());
}

#[test]
fn cpu_generation_fresh_entropy_and_setup_binding() {
    let mut owner = Generator::new([17; 32], [34; 32], Configuration::default()).unwrap();
    let first = owner.generate(9, amounts()).unwrap();
    let second = owner.generate(9, amounts()).unwrap();
    assert_ne!(first.statement, second.statement);
    assert_ne!(first.proof, second.proof);
    for output in [first, second] {
        assert!(super::super::verify(&[34; 32], &output.statement, &output.proof).unwrap());
    }
    clean(&owner);
    assert!(owner.generate(10, amounts()).is_err());
    assert!(owner
        .generate(
            1,
            FixtureAmounts {
                input: [1, 2],
                output: [1, 1]
            }
        )
        .is_err());
    assert!(Generator::new(
        [0; 32],
        [0; 32],
        Configuration {
            aes_lanes: 2,
            ..Configuration::default()
        }
    )
    .is_err());
}

/// Compare exactly the same rejection paths in alternating order. This is a
/// diagnostic entropy feature, never a production/fresh-entropy benchmark.
#[test]
#[ignore]
fn cpu_generation_paired_optimization_screen() {
    use sha3::{Digest, Sha3_256};
    let variants = [
        ("scalar", 1, false),
        ("aes4", 4, false),
        ("aes8", 8, false),
        ("cache", 1, true),
    ];
    let mut rows = Vec::new();
    for workload in 0..2u8 {
        let setup = [17 + 34 * workload; 32];
        let context = [34 + 34 * workload; 32];
        for (count, samples) in [(1, 100), (3, 10), (4, 10)] {
            for sample in 0..samples {
                let mut digests = Vec::new();
                let mut attempt_counts = Vec::new();
                for position in 0..variants.len() {
                    let (name, lanes, cache) = variants[(position + sample) % variants.len()];
                    let start = Instant::now();
                    let mut owner = Generator::new(
                        setup,
                        context,
                        Configuration {
                            aes_lanes: lanes,
                            cache_public_parameters: cache,
                            ..Configuration::default()
                        },
                    )
                    .unwrap();
                    let mut outputs = Vec::with_capacity(count);
                    let mut attempts = 0;
                    let mut spend_ns = 0;
                    let mut parameters_ns = 0;
                    for ordinal in 0..count {
                        let seed: [u8; 32] =
                            Sha3_256::digest([workload, count as u8, sample as u8, ordinal as u8])
                                .into();
                        {
                            let _guard = NATIVE_LOCK.lock().unwrap();
                            assert_eq!(
                                unsafe {
                                    lattica_cpu_generation_test_seed(
                                        owner.owner.as_ptr(),
                                        seed.as_ptr(),
                                    )
                                },
                                1
                            );
                        }
                        let output = owner
                            .generate((sample * count + ordinal) as u64 % 10, amounts())
                            .unwrap();
                        assert!(
                            super::super::verify(&context, &output.statement, &output.proof)
                                .unwrap()
                        );
                        attempts += output.statistics.attempts;
                        spend_ns += output.statistics.spend_ns;
                        parameters_ns += output.statistics.parameters_ns;
                        outputs.push(output);
                    }
                    drop(owner);
                    let whole_stage_ns = start.elapsed().as_nanos();
                    let mut digest = Sha3_256::new();
                    for output in outputs {
                        digest.update(&output.statement);
                        digest.update(&output.proof);
                    }
                    digests.push(digest.finalize());
                    attempt_counts.push(attempts);
                    rows.push(
                        serde_json::json!({"workload":workload,"transactions":count,"sample":sample,
                        "variant":name,"whole_stage_ns":whole_stage_ns,"spend_ns":spend_ns,
                        "parameters_ns":parameters_ns,"attempts":attempts}),
                    );
                }
                assert!(digests.iter().all(|d| *d == digests[0]));
                assert!(attempt_counts.iter().all(|a| *a == attempt_counts[0]));
            }
        }
    }
    println!(
        "CPU_GENERATION_PAIRED_SCREEN {}",
        serde_json::json!({
        "schema":"lattica-cpu-generation-paired-screen-v1","diagnostic_entropy":true,
        "byte_identical":true,"independent_verification":true,"gpu_generation_calls":0,"rows":rows})
    );
}
