//! Process-isolated admission tests: invalid inputs must not reach CPU proving.
use crate::config::Val;
use p3_field::PrimeCharacteristicRing;

fn isolated(name: &str, test: impl FnOnce()) {
    isolated_with_policy(name, "gpu-required", test);
}

fn isolated_with_policy(name: &str, policy: &str, test: impl FnOnce()) {
    const CHILD: &str = "LATTICA_TEST_CPU_ENTRYPOINT_POLICY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        test();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            &format!("proving::tests::entrypoints::{name}"),
            "--exact",
            "--include-ignored",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LATTICA_PROVING_POLICY", policy)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "block-v2")]
#[test]
fn recursive_fixture_helpers_reject_before_witness_arithmetic() {
    isolated(
        "recursive_fixture_helpers_reject_before_witness_arithmetic",
        || {
            use crate::block_v2::recursive::{demo_wallet, demo_wallet_eight};
            // Policy admission precedes both valid fixture construction and
            // invalid-index handling, so neither route reaches the CPU prover.
            for index in [0, usize::MAX] {
                for result in [demo_wallet(index), demo_wallet_eight(index)] {
                    let error = result.err().expect("CPU fixture ignored GPU-required");
                    assert!(error.to_string().contains("GpuRequired"), "{error}");
                }
            }
        },
    );
}

#[cfg(feature = "gpu")]
#[test]
fn mixed_research_prover_rejects_before_debug_constraint_audit() {
    isolated(
        "mixed_research_prover_rejects_before_debug_constraint_audit",
        || {
            use crate::joinsplit_air::{JoinSplitAir, WIDTH};
            use crate::quotient_gpu::{prove_gpu, QuotientMode};
            use p3_matrix::dense::RowMajorMatrix;
            let config = crate::config::make_config();
            for mode in [QuotientMode::P3, QuotientMode::Cpu, QuotientMode::Gpu] {
                rejected_panic(|| {
                    // Deliberately malformed: a debug constraint audit would
                    // panic for a different reason if it ran before admission.
                    prove_gpu(
                        &config,
                        &JoinSplitAir,
                        RowMajorMatrix::new(vec![], WIDTH),
                        &[],
                        mode,
                    );
                });
            }
        },
    );
}

#[cfg(feature = "block-v2")]
#[test]
#[ignore = "two real CPU wallet fixture proofs; run in a bounded service"]
fn recursive_fixture_helpers_cpu_reference_proofs_verify() {
    isolated_with_policy(
        "recursive_fixture_helpers_cpu_reference_proofs_verify",
        "cpu-required",
        || {
            use crate::block_v2::recursive::{demo_wallet, demo_wallet_eight, verify_wallet};
            for mut wallet in [demo_wallet(0).unwrap(), demo_wallet_eight(7).unwrap()] {
                verify_wallet(&wallet).unwrap();
                wallet.public[crate::joinsplit_air::PI_FEE] += Val::ONE;
                assert!(verify_wallet(&wallet).is_err());
            }
        },
    );
}

fn rejected_panic(f: impl FnOnce()) {
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .expect_err("CPU prover ignored the required-GPU policy");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(
        message.contains("policy") && message.contains("GpuRequired"),
        "{message}"
    );
}

#[test]
fn demo_and_measurement_helpers_reject_before_cpu_proving() {
    isolated(
        "demo_and_measurement_helpers_reject_before_cpu_proving",
        || {
            assert!(crate::poseidon2_air::prove_verify([Val::ZERO; 8])
                .unwrap_err()
                .contains("GpuRequired"));
            let mut js = crate::joinsplit_air::demo_witness();
            js.fee = u64::MAX;
            let mut htlc = crate::htlc_air::demo_witness();
            htlc.fee = u64::MAX;
            rejected_panic(|| {
                crate::joinsplit_air::measure(&js);
            });
            rejected_panic(|| {
                crate::htlc_air::measure(&htlc);
            });
        },
    );
}

#[cfg(feature = "recursion")]
#[test]
fn research_entrypoints_reject_before_trace_or_inner_proof_parsing() {
    isolated(
        "research_entrypoints_reject_before_trace_or_inner_proof_parsing",
        || {
            use crate::config::Challenge;
            use crate::recursion::{
                aggregation as a, fri_fold, fri_merkle, transcript, verifier_air as v,
            };
            let z = Val::ZERO;
            let e = Challenge::ZERO;
            rejected_panic(|| {
                v::prove_transcript(&[], &[], [z; 2], [z; 2]);
            });
            rejected_panic(|| {
                v::prove_sample_bits(z, 0);
            });
            rejected_panic(|| {
                v::prove_reduced_opening([z; 4], [e; 4], e, z, e, e);
            });
            rejected_panic(|| {
                v::prove_leaf_hash(&[], [z; 4]);
            });
            rejected_panic(|| {
                v::prove_domain_selectors(e, [e; 4]);
            });
            rejected_panic(|| {
                v::prove_fri_transcript(&[], &[]);
            });
            rejected_panic(|| {
                v::prove_constraint_check(e, e, e, e, e, e, e, z);
            });
            rejected_panic(|| {
                v::prove_ccs(e, e, e, e, z, e);
            });
            rejected_panic(|| {
                fri_merkle::prove_opening([z; 4], &[], [z; 4]);
            });
            rejected_panic(|| {
                fri_fold::prove_fold_chain(e, &[], &[], z, e);
            });
            rejected_panic(|| {
                fri_fold::prove_fold(e, e, e, z, e);
            });
            rejected_panic(|| {
                transcript::prove_squeeze(&[], [z; 4]);
            });
            let dummy = a::JoinSplitAggregateInput {
                proof_bytes: &[],
                public_values: &[],
            };
            for result in [
                a::prove_joinsplit_aggregate_research(
                    &[],
                    a::ResearchAggregationOptions::default(),
                ),
                a::prove_joinsplit_aggregate_production_research(
                    &[],
                    a::ProductionAggregationOptions::default(),
                ),
                a::prove_joinsplit_aggregate_production_padded_research(
                    &[],
                    dummy,
                    a::ProductionAggregationOptions::default(),
                ),
            ] {
                assert!(matches!(
                    result,
                    Err(a::AggregationError::ProvingPolicy(
                        crate::proving::Error::Unsupported { .. }
                    ))
                ));
            }
        },
    );
}

#[cfg(feature = "stream")]
#[test]
fn streaming_entrypoints_reject_before_trace_io_or_fri_callbacks() {
    isolated(
        "streaming_entrypoints_reject_before_trace_io_or_fri_callbacks",
        || {
            use crate::config::{self, ChallengeMmcs, Challenger, MyCompress, MyHash, ValMmcs};
            use crate::stream_prove as s;
            use p3_goldilocks::default_goldilocks_poseidon2_8;
            use p3_matrix::dense::RowMajorMatrix;
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;
            let config = config::make_config();
            let air = crate::joinsplit_air::JoinSplitAir;
            let rejected = |error: std::io::Error| {
                assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
                assert!(error.to_string().contains("GpuRequired"));
            };
            let empty = || RowMajorMatrix::new(vec![], 1);
            rejected(
                s::stream_prove(&config, &air, empty(), &[], 0, 0, 0)
                    .err()
                    .unwrap(),
            );
            rejected(s::stream_prove_seeded(&air, empty(), &[], 0).err().unwrap());
            let store = s::MmapLdeStore::new(1, 1).unwrap();
            rejected(
                s::stream_prove_from_trace_store(&config, &air, &store, &[], 0, 0, 0)
                    .err()
                    .unwrap(),
            );
            rejected(
                s::stream_prove_from_trace_store_owned(&config, &air, store, &[], 0, 0, 0)
                    .err()
                    .unwrap(),
            );
            let perm = default_goldilocks_poseidon2_8();
            let mmcs = ValMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                config::CAP_HEIGHT,
                ChaCha20Rng::seed_from_u64(1),
            );
            let params = config::production_fri(ChallengeMmcs::new(mmcs));
            let mut challenger = Challenger::new(perm);
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            rejected(
                s::stream_prove_fri(
                    &params,
                    vec![],
                    &mut challenger,
                    0,
                    |_| panic!("opening callback must not run"),
                    &mut rng,
                    0,
                )
                .err()
                .unwrap(),
            );
            rejected(
                s::stream_prove_fri_from_input_stores(
                    &params,
                    &[],
                    &mut challenger,
                    0,
                    |_| panic!("opening callback must not run"),
                    &mut rng,
                    0,
                )
                .err()
                .unwrap(),
            );
        },
    );
}
