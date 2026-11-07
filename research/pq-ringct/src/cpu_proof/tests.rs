use super::*;
#[test]
fn cold_target_selection_and_kernel_validation() {
    let parse = |args: &[&str]| Options::parse(args.iter().map(|s| s.to_string()));
    for args in [
        vec!["--input", "x", "--cpu-hash-kernel", "interleaved2"],
        vec!["--input", "x", "--transaction", "3"],
        vec!["--input", "x", "--candidate-first", "1"],
        vec!["--input", "x", "--compare-target", "1"],
        vec!["--input", "x", "--identity-overlap", "yes"],
    ] {
        assert!(parse(&args).is_err());
    }
    let (options, _) = parse(&[
        "--input",
        "x",
        "--cpu-variant",
        "combined",
        "--cpu-hash-kernel",
        "interleaved2",
        "--identity-overlap",
        "1",
        "--mode",
        "paired",
        "--transaction",
        "0",
        "--compare-target",
        "1",
    ])
    .unwrap();
    assert!(options.compare_target && options.identity_overlap);
}

#[test]
fn research_profile_is_explicit_and_keeps_legacy_cpu_cap() {
    use crate::{execution::ProvingContext, host_memory_profile::HostMemoryProfile as Profile};
    assert!(ProvingContext::cpu(36 << 30).is_err());
    for profile in [Profile::Standard, Profile::Expanded36] {
        let context = ProvingContext::cpu_research(profile).unwrap();
        assert_eq!(context.host_profile(), profile);
        assert_eq!(context.host_bytes(), profile.worker_bytes());
        assert_eq!(
            context.policy(),
            lattica_prover_p3::proving::Policy::CpuRequired
        );
    }
    assert!(ProvingContext::cpu_research(Profile::Expanded40).is_err());
}
#[test]
fn worker_budget_is_shared_and_options_are_unambiguous() {
    assert!(
        Options::parse(
            [
                "--input",
                "fixture",
                "--mode",
                "native-mix",
                "--segments",
                "1"
            ]
            .map(str::to_owned)
            .into_iter()
        )
        .is_ok()
    );
    assert!(
        Options::parse(
            ["--input", "fixture", "--mode", "native-mix"]
                .map(str::to_owned)
                .into_iter()
        )
        .is_err()
    );
    for (workers, threads) in [(1, 16), (2, 8), (4, 4), (8, 2), (16, 1)] {
        let args = [
            "--input",
            "fixture",
            "--workers",
            &workers.to_string(),
            "--threads-per-proof",
            &threads.to_string(),
        ]
        .map(str::to_owned);
        assert!(Options::parse(args.into_iter()).is_ok());
    }
    for args in [
        vec![
            "--input",
            "x",
            "--workers",
            "16",
            "--threads-per-proof",
            "16",
        ],
        vec!["--input", "x", "--retain", "true"],
        vec!["--input", "x", "--case", "n5"],
        vec!["--input", "x", "--mode", "full"],
        vec!["--input", "x", "--input", "y"],
    ] {
        assert!(Options::parse(args.into_iter().map(str::to_owned)).is_err());
    }
}
#[test]
fn dependency_priorities_reject_cycles_and_duplicate_consumption() {
    assert_eq!(
        scheduler::priorities(&[vec![], vec![], vec![0, 1], vec![2]], &[1, 2, 3, 4]).unwrap(),
        vec![8, 9, 7, 4]
    );
    assert!(scheduler::priorities(&[vec![1], vec![0]], &[1, 1]).is_err());
    assert!(scheduler::priorities(&[vec![], vec![0], vec![0]], &[1, 1, 1]).is_err());
    assert!(scheduler::priorities(&[vec![]], &[]).is_err());
}

#[test]
fn workers_join_before_originals_release_on_success_and_panic() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for fail in [false, true] {
        let (mut options, _) =
            Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
        options.workers = 2;
        options.threads_per_proof = 1;
        let ledger = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 0,
        });
        let done = Arc::new(AtomicUsize::new(0));
        let jobs = (0..2)
            .map(|i| jobs::Spec {
                kind: jobs::Kind::Probe {
                    panic: fail && i == 0,
                    tag: None,
                    completed: Arc::clone(&done),
                    thread_exit: true,
                    prepared_bytes: None,
                    output_bytes: None,
                    work_bytes: None,
                },
                deps: vec![],
                cost: 1,
            })
            .collect();
        let result = scheduler::run_with_ledger(&options, jobs, 0, &ledger);
        assert_eq!(result.is_err(), fail);
        assert_eq!(done.load(Ordering::SeqCst), 4);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn memory_refusal_never_dispatches_or_leaks() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    let ledger = Ledger::new(WorkerAllowance { host: 1, device: 0 });
    let done = Arc::new(AtomicUsize::new(0));
    let jobs = vec![jobs::Spec {
        kind: jobs::Kind::Probe {
            panic: false,
            tag: None,
            completed: Arc::clone(&done),
            thread_exit: false,
            prepared_bytes: None,
            output_bytes: None,
            work_bytes: None,
        },
        deps: vec![],
        cost: 1,
    }];
    assert!(scheduler::run_with_ledger(&options, jobs, 0, &ledger).is_err());
    assert_eq!(done.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn equal_priority_ready_jobs_reuse_cached_program_before_eviction() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::AtomicUsize;
    let (mut options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    options.workers = 1;
    options.threads_per_proof = 1;
    options.retain = true;
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    });
    let done = Arc::new(AtomicUsize::new(0));
    let jobs = [[0x11; 32], [0x22; 32], [0x11; 32]]
        .into_iter()
        .map(|tag| jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag: Some(tag),
                completed: Arc::clone(&done),
                thread_exit: false,
                prepared_bytes: None,
                output_bytes: None,
                work_bytes: None,
            },
            deps: vec![],
            cost: 1,
        })
        .collect();
    let record = scheduler::run_with_ledger(&options, jobs, 0, &ledger).unwrap();
    assert!(!record.jobs[0].prepared_hit);
    assert!(!record.jobs[1].prepared_hit);
    assert!(record.jobs[2].prepared_hit);
    assert_eq!(serde_json::to_value(record).unwrap()["cache_evictions"], 1);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn cached_program_keeps_its_compiler_original_until_owner_eviction() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::AtomicUsize;
    let (mut options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    options.workers = 1;
    options.threads_per_proof = 1;
    options.retain = true;
    // Three MiB above the fixed envelope admits each task, but retaining the
    // compiler original leaves too little room for the final native task.
    // The scheduler must evict on its owner before it can release that token.
    let ledger = Ledger::new(WorkerAllowance {
        host: scheduler::fixed_bytes(&options) + (3 << 20),
        device: 0,
    });
    let done = Arc::new(AtomicUsize::new(0));
    let jobs = [(None, vec![]), (Some([0x11; 32]), vec![0]), (None, vec![])]
        .into_iter()
        .map(|(tag, deps)| jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag,
                completed: Arc::clone(&done),
                thread_exit: false,
                prepared_bytes: None,
                output_bytes: None,
                work_bytes: None,
            },
            deps,
            cost: 1,
        })
        .collect();
    let record = scheduler::run_with_ledger(&options, jobs, 0, &ledger).unwrap();
    assert_eq!(serde_json::to_value(record).unwrap()["cache_evictions"], 1);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn prepared_claim_shrinks_only_after_completion_and_cache_hits_reserve_scratch() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for oversized in [false, true] {
        let (mut options, _) =
            Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
        options.workers = 1;
        options.threads_per_proof = 1;
        options.retain = true;
        let ledger = Ledger::new(WorkerAllowance {
            host: scheduler::fixed_bytes(&options) + (9 << 19),
            device: 0,
        });
        let done = Arc::new(AtomicUsize::new(0));
        let jobs = [
            (None, vec![]),
            (Some([17; 32]), vec![0]),
            (Some([17; 32]), vec![1]),
            (None, vec![2]),
        ]
        .into_iter()
        .map(|(tag, deps)| jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag,
                completed: Arc::clone(&done),
                thread_exit: true,
                prepared_bytes: tag.map(|_| if oversized { 2 << 20 } else { 1 << 18 }),
                output_bytes: None,
                work_bytes: None,
            },
            deps,
            cost: 1,
        })
        .collect();
        let result = scheduler::run_with_ledger(&options, jobs, 0, &ledger);
        assert_eq!(result.is_err(), oversized);
        if let Ok(record) = result {
            assert!(record.jobs[2].prepared_hit);
            assert_eq!(serde_json::to_value(record).unwrap()["cache_evictions"], 0);
            assert_eq!(done.load(Ordering::SeqCst), 8);
        } else {
            assert_eq!(done.load(Ordering::SeqCst), 4);
        }
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn phase_memory_model_preserves_reference_refusal_and_rejects_unknown_geometry() {
    use lattica_prover_p3::block_v2::cpu_commitment::Variant;
    let mut g = component_tree::Geometry {
        active_rows: 244432,
        padded_rows: 262144,
        wires: 1,
        main_width: 94,
        preprocessed_width: 200,
        permutation_width_base: 51,
        quotient_chunks: 16,
        constraints: 1,
        max_constraint_degree: 1,
        fri_ali_bits: 5,
        retained_lde_bytes: 31_675_383_808,
    };
    let reference = component_tree::cpu::admission_for(&g, Variant::Reference).unwrap();
    let candidate = component_tree::cpu::admission_for(&g, Variant::Combined).unwrap();
    assert!(reference > 36 << 30);
    assert!(candidate > 32 << 30 && candidate < 36 << 30);
    g.preprocessed_width += 1;
    assert!(component_tree::cpu::admission_for(&g, Variant::Combined).is_err());
}

#[test]
fn ready_proofs_retire_compiler_inputs_before_independent_compilation() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    options.workers = 1;
    options.threads_per_proof = 1;
    options.retain = true;
    let ledger = Ledger::new(WorkerAllowance {
        host: scheduler::fixed_bytes(&options) + (5 << 19),
        device: 0,
    });
    let done = Arc::new(AtomicUsize::new(0));
    // Compiling both independent roots first strands two 1-MiB originals.
    // Consuming each root before the next admits both proofs in 2.5 MiB.
    let jobs = [
        (None, vec![], 1),
        (Some([17; 32]), vec![0], 10),
        (None, vec![], 1),
        (Some([18; 32]), vec![2], 10),
    ]
    .into_iter()
    .map(|(tag, deps, cost)| jobs::Spec {
        kind: jobs::Kind::Probe {
            panic: false,
            tag,
            completed: Arc::clone(&done),
            thread_exit: false,
            prepared_bytes: None,
            output_bytes: tag.map(|_| 1024),
            work_bytes: None,
        },
        deps,
        cost,
    })
    .collect();
    let record = scheduler::run_with_ledger(&options, jobs, 0, &ledger).unwrap();
    assert_eq!(record.jobs.len(), 4);
    assert_eq!(done.load(Ordering::SeqCst), 4);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn terminal_results_release_their_originals_after_verification() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    options.workers = 1;
    options.threads_per_proof = 1;
    let ledger = Ledger::new(WorkerAllowance {
        host: scheduler::fixed_bytes(&options) + (5 << 19),
        device: 0,
    });
    let done = Arc::new(AtomicUsize::new(0));
    let jobs = (0..3)
        .map(|_| jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag: None,
                completed: Arc::clone(&done),
                thread_exit: false,
                prepared_bytes: None,
                output_bytes: None,
                work_bytes: None,
            },
            deps: vec![],
            cost: 1,
        })
        .collect();
    let record = scheduler::run_with_ledger(&options, jobs, 0, &ledger).unwrap();
    assert_eq!(record.jobs.len(), 3);
    assert_eq!(done.load(Ordering::SeqCst), 3);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn matching_cache_evicts_before_more_compiler_outputs_strand_its_scratch() {
    use crate::execution::retained_resources::{Bytes, Ledger, WorkerAllowance};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut options, _) =
        Options::parse(["--input", "fixture"].map(str::to_owned).into_iter()).unwrap();
    options.workers = 1;
    options.threads_per_proof = 1;
    options.retain = true;
    let ledger = Ledger::new(WorkerAllowance {
        host: scheduler::fixed_bytes(&options) + (6 << 20),
        device: 0,
    });
    let done = Arc::new(AtomicUsize::new(0));
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let input = jobs.len();
        jobs.push(jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag: None,
                completed: Arc::clone(&done),
                thread_exit: false,
                prepared_bytes: None,
                output_bytes: Some(1 << 20),
                work_bytes: Some(1 << 18),
            },
            deps: vec![],
            cost: 1,
        });
        jobs.push(jobs::Spec {
            kind: jobs::Kind::Probe {
                panic: false,
                tag: Some([17; 32]),
                completed: Arc::clone(&done),
                thread_exit: false,
                prepared_bytes: Some(1 << 20),
                output_bytes: Some(1024),
                work_bytes: Some(4 << 20),
            },
            deps: vec![input],
            cost: 10,
        });
    }
    let record = scheduler::run_with_ledger(&options, jobs, 0, &ledger).unwrap();
    assert_eq!(done.load(Ordering::SeqCst), 8);
    assert_eq!(serde_json::to_value(record).unwrap()["cache_evictions"], 3);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
