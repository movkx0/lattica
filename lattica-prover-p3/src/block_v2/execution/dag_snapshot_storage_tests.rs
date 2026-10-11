//! Structural snapshot/storage checks, not cryptographic proof qualification.
use super::*;
use crate::block_v2::execution::job::test_support::{pin, wallet};

fn tree(dag: &mut Dag, start: u8, level: u8, count: u8) -> Job {
    let (job, inputs) = if start >= count {
        (Job::empty(pin(), [9; 32], start, level).unwrap(), vec![])
    } else if level == 0 {
        (
            Job::wrap(start, wallet(u64::from(start) + 1, &[start + 1])).unwrap(),
            vec![vec![start + 1]],
        )
    } else {
        let left = tree(dag, start, level - 1, count);
        let right = tree(dag, start + (1 << (level - 1)), level - 1, count);
        (Job::merge(&left, &right).unwrap(), vec![])
    };
    dag.admit(job.clone(), inputs, 0).unwrap();
    job
}

fn fixture() -> (Dag, Lease) {
    fixture_with_count(4)
}

fn fixture_with_count(count: u8) -> (Dag, Lease) {
    let mut dag = Dag::new(
        pin(),
        [9; 32],
        1,
        Limits {
            jobs: 256,
            candidates: 8,
            attempts: 256,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 1000,
            workers: Resources {
                ram_bytes: 4096,
                vram_bytes: 4096,
                scratch_bytes: 4096,
                threads: 8,
            },
        },
    )
    .unwrap();
    let root = tree(&mut dag, 0, crate::block_v2::commitment::DEPTH, count);
    dag.attach(root.id(), [2; 32], 1000, 0).unwrap();
    let job = dag
        .jobs
        .values()
        .find(|r| !r.job.wallet_inputs().is_empty())
        .unwrap()
        .job
        .id();
    let lease = dag
        .lease(
            job,
            WorkerId(1),
            Resources {
                ram_bytes: 100,
                vram_bytes: 10,
                scratch_bytes: 100,
                threads: 1,
            },
            1,
            100,
            0,
        )
        .unwrap();
    (dag, lease)
}

fn parity(dag: &Dag) {
    let index = sizing::Index::new(dag).unwrap();
    let owners = if dag.workspaces.is_empty() {
        0
    } else {
        dag.attempts.values().filter(|a| !a.released).count() + dag.workspaces.len()
    };
    assert_eq!(index.jobs.capacity(), dag.jobs.len());
    assert_eq!(
        index.bytes().unwrap(),
        2 * core::mem::size_of::<Vec<WorkerId>>()
            + dag.jobs.len() * core::mem::size_of::<&Record>()
            + owners * core::mem::size_of::<WorkerId>()
    );
    assert!(index.bytes().unwrap() <= dag.limits.snapshot_storage().unwrap().encode_metadata_bytes);
    let expected = reference::encode(dag).unwrap();
    buffer::PAYLOAD_ALLOCATIONS.with(|n| n.set(0));
    let actual = encode_limited(dag, expected.len()).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.capacity(), actual.len());
    assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 1);
    buffer::PAYLOAD_ALLOCATIONS.with(|n| n.set(0));
    assert!(encode_limited(dag, expected.len() - 1).is_err());
    assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 0);
    assert_eq!(encode(dag).unwrap(), expected);
    eprintln!("bounded_snapshot_storage payload_bytes={} capacity_bytes={} allocations=1 short_limit_allocations=0", actual.len(), actual.capacity());
}

#[test]
fn recovery_metadata_is_bounded_before_loading_proofs_and_reencoding() {
    let (mut dag, lease) = fixture_with_count(64);
    dag.limits.artifact_bytes = 512 << 20;
    dag.limits.workers = Resources {
        ram_bytes: 32768,
        vram_bytes: 32768,
        scratch_bytes: 32768,
        threads: 256,
    };
    dag.attempts.get_mut(&lease.id()).unwrap().launch_binding = None;
    dag.reject_worker(lease, 0).unwrap();
    // Keep 255 rejected-but-not-stopped attempts pinned to one shared input.
    // Their output reservations nearly fill the hard artifact quota without
    // allocating proof payloads or starting any actual workers.
    for worker in 2..=255 {
        let pending = dag
            .lease(
                lease.job(),
                WorkerId(worker),
                Resources {
                    ram_bytes: 100,
                    vram_bytes: 10,
                    scratch_bytes: 100,
                    threads: 1,
                },
                1,
                100,
                0,
            )
            .unwrap();
        dag.attempts.get_mut(&pending.id()).unwrap().launch_binding = None;
        dag.reject_worker(pending, 0).unwrap();
    }
    dag.reserve_workspace(
        WorkerId(256),
        Resources {
            ram_bytes: 100,
            vram_bytes: 10,
            scratch_bytes: 100,
            threads: 1,
        },
        0,
    )
    .unwrap();
    let bytes = encode(&dag).unwrap();
    let plan = dag.limits.snapshot_storage().unwrap();
    sizing::RECOVERY_CENSUS.with(|n| n.set(0));
    let mut verified = 0;
    let restored = restore_with(
        &bytes,
        dag.pin,
        dag.chain,
        2,
        dag.limits,
        |identity| {
            let used = sizing::RECOVERY_CENSUS.with(|n| n.get());
            assert!(used > 0 && used <= plan.recover_metadata_bytes);
            let record = dag
                .jobs
                .values()
                .find(|r| r.job.wallet_inputs().contains(&identity))
                .unwrap();
            let input = record
                .job
                .wallet_inputs()
                .iter()
                .position(|i| *i == identity)
                .unwrap();
            let bytes = record.wallets[input].to_vec();
            verified += 1;
            Ok((wallet(u64::from(record.job.start()) + 1, &bytes), bytes))
        },
        |_, _| Err("unexpected output load".into()),
    )
    .unwrap();
    assert_eq!(verified, 64);
    assert_eq!(restored.dag.job_count(), 127);
    assert_eq!(restored.candidates.len(), 1);
    assert_eq!(restored.attempts.len(), 255);
    assert_eq!(restored.workspaces.len(), 1);
    assert!(restored
        .attempts
        .iter()
        .all(|a| a.input_manifest.capacity() == 1));
    assert_eq!(restored.workspaces.capacity(), 1);
    restored.dag.retained_storage().unwrap();
    parity(&restored.dag);
    println!(
        "bounded_recovery_metadata census_bytes={} limit_bytes={} verified_inputs={verified}",
        sizing::RECOVERY_CENSUS.with(|n| n.get()),
        plan.recover_metadata_bytes
    );
}

#[test]
fn snapshot_indexes_reject_invalid_cardinality_and_duplicate_workers_before_payload() {
    let (mut dag, lease) = fixture();
    dag.attempts.get_mut(&lease.id()).unwrap().launch_binding = None;
    dag.limits.jobs = 1;
    buffer::PAYLOAD_ALLOCATIONS.with(|n| n.set(0));
    assert!(encode(&dag).is_err());
    assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 0);
    dag.limits.jobs = 256;
    dag.reserve_workspace(
        WorkerId(2),
        Resources {
            ram_bytes: 100,
            vram_bytes: 10,
            scratch_bytes: 100,
            threads: 1,
        },
        0,
    )
    .unwrap();
    dag.workspaces.values_mut().next().unwrap().worker = WorkerId(1);
    assert!(encode(&dag).is_err());
    assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 0);
}

#[test]
fn artifact_descriptor_decode_allocates_exact_count_and_rejects_truncation() {
    let identity = wallet(1, &[1]).artifact();
    for n in 0..=2 {
        let mut bytes = vec![n as u8];
        for _ in 0..n {
            bytes.push(1);
            bytes.extend(identity.byte_len().to_le_bytes());
            bytes.extend(identity.digest_bytes());
        }
        let decoded = Reader {
            bytes: &bytes,
            offset: 0,
        }
        .artifacts()
        .unwrap();
        assert_eq!(decoded.len(), n);
        assert_eq!(decoded.capacity(), n);
        if n != 0 {
            assert!(Reader {
                bytes: &bytes[..bytes.len() - 1],
                offset: 0
            }
            .artifacts()
            .is_err());
        }
    }
    assert!(Reader {
        bytes: &[3],
        offset: 0
    }
    .artifacts()
    .is_err());
}

#[test]
fn graph_persistence_budget_adds_resume_metadata_overlap_and_has_exact_admission() {
    use crate::block_v2::execution::journal::JournalLimits;
    let (dag, _) = fixture();
    for (name, limits, snapshot_bytes) in [
        (
            "cli",
            Limits {
                artifact_bytes: 256 << 20,
                ..dag.limits
            },
            1 << 20,
        ),
        (
            "hard",
            Limits {
                jobs: 4096,
                candidates: 256,
                attempts: 16384,
                artifact_bytes: 512 << 20,
                ..dag.limits
            },
            8 << 20,
        ),
    ] {
        let graph = JournalLimits { snapshot_bytes }
            .graph_storage(limits)
            .unwrap();
        let total = graph.total_bytes().unwrap();
        assert_eq!(
            total,
            graph.retained.total_bytes().unwrap()
                + graph.payload_bytes
                + graph.snapshot.encode_metadata_bytes
                + graph.snapshot.recover_metadata_bytes
        );
        graph.admit(total).unwrap();
        assert!(graph.admit(total - 1).is_err());
        println!("bounded_graph_persistence profile={name} encode_metadata_bytes={} recover_metadata_bytes={} retained_bytes={} payload_bytes={} total_bytes={total}",
            graph.snapshot.encode_metadata_bytes, graph.snapshot.recover_metadata_bytes,
            graph.retained.total_bytes().unwrap(), graph.payload_bytes);
    }
    assert!(JournalLimits {
        snapshot_bytes: 255
    }
    .graph_storage(dag.limits)
    .is_err());
    assert!(Limits {
        jobs: usize::MAX,
        ..dag.limits
    }
    .snapshot_storage()
    .is_err());
}

#[test]
fn all_snapshot_versions_preserve_bytes_with_one_exact_payload_allocation() {
    for binding in [
        None,
        Some(LaunchBinding::Direct),
        Some(LaunchBinding::Supervised([3; 32])),
        Some(LaunchBinding::Unissued),
        Some(LaunchBinding::Preparing([4; 32])),
        Some(LaunchBinding::Authorized {
            path: [5; 32],
            directory: [7, 8],
        }),
    ] {
        let (mut dag, lease) = fixture();
        dag.launch_root = binding.map(|b| LaunchRoot {
            journal: [1, 2],
            store: if b == LaunchBinding::Unissued {
                [0; 2]
            } else {
                [3, 4]
            },
        });
        dag.attempts.get_mut(&lease.id()).unwrap().launch_binding = binding;
        parity(&dag);
        dag.reserve_workspace(
            WorkerId(99),
            Resources {
                ram_bytes: 100,
                vram_bytes: 10,
                scratch_bytes: 100,
                threads: 0,
            },
            0,
        )
        .unwrap();
        parity(&dag);
    }
}

#[test]
fn invalid_snapshot_limits_and_invariants_fail_before_payload_allocation() {
    let (mut dag, _) = fixture();
    for limit in [0, MAX_SNAPSHOT_BYTES + 1, usize::MAX] {
        buffer::PAYLOAD_ALLOCATIONS.with(|n| n.set(0));
        assert!(encode_limited(&dag, limit).is_err());
        assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 0);
    }
    dag.stored_bytes += 1;
    buffer::PAYLOAD_ALLOCATIONS.with(|n| n.set(0));
    assert!(encode(&dag).is_err());
    assert_eq!(buffer::PAYLOAD_ALLOCATIONS.with(|n| n.get()), 0);
}
