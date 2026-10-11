use super::*;
use crate::block_v2::execution::job::test_support::{pin_for, typed_pin, typed_wallet, wallet_for};

#[test]
fn preparation_list_census_counts_capacity_without_counting_shared_proofs_twice() {
    use crate::block_v2::{
        execution::selection::PreparationStorage,
        typed_recursive::{Policy, Registry},
    };
    let plan = PreparationStorage::new().unwrap();
    let total = plan.total_bytes().unwrap();
    plan.admit(total).unwrap();
    assert!(plan.admit(total - 1).is_err());
    let mut inputs = Vec::with_capacity(CAPACITY);
    let mut policies = Vec::with_capacity(CAPACITY);
    for i in 0..CAPACITY {
        let bytes = vec![i as u8];
        let wallet = typed_wallet(i as u64 + 1, 1, &bytes);
        policies.push((wallet.artifact(), Policy::JoinSplit));
        inputs.push(PublicInput::new(wallet, bytes).unwrap());
    }
    assert_eq!(
        PreparationStorage::input_list_storage_bytes(&inputs).unwrap(),
        plan.input_list_bytes
    );
    assert_eq!(
        PreparationStorage::policy_list_storage_bytes(&policies).unwrap(),
        plan.policy_list_bytes
    );
    inputs.clear();
    policies.clear();
    assert_eq!(
        PreparationStorage::input_list_storage_bytes(&inputs).unwrap(),
        plan.input_list_bytes
    );
    assert_eq!(
        PreparationStorage::policy_list_storage_bytes(&policies).unwrap(),
        plan.policy_list_bytes
    );
    assert!(
        PreparationStorage::input_list_storage_bytes(&Vec::with_capacity(CAPACITY + 1)).is_err()
    );
    assert!(
        PreparationStorage::policy_list_storage_bytes(&Vec::with_capacity(CAPACITY + 1)).is_err()
    );
    let registry = Registry::<12> {
        height: 8,
        caps: std::array::from_fn(|_| {
            vec![[crate::config::Val::default(); 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let retained_registry = registry.storage_bytes().unwrap();
    assert!(retained_registry <= plan.temporary_registry_bytes);
    let pointer = registry.caps[0].as_ptr();
    let caps: Vec<_> = registry.caps.into_iter().collect();
    assert_eq!(caps.capacity(), 12);
    assert_eq!(caps[0].as_ptr(), pointer);
    let converted: [_; 12] = caps.try_into().unwrap();
    assert_eq!(converted[0].as_ptr(), pointer);
    eprintln!("bounded_preparation_lists input_list_bytes={} policy_list_bytes={} temporary_registry_bytes={} registry_conversion_bytes={} total_bytes={total} inputs=64", plan.input_list_bytes, plan.policy_list_bytes, plan.temporary_registry_bytes, plan.registry_conversion_bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn durable_handoff_keeps_lease_inputs_after_all_caller_proof_owners_are_dropped() {
    use crate::block_v2::execution::{
        artifact_store::{ArtifactStore, StoreLimits},
        dag::{Limits, WorkerId},
        journal::{DurableDag, JournalLimits},
        resources::Resources,
    };
    use std::os::unix::fs::DirBuilderExt;
    let path = std::env::temp_dir().join(format!(
        "lattica-preparation-handoff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _temp = Temp(path.clone());
    let count = 3;
    let proof_bytes = 64 << 10;
    let inputs: Vec<_> = (0..count)
        .map(|i| {
            let bytes = vec![i as u8 + 1; proof_bytes];
            PublicInput::new(typed_wallet(i as u64 + 1, 1, &bytes), bytes).unwrap()
        })
        .collect();
    let weak: Vec<_> = inputs
        .iter()
        .map(|input| Arc::downgrade(&input.bytes))
        .collect();
    let selection = Selection::new(typed_pin(), [9; 32], &inputs).unwrap();
    let job = selection
        .jobs()
        .find(|job| job.wallet_inputs().len() == 2)
        .unwrap()
        .clone();
    let store = ArtifactStore::create(
        &path.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 256,
        },
    )
    .unwrap();
    let resources = Resources {
        ram_bytes: 64,
        vram_bytes: 4,
        scratch_bytes: 4,
        threads: 4,
    };
    let mut owner = DurableDag::create(
        &path.join("journal"),
        JournalLimits {
            snapshot_bytes: 1 << 20,
        },
        store,
        typed_pin(),
        [9; 32],
        1,
        Limits {
            jobs: 128,
            candidates: 8,
            attempts: 128,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 1000,
            workers: resources,
        },
    )
    .unwrap();
    let candidate = selection.attach(&mut owner, [3; 32], 10_000, 0).unwrap();
    drop(inputs);
    assert!(weak.iter().all(|input| input.upgrade().is_some()));
    drop(selection);
    assert!(weak.iter().all(|input| input.upgrade().is_none()));
    // Weak observers retain backing themselves; discard them before leasing.
    drop(weak);
    owner.seal(candidate, [3; 32], 0).unwrap();
    let lease = owner
        .lease(
            job.id(),
            WorkerId(1),
            Resources {
                ram_bytes: 1,
                vram_bytes: 1,
                scratch_bytes: 1,
                threads: 1,
            },
            1,
            100,
            1,
        )
        .unwrap();
    for index in 0..2 {
        let bytes = owner.input_bytes(lease, index).unwrap();
        assert_eq!(bytes.len(), proof_bytes);
        assert!(bytes.iter().all(|byte| *byte == index as u8 + 1));
        job.wallet_inputs()[index].check_bytes(bytes).unwrap();
    }
    owner.cancel(candidate, 2).unwrap();
    assert_eq!(owner.resource_use().unwrap().ram_bytes, 1);
    owner.worker_stopped(lease, 3).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    eprintln!("bounded_preparation_handoff inputs={count} proof_bytes_each={proof_bytes} expired_strong_owners={count} preserved_lease_inputs=2 release_requires_stop=true");
}

#[test]
fn all_selection_shapes_keep_metadata_and_shared_proofs_within_the_component() {
    let plan = Selection::storage_plan().unwrap();
    let total = plan.total_bytes().unwrap();
    plan.admit(total).unwrap();
    assert!(plan.admit(total - 1).is_err());
    let mut shapes = 0;
    for (typed, construction) in [
        (false, WrapperConstruction::SingleWallet),
        (false, WrapperConstruction::GroupedPair),
        (true, WrapperConstruction::GroupedPair),
    ] {
        for count in 1..=CAPACITY {
            if !typed && construction == WrapperConstruction::GroupedPair && count % 2 != 0 {
                continue;
            }
            let pin = if typed {
                typed_pin()
            } else {
                pin_for(construction)
            };
            let inputs: Vec<_> = (0..count)
                .map(|i| {
                    let bytes = vec![i as u8 + 1];
                    let wallet = if typed {
                        typed_wallet(i as u64 + 1, 1, &bytes)
                    } else {
                        wallet_for(construction, i as u64 + 1, &bytes)
                    };
                    PublicInput::new(wallet, bytes).unwrap()
                })
                .collect();
            let weak = Arc::downgrade(&inputs[0].bytes);
            let selection = Selection::new(pin, [9; 32], &inputs).unwrap();
            drop(inputs);
            assert!(weak.upgrade().is_some());
            assert_eq!(selection.entries.capacity(), MAX_ENTRIES);
            assert_eq!(selection.root().expected().count as usize, count);
            assert!(selection.retained_storage_bytes().unwrap() <= plan.retained_bytes().unwrap());
            drop(selection);
            assert!(weak.upgrade().is_none());
            shapes += 1;
        }
    }
    assert_eq!(shapes, 160);
    eprintln!(
        "bounded_selection_storage metadata_bytes={} proof_bytes={} construction_bytes={} input_conversion_bytes={} admission_bytes={} total_bytes={total} shapes={shapes}",
        plan.metadata_bytes, plan.proof_bytes, plan.construction_bytes,
        plan.input_conversion_bytes, plan.admission_bytes
    );
}

#[test]
fn maximum_distinct_proofs_survive_caller_release_and_admission_copies_are_independent() {
    let proof = vec![13; MAX_PROOF_BYTES];
    let wallet = typed_wallet(1, 1, &proof);
    let validated = PublicInput::new(wallet, proof).unwrap();
    // Reuse the already checked structural ticket while creating independent
    // allocations of identical bytes. This tests ownership, not proof validity.
    let mut inputs = Vec::with_capacity(CAPACITY);
    for _ in 0..CAPACITY {
        inputs.push(PublicInput {
            wallet,
            bytes: Arc::from(validated.bytes.to_vec()),
        });
    }
    drop(validated);
    let selection = Selection::new(typed_pin(), [9; 32], &inputs).unwrap();
    drop(inputs);
    let plan = Selection::storage_plan().unwrap();
    let retained = selection.retained_storage_bytes().unwrap();
    assert!(CAPACITY * MAX_PROOF_BYTES < retained && retained <= plan.retained_bytes().unwrap());
    let entry = selection
        .entries
        .iter()
        .find(|entry| entry.inputs.len() == 2)
        .unwrap();
    let mut copies = entry.wallet_bytes();
    assert_eq!(copies.capacity(), 2);
    assert!(copies
        .iter()
        .all(|proof| proof.capacity() == MAX_PROOF_BYTES));
    assert_ne!(copies[0].as_ptr(), entry.inputs[0].bytes.as_ptr());
    copies[0][0] ^= 1;
    assert_eq!(entry.inputs[0].bytes[0], 13);
    assert_eq!(copies[1][0], 13);
    eprintln!(
        "bounded_selection_maximum retained_bytes={retained} retained_limit_bytes={} unique_inputs={CAPACITY} proof_bytes_each={MAX_PROOF_BYTES} admission_copy_bytes={}",
        plan.retained_bytes().unwrap(), copies.iter().map(|v| v.capacity()).sum::<usize>()
    );
}

#[test]
fn input_spare_capacity_is_bounded_and_aliases_are_counted_by_allocation() {
    let wallet = typed_wallet(1, 1, &[5]);
    let mut excessive = Vec::with_capacity(PublicInput::INPUT_CAPACITY_BYTES + 1);
    excessive.push(5);
    assert!(PublicInput::new(wallet, excessive).is_err());
    let mut exact = Vec::with_capacity(PublicInput::INPUT_CAPACITY_BYTES);
    exact.push(5);
    let input = PublicInput::new(wallet, exact).unwrap();
    let mut selection = Selection::new(typed_pin(), [9; 32], &[input]).unwrap();
    let aliased = selection.retained_storage_bytes().unwrap();
    let entry = selection
        .entries
        .iter_mut()
        .find(|entry| entry.inputs.len() == 2)
        .unwrap();
    assert!(Arc::ptr_eq(&entry.inputs[0].bytes, &entry.inputs[1].bytes));
    entry.inputs[1].bytes = Arc::from(entry.inputs[1].bytes.to_vec());
    let independent = selection.retained_storage_bytes().unwrap();
    assert_eq!(independent - aliased, arc_slice::<u8>(1).unwrap());
    assert!(arc_slice::<u64>(usize::MAX).is_err());
    eprintln!(
        "bounded_input_conversion capacity_limit_bytes={} proof_limit_bytes={MAX_PROOF_BYTES} alias_bytes={aliased} independent_bytes={independent}",
        PublicInput::INPUT_CAPACITY_BYTES
    );
}
