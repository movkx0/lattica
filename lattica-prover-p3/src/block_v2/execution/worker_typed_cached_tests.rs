//! Structural ownership checks; these fake wallet bytes cannot qualify proving.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::Limits,
    job::test_support::typed_wallet_for,
    journal::JournalLimits,
    launch::{LaunchLimits, LaunchStore},
    selection::{PublicInput, Selection},
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "lattica-typed-workspace-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(temp: &Temp) -> (DurableDag, TypedRegistry<12>, RegistryPin, Selection) {
    use p3_field::PrimeCharacteristicRing;
    let registry = TypedRegistry {
        height: 8,
        caps: std::array::from_fn(|_| {
            vec![[crate::config::Val::ZERO; 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let wallet = typed_wallet_for(pin, 1, 1, &[1]);
    let selection =
        Selection::new(pin, [9; 32], &[PublicInput::new(wallet, vec![1]).unwrap()]).unwrap();
    let store = ArtifactStore::create(
        &temp.0.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 64,
        },
    )
    .unwrap();
    let mut owner = DurableDag::create(
        &temp.0.join("journal"),
        JournalLimits {
            snapshot_bytes: 1 << 20,
        },
        store,
        pin,
        [9; 32],
        1,
        Limits {
            jobs: 32,
            candidates: 4,
            attempts: 16,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 1000,
            workers: Resources {
                ram_bytes: 1100,
                vram_bytes: 0,
                scratch_bytes: 500,
                threads: 2,
            },
        },
    )
    .unwrap();
    selection.attach(&mut owner, [8; 32], 1000, 0).unwrap();
    (owner, registry, pin, selection)
}

fn budgets() -> (Resources, Resources) {
    (
        Resources {
            ram_bytes: 1000,
            vram_bytes: 0,
            scratch_bytes: 500,
            threads: 2,
        },
        Resources {
            ram_bytes: 100,
            vram_bytes: 0,
            scratch_bytes: 0,
            threads: 2,
        },
    )
}

#[test]
fn typed_workspace_reserves_idle_memory_and_releases_only_after_drained_error() {
    let temp = Temp::new();
    let (mut owner, registry, pin, selection) = fixture(&temp);
    let (peak, jobs) = budgets();
    let mut worker = CachedTypedWorker::new(
        &mut owner,
        registry,
        pin,
        WorkerId(1),
        WorkerId(2),
        peak,
        jobs,
        0,
    )
    .unwrap();
    let resident = Resources { threads: 0, ..peak };
    assert_eq!(owner.resource_use().unwrap(), resident);
    let job = selection.jobs().next().unwrap();
    let lease = owner
        .lease(job.id(), WorkerId(2), jobs, 1, 1000, 0)
        .unwrap();
    let task = worker.task(&mut owner, lease, 0).unwrap();
    assert!(worker.close(&mut owner, 0).is_err());
    let request = task.request().unwrap();
    let path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&path, LaunchLimits { records: 4 }).unwrap();
    let token = launches.issue(&mut owner, lease, &request).unwrap();
    let gate = WorkerGate::enter(&path, &token, &request).unwrap();
    let completed = worker
        .execute(gate, task, |_| Err("test host refused policy".into()))
        .unwrap();
    let revoked = launches.revoke(lease).unwrap();
    assert!(launches.try_idle(&revoked).unwrap().is_some());
    assert!(completed.reconcile(&mut owner, 1).is_err());
    owner.reject_worker(lease, 1).unwrap();
    assert_eq!(owner.resource_use().unwrap(), resident);
    assert_eq!(worker.stats().unwrap(), CacheStats::default());
    worker.close(&mut owner, 2).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
}

#[test]
fn typed_workspace_rejects_another_assigned_worker_and_changed_cpu_budget() {
    let temp = Temp::new();
    let (mut owner, registry, pin, selection) = fixture(&temp);
    let (peak, jobs) = budgets();
    let wrong = Resources { threads: 1, ..jobs };
    assert!(CachedTypedWorker::new(
        &mut owner,
        registry.clone(),
        pin,
        WorkerId(1),
        WorkerId(2),
        peak,
        wrong,
        0
    )
    .is_err());
    let worker = CachedTypedWorker::new(
        &mut owner,
        registry,
        pin,
        WorkerId(1),
        WorkerId(2),
        peak,
        jobs,
        0,
    )
    .unwrap();
    let lease = owner
        .lease(
            selection.jobs().next().unwrap().id(),
            WorkerId(3),
            jobs,
            1,
            1000,
            0,
        )
        .unwrap();
    assert!(worker.task(&mut owner, lease, 0).is_err());
    // Failure is not authority to release the outstanding attempt reservation.
    assert_eq!(owner.resource_use().unwrap().threads, 2);
}
