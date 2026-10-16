use super::*;
#[cfg(feature = "block-v2-wide-lanes")]
#[path = "completion_tests.rs"]
mod completion;
#[path = "prefix_tests.rs"]
mod prefix;
#[path = "prefix_transition_tests.rs"]
mod prefix_transition;
#[path = "recovery_tests.rs"]
mod recovery;

#[path = "registry_tests.rs"]
mod registry_tests;
#[path = "service_window_tests.rs"]
mod service_window;
#[path = "storage_tests.rs"]
mod storage;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::Limits,
    job::{test_support::typed_wallet_for, RegistryPin},
    journal::JournalLimits,
    resources::Resources,
    selection::PublicInput,
};
use p3_field::PrimeCharacteristicRing;
use std::{
    cell::RefCell,
    os::unix::fs::DirBuilderExt,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lattica-pool-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Observed {
    contexts: Vec<[u8; 32]>,
    dispatches: usize,
    cancelled: usize,
    closed: usize,
    fail_result: bool,
    retire_requested: bool,
    fail_close: bool,
    dispatch_deadline_ms: Option<u64>,
    shrink_window_on_context: bool,
    last_lease: Option<Lease>,
    result: Option<WorkerResult>,
}
struct SimulatedEndpoint {
    cap: WorkerCapabilities,
    state: Rc<RefCell<Observed>>,
}
impl WorkerEndpoint for SimulatedEndpoint {
    fn retirement_requested(&self) -> bool {
        self.state.borrow().retire_requested
    }
    fn capabilities(&self) -> WorkerCapabilities {
        let mut cap = self.cap.clone();
        if let Some(deadline) = self.state.borrow().dispatch_deadline_ms {
            cap.dispatch_deadline_ms = Some(deadline);
        }
        cap
    }
    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        self.state.borrow_mut().contexts.push(context.binding());
        let shrink = self.state.borrow().shrink_window_on_context;
        if shrink {
            self.state.borrow_mut().dispatch_deadline_ms = Some(0);
        }
        Ok(())
    }
    fn dispatch(&mut self, _: &mut DurableDag, lease: Lease, _: u64) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.dispatches += 1;
        state.last_lease = Some(lease);
        Ok(())
    }
    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now: u64,
    ) -> Result<Option<WorkerResult>, Error> {
        if self.state.borrow().fail_result {
            return Err("simulated broken transport".into());
        }
        let result = self.state.borrow_mut().result.take();
        if let Some(result) = &result {
            // This adapter has no physical worker. Only the coordinator may
            // verify and accept these bytes after the simulated work stops.
            owner.worker_stopped(result.lease, now)?;
        }
        Ok(result)
    }
    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        // This endpoint never starts an OS process; only this test adapter may
        // acknowledge its synthetic work as stopped without OS observation.
        owner.reject_worker(lease, now)?;
        owner.worker_stopped(lease, now)?;
        self.state.borrow_mut().cancelled += 1;
        Ok(())
    }
    fn close(&mut self, _: &mut DurableDag, _: u64) -> Result<(), Error> {
        if self.state.borrow().fail_close {
            return Err("simulated physical shutdown pending".into());
        }
        self.state.borrow_mut().closed += 1;
        Ok(())
    }
}

#[test]
fn cooperative_retirement_requires_successful_idle_close_before_replacement() {
    let temp = Temp::new();
    let (mut pool, _, _, state) = fixture(&temp);
    state.borrow_mut().retire_requested = true;
    state.borrow_mut().fail_close = true;
    assert!(pool.retire_idle_workers(1).is_err());
    assert!(!pool.slots[0].closed);
    assert_eq!(state.borrow().closed, 0);
    assert_eq!(state.borrow().dispatches, 0);
    state.borrow_mut().fail_close = false;
    pool.retire_idle_workers(2).unwrap();
    assert!(pool.slots[0].closed);
    assert_eq!(state.borrow().closed, 1);
    pool.retire_idle_workers(3).unwrap();
    assert_eq!(state.borrow().closed, 1);
}

#[test]
fn failed_transport_is_stopped_before_a_surviving_worker_retries() {
    let temp = Temp::new();
    let (mut pool, selection, context, first) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    pool.step(1).unwrap();
    assert!(pool
        .replace_worker(WorkerId(2), |_| panic!("active factory must not run"))
        .is_err());
    first.borrow_mut().fail_result = true;
    let next = Rc::new(RefCell::new(Observed::default()));
    let mut cap = pool.slots[0].endpoint.capabilities();
    cap.worker = WorkerId(3);
    pool.slots.push(Slot {
        endpoint: Box::new(SimulatedEndpoint {
            cap,
            state: next.clone(),
        }),
        active: None,
        closed: false,
    });
    pool.step(100).unwrap();
    assert_eq!(first.borrow().cancelled, 1);
    assert!(pool.slots[0].closed);
    assert_eq!(next.borrow().dispatches, 1);
    let failures = pool.take_failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, WorkerId(2));
    pool.retire(candidate, 200).unwrap();
    pool.close(201).unwrap();
}

fn fixture(
    temp: &Temp,
) -> (
    PoolCoordinator,
    Selection,
    PolicyContext,
    Rc<RefCell<Observed>>,
) {
    let registry = Registry::<12> {
        height: 8,
        caps: std::array::from_fn(|_| {
            vec![[crate::config::Val::ZERO; 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let resource = Resources {
        ram_bytes: 100,
        vram_bytes: 0,
        scratch_bytes: 0,
        threads: 1,
    };
    let store = ArtifactStore::create(
        &temp.0.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 64,
        },
    )
    .unwrap();
    let owner = DurableDag::create(
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
            candidates: 8,
            attempts: 32,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 1000,
            workers: resource,
        },
    )
    .unwrap();
    let wallet = typed_wallet_for(pin, 1, 1, &[1]);
    let context = PolicyContext::new(
        [42; 32],
        vec![(
            wallet.artifact(),
            crate::block_v2::typed_recursive::Policy::JoinSplit,
        )],
    )
    .unwrap();
    let selection =
        Selection::new(pin, [9; 32], &[PublicInput::new(wallet, vec![1]).unwrap()]).unwrap();
    let state = Rc::new(RefCell::new(Observed::default()));
    let endpoint = SimulatedEndpoint {
        cap: WorkerCapabilities {
            worker: WorkerId(2),
            profile: pin.profile(),
            resources: resource,
            resident_mode: None,
            timing_identity: None,
            forecast_retained_mode: false,
            dispatch_deadline_ms: None,
        },
        state: state.clone(),
    };
    let pool = PoolCoordinator::new(owner, registry, vec![Box::new(endpoint)], 100).unwrap();
    (pool, selection, context, state)
}

#[test]
fn active_work_is_not_redispatched_and_context_is_bound_before_dispatch() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    pool.step(1).unwrap();
    pool.step(100).unwrap();
    assert_eq!(state.borrow().dispatches, 1);
    assert_eq!(state.borrow().contexts, vec![[42; 32]]);
    assert!(!pool.idle());
    assert!(pool.close(100).is_err());
    pool.retire(candidate, 200).unwrap();
    assert_eq!(state.borrow().cancelled, 1);
    assert!(pool.idle());
}

#[test]
fn calibration_cannot_publish_proofs_or_change_an_active_worker() {
    use crate::block_v2::execution::scheduler::TimingIdentity;
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let mut cap = pool.slots[0].endpoint.capabilities();
    cap.timing_identity =
        Some(TimingIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap());
    pool.slots[0].endpoint = Box::new(SimulatedEndpoint {
        cap: cap.clone(),
        state: state.clone(),
    });
    let job = selection
        .jobs()
        .find(|job| job.dependencies().is_empty())
        .unwrap();
    let mut source = CostModel::new(100).unwrap();
    source.observe(&cap, job, false, 10).unwrap();
    let record = source.export_calibration(&cap, job, false).unwrap();
    assert!(pool
        .import_worker_calibration(WorkerId(99), &record, [7; 32])
        .is_err());
    pool.slots[0].closed = true;
    assert!(pool
        .import_worker_calibration(cap.worker, &record, [7; 32])
        .is_err());
    pool.slots[0].closed = false;
    pool.import_worker_calibration(cap.worker, &record, [7; 32])
        .unwrap();
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    assert!(pool
        .export_worker_calibration(cap.worker, job.id(), false)
        .is_err());
    assert!(pool.root(candidate, [3; 32], 0).unwrap().is_none());
    assert_eq!(state.borrow().dispatches, 0);
    pool.step(1).unwrap();
    assert_eq!(state.borrow().dispatches, 1);
    let error = pool
        .import_worker_calibration(cap.worker, &record, [7; 32])
        .unwrap_err();
    assert!(error.to_string().contains("idle live worker"));
    assert!(pool.root(candidate, [3; 32], 1).unwrap().is_none());
    pool.retire(candidate, 2).unwrap();
    assert!(pool.idle());
}

#[test]
fn invalid_context_is_rejected_before_a_candidate_or_worker_is_created() {
    let temp = Temp::new();
    let (mut pool, selection, _, state) = fixture(&temp);
    let wrong = PolicyContext::new([42; 32], vec![]).unwrap();
    assert!(pool.submit(&selection, wrong, [3; 32], 10_000, 0).is_err());
    assert!(pool.candidates.is_empty());
    assert!(state.borrow().contexts.is_empty());
    pool.close(1).unwrap();
    assert_eq!(state.borrow().closed, 1);
}

#[test]
fn no_feasible_deadline_does_not_create_a_lease() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    pool.submit(&selection, context, [3; 32], 100, 0).unwrap();
    assert!(pool.step(1).is_err());
    assert_eq!(state.borrow().dispatches, 0);
    assert!(pool.idle());
}

#[test]
fn worker_duration_conversion_drops_unrepresentable_diagnostics_without_wrapping() {
    use crate::block_v2::execution::worker::Timings;
    let maximum = u128::from(u64::MAX);
    let values = Timings {
        input_verification_ms: 0,
        proving_ms: maximum,
        serialization_ms: 1,
    };
    assert_eq!(
        WorkerTimings::try_from(values).unwrap(),
        WorkerTimings {
            input_verification_ms: 0,
            proving_ms: u64::MAX,
            serialization_ms: 1,
        }
    );
    for oversized in [
        Timings {
            input_verification_ms: maximum + 1,
            ..values
        },
        Timings {
            proving_ms: maximum + 1,
            ..values
        },
        Timings {
            serialization_ms: maximum + 1,
            ..values
        },
    ] {
        assert_eq!(WorkerTimings::try_from(oversized).ok(), None);
    }
}
