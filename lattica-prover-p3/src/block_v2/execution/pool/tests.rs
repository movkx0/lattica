use super::*;
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
}
struct SimulatedEndpoint {
    cap: WorkerCapabilities,
    state: Rc<RefCell<Observed>>,
}
impl WorkerEndpoint for SimulatedEndpoint {
    fn capabilities(&self) -> WorkerCapabilities {
        self.cap.clone()
    }
    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        self.state.borrow_mut().contexts.push(context.binding());
        Ok(())
    }
    fn dispatch(&mut self, _: &mut DurableDag, _: Lease, _: u64) -> Result<(), Error> {
        self.state.borrow_mut().dispatches += 1;
        Ok(())
    }
    fn try_result(&mut self, _: &mut DurableDag, _: u64) -> Result<Option<WorkerResult>, Error> {
        if self.state.borrow().fail_result {
            return Err("simulated broken transport".into());
        }
        Ok(None)
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
        self.state.borrow_mut().closed += 1;
        Ok(())
    }
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
