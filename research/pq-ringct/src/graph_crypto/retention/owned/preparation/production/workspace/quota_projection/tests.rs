use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy, ShakeRequestPlan},
};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: HOST_BYTES,
        device: DEVICE_BYTES,
    })
}

fn owned(ledger: &Ledger, byte: u8) -> ReservedShakeRequest {
    let input = [byte; 16_416];
    let source = ShakeRequestPlan::new_active_opt_validate_v1(
        [41; 32],
        9,
        0,
        &input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap();
    let claim = ledger.admit_phase(source.requirements()).unwrap();
    source.construct(claim, ledger).unwrap()
}

#[test]
fn exact_pending_projection_restores_every_category_and_preserves_source() {
    let ledger = ledger();
    let owner = owned(&ledger, 23);
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger)
        .unwrap()
        .with_outer_bridge()
        .unwrap();
    let before = ledger.snapshot();
    let first = pending.project_outer_quota(&owner, &ledger).unwrap();
    assert_eq!(first.retained_tree_host_bytes, 8 << 30);
    assert_eq!(
        first.startup.device + first.phase_wrappers.device + first.pcs.device,
        DEVICE_BYTES
    );
    assert!(first.phase_wrappers.host > 0);
    let after = ledger.snapshot();
    assert_eq!(after.current, before.current);
    for category in Category::ALL {
        assert_eq!(
            after.categories[category as usize].current,
            before.categories[category as usize].current
        );
    }
    assert_eq!(pending.project_outer_quota(&owner, &ledger).unwrap(), first);
    assert_eq!(
        pending.outputs.iter().filter(|slot| slot.is_some()).count(),
        SEGMENTS
    );
    assert_eq!(
        pending
            .attachments
            .iter()
            .filter(|slot| slot.is_some())
            .count(),
        SEGMENTS
    );
    drop(pending);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn missing_bridge_foreign_identity_and_missing_output_refuse_before_projection() {
    let ledger = ledger();
    let owner = owned(&ledger, 29);
    let other_owner = owned(&ledger, 31);
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger).unwrap();
    let before = ledger.snapshot();
    assert!(matches!(
        pending.project_outer_quota(&owner, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    let mut pending = pending.with_outer_bridge().unwrap();
    let before = ledger.snapshot();
    assert!(matches!(
        pending.project_outer_quota(&other_owner, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    let output = pending.outputs[3].take();
    let before = ledger.snapshot();
    assert!(matches!(
        pending.project_outer_quota(&owner, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    pending.outputs[3] = output;
    drop(pending);
    drop((owner, other_owner));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn startup_shortage_is_cpu_only_and_preserves_the_pending_owner() {
    let ledger = ledger();
    let owner = owned(&ledger, 37);
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger)
        .unwrap()
        .with_outer_bridge()
        .unwrap();
    let startup = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let startup_host = startup.reserved_bytes().host;
    drop(startup);
    let blocker = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: ledger.remaining().host - (startup_host - 1),
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.snapshot().current;
    assert!(matches!(
        pending.project_outer_quota(&owner, &ledger),
        Err(Error::Runtime)
    ));
    assert_eq!(ledger.snapshot().current, before);
    drop(blocker);
    assert!(pending.project_outer_quota(&owner, &ledger).is_ok());
    drop(pending);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
