//! Structural callback boundaries; real proof and policy checks are exercised
//! by the archived journal audits and the fresh registry recovery test.
use super::*;
use crate::block_v2::execution::job::test_support::{typed_pin, typed_wallet, wallet};
use std::sync::Arc;

fn limits() -> Limits {
    Limits {
        jobs: 128, candidates: 4, attempts: 16, artifact_bytes: 32 << 20,
        recovery_window_ms: 10,
        workers: Resources { ram_bytes: 64, vram_bytes: 0, scratch_bytes: 0, threads: 1 },
    }
}

fn fixture() -> (Vec<u8>, Job, VerifiedWallet) {
    let ticket = typed_wallet(1, 1, &[1, 2]);
    let job = Job::typed_pair(0, ticket, None).unwrap();
    let mut dag = Dag::new(typed_pin(), [9; 32], 1, limits()).unwrap();
    dag.admit(job.clone(), vec![vec![1, 2], vec![1, 2]], 0).unwrap();
    let root = Job::finalize(&job).unwrap();
    dag.admit(root, vec![], 0).unwrap();
    (dag.snapshot().unwrap(), job, ticket)
}

#[test]
fn restored_wallet_owners_preserve_exact_backing_and_snapshot_semantics() {
    let (snapshot, job, ticket) = fixture();
    let mut pointers = Vec::new();
    let mut weak = Vec::new();
    let owned = restore_payloads_with(
        &snapshot, typed_pin(), [9; 32], 2, limits(),
        |identity| {
            assert_eq!(identity, ticket.artifact());
            let payload = VerifiedWalletPayload::new(ticket, vec![1, 2])?;
            pointers.push(payload.bytes().as_ptr());
            weak.push(Arc::downgrade(payload.shared_bytes()));
            Ok(payload)
        },
        |_, _| panic!("dormant fixture has no node output"),
    ).unwrap();
    assert_eq!(pointers.len(), 2); // padded slots still verify independently
    assert_ne!(pointers[0], pointers[1]);
    for (index, bytes) in owned.dag.jobs[&job.id()].wallets.iter().enumerate() {
        assert_eq!(bytes.as_ptr(), pointers[index]);
        assert_eq!(bytes.as_ref(), [1, 2]);
    }
    assert_eq!(owned.dag.stored_bytes(), 4);
    assert!(owned.dag.ready().is_empty() && owned.candidates.is_empty() && owned.attempts.is_empty());
    let detached = restore_with(
        &snapshot, typed_pin(), [9; 32], 2, limits(),
        |_| Ok((ticket, vec![1, 2])),
        |_, _| panic!("dormant fixture has no node output"),
    ).unwrap();
    let reference = detached.dag.snapshot().unwrap();
    let mut observed = owned.dag.snapshot().unwrap();
    let start = 8 + 32 + 1 + 32;
    assert_ne!(detached.dag.session, owned.dag.session);
    observed[start..start + 32].copy_from_slice(&detached.dag.session);
    assert_eq!(reference, observed);
    assert!(weak.iter().all(|bytes| bytes.upgrade().is_some()));
    drop(owned);
    assert!(weak.iter().all(|bytes| bytes.upgrade().is_none()));
}

#[test]
fn detached_recovery_rebinds_mutated_bytes_and_rejects_excess_backing() {
    let (snapshot, _, ticket) = fixture();
    for bytes in [vec![], vec![1], vec![1, 0], vec![1, 2, 3]] {
        assert!(restore_with(
            &snapshot, typed_pin(), [9; 32], 2, limits(),
            |_| Ok((ticket, bytes.clone())),
            |_, _| panic!("invalid wallet must precede any node load"),
        ).is_err());
    }
    assert!(restore_with(
        &snapshot, typed_pin(), [9; 32], 2, limits(),
        |_| {
            let mut bytes = Vec::with_capacity(VerifiedWalletPayload::INPUT_CAPACITY_BYTES + 1);
            bytes.extend([1, 2]);
            Ok((ticket, bytes))
        },
        |_, _| panic!("invalid wallet must precede any node load"),
    ).is_err());
}

#[test]
fn owned_recovery_requires_requested_artifact_context_and_valid_envelope() {
    let (snapshot, _, _) = fixture();
    for ticket in [typed_wallet(1, 1, &[3, 4]), wallet(1, &[3, 4])] {
        assert!(restore_payloads_with(
            &snapshot, typed_pin(), [9; 32], 2, limits(),
            |_| VerifiedWalletPayload::new(ticket, vec![3, 4]),
            |_, _| panic!("substituted wallet must precede any node load"),
        ).is_err());
    }
    // The same encoded identity cannot move a legacy ticket into a typed job.
    assert!(restore_payloads_with(
        &snapshot, typed_pin(), [9; 32], 2, limits(),
        |_| VerifiedWalletPayload::new(wallet(1, &[1, 2]), vec![1, 2]),
        |_, _| panic!("wrong wallet context must precede any node load"),
    ).is_err());
    let mut changed = snapshot;
    changed.push(0);
    assert!(restore_payloads_with(
        &changed, typed_pin(), [9; 32], 2, limits(),
        |_| panic!("validate the entire envelope before loading proof bytes"),
        |_, _| panic!("validate the entire envelope before loading proof bytes"),
    ).is_err());
}
