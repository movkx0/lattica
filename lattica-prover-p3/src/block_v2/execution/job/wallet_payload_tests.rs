use super::*;
use std::sync::Arc;
use test_support::{typed_pin, typed_wallet, wallet};

#[test]
fn detached_wallet_binding_rejects_substituted_bytes_kind_and_excess_capacity() {
    let ticket = wallet(1, &[1, 2, 3]);
    for bytes in [vec![], vec![1, 2], vec![1, 2, 0], vec![1, 2, 3, 4]] {
        assert!(VerifiedWalletPayload::new(ticket, bytes).is_err());
    }
    let mut wrong_kind = ticket;
    wrong_kind.artifact = ArtifactRef::from_bytes(ArtifactKind::Node, &[1, 2, 3]).unwrap();
    assert!(VerifiedWalletPayload::new(wrong_kind, vec![1, 2, 3]).is_err());
    let mut oversized = Vec::with_capacity(VerifiedWalletPayload::INPUT_CAPACITY_BYTES + 1);
    oversized.extend([1, 2, 3]);
    assert!(VerifiedWalletPayload::new(ticket, oversized).is_err());
    let mut exact = Vec::with_capacity(VerifiedWalletPayload::INPUT_CAPACITY_BYTES);
    exact.extend([1, 2, 3]);
    let payload = VerifiedWalletPayload::new(ticket, exact).unwrap();
    assert_eq!(payload.ticket(), ticket);
    assert_eq!(payload.bytes(), [1, 2, 3]);
    let alias = payload.clone();
    assert!(Arc::ptr_eq(payload.shared_bytes(), alias.shared_bytes()));
    let weak = Arc::downgrade(alias.shared_bytes());
    drop(payload);
    assert_eq!(alias.bytes(), [1, 2, 3]);
    drop(alias);
    assert!(weak.upgrade().is_none());
}

#[test]
fn owned_wallet_list_requires_exact_order_count_and_context() {
    let left = typed_wallet(1, 1, &[1]);
    let right = typed_wallet(2, 1, &[2]);
    let job = Job::typed_pair(0, left, Some(right)).unwrap();
    let inputs = [
        VerifiedWalletPayload::new(left, vec![1]).unwrap(),
        VerifiedWalletPayload::new(right, vec![2]).unwrap(),
    ];
    VerifiedWalletPayload::check_job_inputs(&job, &inputs).unwrap();
    assert!(VerifiedWalletPayload::check_job_inputs(&job, &inputs[..1]).is_err());
    assert!(VerifiedWalletPayload::check_job_inputs(&job, &[]).is_err());
    assert!(VerifiedWalletPayload::check_job_inputs(&job, &[inputs[1].clone(), inputs[0].clone()]).is_err());
    let alternate = VerifiedWalletPayload::new(typed_wallet(1, 1, &[3]), vec![3]).unwrap();
    assert!(VerifiedWalletPayload::check_job_inputs(&job, &[alternate, inputs[1].clone()]).is_err());
    let empty = Job::empty(typed_pin(), [9; 32], 0, 1).unwrap();
    assert!(VerifiedWalletPayload::check_job_inputs(&empty, &inputs).is_err());
    for index in 0..3 {
        let mut changed = job.clone();
        match index {
            0 => changed.pin.profile[0] ^= 1,
            1 => changed.pin.typed = false,
            _ => changed.expected.context.chain_id[0] ^= 1,
        }
        assert!(VerifiedWalletPayload::check_job_inputs(&changed, &inputs).is_err());
    }
    let odd = Job::typed_pair(0, left, None).unwrap();
    VerifiedWalletPayload::check_job_inputs(&odd, &[inputs[0].clone(), inputs[0].clone()]).unwrap();
}
