use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use crate::graph_crypto::{Payload, Policy, RequestDescriptor};
use crate::shake_air::{self, lane::LaneShakeProof};
use p3_field::PrimeCharacteristicRing;

fn request() -> Request {
    Request::new(
        [7; 32],
        0,
        0,
        RequestDescriptor::Shake(shake_air::Descriptor {
            input_len: 0,
            output_len: 32,
        }),
        Payload::Shake(Vec::new()),
        Policy::default(),
    )
    .unwrap()
}

fn ledger(extra: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host: PROOF_BACKING_CEILING as u64 + extra,
        device: 0,
    })
}

#[test]
fn empty_claim_requires_exact_request_and_pre_admitted_shared_token() {
    let request = request();
    let other = self::request();
    let plan = NativeProductionPlan::new(&request, 0).unwrap();
    assert!(plan.source_storage_bytes() > size_of::<ReservedNativeChild>());
    assert!(plan.source_storage_bytes() < PROOF_BACKING_CEILING);
    assert!(plan.is_for(&request, 0));
    assert!(!plan.is_for(&other, 0));
    assert!(!plan.is_for(&request, 1));
    assert!(NativeProductionPlan::new(&request, 1).is_err());
    let ledger = ledger(0);
    let token = ledger.admit_phase(plan.requirement()).unwrap();
    let before = ledger.snapshot();
    let pending = plan.claim_for(&request, 0, token, &ledger).unwrap();
    assert_eq!(ledger.snapshot(), before);
    let moved = pending;
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    // This exercises only an empty ownership slot. No dispatch permit exists.
}

#[test]
fn request_mismatch_foreign_mixed_and_wrong_size_tokens_cannot_attach() {
    let request = request();
    let other = self::request();
    let ledger = ledger(1);
    for (candidate, index) in [(&other, 0), (&request, 1)] {
        let plan = NativeProductionPlan::new(&request, 0).unwrap();
        let token = ledger.admit_phase(plan.requirement()).unwrap();
        assert_eq!(
            plan.claim_for(candidate, index, token, &ledger).err(),
            Some(IDENTITY)
        );
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let foreign = self::ledger(0);
    let plan = NativeProductionPlan::new(&request, 0).unwrap();
    let token = foreign.admit_phase(plan.requirement()).unwrap();
    assert_eq!(
        plan.claim_for(&request, 0, token, &ledger).err(),
        Some(AUTHORITY)
    );
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    for bytes in [PROOF_BACKING_CEILING - 1, PROOF_BACKING_CEILING + 1] {
        let plan = NativeProductionPlan::new(&request, 0).unwrap();
        let token = ledger
            .reserve(
                Category::NativeProof,
                Bytes {
                    host: bytes as u64,
                    device: 0,
                },
            )
            .unwrap();
        assert_eq!(
            plan.claim_for(&request, 0, token, &ledger).err(),
            Some(AUTHORITY)
        );
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let plan = NativeProductionPlan::new(&request, 0).unwrap();
    let mut mixed = plan.requirement();
    mixed
        .add(Category::Report, Bytes { host: 1, device: 0 })
        .unwrap();
    let token = ledger.admit_phase(mixed).unwrap();
    assert_eq!(
        plan.claim_for(&request, 0, token, &ledger).err(),
        Some(AUTHORITY)
    );
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn payload_drops_before_its_linear_charge_even_on_unwind() {
    struct ObserveDrop<'a> {
        ledger: &'a Ledger,
        observed: &'a core::cell::Cell<bool>,
    }
    impl Drop for ObserveDrop<'_> {
        fn drop(&mut self) {
            assert_eq!(
                self.ledger.snapshot().current.host,
                PROOF_BACKING_CEILING as u64
            );
            self.observed.set(true);
        }
    }
    for unwind in [false, true] {
        let ledger = ledger(0);
        let observed = core::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let request = request();
            let plan = NativeProductionPlan::new(&request, 0).unwrap();
            let token = ledger.admit_phase(plan.requirement()).unwrap();
            let pending = plan.claim_for(&request, 0, token, &ledger).unwrap();
            // Test-only payload exercises the same private owner/drop layout;
            // it is not a producer adapter or a proof-validity receipt.
            let owned = OwnedPayload {
                payload: ObserveDrop {
                    ledger: &ledger,
                    observed: &observed,
                },
                reservation: pending.reservation,
            };
            if unwind {
                panic!("injected producer unwind");
            }
            drop(owned);
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(observed.get());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn private_fixture_owner_keeps_immutable_artifact_with_reserved_backing() {
    let request = request();
    let plan = NativeProductionPlan::new(&request, 0).unwrap();
    let ledger = ledger(0);
    let token = ledger.admit_phase(plan.requirement()).unwrap();
    let pending = plan.claim_for(&request, 0, token, &ledger).unwrap();
    // Deliberately invalid cryptographic fixture, allocated only after its
    // output token. Test construction does not enable a production attachment.
    let air = &request.shake_partition().unwrap().segments()[0];
    let proof = crate::component_tree::shape_diagnostic::invalid_native_template(air, air.height());
    let artifact = SegmentArtifact::Shake(LaneShakeProof {
        public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
        proof,
    });
    let child = RetainedNativeChild::from_fresh(0, [9; 32], pending.plan.shape, artifact).unwrap();
    let owner = ReservedNativeChild {
        owned: OwnedPayload {
            payload: child,
            reservation: pending.reservation,
        },
    };
    assert_eq!(owner.index(), 0);
    assert_eq!(owner.key(), &[9; 32]);
    assert_eq!(
        owner.artifact().public_values().len(),
        shake_air::PUBLIC_VALUES
    );
    assert!(owner.shape().retained_bytes() <= PROOF_BACKING_CEILING);
    assert_eq!(ledger.snapshot().current.host, PROOF_BACKING_CEILING as u64);
    let moved = owner;
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
