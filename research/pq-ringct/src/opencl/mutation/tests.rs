use super::*;
use lattica_prover_p3::block_v2::machine::{verifier::template, MachineAir};
use std::{
    cell::Cell,
    panic::{catch_unwind, AssertUnwindSafe},
};

// Invalid zero templates only exercise storage/restore paths. These tests
// never submit a template to a numerical verifier or claim a valid proof.
fn fixture() -> NodeProof {
    let (program, public, _) = super::super::byte_fixture().unwrap();
    let proof = template::batch(&MachineAir::new(program)).unwrap();
    NodeProof { public, proof }
}
fn snapshot(proof: &NodeProof) -> (Vec<Val>, Vec<u8>) {
    (
        proof.public.clone(),
        serde_json::to_vec(&proof.proof).unwrap(),
    )
}
fn misleading_failures() -> [Check; 4] {
    [
        Ok(()),
        Err(Failure::Admission("proof rejected".into())),
        Err(Failure::Configuration("proof rejected".into())),
        Err(Failure::Allocation("proof rejected".into())),
    ]
}

#[test]
fn only_typed_numerical_rejection_earns_credit() {
    let mut credit = 0;
    for result in misleading_failures() {
        if require_rejection(result).is_ok() {
            credit += 1;
        }
    }
    assert_eq!(credit, 0);
    // Diagnostic content never changes the typed decision, including an empty
    // numerical error or misleading infrastructure text.
    assert!(require_rejection(Err(Failure::RelationRejected(String::new()))).is_ok());
}

#[test]
fn public_mutation_restores_after_every_returned_outcome() {
    let mut proof = fixture();
    let original = snapshot(&proof);
    for result in misleading_failures() {
        assert!(public(&mut proof, 0, |changed| {
            assert_eq!(changed.public[0], original.0[0] + Val::ONE);
            result
        })
        .is_err());
        assert_eq!(snapshot(&proof), original);
    }
    assert!(public(&mut proof, 0, |_| Err(Failure::RelationRejected(
        "numeric".into()
    )))
    .is_ok());
    assert_eq!(snapshot(&proof), original);
}

#[test]
fn both_opening_guard_specializations_restore_after_errors() {
    let mut proof = fixture();
    let original = snapshot(&proof);
    let old_opening = proof.proof.opened_values.instances[0].permutation_local[0];
    for result in misleading_failures() {
        assert!(opening(&mut proof, |changed| {
            assert_eq!(
                changed.proof.opened_values.instances[0].permutation_local[0],
                old_opening + Challenge::ONE
            );
            result
        })
        .is_err());
        assert_eq!(snapshot(&proof), original);
    }
    for result in misleading_failures() {
        assert!(opening(&mut proof.proof, |changed| {
            assert_eq!(
                changed.opened_values.instances[0].permutation_local[0],
                old_opening + Challenge::ONE
            );
            result
        })
        .is_err());
        assert_eq!(snapshot(&proof), original);
    }
    assert!(opening(&mut proof, |_| Err(Failure::RelationRejected(
        "numeric".into()
    )))
    .is_ok());
    assert_eq!(snapshot(&proof), original);
}

#[test]
fn all_guards_restore_during_unwind_without_granting_credit() {
    let mut proof = fixture();
    let original = snapshot(&proof);
    assert!(
        catch_unwind(AssertUnwindSafe(|| public(&mut proof, 0, |_| panic!(
            "injected public verifier unwind"
        ))))
        .is_err()
    );
    assert_eq!(snapshot(&proof), original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| opening(&mut proof, |_| panic!(
            "injected node verifier unwind"
        ))))
        .is_err()
    );
    assert_eq!(snapshot(&proof), original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| opening(&mut proof.proof, |_| panic!(
            "injected batch verifier unwind"
        ))))
        .is_err()
    );
    assert_eq!(snapshot(&proof), original);
}

#[test]
fn invalid_slots_fail_before_verification_or_mutation() {
    let mut proof = fixture();
    let original = snapshot(&proof);
    let called = Cell::new(false);
    let invalid_index = proof.public.len();
    assert!(public(&mut proof, invalid_index, |_| {
        called.set(true);
        Ok(())
    })
    .is_err());
    assert!(!called.get());
    assert_eq!(snapshot(&proof), original);
    proof.proof.opened_values.instances[0]
        .permutation_local
        .clear();
    let original = snapshot(&proof);
    assert!(opening(&mut proof, |_| {
        called.set(true);
        Ok(())
    })
    .is_err());
    assert!(!called.get());
    assert_eq!(snapshot(&proof), original);
    proof.proof.opened_values.instances.clear();
    let original = snapshot(&proof);
    assert!(opening(&mut proof.proof, |_| {
        called.set(true);
        Ok(())
    })
    .is_err());
    assert!(!called.get());
    assert_eq!(snapshot(&proof), original);
}

#[test]
fn byte_public_probe_is_fixed_size_and_preserves_original() {
    let original = [Val::from_u64(17), Val::from_u64(31)];
    assert_eq!(
        wrong_byte_public(&original).unwrap(),
        [original[0] + Val::ONE, original[1]]
    );
    assert_eq!(original, [Val::from_u64(17), Val::from_u64(31)]);
    for invalid in [&[][..], &original[..1], &[Val::ZERO; 3][..]] {
        assert!(wrong_byte_public(invalid).is_err());
    }
}

#[test]
fn added_reservation_is_exact_and_preserves_device_and_row_limits() {
    let limits = Limits {
        host_bytes: 4 << 30,
        device_bytes: 2 << 30,
        max_rows: 1 << 20,
    };
    for stage in [Stage::PqByte, Stage::PqAesComponent] {
        let admitted = Admission::new(stage, limits).unwrap();
        let work = admitted.work_limits();
        assert_eq!(admitted.original_host_bytes(), limits.host_bytes);
        assert!(admitted.reserved_host_bytes() > 0);
        assert_eq!(
            work.host_bytes.checked_add(admitted.reserved_host_bytes()),
            Some(limits.host_bytes)
        );
        assert_eq!(work.device_bytes, limits.device_bytes);
        assert_eq!(work.max_rows, limits.max_rows);
        let exact = Limits {
            host_bytes: (1 << 30) + admitted.reserved_host_bytes(),
            ..limits
        };
        assert_eq!(
            Admission::new(stage, exact)
                .unwrap()
                .work_limits()
                .host_bytes,
            1 << 30
        );
        assert!(Admission::new(
            stage,
            Limits {
                host_bytes: exact.host_bytes - 1,
                ..limits
            }
        )
        .is_err());
        assert!(Admission::new(
            stage,
            Limits {
                host_bytes: 1 << 30,
                ..limits
            }
        )
        .is_err());
        eprintln!(
            "stage={} additional_smoke_host_bytes={} remaining_host_bytes={}",
            stage.name(),
            admitted.reserved_host_bytes(),
            work.host_bytes
        );
    }
    assert!(Admission::subtract(limits, limits.host_bytes + 1).is_err());
    assert!(Admission::new(
        Stage::PqByte,
        Limits {
            device_bytes: 0,
            ..limits
        }
    )
    .is_err());
    assert!(Admission::new(
        Stage::PqByte,
        Limits {
            max_rows: 3,
            ..limits
        }
    )
    .is_err());
}

#[test]
fn reservation_arithmetic_fails_closed_and_diagnostics_stay_bounded() {
    assert!(sum(usize::MAX, 1).is_err());
    assert!(times(usize::MAX, 2).is_err());
    assert_eq!(sum(usize::MAX - 1, 1).unwrap(), usize::MAX);
    assert_eq!(times(usize::MAX, 1).unwrap(), usize::MAX);
    for diagnostic in [
        ACCEPTED,
        ADMISSION,
        CONFIGURATION,
        ALLOCATION,
        PUBLIC_SHAPE,
        BUDGET,
        OVERFLOW,
        "qualification proof is missing its lookup opening",
    ] {
        assert!(diagnostic.len() <= DIAGNOSTIC_BYTES);
    }
    assert!(CLASSIFICATION.len() < 128);
    for key in [
        "mutation_outcome_classification",
        "mutation_numerical_rejections",
        "mutation_probe_host_reserved_bytes",
        "mutation_remaining_host_bytes",
    ] {
        assert!(key.len() < 128);
    }
}
