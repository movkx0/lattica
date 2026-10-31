//! Structural accounting fixtures below are deliberately invalid proofs.
//! The separately ignored CPU qualification uses real registration and proofs.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::machine::ProgramBuilder;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof};
use p3_field::PrimeCharacteristicRing;
use p3_fri::FriProof;
use p3_symmetric::MerkleCap;
use std::{cell::Cell, rc::Rc};

mod genuine;

fn storage() -> Storage {
    let program = ProgramBuilder::new(HEADER + 8)
        .unwrap()
        .finish(Some(1 << 19))
        .unwrap();
    Storage::new(inspect_registered_gpu_output(&program).unwrap(), HEADER + 8).unwrap()
}

fn proof() -> NodeProof {
    let cap = || MerkleCap::new(vec![[Val::ZERO; 4]; 64]);
    NodeProof {
        public: vec![Val::ZERO; HEADER + 8],
        proof: BatchProof {
            commitments: BatchCommitments {
                main: cap(),
                permutation: None,
                quotient_chunks: cap(),
                random: None,
            },
            opened_values: BatchOpenedValues {
                instances: Vec::new(),
            },
            opening_proof: (
                Vec::new(),
                FriProof {
                    commit_phase_commits: Vec::new(),
                    commit_pow_witnesses: Vec::new(),
                    query_proofs: Vec::new(),
                    final_poly: Vec::new(),
                    query_pow_witness: Val::ZERO,
                },
            ),
            lookup_terminals: Vec::new(),
            degree_bits: Vec::new(),
        },
    }
}

#[test]
fn claims_coexist_with_root_and_child_outputs_before_any_producer() {
    let plan = storage();
    let existing = 3 << 20;
    let ledger = Ledger::new(WorkerAllowance {
        host: existing + plan.report.total_claimed_host_bytes,
        device: 0,
    });
    let root = ledger
        .reserve(
            Category::RecursiveProof,
            Bytes {
                host: 2 << 20,
                device: 0,
            },
        )
        .unwrap();
    let child = ledger
        .reserve(
            Category::NativeProof,
            Bytes {
                host: 1 << 20,
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.snapshot();
    let claim = ledger.admit_phase(plan.requirements).unwrap();
    assert_eq!(
        ledger.snapshot().current.host,
        ledger.snapshot().allowance.host
    );
    assert!(ledger
        .reserve(Category::Report, Bytes { host: 1, device: 0 })
        .is_err());
    drop(claim);
    assert_eq!(ledger.snapshot().current, before.current);
    drop(root);
    drop(child);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);

    let short = Ledger::new(WorkerAllowance {
        host: plan.report.total_claimed_host_bytes - 1,
        device: 0,
    });
    assert!(short.admit_phase(plan.requirements).is_err());
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}

#[test]
fn category_transfer_keeps_payload_charge_across_scratch_retirement_and_moves() {
    let plan = storage();
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    });
    let mut claim = ledger.admit_phase(plan.requirements).unwrap();
    // Allocation occurs only after the whole output claim is already held.
    let proof = proof();
    let actual = plan.proof_bytes(&proof).unwrap();
    let key = plan.report.registered_key_host_bytes;
    let report = plan.report.report_host_bytes;
    let retained = retain_claims(&mut claim, actual, key, report).unwrap();
    drop(claim);
    assert_eq!(ledger.snapshot().current.host, actual + key + report);
    assert_eq!(
        retained.requirements().get(Category::IndependentVerifier),
        Bytes::ZERO
    );

    struct WatchedPayload {
        proof: NodeProof,
        ledger: Ledger,
        observed: Rc<Cell<bool>>,
        expected: u64,
    }
    impl Drop for WatchedPayload {
        fn drop(&mut self) {
            assert_eq!(self.ledger.snapshot().current.host, self.expected);
            assert_eq!(self.proof.public.len(), HEADER + 8);
            self.observed.set(true);
        }
    }
    struct Owner {
        _payload: WatchedPayload,
        _retained: Reservation,
    }
    let observed = Rc::new(Cell::new(false));
    let owner = Owner {
        _payload: WatchedPayload {
            proof,
            ledger: ledger.clone(),
            observed: Rc::clone(&observed),
            expected: actual + key + report,
        },
        _retained: retained,
    };
    let moved_owner = owner;
    assert_eq!(ledger.snapshot().current.host, actual + key + report);
    drop(moved_owner);
    assert!(observed.get());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn capacity_checks_do_not_exchange_public_headroom_for_proof_headroom() {
    let plan = storage();
    let mut value = proof();
    assert!(plan.proof_bytes(&value).is_ok());
    value.public.reserve_exact(1);
    assert!(matches!(plan.proof_bytes(&value), Err(Error::Capacity)));

    let mut value = proof();
    value.proof.degree_bits = Vec::with_capacity(
        plan.report.footprint.proof_backing_ceiling_host_bytes as usize / size_of::<usize>() + 1,
    );
    assert!(matches!(plan.proof_bytes(&value), Err(Error::Capacity)));
    assert!(Storage::new(plan.report.footprint, usize::MAX).is_err());
}

#[test]
fn failed_transfer_preserves_claim_and_no_report_grants_execution_authority() {
    let plan = storage();
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    });
    let mut claim = ledger.admit_phase(plan.requirements).unwrap();
    let before = ledger.snapshot();
    assert!(retain_claims(
        &mut claim,
        plan.report.recursive_output_host_bytes + 1,
        0,
        0
    )
    .is_err());
    assert_eq!(ledger.snapshot().current, before.current);
    assert!(!plan.report.independent_verification_complete);
    assert!(!plan.report.authenticated_source_key);
    assert!(!plan.report.transaction_context_authenticated);
    assert!(!plan.report.native_production_admitted);
    assert!(!plan.report.workflow_admitted);
    drop(claim);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
