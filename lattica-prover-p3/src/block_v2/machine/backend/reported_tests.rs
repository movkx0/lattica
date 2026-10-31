use super::*;
use crate::block_v2::machine::ProgramBuilder;
use crate::proving::{CoverageScope, Policy, Request};

const BUDGET: u64 = 1 << 30;
fn air() -> MachineAir {
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    let seven = builder.constant(Val::from_u64(7));
    let sum = builder.add(input, seven);
    let public = builder.public(0).unwrap();
    builder.assert_equal(sum, public);
    MachineAir::new(builder.finish(Some(16)).unwrap())
}
fn silent_cpu() -> Request {
    Request {
        policy: Policy::CpuRequired,
        emit_report: false,
    }
}

#[test]
fn opt_in_silent_receipts_preserve_key_proof_and_independent_verification() {
    let original = RegisteredProgram::new_with_request(air(), BUDGET, silent_cpu()).unwrap();
    let (reported, preprocessing) =
        RegisteredProgram::new_with_request_and_identity_hint_and_report(
            air(),
            BUDGET,
            silent_cpu(),
            None,
        )
        .unwrap();
    assert_eq!(reported.id(), original.id());
    assert_eq!(reported.preprocessing_cap(), original.preprocessing_cap());
    assert_eq!(reported.air().program(), original.air().program());
    assert_eq!(preprocessing.entry_point, "block_v2_preprocessing");
    assert_eq!(preprocessing.policy, Policy::CpuRequired);
    assert_eq!(
        preprocessing.capabilities.scope(),
        CoverageScope::Preprocessing
    );
    assert!(preprocessing.succeeded);
    assert!(!preprocessing.observations.is_empty());

    let public = [Val::from_u64(10)];
    let witness = [Val::from_u64(3)];
    let (proof, receipt) = reported
        .prove_with_request_and_report(&public, &witness, silent_cpu())
        .unwrap();
    assert_eq!(receipt.entry_point, "block_v2_registered_program");
    assert_eq!(receipt.policy, Policy::CpuRequired);
    assert_eq!(receipt.capabilities.scope(), CoverageScope::RegisteredProof);
    assert!(receipt.succeeded);
    assert!(!receipt.observations.is_empty());
    original.verify(&proof, &public).unwrap();
    assert!(original.verify(&proof, &[Val::from_u64(11)]).is_err());
    let original_proof = original
        .prove_with_request(&public, &witness, silent_cpu())
        .unwrap();
    reported.verify(&original_proof, &public).unwrap();
    // Both successful source receipts survive disabled JSON output and remain
    // directly serializable; they contain the exact returned profile metadata.
    for report in [&preprocessing, &receipt] {
        let encoded = serde_json::to_value(report).unwrap();
        assert_eq!(encoded["entry_point"], report.entry_point);
        assert_eq!(
            encoded["capabilities"]["max_log_fri_arity"],
            report.capabilities.max_log_fri_arity()
        );
    }
}

#[test]
fn report_returning_adapters_preserve_policy_and_input_refusals() {
    let gpu = Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    };
    assert!(
        RegisteredProgram::new_with_request_and_identity_hint_and_report(air(), BUDGET, gpu, None,)
            .is_err()
    );
    let (registered, _) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
        air(),
        BUDGET,
        silent_cpu(),
        None,
    )
    .unwrap();
    assert!(registered
        .prove_with_request_and_report(&[], &[Val::from_u64(3)], silent_cpu())
        .is_err());
    assert!(registered
        .prove_with_request_and_report(&[Val::from_u64(10)], &[Val::from_u64(3)], gpu)
        .is_err());
}
