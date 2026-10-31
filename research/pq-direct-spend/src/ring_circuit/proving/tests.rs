use super::*;
use crate::ring_circuit::{compile_with_representation_diagnostics, CompilerMemoryProfile};

fn compile_fixture(context: Context) -> (Statement, CompiledRelation) {
    let (statement, witness) = crate::ring::fixture(context).unwrap();
    let compiled = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        CompilerMemoryProfile::Program2GiB.into(),
        CompilerRepresentation::FusedTernaryRangesV1,
        HOST_BYTES as usize,
    )
    .unwrap();
    drop(witness);
    (statement, compiled)
}

#[test]
#[ignore = "complete relation compilation; coordinator must admit a serialized host slot"]
fn complete_compiled_owner_rejects_wrong_statement_and_mutable_summary() {
    let context = Context([71; 32]);
    let (mut statement, compiled) = compile_fixture(context);
    statement.output_coins[0][0][0] = (statement.output_coins[0][0][0] + 1) % crate::ring::Q;
    assert!(matches!(
        FreshGpuProofInput::new(statement, context, compiled),
        Err(Error::Context)
    ));

    let (statement, mut compiled) = compile_fixture(context);
    compiled.summary.padded_rows /= 2;
    assert!(matches!(
        FreshGpuProofInput::new(statement, context, compiled),
        Err(Error::ResourceLimit)
    ));

    let (statement, mut compiled) = compile_fixture(context);
    compiled.summary.deferred_crypto_obligations = 1;
    assert!(matches!(
        FreshGpuProofInput::new(statement, context, compiled),
        Err(Error::ResourceLimit)
    ));
}

#[test]
#[ignore = "complete fresh GPU proof; coordinator must admit the full serialized GPU envelope"]
fn complete_fused_relation_fresh_gpu_generation_has_native_receipts_and_closed_session() {
    let context = Context([72; 32]);
    let (statement, compiled) = compile_fixture(context);
    assert!(compiled.program.height() <= MAX_ROWS);
    let proof = FreshGpuProofInput::new(statement, context, compiled)
        .unwrap()
        .prove()
        .unwrap();
    assert!(proof.report().independent_verification_required);
    assert_eq!(proof.report().proof_generation, "fresh-only");
    assert_eq!(proof.report().registration_lifetime, "consumed-once");
    assert!(proof.report().witness_instructions_retired_before_quotient);
    assert_eq!(proof.report().policy, Policy::GpuRequired);
    assert!(proof.report().terminal.context_closed);
    assert!(proof.report().terminal.queue_drained);
    assert!(proof.report().terminal.managed_peak_bytes <= DEVICE_BYTES);
    assert!(proof.report().retained_proof_bytes <= PROOF_BYTES);
    receipts::validate(
        &proof.report().registration,
        receipts::NativeScope::Registration,
    )
    .unwrap();
    receipts::validate(&proof.report().proving, receipts::NativeScope::Proof).unwrap();
    assert_eq!(
        proof.descriptor().active_rows,
        proof.report().compiler.active_rows as u64
    );
    assert_eq!(
        proof.descriptor().padded_rows,
        proof.report().compiler.padded_rows as u64
    );
    // This test establishes generation and teardown only. Acceptance belongs
    // to C's independent reconstruction/artifact/CPU-verification lifecycle.
}
