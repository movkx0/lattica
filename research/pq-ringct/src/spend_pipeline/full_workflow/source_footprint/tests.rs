use super::*;
use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};

#[test]
fn exact_native_view_censuses_spare_backing_and_rejects_source_mismatch() {
    let mut statement = vec![0; STATEMENT_BYTES];
    statement[STATEMENT_BYTES - 1] = 1;
    let mut proof = vec![0; PROOF_BYTES];
    statement.reserve_exact(73);
    proof.reserve_exact(29);
    let decoded_statement = Statement::decode(&statement).unwrap();
    let decoded_proof = Proof::decode(&proof).unwrap();
    let source = InitialNativeSource::new(
        [1; 32], [2; 32], &statement, &proof, &decoded_statement, &decoded_proof,
    ).unwrap();
    assert!(source.retained_bytes() >= statement.capacity() + proof.capacity());
    assert!(core::ptr::eq(source.statement(), &decoded_statement));
    assert!(core::ptr::eq(source.proof(), &decoded_proof));
    let identity = source.identity();
    let other_context = InitialNativeSource::new(
        [1; 32], [3; 32], &statement, &proof, &decoded_statement, &decoded_proof,
    ).unwrap();
    assert_ne!(identity, other_context.identity());
    let mut wrong = decoded_proof.clone();
    wrong.z[0][0] += 1;
    assert!(InitialNativeSource::new(
        [1; 32], [2; 32], &statement, &proof, &decoded_statement, &wrong,
    ).is_err());
}
