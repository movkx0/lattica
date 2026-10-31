use super::*;

fn packets() -> (Vec<u8>, Vec<u8>) {
    let mut statement = vec![0; STATEMENT_BYTES];
    // Distinct public serials are required by the maintained decoder.
    statement[STATEMENT_BYTES - 1] = 1;
    (statement, vec![0; PROOF_BYTES])
}

#[test]
fn allocation_free_source_match_agrees_with_both_decoders() {
    let (statement, proof) = packets();
    let mut decoded_statement = Statement::decode(&statement).unwrap();
    let mut decoded_proof = Proof::decode(&proof).unwrap();
    assert!(decoded_statement.matches_encoded(&statement).unwrap());
    assert!(decoded_proof.matches_encoded(&proof).unwrap());
    decoded_statement.ring[9][1].cn[4][D - 1] = 1;
    assert!(!decoded_statement.matches_encoded(&statement).unwrap());
    decoded_proof.z[7][D - 1] += 1;
    assert!(!decoded_proof.matches_encoded(&proof).unwrap());
}

#[test]
fn packed_final_bits_and_trailing_bytes_are_not_ignored() {
    let (_, mut proof) = packets();
    let decoded = Proof::decode(&proof).unwrap();
    proof[PROOF_BYTES - 1] ^= 0x80;
    assert!(!decoded.matches_encoded(&proof).unwrap());
    assert!(Proof::decode(&proof).unwrap().matches_encoded(&proof).unwrap());
    proof.push(0);
    assert!(matches!(decoded.matches_encoded(&proof), Err(VerifyError::Length)));
}

#[test]
fn source_match_reuses_canonical_and_signed_rejections() {
    let (mut statement, mut proof) = packets();
    let decoded_statement = Statement::decode(&statement).unwrap();
    let decoded_proof = Proof::decode(&proof).unwrap();
    statement[32..36].fill(0xff);
    assert!(matches!(Statement::decode(&statement), Err(VerifyError::NonCanonical)));
    assert!(matches!(decoded_statement.matches_encoded(&statement), Err(VerifyError::NonCanonical)));
    proof[..3].fill(0xff);
    proof[3] = 0x0f;
    assert!(matches!(Proof::decode(&proof), Err(VerifyError::NonCanonical)));
    assert!(matches!(decoded_proof.matches_encoded(&proof), Err(VerifyError::NonCanonical)));
    proof[..4].fill(0);
    let x_offset = (7 * D * 28 + 5 * D * 32 + 32 * 8) / 8;
    proof[x_offset] = 3;
    assert!(matches!(Proof::decode(&proof), Err(VerifyError::NonCanonical)));
    assert!(matches!(decoded_proof.matches_encoded(&proof), Err(VerifyError::NonCanonical)));
}

#[test]
fn source_match_rejects_wrong_dimensions_and_duplicate_serials() {
    let (mut statement, proof) = packets();
    let mut decoded_statement = Statement::decode(&statement).unwrap();
    let mut decoded_proof = Proof::decode(&proof).unwrap();
    decoded_statement.recipients[0].pop();
    decoded_proof.z_out[0].pop();
    assert!(!decoded_statement.matches_encoded(&statement).unwrap());
    assert!(!decoded_proof.matches_encoded(&proof).unwrap());
    let decoded_statement = Statement::decode(&statement).unwrap();
    statement[STATEMENT_BYTES - 1] = 0;
    assert!(matches!(decoded_statement.matches_encoded(&statement), Err(VerifyError::DuplicateSerial)));
}
