use super::*;
use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};

#[test]
fn symbolic_scratch_covers_the_fixed_heap_inventory_and_shared_collections() {
    let plan = SymbolicScratch::fixed().unwrap();
    let collections = Collections::fixed().unwrap();
    assert_eq!(
        plan.collection_bytes,
        collections.partial_constructor_requested_bytes
    );
    assert_eq!(
        plan.requested_bytes,
        plan.imported_bytes + plan.parameter_bytes + plan.relation_bytes + plan.collection_bytes,
    );
    let polynomial_backing =
        3 * ((198 + 9 + 185 + 238) * size_of::<Canonical>() + (78 + 12) * size_of::<Signed>());
    assert!(plan.imported_bytes + plan.parameter_bytes + plan.relation_bytes > polynomial_backing);
    assert_eq!(198 + 9 + 185 + 238 + 78 + 12, 720);
    assert!(growing::<Canonical>(usize::MAX).is_err());
}

#[test]
fn actual_symbolic_imports_fit_and_spare_nested_capacity_is_not_lost() {
    let mut bytes = vec![0; STATEMENT_BYTES];
    bytes[STATEMENT_BYTES - 32] = 1;
    let statement = Statement::decode(&bytes).unwrap();
    let proof = Proof::decode(&vec![0; PROOF_BYTES]).unwrap();
    let mut backend = CommittedBackend::new([0; 32]);
    let statement = backend.import_statement(&statement);
    let mut proof = backend.import_proof(&proof);
    let actual = imported_retained_bytes(&statement, &proof).unwrap();
    let bound = SymbolicScratch::fixed().unwrap().imported_bytes;
    let inline = size_of::<ImportedStatement>() + size_of::<ImportedProof>();
    // These actual imports collect from borrowed exact-length slices. The
    // preceding bound additionally keeps the full factor-three overlap margin.
    assert_eq!(bound, 3 * (actual - inline) + inline);
    check_imported_storage(&statement, &proof).unwrap();
    let previous = proof.z_out[1].capacity();
    proof.z_out[1].reserve_exact(bound / size_of::<Signed>() + 1);
    let added = (proof.z_out[1].capacity() - previous) * size_of::<Signed>();
    assert_eq!(
        imported_retained_bytes(&statement, &proof).unwrap(),
        actual + added
    );
    assert!(check_imported_storage(&statement, &proof).is_err());
}
