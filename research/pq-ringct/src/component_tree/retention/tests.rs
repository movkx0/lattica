//! Authored only during the freeze. Templates are invalid shapes, not proofs.
use super::*;
use crate::component_tree::{MachineAir, ProgramBuilder};
use lattica_prover_p3::block_v2::machine::verifier::template;
use p3_field::PrimeCharacteristicRing;

#[test]
fn key_reservation_rejects_overflow_and_keeps_shared_allowance_explicit() {
    assert!(matches!(
        key_reservation_bytes(usize::MAX, 0),
        Err(ExecutionError::TooLarge)
    ));
    assert!(matches!(
        key_reservation_bytes(0, usize::MAX),
        Err(ExecutionError::TooLarge)
    ));
    let envelope = key_reservation_bytes(0, 0).unwrap();
    assert!(envelope >= 2 * size_of::<usize>());
    let one = key_reservation_bytes(2, 17).unwrap();
    let two = key_reservation_bytes(3, 17).unwrap();
    assert_eq!(two - one, size_of::<[Val; 4]>());
    assert_eq!(one - envelope, 2 * size_of::<[Val; 4]>() + 17);
    assert!(matches!(
        public_backing_bytes(usize::MAX),
        Err(ExecutionError::TooLarge)
    ));
}

#[test]
fn node_proof_counts_spare_public_capacity_and_enforces_combined_limit() {
    let air = MachineAir::new(ProgramBuilder::new(0).unwrap().finish(Some(8)).unwrap());
    let proof = template::batch(&air).unwrap();
    let proof_bytes = retained_proof_capacity_bytes(&proof, usize::MAX).unwrap();
    let mut public = Vec::with_capacity(7);
    public.push(Val::ZERO);
    let public_bytes = public.capacity() * size_of::<Val>();
    let node = NodeProof { public, proof };
    let exact = proof_bytes.checked_add(public_bytes).unwrap();
    let public_pointer = node.public.as_ptr();
    let degree_pointer = node.proof.degree_bits.as_ptr();
    assert_eq!(node.retained_backing_bytes(exact).unwrap(), exact);
    assert!(matches!(
        node.retained_backing_bytes(exact - 1),
        Err(ExecutionError::TooLarge)
    ));
    assert!(matches!(
        node.retained_backing_bytes(public_bytes - 1),
        Err(ExecutionError::TooLarge)
    ));
    assert_eq!(node.public.as_ptr(), public_pointer);
    assert_eq!(node.proof.degree_bits.as_ptr(), degree_pointer);
}
