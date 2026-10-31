use super::*;
use crate::rust_verify::committed_backend::{PolynomialKind, PolynomialValues};
#[test]
fn permutation_source_serializes_original_canonical_and_signed_words_only() {
    let canonical = PermutationDescriptor::new(PermutationOperation::AutomorphismQ);
    let inverse = PermutationDescriptor::new(PermutationOperation::InverseChallenge);
    let mut values = [0u64; 256]; values[0] = crate::rust_verify::Q - 1; values[255] = 7;
    let mut raw = WipedRaw(Vec::with_capacity(256));
    let capacity = raw.0.capacity();
    serialize_input(&mut raw.0, &PolynomialKind::Canonical { modulus: crate::rust_verify::Q },
        &PolynomialValues::Canonical(values), canonical).unwrap();
    assert_eq!(raw.0.as_slice(), &values); assert_eq!(raw.0.capacity(), capacity);
    raw.0.clear();
    let mut signed = [0i64; 256]; signed[0] = -1; signed[1] = 1;
    serialize_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Signed(signed), inverse).unwrap();
    assert_eq!(raw.0[0], u64::MAX); assert_eq!(raw.0[1], 1); assert_eq!(raw.0[255], 0);
    assert_eq!(raw.0.capacity(), capacity);
    assert_eq!(serialize_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Signed(signed), inverse), Err(PermutationFailure::Resource));
    assert_eq!(raw.0.capacity(), capacity);
}
#[test]
fn permutation_source_rejects_wrong_kind_noncanonical_values_and_signed_overflow() {
    let canonical = PermutationDescriptor::new(PermutationOperation::AutomorphismQ);
    let inverse = PermutationDescriptor::new(PermutationOperation::InverseChallenge);
    let mut raw = WipedRaw(Vec::with_capacity(256));
    assert_eq!(serialize_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 },
        &PolynomialValues::Signed([0; 256]), canonical), Err(PermutationFailure::Source));
    assert_eq!(serialize_input(&mut raw.0, &PolynomialKind::Canonical { modulus: crate::rust_verify::Q },
        &PolynomialValues::Canonical([crate::rust_verify::Q; 256]), canonical), Err(PermutationFailure::Source));
    assert_eq!(serialize_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 },
        &PolynomialValues::Signed([2; 256]), inverse), Err(PermutationFailure::Source));
    assert_eq!(serialize_input(&mut raw.0, &PolynomialKind::Signed { bound: 2 },
        &PolynomialValues::Signed([0; 256]), inverse), Err(PermutationFailure::Source));
    assert!(raw.0.is_empty());
}
