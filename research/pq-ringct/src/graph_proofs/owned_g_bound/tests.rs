use super::*;
use crate::rust_verify::committed_backend::{PolynomialKind, PolynomialValues};

#[test]
fn g_bound_signed_source_serializes_original_order_and_twos_complement() {
    let mut f = [0i64; 256];
    f[0] = -5086; f[1] = 5086;
    let mut x = [0i64; 256];
    x[0] = 1; x[255] = -1;
    let mut raw = WipedRaw(Vec::with_capacity(512));
    serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 5086 }, &PolynomialValues::Signed(f), 5086).unwrap();
    serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Signed(x), 1).unwrap();
    assert_eq!(raw.0.len(), 512);
    assert_eq!(raw.0[0], (-5086i64) as u64);
    assert_eq!(raw.0[1], 5086);
    assert_eq!(raw.0[256], 1);
    assert_eq!(raw.0[511], (-1i64) as u64);
}

#[test]
fn g_bound_signed_source_refuses_wrong_encoding_bounds_and_minimum_integer() {
    let mut raw = WipedRaw(Vec::with_capacity(512));
    let signed = PolynomialValues::Signed([0; 256]);
    assert_eq!(serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 565 }, &signed, 5086), Err(GBoundFailure::Source));
    assert_eq!(serialize_signed_input(&mut raw.0, &PolynomialKind::Canonical { modulus: 167_770_241 }, &signed, 5086), Err(GBoundFailure::Source));
    assert_eq!(serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Canonical([0; 256]), 1), Err(GBoundFailure::Source));
    for invalid in [2, -2, i64::MIN, i64::MAX] {
        let mut values = [0i64; 256]; values[255] = invalid;
        assert_eq!(serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Signed(values), 1), Err(GBoundFailure::Source));
        assert!(raw.0.is_empty());
    }
}

#[test]
fn g_bound_signed_source_refuses_append_before_capacity_growth() {
    let mut raw = WipedRaw(Vec::new());
    assert_eq!(serialize_signed_input(&mut raw.0, &PolynomialKind::Signed { bound: 1 }, &PolynomialValues::Signed([0; 256]), 1), Err(GBoundFailure::Resource));
    assert_eq!(raw.0.capacity(), 0);
    assert!(raw.0.is_empty());
}
