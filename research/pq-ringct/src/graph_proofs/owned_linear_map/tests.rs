use super::*;
use crate::rust_verify::committed_backend::{PolynomialKind,PolynomialValues};
#[test]
fn linear_map_input_serialization_keeps_order_encoding_and_original_capacity() {
    let mut raw=Vec::with_capacity(512);
    let q=crate::rust_verify::Q;
    serialize_input(&mut raw,&PolynomialKind::Canonical{modulus:q},&PolynomialValues::Canonical([q-1;256]),[q,0]).unwrap();
    serialize_input(&mut raw,&PolynomialKind::Signed{bound:3},&PolynomialValues::Signed([-3;256]),[0,3]).unwrap();
    assert_eq!(raw.len(),512);assert_eq!(raw.capacity(),512);
    assert_eq!(&raw[..256],&[q-1;256]);assert_eq!(&raw[256..],&[-3i64 as u64;256]);
}
#[test]
fn linear_map_input_serialization_refuses_wrong_kind_range_and_underadmission() {
    let q=crate::rust_verify::Q;
    for (kind,values,expected) in [
        (PolynomialKind::Canonical{modulus:q},PolynomialValues::Canonical([q;256]),[q,0]),
        (PolynomialKind::Canonical{modulus:q},PolynomialValues::Canonical([0;256]),[q+1,0]),
        (PolynomialKind::Signed{bound:3},PolynomialValues::Signed([4;256]),[0,3]),
        (PolynomialKind::Signed{bound:3},PolynomialValues::Signed([0;256]),[0,2]),
        (PolynomialKind::Signed{bound:3},PolynomialValues::Canonical([0;256]),[0,3]),
    ] {let mut raw=Vec::with_capacity(256);assert!(serialize_input(&mut raw,&kind,&values,expected).is_err());assert!(raw.is_empty());}
    let mut raw=Vec::with_capacity(255);
    assert!(serialize_input(&mut raw,&PolynomialKind::Signed{bound:3},&PolynomialValues::Signed([0;256]),[0,3]).is_err());
    assert_eq!(raw.capacity(),255);assert!(raw.is_empty());
}
#[test]
fn retained_descriptor_bridge_preserves_exact_content() {
    use crate::linear_map_air::LinearMapDescriptor as Reference;
    for kind in [PolynomialKind::Canonical{modulus:crate::rust_verify::Q},PolynomialKind::Canonical{modulus:crate::rust_verify::QHAT},PolynomialKind::Signed{bound:9}] {
        let mut coefficients=vec![[1;256];3];coefficients[1][4]=-2;
        let reference=Reference::new(vec![kind;3],kind,coefficients,[0;256]).unwrap();
        let core=reference.owned_descriptor().unwrap();
        assert_eq!(Reference::from_owned(&core),reference);
        assert_eq!(Reference::from_owned(&core).owned_descriptor().unwrap(),core);
    }
}
