use super::*;
use p3_field::PrimeCharacteristicRing;

#[test]
fn unused_vector_and_cap_capacity_cannot_escape_retention() {
    let mut audit = CapacityAudit {
        bytes: 0,
        limit: 4096,
    };
    // Length-only accounting would accept this empty vector.
    let spare = Vec::<Val>::with_capacity(32);
    assert!(audit.vector(&spare, 0, 0).is_err());
    let mut roots = Vec::with_capacity(32);
    roots.push([Val::ZERO; 4]);
    let cap = Cap::new(roots);
    assert!(audit.cap(&cap, 1).is_err());
    assert_eq!(audit.bytes, 0);
}

#[test]
fn container_headers_and_each_nested_salt_backing_are_charged_once() {
    let mut salts = Vec::with_capacity(2);
    salts.push(vec![Val::ZERO; 4]);
    let path = vec![[Val::ZERO; 4]; 2];
    let expected = salts.capacity() * size_of::<Vec<Val>>()
        + salts[0].capacity() * size_of::<Val>()
        + path.capacity() * size_of::<Digest>();
    let authentication = (salts, path);
    let mut audit = CapacityAudit {
        bytes: 0,
        limit: expected,
    };
    audit.authentication(&authentication, 1, 1, 2).unwrap();
    assert_eq!(audit.bytes, expected);
    let mut too_small = CapacityAudit {
        bytes: 0,
        limit: expected - 1,
    };
    assert!(too_small.authentication(&authentication, 1, 1, 2).is_err());
}

#[test]
fn public_shape_reserves_both_input_arrays_and_uses_actual_wire_size() {
    let shape = NativeRetentionShape::new(800, 4096).unwrap();
    let taller = NativeRetentionShape::new(800, 8192).unwrap();
    let wider = NativeRetentionShape::new(801, 4096).unwrap();
    assert!(shape.retained_bytes() > size_of::<RetainedNativeChild>());
    assert!(taller.retained_bytes() > shape.retained_bytes());
    assert!(taller.max_input_values() > shape.max_input_values());
    assert!(wider.retained_bytes() > shape.retained_bytes());
    assert!(wider.max_input_values() > shape.max_input_values());
    assert_eq!(
        shape.input_backing_bytes().unwrap(),
        2 * shape.max_input_values() * size_of::<Val>()
    );
    assert_eq!(
        shape.returned_wire_bytes().unwrap(),
        shape.max_input_values() * size_of::<Wire>()
    );
}

#[test]
fn invalid_shapes_and_arithmetic_overflow_fail_closed() {
    assert!(NativeRetentionShape::new(0, 4096).is_err());
    assert!(NativeRetentionShape::new(800, 4095).is_err());
    assert!(NativeRetentionShape::new(usize::MAX, 4096).is_err());
    assert!(capacity_limit(usize::MAX).is_err());
    if let Some(height) = 1usize.checked_shl(Val::TWO_ADICITY as u32) {
        assert!(NativeRetentionShape::new(800, height).is_err());
    }
}
