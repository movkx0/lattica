use super::*;

#[cfg(feature = "stream")]
#[test]
fn fixed_physical_capture_matches_identity_without_string_requests() {
    let mut api = Mock::new();
    api.platforms = 3;
    api.devices = [1, 0, 2, 0, 0, 0, 0, 0];
    let mut scratch = Scratch::new();
    let (physical, requests) = crate::spill_alloc::allocation_requests::measure(|| {
        super::super::fixed::capture_with(&mut api, Mock::request(2), &mut scratch).unwrap()
    });
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    let snapshot = capture(&mut api, Mock::request(2), &mut scratch).unwrap();
    assert_eq!(physical.index(), snapshot.identity().opencl_index);
    assert_eq!(physical.uuid(), snapshot.uuid());
    assert_eq!(physical.global_bytes(), snapshot.identity().global_bytes);
    assert_eq!(
        physical.max_allocation_bytes(),
        snapshot.identity().max_allocation_bytes
    );
    assert!(physical.device() == snapshot.device());
}

#[test]
fn fixed_physical_capture_rejects_duplicate_identity_and_oversized_text() {
    let mut scratch = Scratch::new();
    let mut duplicate = Mock::new();
    duplicate.devices[0] = 2;
    duplicate.duplicate_uuid = true;
    assert!(
        super::super::fixed::capture_with(&mut duplicate, Mock::request(0), &mut scratch).is_err()
    );
    let mut oversized = Mock::new();
    oversized.size_override = Some((Field::Name, STRING_BYTES + 1));
    assert!(
        super::super::fixed::capture_with(&mut oversized, Mock::request(0), &mut scratch).is_err()
    );
}
