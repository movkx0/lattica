use super::*;

fn identity() -> DeviceIdentity {
    DeviceIdentity { opencl_index: 0, uuid: Some("GPU-00000000-0000-0000-0000-000000000000".into()),
        name: "NVIDIA GeForce RTX 5080".into(), pci: None, global_bytes: 16 << 30,
        max_allocation_bytes: 8 << 30, driver: "test".into() }
}

#[test]
fn identity_census_rejects_changed_fields_and_extra_keys() {
    let identity = identity();
    let mut value = serde_json::to_value(&identity).unwrap();
    assert!(identity_json_bytes(&value, &identity).is_ok());
    value["driver"] = Value::String("different".into());
    assert!(identity_json_bytes(&value, &identity).is_err());
    value["driver"] = Value::String(identity.driver.clone());
    value["extra"] = Value::Null;
    assert!(identity_json_bytes(&value, &identity).is_err());
}

#[test]
fn actual_string_capacity_is_charged_even_when_text_is_identical() {
    let identity = identity();
    let mut value = serde_json::to_value(&identity).unwrap();
    let before = identity_json_bytes(&value, &identity).unwrap();
    let text = value.get_mut("driver").unwrap().as_str().unwrap().to_owned();
    let mut larger = String::with_capacity(text.len() + 4096);
    larger.push_str(&text);
    let capacity = larger.capacity();
    let previous = match &value["driver"] { Value::String(text) => text.capacity(), _ => unreachable!() };
    value["driver"] = Value::String(larger);
    let after = identity_json_bytes(&value, &identity).unwrap();
    assert!(after >= before + capacity - previous);
}

#[test]
fn bounded_identity_lengths_do_not_hide_owned_capacity() {
    let mut identity = identity();
    let before = identity_backing(&identity).unwrap();
    let old_capacity = identity.driver.capacity();
    identity.driver.reserve(4096);
    assert_eq!(identity_backing(&identity).unwrap(), before + identity.driver.capacity() - old_capacity);
    identity.driver = "x".repeat(256);
    assert!(identity_backing(&identity).is_err());
}

#[test]
fn arithmetic_overflow_and_unsupported_device_are_refused() {
    assert!(json_object_backing(usize::MAX).is_err());
    assert!(growing::<Value>(usize::MAX).is_err());
    let mut identity = identity();
    identity.name = "different device".into();
    assert!(identity_backing(&identity).is_err());
}
