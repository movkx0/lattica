use super::*;
use driver::Api;
#[cfg(feature = "gpu-bounded-info")]
mod fixed_capture;

#[derive(Clone)]
struct Mock {
    platforms: usize,
    devices: [usize; MAX_PLATFORMS],
    platform_fill_count: Option<usize>,
    device_fill_count: Option<usize>,
    duplicate_platform: bool,
    duplicate_device: bool,
    null_platform: bool,
    null_device: bool,
    duplicate_uuid: bool,
    absent_uuid: Option<usize>,
    absent_pci: bool,
    size_override: Option<(Field, usize)>,
    fill_size_override: Option<(Field, usize)>,
    failure: Option<(Field, bool, i32)>,
    handle_offset: usize,
    platform_offset: usize,
    name: [u8; STRING_BYTES],
    name_len: usize,
    driver: [u8; STRING_BYTES],
    driver_len: usize,
    global: u64,
    maximum: u64,
    pci: [u32; 4],
    calls: [[usize; 2]; 11],
}
impl Mock {
    fn new() -> Self {
        let mut result = Self {
            platforms: 1,
            devices: [0; MAX_PLATFORMS],
            platform_fill_count: None,
            device_fill_count: None,
            duplicate_platform: false,
            duplicate_device: false,
            null_platform: false,
            null_device: false,
            duplicate_uuid: false,
            absent_uuid: None,
            absent_pci: false,
            size_override: None,
            fill_size_override: None,
            failure: None,
            handle_offset: 0,
            platform_offset: 0,
            name: [0; STRING_BYTES],
            name_len: 0,
            driver: [0; STRING_BYTES],
            driver_len: 0,
            global: 16 << 30,
            maximum: 8 << 30,
            pci: [0, 1, 2, 0],
            calls: [[0; 2]; 11],
        };
        result.devices[0] = 2;
        result.set_name(b"  Fixture GPU  \0");
        result.set_driver(b"  test-driver  \0");
        result
    }
    fn set_name(&mut self, value: &[u8]) {
        self.name.fill(0);
        self.name[..value.len()].copy_from_slice(value);
        self.name_len = value.len();
    }
    fn set_driver(&mut self, value: &[u8]) {
        self.driver.fill(0);
        self.driver[..value.len()].copy_from_slice(value);
        self.driver_len = value.len();
    }
    fn record(&mut self, field: Field, fill: bool) -> Option<i32> {
        self.calls[field as usize][usize::from(fill)] += 1;
        self.failure
            .and_then(|(f, b, code)| (f == field && b == fill).then_some(code))
    }
    fn request(index: usize) -> Request {
        Request {
            index,
            uuid: [index as u8 + 1; 16],
        }
    }
    fn fills(&self, field: Field) -> usize {
        self.calls[field as usize][1]
    }
}
impl Api for Mock {
    fn platforms(&mut self, output: &mut [ffi::cl_platform_id]) -> (usize, i32) {
        if let Some(code) = self.record(Field::Platforms, !output.is_empty()) {
            return (0, code);
        }
        if output.is_empty() {
            return (self.platforms, 0);
        }
        for (i, slot) in output.iter_mut().take(self.platforms).enumerate() {
            *slot = if self.null_platform && i == 0 {
                ptr::null_mut()
            } else {
                (100 + self.platform_offset + if self.duplicate_platform { 0 } else { i }) as _
            };
        }
        (self.platform_fill_count.unwrap_or(self.platforms), 0)
    }
    fn devices(
        &mut self,
        platform: ffi::cl_platform_id,
        output: &mut [ffi::cl_device_id],
    ) -> (usize, i32) {
        if let Some(code) = self.record(Field::Devices, !output.is_empty()) {
            return (0, code);
        }
        let p = platform as usize - 100 - self.platform_offset;
        let count = self.devices[p];
        if count == 0 {
            return (0, ffi::CL_DEVICE_NOT_FOUND);
        }
        if !output.is_empty() {
            let preceding: usize = self.devices[..p].iter().sum();
            for (i, slot) in output.iter_mut().take(count).enumerate() {
                *slot = if self.null_device && i == 0 {
                    ptr::null_mut()
                } else {
                    (1000
                        + self.handle_offset
                        + if self.duplicate_device {
                            0
                        } else {
                            preceding + i
                        }) as _
                };
            }
        }
        (
            if output.is_empty() {
                count
            } else {
                self.device_fill_count.unwrap_or(count)
            },
            0,
        )
    }
    fn info(&mut self, device: ffi::cl_device_id, field: Field, output: &mut [u8]) -> (usize, i32) {
        let fill = !output.is_empty();
        if let Some(code) = self.record(field, fill) {
            return (0, code);
        }
        let index = device as usize - 1000 - self.handle_offset;
        let mut bytes = [0u8; STRING_BYTES];
        let size = match field {
            Field::Uuid => {
                if self.absent_uuid == Some(index) {
                    return (0, ffi::CL_INVALID_VALUE);
                }
                bytes[..16].fill(if self.duplicate_uuid {
                    1
                } else {
                    index as u8 + 1
                });
                16
            }
            Field::Name => {
                bytes = self.name;
                self.name_len
            }
            Field::Driver => {
                bytes = self.driver;
                self.driver_len
            }
            Field::Global => {
                bytes[..8].copy_from_slice(&self.global.to_ne_bytes());
                8
            }
            Field::MaxAllocation => {
                bytes[..8].copy_from_slice(&self.maximum.to_ne_bytes());
                8
            }
            Field::Pci => {
                if self.absent_pci {
                    return (0, ffi::CL_INVALID_VALUE);
                }
                for (slot, word) in bytes[..16].chunks_exact_mut(4).zip(self.pci) {
                    slot.copy_from_slice(&word.to_ne_bytes());
                }
                16
            }
            _ => panic!("non-info mock field"),
        };
        if fill {
            let take = size.min(output.len());
            output[..take].copy_from_slice(&bytes[..take]);
        }
        let change = if fill {
            self.fill_size_override
        } else {
            self.size_override
        };
        (
            change.filter(|(f, _)| *f == field).map_or(size, |(_, n)| n),
            0,
        )
    }
}

#[test]
fn pinned_requests_accept_only_bounded_canonical_selectors() {
    let text = "GPU-01234567-89ab-cdef-0123-456789abcdef";
    let parsed = Request::parse("0", text).unwrap();
    assert_eq!(parsed.index(), 0);
    assert_eq!(uuid_text(parsed.uuid()).as_str(), text);
    assert_eq!(
        parsed,
        Request::parse("0", "GPU-01234567-89AB-CDEF-0123-456789ABCDEF").unwrap()
    );
    for index in ["", "00", "01", "+1", "-1", " 1", "1 ", "64", "999", "1000"] {
        assert!(Request::parse(index, text).is_err());
    }
    for uuid in [
        "",
        "gpu-01234567-89ab-cdef-0123-456789abcdef",
        "GPU-0123456789ab-cdef-0123-456789abcdef",
        "GPU-01234567-89ab-cdef-0123-456789abcdeg",
        "GPU-01234567-89ab-cdef-0123-456789abcde-",
        "GPU-01234567-89ab-cdef-0123-456789abcdef\0",
    ] {
        assert!(Request::parse("0", uuid).is_err());
    }
}

#[test]
fn capture_uses_existing_identity_and_global_gpu_order() {
    let mut api = Mock::new();
    api.platforms = 3;
    api.devices = [1, 0, 2, 0, 0, 0, 0, 0];
    let mut scratch = Scratch::new();
    let snapshot = capture(&mut api, Mock::request(2), &mut scratch).unwrap();
    let identity = snapshot.identity();
    assert_eq!(identity.opencl_index, 2);
    assert_eq!(identity.uuid, super::super::uuid(&[3; 16]));
    assert_eq!(identity.name, "Fixture GPU");
    assert_eq!(identity.driver, "test-driver");
    assert_eq!(identity.pci.as_deref(), Some("0000:01:02.0"));
    assert_eq!(identity.global_bytes, 16 << 30);
    assert_eq!(identity.max_allocation_bytes, 8 << 30);
    assert_eq!(snapshot.uuid(), [3; 16]);
    assert!(snapshot.requested_string_bytes() <= MAX_IDENTITY_REQUESTED_BYTES);
    recheck(&mut api, &snapshot, Mock::request(2), &mut scratch).unwrap();
}

#[test]
fn count_caps_and_changed_enumerations_reject_before_over_cap_fill() {
    let mut scratch = Scratch::new();
    let mut api = Mock::new();
    api.platforms = MAX_PLATFORMS + 1;
    assert_eq!(
        capture(&mut api, Mock::request(0), &mut scratch)
            .err()
            .unwrap()
            .fault,
        Fault::Count
    );
    assert_eq!(api.fills(Field::Platforms), 0);
    let mut api = Mock::new();
    api.devices[0] = MAX_DEVICES + 1;
    assert!(capture(&mut api, Mock::request(0), &mut scratch).is_err());
    assert_eq!(api.fills(Field::Devices), 0);
    let mut api = Mock::new();
    api.platforms = 2;
    api.devices[0] = MAX_DEVICES;
    api.devices[1] = 1;
    assert!(capture(&mut api, Mock::request(0), &mut scratch).is_err());
    assert_eq!(api.fills(Field::Devices), 1);
    for platform in [false, true] {
        let mut api = Mock::new();
        if platform {
            api.platform_fill_count = Some(2);
        } else {
            api.device_fill_count = Some(1);
        }
        assert!(capture(&mut api, Mock::request(0), &mut scratch).is_err());
    }
    let mut api = Mock::new();
    api.platforms = MAX_PLATFORMS;
    api.devices.fill(8);
    let snapshot = capture(&mut api, Mock::request(63), &mut scratch).unwrap();
    assert_eq!(snapshot.identity().opencl_index, 63);
}

#[test]
fn null_duplicate_missing_and_disagreeing_physical_identities_reject() {
    let mut scratch = Scratch::new();
    for case in 0..7 {
        let mut api = Mock::new();
        let mut request = Mock::request(0);
        match case {
            0 => api.null_platform = true,
            1 => {
                api.platforms = 2;
                api.duplicate_platform = true;
            }
            2 => api.null_device = true,
            3 => api.duplicate_device = true,
            4 => api.duplicate_uuid = true,
            5 => api.absent_uuid = Some(0),
            _ => request.uuid = [2; 16],
        }
        assert!(
            capture(&mut api, request, &mut scratch).is_err(),
            "case {case}"
        );
    }
    let mut api = Mock::new();
    api.absent_uuid = Some(1); // UUID is mandatory only for the selected device.
    api.absent_pci = true;
    assert!(capture(&mut api, Mock::request(0), &mut scratch)
        .unwrap()
        .identity
        .pci
        .is_none());
}

#[test]
fn driver_lengths_are_checked_before_fixed_buffers_or_strings_are_filled() {
    let mut scratch = Scratch::new();
    for (field, size) in [
        (Field::Uuid, 17),
        (Field::Uuid, 0),
        (Field::Global, 9),
        (Field::MaxAllocation, 7),
        (Field::Pci, 15),
        (Field::Name, STRING_BYTES + 1),
        (Field::Driver, usize::MAX),
    ] {
        let mut api = Mock::new();
        api.size_override = Some((field, size));
        let error = capture(&mut api, Mock::request(0), &mut scratch)
            .err()
            .unwrap();
        assert_eq!(error.field, field);
        assert_eq!(error.fault, Fault::Size);
        assert_eq!(error.reported, size);
        assert_eq!(api.fills(field), 0);
    }
    let mut api = Mock::new();
    api.fill_size_override = Some((Field::Name, 3));
    assert_eq!(
        capture(&mut api, Mock::request(0), &mut scratch)
            .err()
            .unwrap()
            .fault,
        Fault::Size
    );
}

#[test]
fn text_encodings_and_memory_limits_are_validated_before_identity_allocation() {
    let mut scratch = Scratch::new();
    for text in [b"".as_slice(), b"no NUL", b"a\0b\0", b"\xff\0", b" \n\0"] {
        let mut api = Mock::new();
        api.set_name(text);
        assert!(capture(&mut api, Mock::request(0), &mut scratch).is_err());
    }
    for (global, maximum) in [(0, 1), (1, 0), (1, 2)] {
        let mut api = Mock::new();
        api.global = global;
        api.maximum = maximum;
        assert!(capture(&mut api, Mock::request(0), &mut scratch).is_err());
    }
}

#[test]
fn recheck_compares_exact_handle_uuid_index_limits_and_public_labels() {
    let mut scratch = Scratch::new();
    let api = Mock::new();
    let snapshot = capture(&mut api.clone(), Mock::request(0), &mut scratch).unwrap();
    for case in 0..8 {
        let mut changed = api.clone();
        let mut request = Mock::request(0);
        match case {
            0 => changed.handle_offset = 100,
            1 => changed.platform_offset = 100,
            2 => changed.global -= 1,
            3 => changed.maximum -= 1,
            4 => changed.set_name(b"different\0"),
            5 => changed.set_driver(b"different\0"),
            6 => changed.pci[1] = 3,
            _ => request = Mock::request(1),
        }
        assert!(
            recheck(&mut changed, &snapshot, request, &mut scratch).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn bounded_diagnostics_preserve_original_signed_query_failures() {
    let mut scratch = Scratch::new();
    for (field, fill) in [
        (Field::Platforms, false),
        (Field::Platforms, true),
        (Field::Devices, false),
        (Field::Devices, true),
        (Field::Uuid, false),
        (Field::Uuid, true),
        (Field::Name, false),
        (Field::Driver, true),
    ] {
        let mut api = Mock::new();
        api.failure = Some((field, fill, i32::MIN));
        let error = capture(&mut api, Mock::request(0), &mut scratch)
            .err()
            .unwrap();
        assert_eq!(error.field, field);
        assert_eq!(error.status, i32::MIN);
        let diagnostic = error.diagnostic();
        assert!(diagnostic.0.len < 192);
        assert!(diagnostic.0.as_str().contains("status=-2147483648"));
    }
}

#[cfg(feature = "stream")]
#[test]
fn mock_capture_allocates_only_capped_shared_identity_strings_and_recheck_none() {
    let mut api = Mock::new();
    api.name.fill(b'a');
    api.name[STRING_BYTES - 1] = 0;
    api.name_len = STRING_BYTES;
    api.driver.fill(b'b');
    api.driver[STRING_BYTES - 1] = 0;
    api.driver_len = STRING_BYTES;
    api.pci = [u32::MAX; 4];
    let mut scratch = Scratch::new();
    let (snapshot, requests) = crate::spill_alloc::allocation_requests::measure(|| {
        capture(&mut api, Mock::request(0), &mut scratch).unwrap()
    });
    assert_eq!(requests.calls, 4);
    assert_eq!(requests.bytes, MAX_IDENTITY_REQUESTED_BYTES);
    assert!(!requests.overflow);
    assert_eq!(
        snapshot.requested_string_bytes(),
        MAX_IDENTITY_REQUESTED_BYTES
    );
    let (_, requests) = crate::spill_alloc::allocation_requests::measure(|| {
        recheck(&mut api, &snapshot, Mock::request(0), &mut scratch).unwrap();
        let _diagnostic =
            Error::new(Field::MaxAllocation, Fault::Status, i32::MIN, usize::MAX).diagnostic();
    });
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
    let mut api = Mock::new();
    api.size_override = Some((Field::Name, usize::MAX));
    let (error, requests) = crate::spill_alloc::allocation_requests::measure(|| {
        capture(&mut api, Mock::request(0), &mut scratch)
            .err()
            .unwrap()
    });
    assert_eq!(error.fault, Fault::Size);
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
}

#[test]
#[ignore = "serialized selected-device query qualification; sealed bounded environment and process guard required"]
fn selected_device_matches_existing_shared_selector_and_rechecks() {
    // The reference selector and environment copies are outside the candidate's
    // allocation claim. Root's sealed startup guard bounds them for this test.
    let index = std::env::var("LATTICA_V2_GPU_DEVICE").unwrap();
    let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap();
    let request = Request::parse(&index, &uuid).unwrap();
    let mut scratch = Scratch::new();
    let snapshot = Snapshot::capture(request, &mut scratch).unwrap();
    let (platform, device, identity) = super::super::select().unwrap();
    // Do not format ocl::Device: its Debug implementation queries driver data.
    // Platform has no PartialEq in ocl 0.19.7; compare the OpenCL handles.
    assert!(snapshot.platform().as_core().as_ptr() == platform.as_core().as_ptr());
    assert!(snapshot.device() == device);
    assert_eq!(snapshot.identity().opencl_index, identity.opencl_index);
    assert_eq!(snapshot.identity().uuid, identity.uuid);
    assert_eq!(snapshot.identity().name, identity.name);
    assert_eq!(snapshot.identity().driver, identity.driver);
    assert_eq!(snapshot.identity().pci, identity.pci);
    assert_eq!(snapshot.identity().global_bytes, identity.global_bytes);
    assert_eq!(
        snapshot.identity().max_allocation_bytes,
        identity.max_allocation_bytes
    );
    assert!(snapshot.requested_string_bytes() <= MAX_IDENTITY_REQUESTED_BYTES);
    snapshot.recheck(request, &mut scratch).unwrap();
    let census = footprint();
    eprintln!("bounded_device_query_parity=true owned_string_bytes={} scratch_inline={} fixed_selection_inline={} snapshot_inline={} opaque_driver_bound=false dispatch_authority=false",
        snapshot.requested_string_bytes(), census.scratch_inline, census.fixed_selection_inline, census.snapshot_inline);
}
