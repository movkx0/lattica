use super::*;
use std::{
    cell::Cell,
    fmt::{self, Write},
};

// These tests call the same preallocation boundaries as functions.rs. They do
// not call OpenCL, create a context, or qualify a driver/process memory bound.

#[test]
fn general_reply_boundaries_precede_allocation() {
    for size in [0, 1, MAX_REPLY_BYTES] {
        let called = Cell::new(false);
        let reply = reply_using("clGetPlatformInfo", 0, size, 32, |n, fill| {
            called.set(true);
            vec![fill; n]
        })
        .unwrap();
        assert!(called.get());
        assert_eq!(reply.len(), size);
        assert!(reply.iter().all(|&b| b == 32));
    }
    for size in [MAX_REPLY_BYTES + 1, usize::MAX] {
        let called = Cell::new(false);
        assert_eq!(
            reply_using("clGetPlatformInfo", 17, size, 0, |_, _| {
                called.set(true);
                Vec::new()
            }),
            Err(Error::Bytes {
                operation: "clGetPlatformInfo",
                request: 17,
                bytes: size,
                limit: MAX_REPLY_BYTES,
            })
        );
        assert!(!called.get());
    }
}

#[test]
fn typed_replies_refuse_counts_and_malformed_lengths_before_allocation() {
    let arrays = [
        (
            "clGetContextInfo",
            ffi::CL_CONTEXT_DEVICES,
            size_of::<ffi::cl_device_id>(),
            MAX_DEVICES,
        ),
        (
            "clGetGlContextInfoKhr",
            crate::GlContextInfo::Devices as u32,
            size_of::<ffi::cl_device_id>(),
            MAX_DEVICES,
        ),
        (
            "clGetProgramInfo",
            ffi::CL_PROGRAM_DEVICES,
            size_of::<ffi::cl_device_id>(),
            MAX_DEVICES,
        ),
        (
            "clGetProgramInfo",
            ffi::CL_PROGRAM_BINARY_SIZES,
            size_of::<usize>(),
            MAX_DEVICES,
        ),
        (
            "clGetDeviceInfo",
            ffi::CL_DEVICE_MAX_WORK_ITEM_SIZES,
            size_of::<usize>(),
            MAX_WORK_ITEM_DIMENSIONS,
        ),
    ];
    for (operation, request, width, limit) in arrays {
        for n in [0, width, width * limit] {
            assert!(reply_buffer(operation, request, n, 0).is_ok());
        }
        for (n, expected) in [
            (
                width * (limit + 1),
                Error::Count {
                    operation,
                    request,
                    count: limit + 1,
                    limit,
                },
            ),
            (width * limit - 1, Error::Malformed { operation, request }),
        ] {
            let called = Cell::new(false);
            assert_eq!(
                reply_using(operation, request, n, 0, |_, _| {
                    called.set(true);
                    Vec::new()
                }),
                Err(expected)
            );
            assert!(!called.get());
        }
    }
}

#[test]
fn tiny_scalar_replies_cannot_authorize_large_fanouts() {
    for (operation, request, limit) in [
        (
            "clGetKernelInfo",
            ffi::CL_KERNEL_NUM_ARGS,
            MAX_KERNEL_ARGUMENTS,
        ),
        ("clGetProgramInfo", ffi::CL_PROGRAM_NUM_DEVICES, MAX_DEVICES),
        ("clGetContextInfo", ffi::CL_CONTEXT_NUM_DEVICES, MAX_DEVICES),
        (
            "clGetDeviceInfo",
            ffi::CL_DEVICE_PARTITION_MAX_SUB_DEVICES,
            MAX_DEVICES,
        ),
        (
            "clGetDeviceInfo",
            ffi::CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS,
            MAX_WORK_ITEM_DIMENSIONS,
        ),
    ] {
        for count in [0, limit as u32] {
            assert!(validate_reply(operation, request, &count.to_ne_bytes()).is_ok());
        }
        for count in [limit as u32 + 1, u32::MAX] {
            assert_eq!(
                validate_reply(operation, request, &count.to_ne_bytes()),
                Err(Error::Count {
                    operation,
                    request,
                    count: count as usize,
                    limit
                })
            );
        }
        for raw in [&[0u8; 1][..], &[0u8; 3][..], &[0u8; 5][..]] {
            assert_eq!(
                validate_reply(operation, request, raw),
                Err(Error::Malformed { operation, request })
            );
        }
        // Empty replies keep the existing downstream EmptyInfoResult behavior.
        assert!(validate_reply(operation, request, &[]).is_ok());
    }
    let operation = "clGetProgramInfo";
    let request = ffi::CL_PROGRAM_NUM_KERNELS;
    for count in [0, MAX_PROGRAM_KERNELS] {
        assert!(validate_reply(operation, request, &count.to_ne_bytes()).is_ok());
    }
    for count in [MAX_PROGRAM_KERNELS + 1, usize::MAX] {
        assert_eq!(
            validate_reply(operation, request, &count.to_ne_bytes()),
            Err(Error::Count {
                operation,
                request,
                count,
                limit: MAX_PROGRAM_KERNELS
            })
        );
    }
    assert_eq!(
        validate_reply(operation, request, &[0]),
        Err(Error::Malformed { operation, request })
    );
}

#[test]
fn context_properties_need_whole_pairs_and_a_terminator() {
    let operation = "clGetContextInfo";
    let request = ffi::CL_CONTEXT_PROPERTIES;
    let width = size_of::<isize>();
    let words = 2 * MAX_CONTEXT_PROPERTIES + 1;
    for size in [0, width, words * width] {
        assert!(validate_reply(operation, request, &vec![0; size]).is_ok());
    }
    for size in [1, 2 * width, (words - 1) * width] {
        assert_eq!(
            reply_size(operation, request, size),
            Err(Error::Malformed { operation, request })
        );
    }
    assert_eq!(
        reply_size(operation, request, (words + 2) * width),
        Err(Error::Count {
            operation,
            request,
            count: words + 2,
            limit: words
        })
    );
    let mut raw = vec![0; words * width];
    raw[(words - 1) * width..].copy_from_slice(&1isize.to_ne_bytes());
    assert_eq!(
        validate_reply(operation, request, &raw),
        Err(Error::Malformed { operation, request })
    );
}

#[test]
fn profiling_reply_has_an_eight_byte_ceiling() {
    for n in [0, 1, size_of::<u64>()] {
        assert!(reply_buffer("clGetEventProfilingInfo", 0, n, 0).is_ok());
    }
    assert_eq!(
        reply_buffer("clGetEventProfilingInfo", 0, size_of::<u64>() + 1, 0),
        Err(Error::Bytes {
            operation: "clGetEventProfilingInfo",
            request: 0,
            bytes: size_of::<u64>() + 1,
            limit: size_of::<u64>()
        })
    );
}

#[test]
fn enumeration_bounds_count_product_and_returned_device_count() {
    for (operation, limit) in [
        ("clGetPlatformIDs", MAX_PLATFORMS),
        ("clGetDeviceIDs", MAX_DEVICES),
        ("device_versions", MAX_DEVICES),
    ] {
        assert!(enumeration(operation, limit, limit, size_of::<usize>()).is_ok());
        assert_eq!(
            enumeration(operation, limit + 1, limit, size_of::<usize>()),
            Err(Error::Count {
                operation,
                request: 0,
                count: limit + 1,
                limit
            })
        );
    }
    assert!(enumeration("test", 1, 1, MAX_REPLY_BYTES).is_ok());
    assert!(matches!(
        enumeration("test", 1, 1, MAX_REPLY_BYTES + 1),
        Err(Error::Bytes { .. })
    ));
    assert!(matches!(
        enumeration("test", 2, 2, usize::MAX),
        Err(Error::Overflow { .. })
    ));
    for (available, requested) in [(0, 0), (0, 1), (1, 1), (MAX_DEVICES, MAX_DEVICES)] {
        assert!(returned_devices(available, requested).is_ok());
    }
    for (available, requested, limit) in [
        (1, 0, 0),
        (2, 1, 1),
        (MAX_DEVICES + 1, usize::MAX, MAX_DEVICES),
    ] {
        assert_eq!(
            returned_devices(available, requested),
            Err(Error::Count {
                operation: "clGetDeviceIDs",
                request: 0,
                count: available,
                limit,
            })
        );
    }
}

#[test]
fn image_formats_include_simultaneous_raw_and_parsed_vectors() {
    let width = size_of::<ffi::cl_image_format>() + size_of::<crate::ImageFormatParseResult>();
    let fitting = MAX_REPLY_BYTES / width;
    assert!(image_formats(0).is_ok());
    assert!(image_formats(fitting).is_ok());
    assert_eq!(
        image_formats(fitting + 1),
        Err(Error::Bytes {
            operation: "clGetSupportedImageFormats",
            request: 0,
            bytes: (fitting + 1) * width,
            limit: MAX_REPLY_BYTES,
        })
    );
    assert!(matches!(
        image_formats(usize::MAX),
        Err(Error::Overflow { .. })
    ));
}

#[test]
fn binary_accounting_includes_payload_headers_pointers_and_size_capacity() {
    let overhead = size_of::<usize>() + size_of::<Vec<u8>>() + size_of::<*const u8>();
    let payload = MAX_REPLY_BYTES - overhead;
    assert_eq!(binary_storage(&[], 0), Ok(0));
    assert_eq!(binary_storage(&[payload], 1), Ok(MAX_REPLY_BYTES));
    assert!(matches!(
        binary_storage(&[payload + 1], 1),
        Err(Error::Bytes { .. })
    ));
    assert!(matches!(
        binary_storage(&[payload], 2),
        Err(Error::Bytes { .. })
    ));
    assert!(matches!(
        binary_storage(&[1], 0),
        Err(Error::Malformed { .. })
    ));
    assert!(matches!(
        binary_storage(&[0], usize::MAX),
        Err(Error::Overflow { .. })
    ));
    assert!(matches!(
        binary_storage(&[usize::MAX], 1),
        Err(Error::Overflow { .. })
    ));
    assert!(matches!(
        binary_storage(&[usize::MAX / 2, usize::MAX / 2], 2),
        Err(Error::Overflow { .. })
    ));
    assert!(matches!(
        binary_storage(&vec![0; MAX_DEVICES + 1], MAX_DEVICES + 1),
        Err(Error::Count { .. })
    ));
}

#[test]
fn binary_refusals_do_not_enter_nested_allocation_callback() {
    let mut spare = Vec::with_capacity(128);
    // This payload fits if only length rather than actual capacity is charged.
    let one_entry = size_of::<usize>() + size_of::<Vec<u8>>() + size_of::<*const u8>();
    spare.push(MAX_REPLY_BYTES - one_entry);
    for sizes in [vec![usize::MAX], vec![MAX_REPLY_BYTES / 2; 2], spare] {
        let called = Cell::new(false);
        let result = binaries_using(sizes, |_| called.set(true));
        assert!(result.is_err());
        assert!(!called.get());
    }
    let mut sizes = vec![0];
    let overhead =
        sizes.capacity() * size_of::<usize>() + size_of::<Vec<u8>>() + size_of::<*const u8>();
    sizes[0] = MAX_REPLY_BYTES - overhead;
    let (binaries, pointers) = binary_buffers(sizes).unwrap();
    assert_eq!(binaries[0].len(), MAX_REPLY_BYTES - overhead);
    assert!(binaries[0].iter().all(|&b| b == 0));
    assert_eq!(pointers, vec![binaries[0].as_ptr()]);
    let (binaries, pointers) = binary_buffers(Vec::new()).unwrap();
    assert!(binaries.is_empty());
    assert!(pointers.is_empty());
}

#[test]
fn version_syntax_preserves_upstream_accepted_prefix_and_u16_rules() {
    for (text, expected) in [
        ("OpenCL 1.2 NVIDIA", (1, 2)),
        ("vendor oPeNcL 3.0", (3, 0)),
        ("OpenCL_suffix +1.002", (1, 2)),
        ("\u{2003}OpenCL\t65535.65535", (65535, 65535)),
        ("OpenC 9.9 OpenCL 2.1", (2, 1)),
        ("OpenCL 0.0 OpenCL bad", (0, 0)),
    ] {
        assert_eq!(version(text).unwrap().to_raw(), expected);
        assert_eq!(
            OpenclVersion::from_info_str(text).unwrap().to_raw(),
            expected
        );
    }
    for text in [
        "",
        "OpenCL",
        "OpenCL bad OpenCL 1.2",
        "OpenCL .2",
        "OpenCL 1.",
        "OpenCL 1.2.3",
        "OpenCL 65536.0",
        "OpenCL 0.65536",
        "OpenCL -1.2",
        "ΟpenCL 1.2",
        "not_opencl 1.2",
    ] {
        assert_eq!(
            version(text),
            Err(Error::Malformed {
                operation: "OpenclVersion::from_info_str",
                request: 0,
            })
        );
    }
    let mut exact = String::from("OpenCL 1.2 ");
    exact.extend(std::iter::repeat('x').take(MAX_REPLY_BYTES - exact.len()));
    assert_eq!(version(&exact).unwrap().to_raw(), (1, 2));
    exact.push('x');
    assert_eq!(
        version(&exact),
        Err(Error::Bytes {
            operation: "OpenclVersion::from_info_str",
            request: 0,
            bytes: MAX_REPLY_BYTES + 1,
            limit: MAX_REPLY_BYTES,
        })
    );
}

struct InlineText {
    storage: [u8; 192],
    len: usize,
}
impl fmt::Write for InlineText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        if end > self.storage.len() {
            return Err(fmt::Error);
        }
        self.storage[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn native_status_is_signed_and_display_needs_no_driver_text() {
    for (operation, status, expected) in [
        (
            "clSetKernelArg",
            -49,
            Some(crate::Status::CL_INVALID_ARG_INDEX),
        ),
        (
            "clEnqueueNDRangeKernel",
            -52,
            Some(crate::Status::CL_INVALID_KERNEL_ARGS),
        ),
        ("clEnqueueNDRangeKernel", i32::MIN, None),
    ] {
        let native = Error::ApiFailure {
            operation,
            request: 19,
            status,
        };
        let wrapper: crate::Error = native.into();
        assert_eq!(wrapper.api_status(), expected);
        match wrapper {
            crate::Error::BoundedInfo(Error::ApiFailure { status: found, .. }) => {
                assert_eq!(found, status)
            }
            other => panic!("lost original native status: {:?}", other),
        }
        let mut display = InlineText {
            storage: [0; 192],
            len: 0,
        };
        write!(&mut display, "{}", native).unwrap();
        let text = std::str::from_utf8(&display.storage[..display.len]).unwrap();
        assert!(text.starts_with("OpenCL API failure: "));
        assert!(text.contains(operation));
        assert!(text.contains("request=19 status=-"));
    }
    let mut display = InlineText {
        storage: [0; 192],
        len: 0,
    };
    write!(
        &mut display,
        "{}",
        Error::Bytes {
            operation: "clGetProgramBuildInfo",
            request: u32::MAX,
            bytes: usize::MAX,
            limit: MAX_REPLY_BYTES
        }
    )
    .unwrap();
    assert!(display.len < display.storage.len());
}
