//! Opt-in ceilings for Rust allocations derived from OpenCL information.
//!
//! This bounds reply payloads and selected count fanouts, not driver memory,
//! caller-owned arguments, retained query results, or complete process memory.
//! There is no environment switch, mutable limit, or admission authority here.
use crate::{ffi, OpenclVersion};
use std::{convert::TryInto, mem::size_of};

pub const MAX_REPLY_BYTES: usize = 64 * 1024;
pub const MAX_PLATFORMS: usize = 8;
pub const MAX_DEVICES: usize = 64;
pub const MAX_KERNEL_ARGUMENTS: usize = 128;
pub const MAX_PROGRAM_KERNELS: usize = 4096;
pub const MAX_CONTEXT_PROPERTIES: usize = 32;
pub const MAX_WORK_ITEM_DIMENSIONS: usize = 3;

/// Every field is inline. Refusal does not copy or format driver text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("OpenCL info ceiling: {operation} request={request} bytes={bytes} limit={limit}")]
    Bytes {
        operation: &'static str,
        request: u32,
        bytes: usize,
        limit: usize,
    },
    #[error("OpenCL info ceiling: {operation} request={request} count={count} limit={limit}")]
    Count {
        operation: &'static str,
        request: u32,
        count: usize,
        limit: usize,
    },
    #[error("OpenCL info size overflow: {operation} request={request}")]
    Overflow {
        operation: &'static str,
        request: u32,
    },
    #[error("OpenCL malformed info: {operation} request={request}")]
    Malformed {
        operation: &'static str,
        request: u32,
    },
    #[error("OpenCL API failure: {operation} request={request} status={status}")]
    ApiFailure {
        operation: &'static str,
        request: u32,
        status: i32,
    },
}
type Result<T> = std::result::Result<T, Error>;

pub(crate) fn count(operation: &'static str, request: u32, n: usize, limit: usize) -> Result<()> {
    if n > limit {
        return Err(Error::Count {
            operation,
            request,
            count: n,
            limit,
        });
    }
    Ok(())
}
fn bytes(operation: &'static str, request: u32, n: usize, limit: usize) -> Result<()> {
    if n > limit {
        return Err(Error::Bytes {
            operation,
            request,
            bytes: n,
            limit,
        });
    }
    Ok(())
}
fn product(operation: &'static str, request: u32, n: usize, width: usize) -> Result<usize> {
    n.checked_mul(width)
        .ok_or(Error::Overflow { operation, request })
}
fn sum(operation: &'static str, request: u32, a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Overflow { operation, request })
}
fn array_count(
    operation: &'static str,
    request: u32,
    n: usize,
    width: usize,
    limit: usize,
) -> Result<()> {
    if n % width != 0 {
        return Err(Error::Malformed { operation, request });
    }
    count(operation, request, n / width, limit)
}

pub(crate) fn reply_size(operation: &'static str, request: u32, n: usize) -> Result<()> {
    bytes(operation, request, n, MAX_REPLY_BYTES)?;
    match operation {
        "clGetContextInfo" if request == ffi::CL_CONTEXT_DEVICES => {
            array_count(
                operation,
                request,
                n,
                size_of::<ffi::cl_device_id>(),
                MAX_DEVICES,
            )?;
        }
        "clGetGlContextInfoKhr" if request == crate::GlContextInfo::Devices as u32 => {
            array_count(
                operation,
                request,
                n,
                size_of::<ffi::cl_device_id>(),
                MAX_DEVICES,
            )?;
        }
        "clGetProgramInfo" if request == ffi::CL_PROGRAM_DEVICES => {
            array_count(
                operation,
                request,
                n,
                size_of::<ffi::cl_device_id>(),
                MAX_DEVICES,
            )?;
        }
        "clGetProgramInfo" if request == ffi::CL_PROGRAM_BINARY_SIZES => {
            array_count(operation, request, n, size_of::<usize>(), MAX_DEVICES)?;
        }
        "clGetContextInfo" if request == ffi::CL_CONTEXT_PROPERTIES => {
            array_count(
                operation,
                request,
                n,
                size_of::<isize>(),
                2 * MAX_CONTEXT_PROPERTIES + 1,
            )?;
            if n != 0 && (n / size_of::<isize>()) % 2 != 1 {
                return Err(Error::Malformed { operation, request });
            }
        }
        "clGetDeviceInfo" if request == ffi::CL_DEVICE_MAX_WORK_ITEM_SIZES => {
            array_count(
                operation,
                request,
                n,
                size_of::<usize>(),
                MAX_WORK_ITEM_DIMENSIONS,
            )?;
        }
        "clGetEventProfilingInfo" => bytes(operation, request, n, size_of::<u64>())?,
        _ => {}
    }
    Ok(())
}

fn reply_using(
    operation: &'static str,
    request: u32,
    n: usize,
    fill: u8,
    allocate: impl FnOnce(usize, u8) -> Vec<u8>,
) -> Result<Vec<u8>> {
    reply_size(operation, request, n)?;
    Ok(allocate(n, fill))
}
pub(crate) fn reply_buffer(
    operation: &'static str,
    request: u32,
    n: usize,
    fill: u8,
) -> Result<Vec<u8>> {
    reply_using(operation, request, n, fill, |n, fill| vec![fill; n])
}

/// Scalar replies are checked before higher wrappers can use them to reserve
/// vectors or iterate over argument/device/kernel counts.
pub(crate) fn validate_reply(operation: &'static str, request: u32, raw: &[u8]) -> Result<()> {
    reply_size(operation, request, raw.len())?;
    if raw.is_empty() {
        return Ok(());
    } // Keep existing EmptyInfoResult behavior.
    let limit = match (operation, request) {
        ("clGetKernelInfo", ffi::CL_KERNEL_NUM_ARGS) => Some(MAX_KERNEL_ARGUMENTS),
        ("clGetProgramInfo", ffi::CL_PROGRAM_NUM_DEVICES)
        | ("clGetContextInfo", ffi::CL_CONTEXT_NUM_DEVICES)
        | ("clGetDeviceInfo", ffi::CL_DEVICE_PARTITION_MAX_SUB_DEVICES) => Some(MAX_DEVICES),
        ("clGetDeviceInfo", ffi::CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS) => {
            Some(MAX_WORK_ITEM_DIMENSIONS)
        }
        _ => None,
    };
    if let Some(limit) = limit {
        let value = u32::from_ne_bytes(
            raw.try_into()
                .map_err(|_| Error::Malformed { operation, request })?,
        );
        count(operation, request, value as usize, limit)?;
    }
    if operation == "clGetProgramInfo" && request == ffi::CL_PROGRAM_NUM_KERNELS {
        let value = usize::from_ne_bytes(
            raw.try_into()
                .map_err(|_| Error::Malformed { operation, request })?,
        );
        count(operation, request, value, MAX_PROGRAM_KERNELS)?;
    }
    if operation == "clGetContextInfo" && request == ffi::CL_CONTEXT_PROPERTIES {
        let last = isize::from_ne_bytes(
            raw[raw.len() - size_of::<isize>()..]
                .try_into()
                .map_err(|_| Error::Malformed { operation, request })?,
        );
        if last != 0 {
            return Err(Error::Malformed { operation, request });
        }
    }
    Ok(())
}

pub(crate) fn enumeration(
    operation: &'static str,
    n: usize,
    limit: usize,
    element_bytes: usize,
) -> Result<()> {
    count(operation, 0, n, limit)?;
    bytes(
        operation,
        0,
        product(operation, 0, n, element_bytes)?,
        MAX_REPLY_BYTES,
    )
}
pub(crate) fn returned_devices(available: usize, requested: usize) -> Result<()> {
    // OpenCL may report the total available count even when fewer handles were
    // requested. Never set_len to unwritten/out-of-capacity entries.
    count("clGetDeviceIDs", 0, available, requested.min(MAX_DEVICES))
}
pub(crate) fn image_formats(n: usize) -> Result<()> {
    let element_bytes = sum(
        "clGetSupportedImageFormats",
        0,
        size_of::<ffi::cl_image_format>(),
        size_of::<crate::ImageFormatParseResult>(),
    )?;
    bytes(
        "clGetSupportedImageFormats",
        0,
        product("clGetSupportedImageFormats", 0, n, element_bytes)?,
        MAX_REPLY_BYTES,
    )
}

fn binary_storage(sizes: &[usize], capacity: usize) -> Result<usize> {
    const OP: &str = "clGetProgramInfo";
    const REQUEST: u32 = ffi::CL_PROGRAM_BINARIES;
    count(OP, REQUEST, sizes.len(), MAX_DEVICES)?;
    if capacity < sizes.len() {
        return Err(Error::Malformed {
            operation: OP,
            request: REQUEST,
        });
    }
    let mut total = product(OP, REQUEST, capacity, size_of::<usize>())?;
    total = sum(
        OP,
        REQUEST,
        total,
        product(OP, REQUEST, sizes.len(), size_of::<Vec<u8>>())?,
    )?;
    total = sum(
        OP,
        REQUEST,
        total,
        product(OP, REQUEST, sizes.len(), size_of::<*const u8>())?,
    )?;
    for &size in sizes {
        total = sum(OP, REQUEST, total, size)?;
    }
    bytes(OP, REQUEST, total, MAX_REPLY_BYTES)?;
    Ok(total)
}
fn binaries_using<T>(sizes: Vec<usize>, allocate: impl FnOnce(Vec<usize>) -> T) -> Result<T> {
    binary_storage(&sizes, sizes.capacity())?;
    Ok(allocate(sizes))
}
pub(crate) fn binary_buffers(sizes: Vec<usize>) -> Result<(Vec<Vec<u8>>, Vec<*const u8>)> {
    binaries_using(sizes, |sizes| {
        let binaries: Vec<Vec<u8>> = sizes.into_iter().map(|n| vec![0u8; n]).collect();
        let pointers = binaries.iter().map(|value| value.as_ptr()).collect();
        (binaries, pointers)
    })
}

/// Same prefix/two-u16 syntax as upstream, without collecting dot-separated
/// substrings or echoing an arbitrary caller/driver string into an error.
pub(crate) fn version(value: &str) -> Result<OpenclVersion> {
    const OP: &str = "OpenclVersion::from_info_str";
    bytes(OP, 0, value.len(), MAX_REPLY_BYTES)?;
    let mut words = value.split_whitespace();
    while let Some(word) = words.next() {
        if word
            .as_bytes()
            .get(..6)
            .map(|prefix| prefix.eq_ignore_ascii_case(b"opencl"))
            != Some(true)
        {
            continue;
        }
        let next = words.next().ok_or(Error::Malformed {
            operation: OP,
            request: 0,
        })?;
        let mut parts = next.split('.');
        let major = parts.next().and_then(|part| part.parse::<u16>().ok());
        let minor = parts.next().and_then(|part| part.parse::<u16>().ok());
        if let (Some(major), Some(minor), None) = (major, minor, parts.next()) {
            return Ok(OpenclVersion::new(major, minor));
        }
        break;
    }
    Err(Error::Malformed {
        operation: OP,
        request: 0,
    })
}

#[cfg(test)]
mod tests;
