//! Disconnected fixed-capacity queries for the existing shared GPU identity.
//! The caller supplies its sealed selector values and owns admission of Scratch,
//! Snapshot and opaque driver/startup storage. This is not a runtime lease.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::Identity;
use core::{fmt, mem::size_of, ptr};
use ocl::{core as cl_core, ffi, Device, Platform};

mod driver;
#[cfg(feature = "gpu-bounded-info")]
pub(crate) mod fixed;
#[cfg(test)]
mod tests;

pub(crate) const MAX_PLATFORMS: usize = 8;
pub(crate) const MAX_DEVICES: usize = 64;
const STRING_BYTES: usize = 256; // Includes the driver-supplied terminating NUL.
const UUID_BYTES: usize = 40; // GPU- plus 36 UUID characters; no NUL is retained.
const PCI_BYTES: usize = 37; // Four arbitrary u32 fields in the existing format.
pub(crate) const MAX_IDENTITY_REQUESTED_BYTES: usize =
    UUID_BYTES + 2 * (STRING_BYTES - 1) + PCI_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    index: usize,
    uuid: [u8; 16],
}
impl Request {
    /// Borrow already bounded, immutable startup values. No environment read or
    /// String copy occurs here. Both selectors are required for this experiment.
    pub(crate) fn parse(index: &str, uuid: &str) -> Result<Self, Error> {
        if index.is_empty()
            || index.len() > 3
            || (index.len() > 1 && index.as_bytes()[0] == b'0')
            || !index.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::new(Field::Request, Fault::Text, 0, index.len()));
        }
        let index = index
            .bytes()
            .fold(0usize, |n, b| n * 10 + usize::from(b - b'0'));
        if index >= MAX_DEVICES {
            return Err(Error::new(Field::Request, Fault::Count, 0, index));
        }
        Ok(Self {
            index,
            uuid: parse_uuid(uuid)?,
        })
    }
    pub(crate) fn index(self) -> usize {
        self.index
    }
    pub(crate) fn uuid(self) -> [u8; 16] {
        self.uuid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Request,
    Platforms,
    Devices,
    Uuid,
    Name,
    Driver,
    Global,
    MaxAllocation,
    Pci,
    Identity,
    Allocation,
}
impl Field {
    fn code(self) -> ffi::cl_device_info {
        match self {
            Self::Uuid => 0x106a,
            Self::Name => ffi::CL_DEVICE_NAME,
            Self::Driver => ffi::CL_DRIVER_VERSION,
            Self::Global => ffi::CL_DEVICE_GLOBAL_MEM_SIZE,
            Self::MaxAllocation => ffi::CL_DEVICE_MAX_MEM_ALLOC_SIZE,
            Self::Pci => 0x410f,
            _ => unreachable!("non-query field"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Status,
    Count,
    Size,
    Null,
    Duplicate,
    Text,
    Missing,
    Mismatch,
    Allocation,
}

/// Fixed context and original signed driver code. Formatting this type never
/// asks OpenCL for a platform/device name, version or diagnostic string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Error {
    field: Field,
    fault: Fault,
    status: i32,
    reported: usize,
}
impl Error {
    fn new(field: Field, fault: Fault, status: i32, reported: usize) -> Self {
        Self {
            field,
            fault,
            status,
            reported,
        }
    }
    pub(crate) fn diagnostic(self) -> Diagnostic {
        use fmt::Write;
        let mut output = Diagnostic(Text::empty());
        if write!(output, "{self}").is_err() {
            output.0.len = 0;
            let _ = output.write_str("bounded_device diagnostic capacity exceeded");
        }
        output
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded_device field={:?} fault={:?} status={} reported={}",
            self.field, self.fault, self.status, self.reported
        )
    }
}
pub(crate) struct Diagnostic(Text<192>);
impl fmt::Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write(value)
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[derive(Clone, Copy)]
struct Entry {
    platform: ffi::cl_platform_id,
    device: ffi::cl_device_id,
}
impl Entry {
    const EMPTY: Self = Self {
        platform: ptr::null_mut(),
        device: ptr::null_mut(),
    };
}
// Alignment also makes fixed u64 and PCI info outputs suitable for the C API.
#[repr(C, align(8))]
struct QueryBytes([u8; STRING_BYTES]);

/// Actual fixed query owner. It has no Vec, String, OpenCL context or lease.
/// The enclosing planner must cover its storage before constructing it.
pub(crate) struct Scratch {
    platforms: [ffi::cl_platform_id; MAX_PLATFORMS],
    devices: [ffi::cl_device_id; MAX_DEVICES],
    entries: [Entry; MAX_DEVICES],
    query: QueryBytes,
}
impl Scratch {
    pub(crate) fn new() -> Self {
        Self {
            platforms: [ptr::null_mut(); MAX_PLATFORMS],
            devices: [ptr::null_mut(); MAX_DEVICES],
            entries: [Entry::EMPTY; MAX_DEVICES],
            query: QueryBytes([0; STRING_BYTES]),
        }
    }
}

#[derive(Clone, Copy)]
struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Text<N> {
    const fn empty() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    fn from_str(value: &str) -> Result<Self, Error> {
        let mut text = Self::empty();
        text.write(value)
            .map_err(|_| Error::new(Field::Identity, Fault::Size, 0, value.len()))?;
        Ok(text)
    }
    fn write(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
    fn as_str(&self) -> &str {
        // Constructors copy only complete UTF-8 strings; formatting is ASCII.
        core::str::from_utf8(&self.bytes[..self.len]).expect("bounded text is UTF-8")
    }
}
impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write(value)
    }
}
struct FixedSelection {
    entry: Entry,
    request: Request,
    name: Text<STRING_BYTES>,
    driver: Text<STRING_BYTES>,
    pci: Option<Text<PCI_BYTES>>,
    global: u64,
    maximum: u64,
}

/// The existing shared Identity is the only external identity representation.
/// Private fields prevent mutation between capture and bounded recheck. No
/// Clone or Device Debug implementation can introduce hidden query allocations.
pub(crate) struct Snapshot {
    platform: Platform,
    device: Device,
    request: Request,
    identity: Identity,
}
impl Snapshot {
    pub(crate) fn capture(request: Request, scratch: &mut Scratch) -> Result<Self, Error> {
        capture(&mut driver::Driver, request, scratch)
    }
    pub(crate) fn recheck(&self, request: Request, scratch: &mut Scratch) -> Result<(), Error> {
        recheck(&mut driver::Driver, self, request, scratch)
    }
    pub(crate) fn platform(&self) -> Platform {
        self.platform
    }
    pub(crate) fn device(&self) -> Device {
        self.device
    }
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }
    pub(crate) fn uuid(&self) -> [u8; 16] {
        self.request.uuid
    }
    pub(crate) fn requested_string_bytes(&self) -> usize {
        self.identity.name.capacity()
            + self.identity.driver.capacity()
            + self.identity.uuid.as_ref().map_or(0, String::capacity)
            + self.identity.pci.as_ref().map_or(0, String::capacity)
    }
    pub(crate) fn into_parts(self) -> (Platform, Device, Identity) {
        (self.platform, self.device, self.identity)
    }
}

/// Source inventory, not a compiled maximum stack/allocator/driver bound.
/// The caller must cover Scratch plus fixed query/selection temporaries, the
/// Snapshot inline owner and its strings. Recheck creates no new strings.
pub(crate) struct Footprint {
    pub(crate) scratch_inline: usize,
    pub(crate) fixed_selection_inline: usize,
    pub(crate) snapshot_inline: usize,
    pub(crate) maximum_string_requests: usize,
    pub(crate) diagnostic_inline: usize,
}
pub(crate) const fn footprint() -> Footprint {
    Footprint {
        scratch_inline: size_of::<Scratch>(),
        fixed_selection_inline: size_of::<FixedSelection>(),
        snapshot_inline: size_of::<Snapshot>(),
        maximum_string_requests: MAX_IDENTITY_REQUESTED_BYTES,
        diagnostic_inline: size_of::<Diagnostic>(),
    }
}

fn parse_uuid(value: &str) -> Result<[u8; 16], Error> {
    let bad = || Error::new(Field::Request, Fault::Text, 0, value.len());
    let bytes = value.as_bytes();
    if bytes.len() != UUID_BYTES
        || &bytes[..4] != b"GPU-"
        || [12, 17, 22, 27].into_iter().any(|at| bytes[at] != b'-')
    {
        return Err(bad());
    }
    let digit = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut result = [0u8; 16];
    let mut at = 4;
    for byte in &mut result {
        if matches!(at, 12 | 17 | 22 | 27) {
            at += 1;
        }
        *byte = digit(bytes[at]).ok_or_else(bad)? * 16 + digit(bytes[at + 1]).ok_or_else(bad)?;
        at += 2;
    }
    Ok(result)
}
fn uuid_text(uuid: [u8; 16]) -> Text<UUID_BYTES> {
    let mut text = Text::empty();
    text.bytes[..4].copy_from_slice(b"GPU-");
    let mut at = 4;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in uuid.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.bytes[at] = b'-';
            at += 1;
        }
        text.bytes[at] = HEX[usize::from(byte >> 4)];
        text.bytes[at + 1] = HEX[usize::from(byte & 15)];
        at += 2;
    }
    text.len = at;
    text
}

fn count(field: Field, result: (usize, i32), maximum: usize, absent: i32) -> Result<usize, Error> {
    let (n, status) = result;
    if status == absent && n == 0 {
        return Ok(0);
    }
    if status != ffi::CL_SUCCESS {
        return Err(Error::new(field, Fault::Status, status, n));
    }
    if n > maximum {
        return Err(Error::new(field, Fault::Count, status, n));
    }
    Ok(n)
}
fn inventory(api: &mut impl driver::Api, scratch: &mut Scratch) -> Result<usize, Error> {
    scratch.platforms.fill(ptr::null_mut());
    scratch.entries.fill(Entry::EMPTY);
    let platforms = count(
        Field::Platforms,
        api.platforms(&mut []),
        MAX_PLATFORMS,
        ffi::CL_PLATFORM_NOT_FOUND_KHR,
    )?;
    if platforms == 0 {
        return Err(Error::new(Field::Platforms, Fault::Missing, 0, 0));
    }
    let filled = count(
        Field::Platforms,
        api.platforms(&mut scratch.platforms),
        MAX_PLATFORMS,
        ffi::CL_PLATFORM_NOT_FOUND_KHR,
    )?;
    if filled != platforms {
        return Err(Error::new(Field::Platforms, Fault::Count, 0, filled));
    }
    let mut total = 0;
    for p in 0..platforms {
        let platform = scratch.platforms[p];
        if platform.is_null() {
            return Err(Error::new(Field::Platforms, Fault::Null, 0, p));
        }
        if scratch.platforms[..p].contains(&platform) {
            return Err(Error::new(Field::Platforms, Fault::Duplicate, 0, p));
        }
        let devices = count(
            Field::Devices,
            api.devices(platform, &mut []),
            MAX_DEVICES - total,
            ffi::CL_DEVICE_NOT_FOUND,
        )?;
        if devices == 0 {
            continue;
        }
        scratch.devices.fill(ptr::null_mut());
        let filled = count(
            Field::Devices,
            api.devices(platform, &mut scratch.devices),
            MAX_DEVICES - total,
            ffi::CL_DEVICE_NOT_FOUND,
        )?;
        if filled != devices {
            return Err(Error::new(Field::Devices, Fault::Count, 0, filled));
        }
        for d in 0..devices {
            let device = scratch.devices[d];
            if device.is_null() {
                return Err(Error::new(Field::Devices, Fault::Null, 0, total));
            }
            if scratch.entries[..total]
                .iter()
                .any(|entry| entry.device == device)
            {
                return Err(Error::new(Field::Devices, Fault::Duplicate, 0, total));
            }
            scratch.entries[total] = Entry { platform, device };
            total += 1;
        }
    }
    Ok(total)
}

fn query(
    api: &mut impl driver::Api,
    device: ffi::cl_device_id,
    field: Field,
    storage: &mut QueryBytes,
    exact: Option<usize>,
    optional: bool,
) -> Result<Option<usize>, Error> {
    let (size, status) = api.info(device, field, &mut []);
    if optional && status == ffi::CL_INVALID_VALUE {
        return Ok(None);
    }
    if status != ffi::CL_SUCCESS {
        return Err(Error::new(field, Fault::Status, status, size));
    }
    let capacity = exact.unwrap_or(STRING_BYTES);
    if size == 0 || size > capacity || exact.is_some_and(|n| n != size) {
        return Err(Error::new(field, Fault::Size, status, size));
    }
    storage.0[..capacity].fill(0);
    let (filled, status) = api.info(device, field, &mut storage.0[..capacity]);
    if status != ffi::CL_SUCCESS {
        return Err(Error::new(field, Fault::Status, status, filled));
    }
    if filled != size {
        return Err(Error::new(field, Fault::Size, status, filled));
    }
    Ok(Some(size))
}
fn text_query(
    api: &mut impl driver::Api,
    device: ffi::cl_device_id,
    field: Field,
    storage: &mut QueryBytes,
) -> Result<Text<STRING_BYTES>, Error> {
    let length = query(api, device, field, storage, None, false)?.expect("required query");
    let bytes = &storage.0[..length];
    if bytes[length - 1] != 0 || bytes[..length - 1].contains(&0) {
        return Err(Error::new(field, Fault::Text, 0, length));
    }
    let text = core::str::from_utf8(&bytes[..length - 1])
        .map_err(|_| Error::new(field, Fault::Text, 0, length))?
        .trim();
    if text.is_empty() {
        return Err(Error::new(field, Fault::Text, 0, length));
    }
    Text::from_str(text)
}
fn number_query(
    api: &mut impl driver::Api,
    device: ffi::cl_device_id,
    field: Field,
    storage: &mut QueryBytes,
) -> Result<u64, Error> {
    query(api, device, field, storage, Some(8), false)?;
    Ok(u64::from_ne_bytes(
        storage.0[..8].try_into().expect("fixed u64 query"),
    ))
}
fn select_fixed(
    api: &mut impl driver::Api,
    request: Request,
    scratch: &mut Scratch,
) -> Result<FixedSelection, Error> {
    let total = inventory(api, scratch)?;
    if request.index >= total {
        return Err(Error::new(Field::Devices, Fault::Missing, 0, request.index));
    }
    let mut selected = None;
    for index in 0..total {
        let entry = scratch.entries[index];
        let found = query(
            api,
            entry.device,
            Field::Uuid,
            &mut scratch.query,
            Some(16),
            true,
        )?
        .is_some();
        if !found {
            continue;
        }
        if scratch.query.0[..16] == request.uuid {
            if selected.is_some() {
                return Err(Error::new(Field::Uuid, Fault::Duplicate, 0, index));
            }
            selected = Some(index);
        }
    }
    if selected != Some(request.index) {
        return Err(Error::new(
            Field::Identity,
            Fault::Mismatch,
            0,
            request.index,
        ));
    }
    let entry = scratch.entries[request.index];
    let global = number_query(api, entry.device, Field::Global, &mut scratch.query)?;
    let maximum = number_query(api, entry.device, Field::MaxAllocation, &mut scratch.query)?;
    if global == 0 || maximum == 0 || maximum > global {
        return Err(Error::new(Field::Identity, Fault::Size, 0, 0));
    }
    let name = text_query(api, entry.device, Field::Name, &mut scratch.query)?;
    let driver = text_query(api, entry.device, Field::Driver, &mut scratch.query)?;
    let pci = if query(
        api,
        entry.device,
        Field::Pci,
        &mut scratch.query,
        Some(16),
        true,
    )?
    .is_some()
    {
        use fmt::Write;
        let words: [u32; 4] = core::array::from_fn(|i| {
            u32::from_ne_bytes(
                scratch.query.0[i * 4..i * 4 + 4]
                    .try_into()
                    .expect("fixed PCI query"),
            )
        });
        let mut text = Text::empty();
        write!(
            text,
            "{:04x}:{:02x}:{:02x}.{}",
            words[0], words[1], words[2], words[3]
        )
        .map_err(|_| Error::new(Field::Pci, Fault::Size, 0, PCI_BYTES))?;
        Some(text)
    } else {
        None
    };
    Ok(FixedSelection {
        entry,
        request,
        name,
        driver,
        pci,
        global,
        maximum,
    })
}

fn owned(value: &str) -> Result<String, Error> {
    let mut text = String::new();
    text.try_reserve_exact(value.len())
        .map_err(|_| Error::new(Field::Allocation, Fault::Allocation, 0, value.len()))?;
    text.push_str(value);
    Ok(text)
}
fn capture(
    api: &mut impl driver::Api,
    request: Request,
    scratch: &mut Scratch,
) -> Result<Snapshot, Error> {
    let selected = select_fixed(api, request, scratch)?;
    // All driver sizes, exact identity and text encodings were checked before
    // the first Rust allocation. Partial String construction drops on failure.
    let identity = Identity {
        opencl_index: selected.request.index,
        uuid: Some(owned(uuid_text(selected.request.uuid).as_str())?),
        name: owned(selected.name.as_str())?,
        pci: selected
            .pci
            .as_ref()
            .map(|v| owned(v.as_str()))
            .transpose()?,
        global_bytes: selected.global,
        max_allocation_bytes: selected.maximum,
        driver: owned(selected.driver.as_str())?,
    };
    // SAFETY: nonnull root-device and platform IDs came from successful bounded
    // enumeration. These ocl wrappers are Copy handles, with no retain/query.
    let (platform, device) = unsafe {
        (
            Platform::new(cl_core::PlatformId::from_raw(selected.entry.platform)),
            Device::from(cl_core::DeviceId::from_raw(selected.entry.device)),
        )
    };
    Ok(Snapshot {
        platform,
        device,
        request,
        identity,
    })
}
fn recheck(
    api: &mut impl driver::Api,
    snapshot: &Snapshot,
    request: Request,
    scratch: &mut Scratch,
) -> Result<(), Error> {
    if request != snapshot.request {
        return Err(Error::new(
            Field::Request,
            Fault::Mismatch,
            0,
            request.index,
        ));
    }
    let selected = select_fixed(api, request, scratch)?;
    let platform: cl_core::PlatformId = snapshot.platform.into();
    let device: cl_core::DeviceId = snapshot.device.into();
    let identity = &snapshot.identity;
    if platform.as_ptr() != selected.entry.platform
        || device.as_raw() != selected.entry.device
        || identity.opencl_index != request.index
        || identity.uuid.as_deref() != Some(uuid_text(request.uuid).as_str())
        || identity.name != selected.name.as_str()
        || identity.driver != selected.driver.as_str()
        || identity.pci.as_deref() != selected.pci.as_ref().map(Text::as_str)
        || identity.global_bytes != selected.global
        || identity.max_allocation_bytes != selected.maximum
    {
        return Err(Error::new(
            Field::Identity,
            Fault::Mismatch,
            0,
            request.index,
        ));
    }
    Ok(())
}
