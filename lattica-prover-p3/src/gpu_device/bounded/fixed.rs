//! Allocation-free physical facts for repeated bounded backend selection.
//! The caller owns its preceding startup/preflight reservation and immutable
//! environment contract. This object conveys neither quota nor GPU dispatch.
use super::*;

/// No Identity strings, Clone, Debug formatting or hidden driver queries.
pub(crate) struct Physical {
    device: Device,
    request: Request,
    global_bytes: u64,
    max_allocation_bytes: u64,
}

impl Physical {
    pub(crate) fn index(&self) -> usize {
        self.request.index()
    }
    pub(crate) fn uuid(&self) -> [u8; 16] {
        self.request.uuid()
    }
    pub(crate) fn global_bytes(&self) -> u64 {
        self.global_bytes
    }
    pub(crate) fn max_allocation_bytes(&self) -> u64 {
        self.max_allocation_bytes
    }
    pub(crate) fn device(&self) -> Device {
        self.device
    }
}

/// Input strings were already bounded/captured by the enclosing startup owner.
/// Reuses the exact fixed-size scanner used by Snapshot, including duplicate
/// physical UUID/handle and invalid size/encoding rejection before any copy.
pub(crate) fn capture(request: Request, scratch: &mut Scratch) -> Result<Physical, Error> {
    capture_with(&mut driver::Driver, request, scratch)
}

pub(super) fn capture_with(
    api: &mut impl driver::Api,
    request: Request,
    scratch: &mut Scratch,
) -> Result<Physical, Error> {
    let selected = select_fixed(api, request, scratch)?;
    // SAFETY: the root-device ID was just returned by checked bounded GPU
    // enumeration. These handle wrappers do not retain or query the device.
    let device = unsafe { Device::from(cl_core::DeviceId::from_raw(selected.entry.device)) };
    Ok(Physical {
        device,
        request: selected.request,
        global_bytes: selected.global,
        max_allocation_bytes: selected.maximum,
    })
}

/// Fixed inline source owners, not a bound on the compiled thread stack or
/// opaque driver heap. The existing external guard retains that obligation.
pub(crate) const fn inline_bytes() -> usize {
    size_of::<Scratch>() + size_of::<FixedSelection>() + size_of::<Physical>()
}
