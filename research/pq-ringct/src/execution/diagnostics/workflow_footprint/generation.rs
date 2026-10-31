//! Pre-context declared diagnostic inventory for the fixed generation wrapper.
//! Actual device identity capacities are checked against the original claim
//! immediately after startup, before any native spend call is available.
use super::*;

pub(in crate::execution) fn declared_identity_json() -> Result<usize, Error> {
    let mut bytes = object_keys(&[
        "opencl_index", "uuid", "name", "pci", "global_bytes", "max_allocation_bytes", "driver",
    ])?;
    for length in [255, 255, 40, 37] {
        bytes = add(bytes, growing::<u8>(length)?)?;
    }
    Ok(bytes)
}

impl Diagnostics {
    pub(in crate::execution) fn generation_declared_identity_json_bytes() -> Result<usize, Error> {
        declared_identity_json()
    }
    pub(in crate::execution) fn generation_declared_enclosing_bytes() -> Result<usize, Error> {
        let mut event = object_keys(&EVENT_KEYS)?;
        event = add(event, growing::<u8>(longest(&STAGES))?)?;
        event = add(event, growing::<u8>("gpu_required".len())?)?;
        event = add(event, declared_identity_json()?)?;
        event = add(event, growing::<u8>(mul(MAX_ERROR_CHARS, 4)?)?)?;
        event = add(event, object_keys(&DETAIL_KEYS)?)?;
        event = add(event, object_keys(&IDENTITY_KEYS)?)?;
        event = add(event, mul(4, growing::<u8>(64)?)?)?;
        event = add(event, mul(2, cap_bytes()?)?)?;
        event = add(event, growing::<Value>(4)?)?;
        event = add(event, growing::<u8>(longest(&NATIVE_ENTRIES))?)?;
        let mut bytes = add(size_of::<Self>(), mul(2, size_of::<usize>())?)?;
        bytes = add(bytes, declared_identity_json()?)?;
        bytes = add(bytes, mul(mul(add(MAX_EVENTS, 1)?, 2)?, event)?)?;
        add(bytes, growing::<Value>(add(MAX_EVENTS, 1)?)?)
    }
}
