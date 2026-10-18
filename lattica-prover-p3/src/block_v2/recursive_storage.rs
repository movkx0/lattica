//! Payload components for a legacy session and its bounded registry startup.
//! Caller inputs, allocator/runtime overhead and stacks remain separate.

use super::*;

pub(crate) const SESSION_HOST_BYTES: u64 = 1 << 20;
pub(super) const REGISTRY_HOST_BYTES: usize = 64 << 10;
pub(crate) const STARTUP_HOST_BYTES: u64 =
    SESSION_HOST_BYTES + programs::registry_setup::INITIAL_STORAGE_BYTES as u64;

pub(crate) fn admit_startup(total: u64) -> Result<(), Error> {
    if total < STARTUP_HOST_BYTES {
        return Err("legacy session requires RAM for bounded registry setup".into());
    }
    Ok(())
}

pub(super) fn active_memory_bytes(total: u64) -> Result<u64, Error> {
    total
        .checked_sub(SESSION_HOST_BYTES)
        .filter(|free| *free != 0)
        .ok_or_else(|| "legacy session requires RAM beyond retained session storage".into())
}

pub(super) fn registry_backing(registry: &Registry) -> Result<usize, Error> {
    let backing = registry
        .caps
        .iter()
        .try_fold(0usize, |bytes, cap| {
            bytes.checked_add(
                cap.capacity()
                    .checked_mul(core::mem::size_of::<[Val; 4]>())?,
            )
        })
        .ok_or("legacy registry storage overflow")?;
    let total = core::mem::size_of::<Registry>()
        .checked_add(backing)
        .ok_or("legacy registry storage overflow")?;
    if total > REGISTRY_HOST_BYTES {
        return Err("legacy registry cap capacity exceeds storage allowance".into());
    }
    Ok(backing)
}

pub(super) fn admit_session(registry: &Registry) -> Result<usize, Error> {
    let retained = core::mem::size_of::<ProverSession>()
        .checked_add(registry_backing(registry)?)
        // Optional input binding retains a second public cap set and a bounded
        // compilation receipt beside the existing authenticated program.
        .and_then(|bytes| bytes.checked_add(2 * REGISTRY_HOST_BYTES))
        .ok_or("legacy session storage overflow")?;
    if retained as u64 > SESSION_HOST_BYTES {
        return Err("legacy session exceeds retained storage allowance".into());
    }
    Ok(retained)
}
