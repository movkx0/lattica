//! Persistent coordinator-side worker ownership. Pending Task/request/result
//! heaps belong to the existing per-job packet/decode/verifier reservation.
//! Child/Command internals, stacks, allocator and OS state remain separate.

use super::*;
use crate::block_v2::execution::{os_worker, policy_context, storage_bound::add};
use core::mem::size_of;

pub(super) const UNIT_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStorage {
    pub retained_bytes: usize,
    pub control_bytes: usize,
}

impl ProcessWorker {
    pub fn storage_plan() -> Result<ProcessStorage, Error> {
        let retained_bytes = add(
            size_of::<ProcessWorker>(),
            add(
                os_worker::observation_storage()?.identity_heap_bytes,
                UNIT_BYTES,
            )?,
        )?;
        // HELLO/READY, context encoding, descriptor/spec copies and heartbeat
        // framing. The active proof protocol has a separate per-job allowance.
        let census = 8
            * (SESSION_BYTES
                + size_of::<Descriptor>()
                + policy_context::MAX_BYTES
                + size_of::<Vec<u8>>())
            + 4096;
        let control_bytes = 64 << 10;
        if census > control_bytes {
            return Err("persistent process control storage allowance".into());
        }
        Ok(ProcessStorage {
            retained_bytes,
            control_bytes,
        })
    }

    pub fn persistent_storage_bytes(&self) -> Result<usize, Error> {
        let mut bytes = size_of::<ProcessWorker>();
        if let Some(service) = &self.service {
            bytes = add(bytes, service.retained_heap_bytes()?)?;
        }
        if bytes > Self::storage_plan()?.retained_bytes {
            return Err("persistent process backing invariant".into());
        }
        Ok(bytes)
    }
}
