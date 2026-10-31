//! Feature-only GPU phase digests for deterministic native C qualification.
//! Records are private diagnostics, never a wire format or production receipt.
use super::{types, PrivateSpendOutput, PrivateSpendRequest, SpendEvidence, SpendLimits};
use crate::block_v2::gpu_hash::device::DeviceSession;
use crate::proving::{
    Backend, Capabilities, CoverageScope, Policy, Profile, Report, Request, Run, Stage,
};
use std::sync::atomic::{compiler_fence, Ordering};

pub const ENTRY_POINT: &str = "native_matrict_phase_probe";
pub const MAX_ATTEMPTS: u64 = 8192;
pub(crate) const RECORD_WORDS: usize = 7;

/// Mirrors the private reference ABI. No Debug/Clone/serde implementation.
#[repr(C)]
#[derive(Default)]
pub struct PrivatePhaseRecord {
    pub phase: u32,
    pub component: u32,
    pub bytes: u64,
    pub digest: [u8; 32],
    pub private_blocks: u64,
}
const _: () = assert!(std::mem::size_of::<PrivatePhaseRecord>() == 56);
const _: () = assert!(std::mem::align_of::<PrivatePhaseRecord>() == 8);

/// Owns and wipes all initialized capacity, including unused record slots.
pub struct PrivatePhaseRecords {
    storage: Vec<PrivatePhaseRecord>,
    used: usize,
}

impl PrivatePhaseRecords {
    pub fn records(&self) -> &[PrivatePhaseRecord] {
        &self.storage[..self.used]
    }

    pub(crate) fn zeroed(capacity: usize, used: usize) -> Result<Self, String> {
        if used > capacity || capacity > capacity_for(MAX_ATTEMPTS)? {
            return Err("phase diagnostic record geometry is invalid".into());
        }
        let mut storage = Vec::with_capacity(capacity);
        storage.resize_with(capacity, PrivatePhaseRecord::default);
        Ok(Self { storage, used })
    }

    pub(crate) fn words_mut(&mut self) -> &mut [u64] {
        // SAFETY: repr(C), size56/alignment8 asserted above, no padding or
        // invalid integer representations. The returned slice is exclusively
        // borrowed from the initialized owner and never outlives it.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.storage.as_mut_ptr().cast::<u64>(),
                self.storage.len() * RECORD_WORDS,
            )
        }
    }
}

impl Drop for PrivatePhaseRecords {
    fn drop(&mut self) {
        for record in &mut self.storage {
            unsafe { std::ptr::write_volatile(record, PrivatePhaseRecord::default()) };
        }
        unsafe { std::ptr::write_volatile(&mut self.used, 0) };
        compiler_fence(Ordering::SeqCst);
    }
}

pub(crate) fn capacity_for(attempts: u64) -> Result<usize, String> {
    if !(1..=MAX_ATTEMPTS).contains(&attempts) {
        return Err("phase diagnostic attempts must be in 1..=8192".into());
    }
    usize::try_from(attempts)
        .ok()
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| n.checked_add(2))
        .ok_or_else(|| "phase diagnostic record capacity overflow".into())
}

/// Execute the unchanged production schedule and observe its resident phase
/// data with GPU SHAKE256. Private RNG state is read, never advanced by capture.
/// Caller holds the admitted OpenCL lifetime and serializes prepared work.
pub fn spend(
    input: PrivateSpendRequest,
    limits: SpendLimits,
    request: Request,
    mut key: [u8; 32],
) -> Result<
    (
        PrivateSpendOutput,
        PrivatePhaseRecords,
        Report,
        SpendEvidence,
    ),
    String,
> {
    let entropy = types::PrivateEntropy::for_oracle(key);
    for byte in &mut key {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    // Check the diagnostic cap first, including the zero case, before any
    // session or record allocation. Normal production retains its own bound.
    capacity_for(limits.max_attempts)?;
    limits.validate()?;
    if request.policy != Policy::GpuRequired {
        return Err("phase diagnostic requires explicit GPU-required policy".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::MatrictN10, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    let run = Run::new(ENTRY_POINT, request, capabilities).map_err(|e| e.to_string())?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let packed = input.pack_with_entropy(limits.host_bytes, entropy)?;
    let (output, evidence, records) =
        session.create_native_private_spend_with_phases(packed, limits, &run)?;
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok((output, records, report, evidence))
}
