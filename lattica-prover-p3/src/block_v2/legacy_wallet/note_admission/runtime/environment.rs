//! Fixed profile values captured before allocating legacy environment helpers.
//! Process exclusivity is a precondition of the unsafe constructor, not a claim
//! that getenv or rechecking can prevent concurrent environment mutation.
use super::{add, Error};
use crate::gpu_device::{bounded, sealed_environment::Captured};
use core::{ffi::CStr, mem::size_of};

const VALUE_BYTES: usize = 256;
const FIXED: &[(&CStr, &[u8])] = &[
    (c"LATTICA_V2_GPU_HASH", b"1"),
    (c"LATTICA_V2_GPU_RETAIN_TREES", b"1"),
    (c"LATTICA_V2_GPU_QUERY_GATHER", b"1"),
    (c"LATTICA_V2_GPU_RESIDENT_LDE", b"1"),
    (c"LATTICA_V2_GPU_OPENINGS", b"1"),
    (c"LATTICA_V2_GPU_QUOTIENT_LDE", b"1"),
    (c"LATTICA_V2_GPU_QUOTIENT_EVAL", b"1"),
    (c"LATTICA_V2_GPU_QUOTIENT_RESIDENT", b"1"),
    (c"LATTICA_V2_GPU_LOOKUP", b"1"),
    (c"LATTICA_V2_GPU_OPENING_EVAL", b"1"),
    (c"LATTICA_V2_GPU_FRI_RESIDENT", b"1"),
    (c"LATTICA_V2_GPU_PCS_DEVICE_ONLY", b"1"),
    (c"LATTICA_V2_GPU_WITNESS", b"1"),
    (c"LATTICA_V2_GPU_RANDOMNESS", b"1"),
    (c"LATTICA_V2_GPU_TRANSCRIPT", b"1"),
    (c"LATTICA_V2_GPU_FRI_FOLD", b"1"),
    (c"LATTICA_V2_QUOTIENT_FUSION", b"1"),
    (c"LATTICA_PROVING_REPORT", b"1"),
    (c"LATTICA_PROVING_POLICY", b"gpu-required"),
    (c"LATTICA_V2_GPU_PUBLIC_HASH", b"baseline"),
    (c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE", b"device"),
    (c"LATTICA_V2_GPU_PIPELINE", b"0"),
    (c"LATTICA_V2_GPU_MANAGED_BYTES", b"8589934592"),
    (c"LATTICA_V2_GPU_CONTEXT_BYTES", b"4294967296"),
    (c"LATTICA_V2_HOST_OUTPUT_BYTES", b"25769803776"),
    (c"RAYON_NUM_THREADS", b"8"),
];

// Absence is stricter than accepting "0". This is the exact env-clear parent
// profile, including branches that would introduce files, caching or a second
// runtime policy. Empty present values are deliberately rejected too.
const ABSENT: &[&CStr] = &[
    c"LATTICA_V2_WORKER_BUDGET",
    c"LATTICA_WALLET_WORKER_BUDGET",
    c"LATTICA_V2_GPU_WORKERS",
    c"LATTICA_V2_GPU_TUNING",
    c"LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE",
    c"LATTICA_V2_GPU_COMPACT_PROVER_DATA",
    c"LATTICA_V2_GPU_OPENING_COMPACT",
    c"LATTICA_V2_GPU_OPENING_PINNED",
    c"LATTICA_V2_GPU_PARALLEL_READBACK",
    c"LATTICA_V2_GPU_DIRECT_READBACK",
    c"LATTICA_V2_SHARED_PREPROCESSING_DIR",
    c"LATTICA_V2_SHARED_PREPROCESSING_MAX_BYTES",
    c"LATTICA_V2_PHASE_DIR",
    c"LATTICA_V2_PHASE_SLOTS",
    c"LATTICA_V2_LATE_PHASE_DIR",
    c"LATTICA_V2_LATE_PHASE_SLOTS",
    c"LATTICA_V2_QUERY_PHASE_DIR",
    c"LATTICA_V2_QUERY_PHASE_SLOTS",
    c"LATTICA_V2_LDE_SCRATCH_BYTES",
    c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES",
    c"LATTICA_V2_GPU_LDE_WORKSPACE_BYTES",
    c"LATTICA_V2_COMPACT_SALTS",
    c"LATTICA_V2_MEMORY_RECLAIM",
    c"LATTICA_V2_OPENING_PROFILE",
    c"LATTICA_PROFILE_TIMELINE",
    c"LATTICA_FFT_TRACE",
    c"LATTICA_SPILL_BACKING",
    c"LATTICA_SPILL_DIR",
    c"LATTICA_SPILL_MAX_BYTES",
    c"RAYON_RS_NUM_CPUS",
    c"RUST_MIN_STACK",
];
const INDEX: &CStr = c"LATTICA_V2_GPU_DEVICE";
const UUID: &CStr = c"LATTICA_GPU_DEVICE_UUID";
const KEY_COUNT: usize = FIXED.len() + ABSENT.len() + 2;
const NAMES: [&CStr; KEY_COUNT] = {
    let mut names = [c""; KEY_COUNT];
    let mut i = 0;
    while i < FIXED.len() {
        names[i] = FIXED[i].0;
        i += 1;
    }
    let mut j = 0;
    while j < ABSENT.len() {
        names[i + j] = ABSENT[j];
        j += 1;
    }
    names[KEY_COUNT - 2] = INDEX;
    names[KEY_COUNT - 1] = UUID;
    names
};

pub(super) struct SealedNoteEnvironment {
    captured: Captured<KEY_COUNT, VALUE_BYTES>,
    request: bounded::Request,
}

impl SealedNoteEnvironment {
    pub(super) fn requested_bytes() -> Result<usize, Error> {
        // The retained capability plus capture/recheck inline overlap is
        // explicit. At most four complete fixed-value copies cover the live
        // outer selector OsStrings, explicit UUID, lease UUID and the current
        // nested helper lookup. Absent overrides allocate no returned value.
        // Named worker keys additionally cover env_name's formatted key copies.
        // This is requested source backing, not a compiled stack bound.
        let mut values = 40 + 3;
        let mut names = 0;
        for (name, value) in FIXED {
            values = add(values, value.len())?;
            names = add(names, name.to_bytes().len())?;
        }
        for name in ABSENT {
            names = add(names, name.to_bytes().len())?;
        }
        let copies = super::super::mul(4, add(values, names)?)?;
        add(
            add(
                size_of::<Self>(),
                Captured::<KEY_COUNT, VALUE_BYTES>::inline_and_scratch_bytes(),
            )?,
            copies,
        )
    }

    /// # Safety
    /// Caller retains its preceding real reservation and excludes environment
    /// mutation for this owner's complete lifetime, including all threads.
    /// The dedicated worker was launched with the reviewed fixed env-clear
    /// whitelist; inherited/untracked runtime override keys are not permitted.
    pub(super) unsafe fn capture() -> Result<Self, Error> {
        // SAFETY: inherited from this method's dedicated-process contract.
        let captured = unsafe { Captured::capture(&NAMES) }.map_err(|_| Error::Configuration)?;
        let request = validate(|name| captured.value(name).map_err(|_| Error::Configuration))?;
        Ok(Self { captured, request })
    }

    pub(super) fn request(&self) -> bounded::Request {
        self.request
    }

    pub(super) fn recheck(&self) -> Result<(), Error> {
        // SAFETY: construction required process immutability until destruction.
        unsafe { self.captured.recheck() }.map_err(|_| Error::Configuration)?;
        let current = validate(|name| self.captured.value(name).map_err(|_| Error::Configuration))?;
        if current != self.request {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

// Pure policy validation grants no capture/runtime authority. The production-
// shaped constructor above always reads the actual bounded captured values.
fn validate<'a>(
    get: impl Fn(&CStr) -> Result<Option<&'a [u8]>, Error>,
) -> Result<bounded::Request, Error> {
    for (name, expected) in FIXED {
        if get(name)? != Some(*expected) {
            return Err(Error::Configuration);
        }
    }
    for name in ABSENT {
        if get(name)?.is_some() {
            return Err(Error::Configuration);
        }
    }
    let index = core::str::from_utf8(get(INDEX)?.ok_or(Error::Configuration)?)
        .map_err(|_| Error::Configuration)?;
    let uuid = core::str::from_utf8(get(UUID)?.ok_or(Error::Configuration)?)
        .map_err(|_| Error::Configuration)?;
    bounded::Request::parse(index, uuid).map_err(|_| Error::Configuration)
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
