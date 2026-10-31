//! Reviewed n10 C declared-object storage and Rust SHAKE callback frames.
//!
//! These are requested backing and declared values. Compiler stack layout,
//! allocator metadata, libc and driver RSS remain under the external guards.
//! A caller must separately charge its packet, report and context owners.
mod sources;

use core::mem::size_of;
use sha3::{Sha3_256, Shake256, Shake256Reader};

unsafe extern "C" {
    fn lattica_matrict_declared_footprint_v1(out: *mut u64, words: usize) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeclaredNativeFootprint {
    shared_static: u64,
    fixture: u64,
    verifier: u64,
}

impl DeclaredNativeFootprint {
    /// Runs before fixture/verifier dispatch. No native state is allocated.
    /// Source mismatch refuses admission; sizeof alone is not a source census.
    pub(crate) fn reviewed() -> Result<Self, &'static str> {
        if !sources::matches_reviewed_sources() {
            return Err("native declaration census source mismatch");
        }
        let mut words = [0u64; 8];
        // The getter checks the exact length and writes initialized scalars.
        // It contains only sizeof expressions and touches no native globals.
        if unsafe { lattica_matrict_declared_footprint_v1(words.as_mut_ptr(), words.len()) } != 1
            || words[0] != 1 || words[1] != 0
        {
            return Err("native declaration census requires non-oracle n10 ABI v1");
        }
        let callback = Self::callback_frames()?;
        let sum = |a: u64, b: u64| a.checked_add(b).ok_or("native census overflow");
        Ok(Self {
            shared_static: sum(words[3], sources::retained_source_bytes()?)?,
            fixture: sum(sum(sum(words[2], words[4])?, words[5])?, callback)?,
            verifier: sum(sum(sum(words[2], words[6])?, words[7])?, callback)?,
        })
    }

    /// One original process-lifetime claim, not one copy per transaction.
    pub(crate) fn shared_static_bytes(self) -> u64 { self.shared_static }
    pub(crate) fn fixture_bytes(self) -> u64 { self.fixture }
    pub(crate) fn verifier_bytes(self) -> u64 { self.verifier }

    pub(crate) fn inspection_frame_bytes() -> Result<u64, &'static str> {
        // Source hash state, getter output, returned census and forwarding
        // values all coexist; no native allocation is hidden in inspection.
        let bytes = size_of::<Sha3_256>() + size_of::<[u64; 8]>()
            + 4 * size_of::<Self>() + 8 * size_of::<usize>() + 2 * size_of::<[u8; 32]>();
        u64::try_from(bytes).map_err(|_| "native census frame width")
    }

    fn callback_frames() -> Result<u64, &'static str> {
        // SHAKE256's state, finalized reader, borrowed input/output views,
        // four C arguments and their captured closure coexist conservatively.
        // The native source lock permits only one nonrecursive callback.
        let bytes = size_of::<Shake256>() + size_of::<Shake256Reader>()
            + 2 * size_of::<&[u8]>() + 8 * size_of::<usize>()
            + size_of::<Result<(), Box<dyn core::any::Any + Send>>>();
        u64::try_from(bytes).map_err(|_| "native callback frame width")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_pinned_census_preserves_shared_and_phase_lifetimes() {
        let census = DeclaredNativeFootprint::reviewed().unwrap();
        assert_eq!(sources::retained_source_bytes().unwrap(), 167_505);
        assert_eq!(census.shared_static_bytes(), 2_289_570 + 167_505);
        let callback = DeclaredNativeFootprint::callback_frames().unwrap();
        assert_eq!(census.fixture_bytes(), 1_112_848 + 55_090 + callback);
        assert_eq!(census.verifier_bytes(), 1_112_848 + 29_310 + callback);
        assert!(DeclaredNativeFootprint::inspection_frame_bytes().unwrap() > 0);
    }
}
