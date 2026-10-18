//! Shared bounds for the maintained Poseidon2 duplex transcript profile.
//! The state ABI is sponge[8], pending[4], output[4], and two lengths.
pub(crate) const LIVE_STATES: usize = 2;
pub(crate) const STATE_WORDS: usize = 18;
pub(crate) const BATCH_WORDS: usize = 4096;
pub(crate) const SCALAR_OUTPUTS: usize = 4096;
pub(crate) const PARTITION_COSETS: usize = 256;
pub(crate) const GRIND_BATCH: usize = 1 << 16;
pub(crate) const GRIND_TILE: usize = 256;
pub(crate) const GRIND_BITS: usize = 20;
pub(crate) const GRIND_CANDIDATES: usize = 1 << 26;
pub(crate) const HOST_BYTES: usize = 1 << 20;
