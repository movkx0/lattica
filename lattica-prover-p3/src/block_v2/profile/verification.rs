//! Fresh reference verification configuration with explicit entropy failure.
//! No thread-local RNG initialization or deterministic production seeds.

use super::{config_with_rngs, Config};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub(crate) fn make_config() -> Result<Config, &'static str> {
    let salt = ChaCha20Rng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| "native verifier entropy unavailable")?;
    let hiding = ChaCha20Rng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| "native verifier entropy unavailable")?;
    Ok(config_with_rngs(salt, hiding, None, false, false))
}

// These are allocation-request layouts, not allocator usable sizes or RSS.
// Pinned Rust ArcInner has two AtomicUsize counters followed by aligned T.
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
pub(crate) fn arc_bytes<T>() -> usize {
    #[repr(C)]
    struct Allocation<T> {
        _strong: std::sync::atomic::AtomicUsize,
        _weak: std::sync::atomic::AtomicUsize,
        _value: T,
    }
    core::mem::size_of::<Allocation<T>>()
}

/// Cumulative Rust allocation requests while constructing a fresh config.
/// Qualified for release x86_64 with the pinned p3 0.6.1 / Rust 1.96 sources.
/// OS/libc entropy-provider internals, callbacks and stacks are separate.
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
pub(crate) fn requested_bytes() -> usize {
    // One Poseidon2 set: two 4-round vectors of 8 Goldilocks constants,
    // and 22 internal constants. Original challenger + hash/compressor +
    // cloned hash/compressor in the FRI MMCS = five sets, with no growth.
    let permutations = 5 * (2 * 4 * 8 + 22) * core::mem::size_of::<super::Val>();
    // Empty Radix2DitParallel has three Arc<spin::RwLock<BTreeMap>> roots.
    // spin 0.12.1 uses one AtomicUsize plus the inline map; an empty map has
    // no nodes. Key/value types do not affect its inline root/length layout.
    #[repr(C)]
    struct Cache {
        _lock: std::sync::atomic::AtomicUsize,
        _map: std::collections::BTreeMap<usize, usize>,
    }
    // HeapNormalizedDft -> BoundedCosetDft contains two Radix2DitParallel
    // instances; the reference PCS clones their Arcs without allocating.
    let roots = if cfg!(feature = "stream") { 6 } else { 3 };
    let bytes = permutations + roots * arc_bytes::<Cache>();
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let bytes = bytes
        + 2 * arc_bytes::<crate::config::ValMmcs>()
        + 2 * crate::block_v2::randomness::ProofRng::host_storage_bytes();
    bytes
}
