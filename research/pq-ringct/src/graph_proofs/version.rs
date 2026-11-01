include!(concat!(env!("OUT_DIR"), "/graph-proof-sources.rs"));

/// Source, compiler, target, build mode and feature identity, computed at build
/// time with the original v1 encoding. Cache invalidation, not proof authority.
pub(super) const fn source_fingerprint() -> [u8; 32] {
    SOURCE_FINGERPRINT
}
