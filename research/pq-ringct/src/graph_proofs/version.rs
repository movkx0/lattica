use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;
include!(concat!(env!("OUT_DIR"), "/graph-proof-sources.rs"));

/// Compiled Rust research/prover/local patched-dependency sources, manifests,
/// dependency lock, compiler, target, build mode and active research features.
/// Registry dependency content is pinned by Cargo.lock's checksums. This is a
/// cache invalidation identity, not a reproducible-build or hardware attestation.
pub(super) fn source_fingerprint() -> [u8; 32] {
    static FINGERPRINT: OnceLock<[u8; 32]> = OnceLock::new();
    *FINGERPRINT.get_or_init(|| {
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/compiled-proof-sources/v1");
        hash.update(BUILD_IDENTITY.as_bytes());
        hash.update([
            u8::from(cfg!(feature = "recursive-wide")),
            u8::from(cfg!(feature = "native-matrict")),
        ]);
        for (name, contents) in SOURCES {
            hash.update((name.len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            hash.update((contents.len() as u64).to_le_bytes());
            hash.update(contents);
        }
        hash.finalize().into()
    })
}
