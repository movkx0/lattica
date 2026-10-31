//! Cache adapter rejection plumbing under an actual registered header-only
//! cap. No outer proof is generated, no complete branch is registered, and no
//! invalid template is accepted or represented as a valid proof baseline.
use super::*;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn header_only_cache_probe_rejects_invalid_entries_without_overwrite_or_proving() {
    let node = header_only_probe(Descriptor::AlphaUniform);
    node.evaluate().unwrap();
    assert!(node.geometry().unwrap().retained_lde_bytes < 512 << 20);
    let prepared = node.prepare(512 << 20).unwrap();
    let key = prepared.key();
    let identity = prepared.cache_identity(&key).unwrap();
    let public = prepared.public.clone();
    let invalid = verifier::template::batch(&key.air().unwrap()).unwrap();
    assert!(key.verifier.verify(&invalid, &public).is_err());
    let directory = std::env::temp_dir().join(format!(
        "lattica-producer-header-cache-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
    ));
    let cache = OuterProofCache::new(&directory, 64 << 20).unwrap();
    let path = cache.entry_path(&identity);
    let verify = |values: &[Val], proof: &BatchProof<Config>| {
        key.verifier
            .verify(proof, values)
            .map_err(|error| format!("{error:?}"))
    };
    // A missing entry is a successful lookup, but the adapter is deliberately
    // not invoked on a miss: that would generate a header-only outer proof.
    assert!(cache
        .load_verified(&identity, &public, verify)
        .unwrap()
        .is_none());

    let source = crate::graph_proofs::compiled_source_fingerprint();
    let entry = serde_json::to_vec(&(1u64, source, identity, &public, &invalid)).unwrap();
    fs::write(&path, &entry).unwrap();
    assert!(cache.load_verified(&identity, &public, verify).is_err());
    assert_eq!(fs::read(&path).unwrap(), entry);
    assert!(cache
        .store_verified(&identity, &public, &invalid, verify)
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), entry);

    // Schema/identity/public checks have distinct expected diagnostics, so an
    // independently invalid proof cannot mask a missing cache binding here.
    let mut changed_identity = identity;
    changed_identity[0] ^= 1;
    for (schema, stored_source, stored_identity) in [
        (2u64, source, identity),
        (1u64, [0; 32], identity),
        (1u64, source, changed_identity),
    ] {
        let changed =
            serde_json::to_vec(&(schema, stored_source, stored_identity, &public, &invalid))
                .unwrap();
        fs::write(&path, &changed).unwrap();
        let error = cache
            .load_verified(&identity, &public, verify)
            .err()
            .unwrap();
        assert!(
            error.0.contains("schema/source/identity mismatch"),
            "{error}"
        );
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
    let mut changed_public = public.clone();
    changed_public[NODE_MANIFEST] += Val::ONE;
    let changed = serde_json::to_vec(&(1u64, source, identity, &changed_public, &invalid)).unwrap();
    fs::write(&path, &changed).unwrap();
    let error = cache
        .load_verified(&identity, &public, verify)
        .err()
        .unwrap();
    assert!(error.0.contains("expected public mismatch"), "{error}");
    assert_eq!(fs::read(&path).unwrap(), changed);

    let malformed = b"[1,null]";
    fs::write(&path, malformed).unwrap();
    assert!(prepared.prove_or_load(&cache).is_err());
    assert_eq!(fs::read(&path).unwrap(), malformed);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    fs::remove_dir_all(directory).unwrap();
}
