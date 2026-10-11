//! Native startup qualification uses separately prepared CPU registry data.
use super::*;
use crate::block_v2::{codec, gpu_hash, typed_recursive};
use crate::native_gpu::{
    lattica_gpu_drain, lattica_gpu_initialize_from_env,
    lattica_gpu_public_worker_initialize_from_env, lattica_gpu_shutdown,
};

const HEIGHT: usize = 2048;

fn directory() -> std::path::PathBuf {
    std::env::var_os("LATTICA_NATIVE_PUBLIC_DIR")
        .unwrap()
        .into()
}

#[test]
#[ignore = "isolated CPU fixture preparation before native GPU startup"]
fn cpu_fixture() {
    use crate::block_v2::machine::gpu_backend::resources::Bounds;
    assert!(!gpu_hash::is_enabled());
    assert!(std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_none());
    let registry = typed_recursive::Registry::<12> {
        height: HEIGHT,
        caps: empty_key(HEIGHT),
    };
    let program = programs::empty(HEIGHT, &registry.caps)
        .unwrap()
        .program
        .pad_to(HEIGHT)
        .unwrap();
    let bounds = Bounds::for_program(&program).unwrap();
    let fixture = serde_json::json!({
        "registry": registry,
        "profile": registry.id().unwrap(),
        "witness_bounds": bounds,
    });
    std::fs::write(
        directory().join("fixture.json"),
        serde_json::to_vec_pretty(&fixture).unwrap(),
    )
    .unwrap();
    assert!(!gpu_hash::is_enabled());
}

#[test]
#[ignore = "complete public GPU proof through native startup in an isolated capped fleet"]
fn native_public_proofs_verify_after_shutdown() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        registry: typed_recursive::Registry<12>,
        profile: [u8; 32],
    }
    let fixture: Fixture =
        serde_json::from_slice(&std::fs::read(directory().join("fixture.json")).unwrap()).unwrap();
    // The wallet ABI must reject this public-worker assignment before allocating.
    assert_eq!(lattica_gpu_initialize_from_env(), 1);
    assert!(!gpu_hash::is_enabled());
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 0);
    let _shutdown = gpu_hash::TestShutdownGuard;
    assert_eq!(rayon::current_num_threads(), 4);
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), 1);
    let mut session =
        typed_recursive::Session::new(fixture.registry.clone(), fixture.profile, 3 << 30).unwrap();
    let mut proofs = Vec::new();
    for level in [0, 5] {
        let proof = session.empty(context().chain_id, level).unwrap();
        let expected = commitment::empty_subtree(
            Context {
                profile_id: fixture.profile,
                ..context()
            },
            level,
        )
        .unwrap();
        assert_eq!(proof.public, programs::statement(expected, programs::EMPTY));
        let bytes = codec::encode_node(&proof).unwrap();
        std::fs::write(directory().join(format!("proof-{level}.bin")), &bytes).unwrap();
        proofs.push(bytes);
    }
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 1 }
    );
    assert_eq!(lattica_gpu_drain(), 0);
    assert_eq!(lattica_gpu_shutdown(), 1);
    drop(session);
    assert_eq!(lattica_gpu_shutdown(), 0);
    assert_eq!(lattica_gpu_shutdown(), 0);
    for bytes in proofs {
        let mut proof = codec::decode_node(&bytes).unwrap();
        fixture
            .registry
            .verify(fixture.profile, &proof, &proof.public)
            .unwrap();
        proof.public[programs::COUNT] += Val::ONE;
        assert!(fixture
            .registry
            .verify(fixture.profile, &proof, &proof.public)
            .is_err());
    }
    println!("native_public_gpu_verified proofs=2 height={HEIGHT} cached_setups=1 cache_hits=1 after_shutdown=true");
}
