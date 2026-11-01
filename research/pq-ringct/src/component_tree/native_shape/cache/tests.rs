use super::super::unchanged::OtherNativeDescriptor;
use super::super::{native_core_bound, NativeCoreCounts, NativeDescriptor, NativePlanningStorage};
use super::*;
use crate::{
    aes_lane_air,
    graph_proofs::ComponentKind,
    linear_map_air::LinearMapDescriptor,
    rust_verify::{committed_backend::PolynomialKind, D, Q, QHAT},
    transcript_air::PartKind,
};
fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: lattica_prover_p3::block_v2::machine::program::MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
fn fixture() -> NativeCoreBound {
    NativeCoreBound {
        counts: NativeCoreCounts {
            quotient_chunks: 1,
            operations: Default::default(),
            wires: 1,
            input_values: 1,
            selection_hint_words: 0,
            planner_requested_program_bytes_peak: 0,
        },
        storage: NativePlanningStorage::for_descriptor(
            NativeDescriptor::Transcript(&[PartKind::Bytes32]),
            limits(),
        )
        .unwrap(),
    }
}
#[test]
fn native_metadata_cache_keys_every_closed_descriptor_field_and_limit() {
    let base = aes_lane_air::Descriptor {
        domain: 1,
        start_counter: 2,
        output_len: 64,
    };
    let aes = |d, first, count| NativeDescriptor::Aes {
        descriptor: d,
        first,
        count,
    };
    let reference = key([1; 32], 0, &aes(base, 0, 1), limits(), 512 << 20);
    for d in [
        aes(aes_lane_air::Descriptor { domain: 2, ..base }, 0, 1),
        aes(
            aes_lane_air::Descriptor {
                start_counter: 3,
                ..base
            },
            0,
            1,
        ),
        aes(
            aes_lane_air::Descriptor {
                output_len: 65,
                ..base
            },
            0,
            1,
        ),
        aes(base, 1, 1),
        aes(base, 0, 2),
    ] {
        assert_ne!(key([1; 32], 0, &d, limits(), 512 << 20), reference);
    }
    assert_ne!(
        reference,
        key([2; 32], 0, &aes(base, 0, 1), limits(), 512 << 20)
    );
    assert_ne!(
        reference,
        key([1; 32], 1, &aes(base, 0, 1), limits(), 512 << 20)
    );
    for limit in [
        ConstructionLimits {
            max_requested_program_bytes: 1 << 30,
            ..limits()
        },
        ConstructionLimits {
            max_wires: 100,
            ..limits()
        },
        ConstructionLimits {
            max_input_values: 100,
            ..limits()
        },
    ] {
        assert_ne!(
            reference,
            key([1; 32], 0, &aes(base, 0, 1), limit, 512 << 20)
        );
    }
    assert_ne!(
        reference,
        key([1; 32], 0, &aes(base, 0, 1), limits(), 256 << 20)
    );
    let hash = |d: OtherNativeDescriptor<'_>| key([1; 32], 1, &d, limits(), 512 << 20);
    assert_ne!(
        hash(OtherNativeDescriptor::Statement {
            setup_seed: [0; 32]
        }),
        hash(OtherNativeDescriptor::Statement {
            setup_seed: [1; 32]
        })
    );
    let map = |modulus, coefficient| {
        let kind = PolynomialKind::Canonical { modulus };
        ComponentKind::LinearMap {
            descriptor: LinearMapDescriptor::new(vec![kind], kind, vec![[coefficient; D]], [0; D])
                .unwrap(),
        }
    };
    let a = map(Q, 1);
    let b = map(Q, 2);
    let c = map(QHAT, 1);
    let descriptor = |kind| OtherNativeDescriptor::Algebra { kind, count: 1 };
    assert_eq!(
        descriptor(&a).geometry().unwrap(),
        descriptor(&b).geometry().unwrap()
    );
    assert_ne!(hash(descriptor(&a)), hash(descriptor(&b)));
    assert_ne!(hash(descriptor(&a)), hash(descriptor(&c)));
}

#[test]
fn canonical_linear_keys_preserve_constants_normalization_and_owned_bridge() {
    let k = PolynomialKind::Canonical { modulus: Q };
    let make = |coefficient, constant| {
        LinearMapDescriptor::new(vec![k], k, vec![[coefficient; D]], [constant; D]).unwrap()
    };
    let base = make(1, 0);
    assert_eq!(base.metadata_key(), make(1 + Q as i64, 0).metadata_key());
    assert_ne!(base.metadata_key(), make(1, 1).metadata_key());
    assert_ne!(base.metadata_key(), make(2, 0).metadata_key());
    let many = LinearMapDescriptor::new(vec![k; 2], k, vec![[1; D]; 2], [0; D]).unwrap();
    assert_ne!(base.metadata_key(), many.metadata_key());
    #[cfg(feature = "full-workflow-experiment")]
    {
        let owned = many.owned_descriptor().unwrap();
        assert_eq!(many, LinearMapDescriptor::from_owned(&owned));
    }
    let signed = |bound| {
        LinearMapDescriptor::new(
            vec![PolynomialKind::Signed { bound }],
            PolynomialKind::Signed { bound: 100 },
            vec![[1; D]],
            [0; D],
        )
        .unwrap()
    };
    assert_ne!(signed(1).metadata_key(), signed(2).metadata_key());
}
#[test]
fn native_metadata_cache_is_bounded_and_does_not_cache_errors() {
    let scope = Scope::begin([1; 32]).unwrap();
    assert!(Scope::begin([1; 32]).is_err());
    let value = fixture();
    let get = |n| memoized(0, &n, limits(), 512 << 20, value.storage, || Ok(value)).unwrap();
    for n in 0..ENTRIES {
        get(n);
    }
    get(0);
    get(ENTRIES);
    let before = scope.statistics();
    get(0);
    get(1);
    assert_eq!(scope.statistics().hits, before.hits + 1);
    assert_eq!(scope.statistics().misses, before.misses + 1);
    assert_eq!(scope.statistics().evictions, 2);
    assert_eq!(scope.statistics().entries, ENTRIES);
    for _ in 0..2 {
        assert!(
            memoized(0, &999usize, limits(), 512 << 20, value.storage, || Err(
                busy()
            ))
            .is_err()
        );
    }
    assert_eq!(scope.statistics().failed_computations, 2);
}
#[test]
fn native_metadata_cache_drops_on_unwind_and_preserves_real_bounds() {
    let _ = std::panic::catch_unwind(|| {
        let _scope = Scope::begin([1; 32]).unwrap();
        panic!("scope cleanup");
    });
    let descriptor = NativeDescriptor::Aes {
        descriptor: aes_lane_air::Descriptor {
            domain: 0,
            start_counter: 0,
            output_len: 16,
        },
        first: 0,
        count: 1,
    };
    let expected = native_core_bound(descriptor, limits(), 512 << 20).unwrap();
    let scope = Scope::begin([2; 32]).unwrap();
    let start = Instant::now();
    assert_eq!(
        native_core_bound(descriptor, limits(), 512 << 20).unwrap(),
        expected
    );
    let cold_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    assert_eq!(
        native_core_bound(descriptor, limits(), 512 << 20).unwrap(),
        expected
    );
    let warm_ns = start.elapsed().as_nanos();
    assert_eq!((scope.statistics().misses, scope.statistics().hits), (1, 1));
    assert!(native_core_bound(descriptor, limits(), 0).is_err());
    assert_eq!(scope.statistics().hits, 1);
    eprintln!(
        "NATIVE_METADATA_CACHE_QUALIFICATION {}",
        serde_json::json!({
        "counts_equal": true, "cold_ns": cold_ns, "warm_ns": warm_ns, "cache": scope.statistics() })
    );
}

#[test]
#[ignore = "requires regenerated qualified tables and the serialized release guard"]
fn qualified_registered_tables_are_used_by_workflow_profile() {
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
        verifier_height_envelope, HeightEnvelopeCacheScope, MetadataCpuOptions,
        MetadataPlanningScope,
    };
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("cpu-required")
    );
    let planner = MetadataPlanningScope::begin(MetadataCpuOptions::workers(1).unwrap()).unwrap();
    let cache = HeightEnvelopeCacheScope::begin_with_precomputed(
        crate::graph_proofs::compiled_source_fingerprint(),
    )
    .unwrap();
    let started = Instant::now();
    for publics in [25, 28, 38, 46] {
        let envelope = verifier_height_envelope(publics, 1 << 20, limits(), 512 << 20).unwrap();
        assert_eq!(envelope.heights_enumerated, 18);
    }
    let elapsed = started.elapsed().as_nanos();
    assert_eq!(
        cache.statistics().table_hits,
        4,
        "workflow dependency build must use the qualified tables"
    );
    assert_eq!(planner.statistics().jobs_started, 0);
    assert_eq!(planner.statistics().symbolic_preparations, 0);
    eprintln!(
        "WORKFLOW_METADATA_TABLE_QUALIFICATION {}",
        serde_json::json!({
        "envelopes": 4, "heights": 72, "elapsed_ns": elapsed,
        "cache": cache.statistics(), "planning": planner.statistics(), "gpu_used": false })
    );
}
