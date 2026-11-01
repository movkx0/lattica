use super::*;
use crate::component_tree::native_shape::{
    self, cache, unchanged, NativeCoreBound, NativeDescriptor,
};
use crate::{
    aes_lane_air,
    affine_air::AffineKind,
    graph_proofs::ComponentKind,
    linear_map_air::LinearMapDescriptor,
    permutation_air::PermutationKind,
    rust_verify::{committed_backend::PolynomialKind, D, Q, QHAT},
    shake_air, sparse_air,
    transcript_air::PartKind,
    uniform_air,
};
use lattica_prover_p3::block_v2::machine::program::{ConstructionLimits, MAX_WIRES};
use std::collections::HashSet;

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
enum Descriptor {
    Native(NativeDescriptor<'static>),
    Statement([u8; 32]),
    Private,
    Algebra(ComponentKind, usize),
}
struct Case {
    name: String,
    family: &'static str,
    descriptor: Descriptor,
}
impl Case {
    fn descriptor(&self) -> native_shape::cohort::Descriptor<'_> {
        use native_shape::cohort::Descriptor as D;
        match &self.descriptor {
            Descriptor::Native(d) => D::Native(*d),
            Descriptor::Statement(seed) => {
                D::Other(unchanged::OtherNativeDescriptor::Statement { setup_seed: *seed })
            }
            Descriptor::Private => D::Other(unchanged::OtherNativeDescriptor::PrivateProof),
            Descriptor::Algebra(kind, count) => {
                D::Other(unchanged::OtherNativeDescriptor::Algebra {
                    kind,
                    count: *count,
                })
            }
        }
    }
    fn bound(&self) -> Result<NativeCoreBound, CompileError> {
        match &self.descriptor {
            Descriptor::Native(d) => native_shape::native_core_bound(*d, limits(), 512 << 20),
            Descriptor::Statement(setup_seed) => unchanged::other_native_core_bound(
                unchanged::OtherNativeDescriptor::Statement {
                    setup_seed: *setup_seed,
                },
                limits(),
                512 << 20,
            ),
            Descriptor::Private => unchanged::other_native_core_bound(
                unchanged::OtherNativeDescriptor::PrivateProof,
                limits(),
                512 << 20,
            ),
            Descriptor::Algebra(kind, count) => unchanged::other_native_core_bound(
                unchanged::OtherNativeDescriptor::Algebra {
                    kind,
                    count: *count,
                },
                limits(),
                512 << 20,
            ),
        }
    }
    fn key(&self, source: [u8; 32]) -> [u8; 32] {
        match &self.descriptor {
            Descriptor::Native(d) => cache::key(source, 0, d, limits(), 512 << 20),
            Descriptor::Statement(setup_seed) => cache::key(
                source,
                1,
                &unchanged::OtherNativeDescriptor::Statement {
                    setup_seed: *setup_seed,
                },
                limits(),
                512 << 20,
            ),
            Descriptor::Private => cache::key(
                source,
                1,
                &unchanged::OtherNativeDescriptor::PrivateProof,
                limits(),
                512 << 20,
            ),
            Descriptor::Algebra(kind, count) => cache::key(
                source,
                1,
                &unchanged::OtherNativeDescriptor::Algebra {
                    kind,
                    count: *count,
                },
                limits(),
                512 << 20,
            ),
        }
    }
}
fn catalogue() -> Vec<Case> {
    let mut cases = Vec::with_capacity(159);
    let mut native = |name: &str, family, d| {
        cases.push(Case {
            name: name.into(),
            family,
            descriptor: Descriptor::Native(d),
        })
    };
    for (name, domain, start_counter, output_len, first, count) in [
        ("aes-single", 0, 0, 16, 0, 1),
        ("aes-sample-g64", 0, 0, 1197 * 4, 0, 64),
        ("aes-alpha-middle64", 0x4368, 0, 2572, 64, 64),
        ("aes-alpha-tail33", 0x4368, 0, 2572, 128, 33),
        ("aes-sparse-tail8", 0x4368, 161, 127, 0, 8),
        ("aes-counter-variant", 0, 1, 16, 0, 1),
    ] {
        native(
            name,
            "aes",
            NativeDescriptor::Aes {
                descriptor: aes_lane_air::Descriptor {
                    domain,
                    start_counter,
                    output_len,
                },
                first,
                count,
            },
        );
    }
    for (name, input_len, output_len, first, count) in [
        ("shake-single", 1, 32, 0, 1),
        ("shake-absorb8", 136 * 9 + 1, 32, 0, 8),
        ("shake-padding", 136 * 2, 32, 2, 1),
        ("shake-squeeze8", 1, 136 * 10, 1, 8),
    ] {
        native(
            name,
            "shake",
            NativeDescriptor::Shake {
                descriptor: shake_air::Descriptor {
                    input_len,
                    output_len,
                },
                first,
                count,
            },
        );
    }
    native(
        "transcript-bytes",
        "transcript",
        NativeDescriptor::Transcript(&[PartKind::Bytes32]),
    );
    native(
        "transcript-mixed",
        "transcript",
        NativeDescriptor::Transcript(&[
            PartKind::Bytes32,
            PartKind::PolynomialQ,
            PartKind::PolynomialQhat,
        ]),
    );
    native(
        "sparse-alpha",
        "sparse",
        NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39),
    );
    native(
        "sparse-x",
        "sparse",
        NativeDescriptor::Sparse(sparse_air::Kind::ChallengeX44),
    );
    native(
        "uniform-g",
        "uniform",
        NativeDescriptor::Uniform(uniform_air::Kind::SampleG4),
    );
    native(
        "uniform-alpha",
        "uniform",
        NativeDescriptor::Uniform(uniform_air::Kind::ExpandAlpha2),
    );
    drop(native);
    for seed in [19, 20] {
        cases.push(Case {
            name: format!("statement-{seed}"),
            family: "statement",
            descriptor: Descriptor::Statement([seed; 32]),
        });
    }
    cases.push(Case {
        name: "private-proof".into(),
        family: "private",
        descriptor: Descriptor::Private,
    });
    let mut algebra = |name: String, family, kind, count| {
        cases.push(Case {
            name,
            family,
            descriptor: Descriptor::Algebra(kind, count),
        })
    };
    for (label, modulus) in [("q", Q), ("qhat", QHAT)] {
        for count in [1, 64] {
            algebra(
                format!("affine-{label}-{count}"),
                "affine",
                ComponentKind::Affine {
                    kind: AffineKind::Add,
                    modulus,
                },
                count,
            );
        }
        for count in [1, 32] {
            algebra(
                format!("ntt-{label}-{count}"),
                "ntt",
                ComponentKind::Ntt { modulus },
                count,
            );
            algebra(
                format!("mul-{label}-{count}"),
                "mul",
                ComponentKind::Mul { modulus },
                count,
            );
        }
    }
    for bound in [6_825_771, 1_137_628] {
        algebra(
            format!("g-bound-{bound}"),
            "g_bound",
            ComponentKind::GBound { bound },
            1,
        );
    }
    for (name, kind) in [
        ("permutation-q", PermutationKind::AutomorphismQ),
        ("permutation-x", PermutationKind::InverseChallenge),
    ] {
        algebra(
            name.into(),
            "permutation",
            ComponentKind::Permutation { kind },
            1,
        );
    }
    for (name, inputs, modulus, coefficient) in [
        ("linear-q-1", 1, Q, 1),
        ("linear-q-2", 1, Q, 2),
        ("linear-qhat-16", 16, QHAT, 1),
    ] {
        let kind = PolynomialKind::Canonical { modulus };
        let descriptor = LinearMapDescriptor::new(
            vec![kind; inputs],
            kind,
            vec![[coefficient; D]; inputs],
            [0; D],
        )
        .unwrap();
        algebra(
            name.into(),
            "linear_map",
            ComponentKind::LinearMap { descriptor },
            1,
        );
    }
    let descriptor = LinearMapDescriptor::new(
        vec![PolynomialKind::Signed { bound: 1 }],
        PolynomialKind::Signed {
            bound: i32::MAX as u32,
        },
        vec![[0; D]],
        [0; D],
    )
    .unwrap();
    algebra(
        "linear-signed".into(),
        "linear_map",
        ComponentKind::LinearMap { descriptor },
        1,
    );
    // Original 39 descriptors remain the comparable timing cohort. Qualify
    // every intermediate supported NTT/mul batch size as additional exact rows.
    drop(algebra);
    assert_eq!(cases.len(), 39);
    for (label, modulus) in [("q", Q), ("qhat", QHAT)] {
        for count in 2..32 {
            for (family, kind) in [
                ("ntt", ComponentKind::Ntt { modulus }),
                ("mul", ComponentKind::Mul { modulus }),
            ] {
                cases.push(Case {
                    name: format!("{family}-{label}-{count}"),
                    family,
                    descriptor: Descriptor::Algebra(kind, count),
                });
            }
        }
    }
    assert_eq!(cases.len(), 159);
    cases
}
fn values(bound: NativeCoreBound) -> [usize; 8] {
    let c = bound.counts;
    [
        c.quotient_chunks,
        c.operations.scalar,
        c.operations.cubic,
        c.operations.poseidon,
        c.wires,
        c.input_values,
        c.selection_hint_words,
        c.planner_requested_program_bytes_peak,
    ]
}
#[test]
#[ignore = "metadata-only CPU profiling; serialized native metadata guard required"]
fn native_metadata_profile() {
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("cpu-required")
    );
    let start = Instant::now();
    let source = crate::graph_proofs::compiled_source_fingerprint();
    let fingerprint_cold_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    assert_eq!(source, crate::graph_proofs::compiled_source_fingerprint());
    let fingerprint_warm_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let cases = catalogue();
    let catalogue_ns = start.elapsed().as_nanos();
    let cache = cache::Scope::begin(source).unwrap();
    let mut keys = HashSet::new();
    let mut total_cold_ns = 0;
    let mut total_warm_ns = 0;
    let mut peak = 0;
    let mut expected = [None; 256];
    for (index, case) in cases.iter().enumerate() {
        let key = case.key(source);
        assert!(keys.insert(key), "duplicate profile descriptor");
        let scope = Scope::begin().unwrap();
        let start = Instant::now();
        let cold = case
            .bound()
            .unwrap_or_else(|e| panic!("{}: {e:?}", case.name));
        let cold_ns = start.elapsed().as_nanos();
        let cold_phases = scope.statistics();
        let lowering_phases = scope.lowering();
        expected[index] = Some(cold);
        drop(scope);
        assert_eq!(cache.statistics().misses, index as u64 + 1);
        let scope = Scope::begin().unwrap();
        let start = Instant::now();
        for _ in 0..8 {
            assert_eq!(cold, case.bound().unwrap());
        }
        let warm_total_ns = start.elapsed().as_nanos();
        let warm_phases = scope.statistics();
        drop(scope);
        total_cold_ns += cold_ns;
        total_warm_ns += warm_total_ns;
        peak = peak.max(cold.storage.total_requested_bytes);
        let g = cold.storage.geometry;
        eprintln!(
            "\nNATIVE_METADATA_PROFILE_ROW {}",
            serde_json::json!({
            "name":case.name,"family":case.family,"key":key,"descriptor_key":case.descriptor().key(),"values":values(cold),
            "geometry":[g.width,g.height,g.public_values,g.periodic_columns,g.maximum_period],
            "cold_ns":cold_ns,"warm_total_ns":warm_total_ns,"warm_calls":8,
            "cold_phases":cold_phases,"warm_phases":warm_phases,"lowering_phases":lowering_phases,
            "original_host_bytes":cold.storage.total_requested_bytes,"counts_equal":true})
        );
    }
    assert_eq!(cache.statistics().hits, cases.len() as u64 * 8);
    assert_eq!(cache.statistics().failed_computations, 0);
    eprintln!(
        "NATIVE_METADATA_PROFILE {}",
        serde_json::json!({
        "scope":"native descriptor metadata only; no transactions or proofs", "cases":cases.len(),
        "fingerprint_cold_ns":fingerprint_cold_ns,"fingerprint_warm_ns":fingerprint_warm_ns,
        "catalogue_ns":catalogue_ns,"cold_ns":total_cold_ns,"warm_total_ns":total_warm_ns,
        "original_host_bytes_peak":peak,"cache":cache.statistics(),"gpu_used":false})
    );
    drop(cache);
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
        MetadataCpuOptions, MetadataPlanningScope,
    };
    use native_shape::{cohort, precomputed};
    for case_count in [39, cases.len()] {
        for workers in [1, 2, 4, 8, 16] {
            let _planner =
                MetadataPlanningScope::begin(MetadataCpuOptions::workers(workers).unwrap())
                    .unwrap();
            let cache = cache::Scope::begin(source).unwrap();
            let start = Instant::now();
            for (group, cases) in cases[..case_count].chunks(cohort::MAX).enumerate() {
                let mut descriptors =
                    [cohort::Descriptor::Other(unchanged::OtherNativeDescriptor::PrivateProof);
                        cohort::MAX];
                for (d, case) in descriptors.iter_mut().zip(cases) {
                    *d = case.descriptor();
                }
                let result =
                    cohort::bounds(&descriptors[..cases.len()], limits(), 512 << 20).unwrap();
                for (i, bound) in result[..cases.len()].iter().enumerate() {
                    assert_eq!(
                        bound.map(|mut b| {
                            b.counts.planner_requested_program_bytes_peak = 0;
                            b
                        }),
                        expected[group * cohort::MAX + i].map(|mut b| {
                            b.counts.planner_requested_program_bytes_peak = 0;
                            b
                        }),
                        "{} workers={workers}",
                        cases[i].name
                    );
                }
            }
            let elapsed = start.elapsed().as_nanos();
            let s = cache.statistics();
            assert!(s.peak_workers <= workers && s.admitted_host_bytes_peak <= peak);
            assert_eq!(s.entries, case_count);
            if case_count == 39 {
                assert_eq!(s.periodic_preparations, 1);
            }
            eprintln!(
                "{} {}",
                if case_count == 39 {
                    "NATIVE_METADATA_COHORT"
                } else {
                    "NATIVE_METADATA_QUEUE"
                },
                serde_json::json!({"workers":workers,"cases":case_count,
            "elapsed_ns":elapsed,"counts_equal":true,"original_host_bytes_peak":peak,"cache":s,"gpu_used":false})
            );
        }
    }
    eprintln!(
        "NATIVE_METADATA_TABLE_IDENTITY {}",
        serde_json::json!({
        "source":crate::graph_proofs::native_numeric_source_fingerprint(),
        "profile":lattica_prover_p3::block_v2::profile::CANDIDATE_PROFILE_ID,
        "available":precomputed::available()})
    );
    if precomputed::available() {
        let cache = cache::Scope::begin_with_precomputed(source).unwrap();
        let phases = Scope::begin().unwrap();
        let start = Instant::now();
        for (i, case) in cases.iter().enumerate() {
            assert_eq!(Some(case.bound().unwrap()), expected[i]);
        }
        let elapsed = start.elapsed().as_nanos();
        let s = phases.statistics();
        assert_eq!(
            (
                s.periodic_ns,
                s.symbolic_ns,
                s.lowering_ns,
                s.finalization_ns
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(cache.statistics().table_hits, cases.len() as u64);
        eprintln!(
            "NATIVE_METADATA_TABLE_QUALIFICATION {}",
            serde_json::json!({"elapsed_ns":elapsed,
            "cases":cases.len(),"counts_equal":true,"cache":cache.statistics(),"phases":s,"gpu_used":false})
        );
    }
}
