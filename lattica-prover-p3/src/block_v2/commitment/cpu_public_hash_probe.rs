//! Disconnected CPU-only component comparator. The coordinator owns its test
//! module hook and serial execution. No registration path, receipt, execution
//! policy, proof dispatch, or production selector is changed by this file.
use super::{stream, CommitmentError, Digest, MODULUS};
use sha3::{Digest as _, Sha3_256};
use std::{hint::black_box, time::Instant};

const DOMAIN: u64 = 0x4c42563210;
const MULTIPLIER: u64 = 0x9e3779b97f4a7c15;
const SMALL_FIELDS: usize = (1 << 20) + 1;
const REGISTRATION_FIELD_COUNT: usize = 50_764_992;
const SHA3_BATCH_BYTES: usize = 4096 * 8;
const INPUT_ENCODING: &str =
    "lattica-redux-sum-input-v1/domain-u64le/length-u64le/fields-u64le";
const ALGORITHM: &str = "existing commitment::stream::hash_fields scalar Poseidon2";
// Pinned from the frozen A005 exact test's independent slice CPU oracle and
// equal GPU kernels. They apply to the small synthetic fixture only.
const SMALL_INPUT_SHA3: [u8; 32] = [
    220, 86, 204, 190, 166, 245, 83, 12, 195, 90, 64, 148, 141, 205, 73, 55,
    19, 209, 221, 96, 68, 98, 85, 13, 194, 205, 179, 21, 138, 172, 169, 253,
];
const SMALL_REFERENCE: Digest = [
    9794416103781300712, 4756606832771721594,
    5307240493000710151, 11963553263942151644,
];

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    count: usize,
    captured_registration_input: bool,
}
const FIXTURES: [Fixture; 2] = [
    Fixture {
        name: "a005_exact_small_synthetic",
        count: SMALL_FIELDS,
        captured_registration_input: false,
    },
    Fixture {
        name: "registration_count_synthetic",
        count: REGISTRATION_FIELD_COUNT,
        captured_registration_input: false,
    },
];

/// Exact A005 recipe, including u64 wrap before Goldilocks reduction. One
/// field at a time; neither fixture allocates a payload-sized Vec.
#[derive(Clone)]
struct Fields {
    next: usize,
    end: usize,
}
impl Fields {
    fn new(count: usize) -> Self {
        Self { next: 0, end: count }
    }
}
impl Iterator for Fields {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        let index = u64::try_from(self.next).expect("fixture index fits u64");
        self.next += 1;
        Some(index.wrapping_mul(MULTIPLIER) % MODULUS)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end - self.next;
        (left, Some(left))
    }
}
impl ExactSizeIterator for Fields {}
impl std::iter::FusedIterator for Fields {}

fn input_sha3(count: usize) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica-redux-sum-input-v1");
    hash.update(DOMAIN.to_le_bytes());
    hash.update(u64::try_from(count).expect("fixture count fits u64").to_le_bytes());
    let mut batch = [0u8; SHA3_BATCH_BYTES];
    let mut filled = 0;
    for field in Fields::new(count) {
        batch[filled..filled + 8].copy_from_slice(&field.to_le_bytes());
        filled += 8;
        if filled == batch.len() {
            hash.update(&batch);
            filled = 0;
        }
    }
    hash.update(&batch[..filled]);
    hash.finalize().into()
}

fn cpu_hash(count: usize) -> Result<(Digest, u128), CommitmentError> {
    // Include iterator generation, canonical-field checks, scalar permutation
    // initialization and all sponge permutations. SHA3/input reporting and
    // JSON formatting are outside this boundary and timed separately.
    let fields = black_box(Fields::new(count));
    let start = Instant::now();
    let digest = stream::hash_fields(black_box(DOMAIN), black_box(count), fields)?;
    let elapsed = start.elapsed().as_nanos();
    Ok((black_box(digest), elapsed))
}

struct InputEvidence {
    sha3: [u8; 32],
    reference: Digest,
    identity_ns: u128,
    reference_ns: u128,
    independent_reference: bool,
}
impl InputEvidence {
    fn prepare(fixture: Fixture) -> Self {
        let start = Instant::now();
        let sha3 = input_sha3(fixture.count);
        let identity_ns = start.elapsed().as_nanos();
        let (reference, reference_ns) = cpu_hash(fixture.count).expect("canonical fixed fixture");
        let independent_reference = fixture.count == SMALL_FIELDS;
        if independent_reference {
            assert_eq!(sha3, SMALL_INPUT_SHA3, "small fixture changed from frozen A005");
            assert_eq!(reference, SMALL_REFERENCE, "small CPU/GPU oracle digest differs");
        }
        assert!(reference.iter().all(|&field| field < MODULUS));
        assert!(identity_ns > 0 && reference_ns > 0);
        Self { sha3, reference, identity_ns, reference_ns, independent_reference }
    }
}

#[test]
fn cpu_public_hash_fixture_stream_matches_slice_boundaries() {
    // Small correctness fixtures only; no large input Vec is used by the
    // ignored timing experiment below.
    for count in (0..18).chain([31, 32, 33, 135, 136, 137, 4095, 4096, 4097]) {
        let fields: Vec<_> = (0..count)
            .map(|index| (index as u64).wrapping_mul(MULTIPLIER) % MODULUS)
            .collect();
        assert_eq!(Fields::new(count).collect::<Vec<_>>(), fields);
        assert_eq!(stream::hash_fields(DOMAIN, count, Fields::new(count)),
                   super::hash_fields(DOMAIN, &fields));
        // Independent direct encoding checks the batched SHA3 helper at both
        // complete batches and nonempty final tails.
        let mut direct = Sha3_256::new();
        direct.update(b"lattica-redux-sum-input-v1");
        direct.update(DOMAIN.to_le_bytes());
        direct.update((count as u64).to_le_bytes());
        for field in fields {
            direct.update(field.to_le_bytes());
        }
        assert_eq!(input_sha3(count).as_slice(), direct.finalize().as_slice());
    }
}

#[test]
fn cpu_public_hash_fixture_geometry_and_iterator_termination_are_fixed() {
    assert_eq!(FIXTURES.map(|fixture| fixture.count), [1_048_577, 50_764_992]);
    assert_eq!(FIXTURES.map(|fixture| fixture.count.div_ceil(4)), [262_145, 12_691_248]);
    assert_eq!(FIXTURES.map(|fixture| fixture.count.div_ceil(4096)), [257, 12_394]);
    assert_eq!(FIXTURES.map(|fixture| fixture.count * 8), [8_388_616, 406_119_936]);
    assert!(FIXTURES.iter().all(|fixture| !fixture.captured_registration_input));
    let mut fields = Fields::new(2);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.next(), Some(0));
    assert_eq!(fields.next(), Some(MULTIPLIER));
    assert_eq!(fields.len(), 0);
    assert_eq!(fields.next(), None);
    assert_eq!(fields.next(), None);
}

#[test]
#[ignore = "standalone CPU component screen; coordinator serial CPU guard required"]
fn cpu_public_hash_exact_small_and_registration_count_timing() {
    println!(
        "\nCPU_PUBLIC_HASH_CONFIGURATION {}",
        serde_json::json!({
            "schema":"lattica-cpu-public-hash-component-v1",
            "algorithm":ALGORITHM,"architecture":std::env::consts::ARCH,
            "target_feature_avx2":cfg!(target_feature="avx2"),
            "target_feature_avx512f":cfg!(target_feature="avx512f"),
            "distinct_synthetic_inputs":2,"repetitions_per_input":3,
            "domain":DOMAIN,"input_encoding":INPUT_ENCODING,
            "field_formula":"((i * 0x9e3779b97f4a7c15) mod 2^64) mod 0xffffffff00000001",
            "sha3_batch_bytes":SHA3_BATCH_BYTES,
            "iterator_inline_bytes":std::mem::size_of::<Fields>(),
            "payload_vector_allocated":false,"packed_lanes":1,
            "gpu_execution":false,"gpu_required_preprocessing_satisfied":false,
            "gpu_identity_receipt_minted":false,"production_selector_available":false,
            "complete_workflow_measurement":false,"peak_memory_measured_by_probe":false
        })
    );
    let inputs = FIXTURES.map(InputEvidence::prepare);
    for (fixture, evidence) in FIXTURES.iter().zip(&inputs) {
        println!(
            "\nCPU_PUBLIC_HASH_INPUT {}",
            serde_json::json!({
                "fixture":fixture.name,"fields":fixture.count,"domain":DOMAIN,
                "canonical_encoded_field_bytes":fixture.count * 8,
                "sponge_permutations":fixture.count.div_ceil(4),
                "final_chunk_fields":if fixture.count % 4 == 0 {4} else {fixture.count % 4},
                "input_encoding":INPUT_ENCODING,"input_sha3_256":evidence.sha3,
                "captured_registration_input":fixture.captured_registration_input,
                "reference_digest":evidence.reference,
                "independent_reference_digest":evidence.independent_reference,
                "reference_basis":if evidence.independent_reference {
                    "pinned A005 independent CPU slice oracle and equal GPU digests"
                } else {
                    "first execution of same scalar stream implementation; repeat check only"
                },
                "input_sha3_ns":evidence.identity_ns,
                "reference_hash_ns":evidence.reference_ns,
                "payload_vector_allocated":false,"gpu_execution":false,
                "complete_workflow_measurement":false
            })
        );
    }
    // Reorder only the two input sizes. This is not a matched alternating
    // CPU/GPU benchmark: this process executes no GPU work at all.
    for (round, order) in [[0usize, 1], [1, 0], [0, 1]].into_iter().enumerate() {
        for index in order {
            let fixture = FIXTURES[index];
            let evidence = &inputs[index];
            let (actual, wall_ns) = cpu_hash(fixture.count).expect("canonical fixed fixture");
            assert_eq!(actual, evidence.reference);
            assert!(wall_ns > 0);
            println!(
                "\nCPU_PUBLIC_HASH_COMPONENT_TIMING {}",
                serde_json::json!({
                    "round":round,"fixture":fixture.name,"algorithm":ALGORITHM,
                    "fields":fixture.count,"domain":DOMAIN,
                    "input_encoding":INPUT_ENCODING,"input_sha3_256":evidence.sha3,
                    "sponge_permutations":fixture.count.div_ceil(4),
                    "expected_digest":evidence.reference,"actual_digest":actual,
                    "wall_ns":wall_ns,"repeat_equal":true,
                    "independent_reference_digest":evidence.independent_reference,
                    "captured_registration_input":fixture.captured_registration_input,
                    "includes_field_generation":true,
                    "includes_permutation_initialization":true,
                    "includes_canonical_validation":true,
                    "includes_input_sha3":false,"includes_json_reporting":false,
                    "prepared_state_reused":false,"gpu_execution":false,
                    "gpu_required_preprocessing_satisfied":false,
                    "gpu_identity_receipt_minted":false,"fresh_proof_qualification":false,
                    "production_selector_available":false,"complete_workflow_measurement":false
                })
            );
        }
    }
    println!(
        "\nCPU_PUBLIC_HASH_VALIDATION {}",
        serde_json::json!({
            "distinct_synthetic_inputs":2,"reference_hash_calls":2,
            "timed_hash_calls":6,"repetitions_per_input":3,
            "all_calls_completed":true,"small_a005_digest_equal":true,
            "large_repeated_digest_equal":true,"large_independent_oracle_executed":false,
            "actual_registration_metadata_hashed":false,
            "gpu_execution":false,"gpu_identity_receipt_minted":false,
            "gpu_required_preprocessing_satisfied":false,
            "fresh_proof_qualification":false,"complete_workflow_measurement":false,
            "faithful_ringct_performance_qualified":false
        })
    );
}
