//! Disconnected public-sponge component probe. The coordinator owns its
//! all(test,gpu,gpu-tuning) hook, build, execution guard and terminal audit.
use super::*;
use ocl::{
    enums::{KernelWorkGroupInfo, KernelWorkGroupInfoResult, ProfilingInfo, ProfilingInfoResult},
    Buffer, Event, Kernel, ProQue,
};
use sha3::Digest as _;
use std::time::Instant;

const SOURCE: &str = include_str!("serial_lane_probe.cl");
const DOMAIN: u64 = 0x4c42563210;
const FIELDS: usize = (1 << 20) + 1;
const MULTIPLIER: u64 = 0x9e3779b97f4a7c15;
const CONSTANT_BYTES: u64 = (32 + 22 + 32 + 8) * 8;
const INPUT_SHA3: [u8; 32] = [
    220, 86, 204, 190, 166, 245, 83, 12, 195, 90, 64, 148, 141, 205, 73, 55, 19, 209, 221, 96, 68,
    98, 85, 13, 194, 205, 179, 21, 138, 172, 169, 253,
];
const CPU_REFERENCE: [u64; 4] = [
    9794416103781300712,
    4756606832771721594,
    5307240493000710151,
    11963553263942151644,
];
const INPUT_ENCODING: &str = "lattica-redux-sum-input-v1/domain-u64le/length-u64le/fields-u64le";

fn fixture(length: usize) -> Vec<u64> {
    assert!(length <= FIELDS);
    (0..length)
        .map(|i| (i as u64).wrapping_mul(MULTIPLIER) % GOLDILOCKS_MODULUS)
        .collect()
}

fn workload_digest(fields: &[u64]) -> [u8; 32] {
    let mut hash = sha3::Sha3_256::new();
    hash.update(b"lattica-redux-sum-input-v1");
    hash.update(DOMAIN.to_le_bytes());
    hash.update(u64::try_from(fields.len()).unwrap().to_le_bytes());
    for field in fields {
        hash.update(field.to_le_bytes());
    }
    hash.finalize().into()
}

fn source_digest(source: &str) -> [u8; 32] {
    sha3::Sha3_256::digest(source.as_bytes()).into()
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    Cooperative,
    SboxPair,
    ExistingSerial,
    NamedSerial,
}
const VARIANTS: [Variant; 4] = [
    Variant::Cooperative,
    Variant::SboxPair,
    Variant::ExistingSerial,
    Variant::NamedSerial,
];
impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Cooperative => "device_public_hash_cooperative",
            Self::SboxPair => "device_public_hash_sbox_pair",
            Self::ExistingSerial => "device_public_hash",
            Self::NamedSerial => "device_public_hash_serial_lane_probe",
        }
    }
    fn lanes(self) -> usize {
        match self {
            Self::Cooperative => 8,
            Self::SboxPair => 16,
            Self::ExistingSerial | Self::NamedSerial => 1,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Cooperative => 0,
            Self::SboxPair => 1,
            Self::ExistingSerial => 2,
            Self::NamedSerial => 3,
        }
    }
    fn compiled_geometry(self) -> [usize; 3] {
        // The existing serial kernel has no reqd_work_group_size attribute.
        if matches!(self, Self::ExistingSerial) {
            [0, 0, 0]
        } else {
            [self.lanes(), 1, 1]
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Census {
    requested_global_items: usize,
    requested_local_items: usize,
    compiled_geometry: [usize; 3],
    local_bytes: u64,
    private_bytes_per_work_item: u64,
}
impl Census {
    fn inspect(pq: &ProQue, kernel: &Kernel, variant: Variant) -> Self {
        use KernelWorkGroupInfo as I;
        use KernelWorkGroupInfoResult as R;
        let info = |kind| kernel.wg_info(pq.device(), kind).unwrap();
        let R::LocalMemSize(local) = info(I::LocalMemSize) else {
            panic!("local storage unavailable")
        };
        let R::PrivateMemSize(private) = info(I::PrivateMemSize) else {
            panic!("private storage unavailable")
        };
        let R::WorkGroupSize(maximum) = info(I::WorkGroupSize) else {
            panic!("workgroup limit unavailable")
        };
        let R::CompileWorkGroupSize(geometry) = info(I::CompileWorkGroupSize) else {
            panic!("compiled geometry unavailable")
        };
        assert_eq!(geometry, variant.compiled_geometry());
        assert!(maximum >= variant.lanes());
        assert!(local <= selection::PAIR_LOCAL_BYTES);
        assert!(private <= selection::PAIR_PRIVATE_BYTES_PER_LANE);
        // No source local array does not imply a zero driver storage report.
        // All variants retain the same finite local/private ceilings, and the
        // observed local value is preserved in the census below.
        Self {
            requested_global_items: variant.lanes(),
            requested_local_items: variant.lanes(),
            compiled_geometry: geometry,
            local_bytes: local,
            private_bytes_per_work_item: private,
        }
    }
}

struct HashKernel {
    kernel: Kernel,
    census: Census,
}
impl HashKernel {
    fn new(pq: &ProQue, variant: Variant) -> Self {
        let mut builder = pq.kernel_builder(variant.name());
        builder
            .global_work_size(variant.lanes())
            .local_work_size(variant.lanes())
            .arg(None::<&Buffer<u64>>)
            .arg(None::<&Buffer<u64>>)
            .arg(0u64)
            .arg(0u64)
            .arg(0u32)
            .arg(0u32);
        for _ in 0..4 {
            builder.arg(None::<&Buffer<u64>>);
        }
        let kernel = builder.build().unwrap();
        let census = Census::inspect(pq, &kernel, variant);
        Self { kernel, census }
    }
}

struct Sample {
    digest: [u64; 4],
    device_ns: u64,
    dispatches: usize,
    uploaded_bytes: usize,
}

struct Harness {
    // Kernel arguments retain buffers. Destroy those owners before explicit
    // buffers and the program/queue. No pending work remains on a successful call.
    hashes: [HashKernel; 4],
    state: Buffer<u64>,
    scratch: Buffer<u64>,
    _constants: [Buffer<u64>; 4],
    pq: ProQue,
}
impl Harness {
    fn new() -> Self {
        assert!(cfg!(feature = "gpu-tuning"));
        let setup = Instant::now();
        let (platform, device, identity) = crate::gpu_device::select().unwrap();
        let prefix = nvidia::source_prefix(device);
        assert!(
            !prefix.is_empty(),
            "component comparison requires NVIDIA SM7+ / warp32"
        );
        assert!(identity.max_allocation_bytes >= MAX_ALLOCATION_BYTES);
        assert!(identity.global_bytes >= WORKSPACE_BYTES + CONSTANT_BYTES);
        let source = format!(
            "{}\n#define LATTICA_PUBLIC_HASH_SERIAL_LANE_PROBE 1\n{}\n{}\n{}",
            prefix,
            crate::gpu::KERNEL_SRC,
            KERNEL_SRC,
            SOURCE
        );
        let combined_source_sha3 = source_digest(&source);
        let source_bytes = source.len();
        let compile = Instant::now();
        let pq = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(source)
            .queue_properties(ocl::flags::QUEUE_PROFILING_ENABLE)
            .dims(1)
            .build()
            .unwrap();
        let program_queue_setup_ns = compile.elapsed().as_nanos();
        // Construct and inspect the exact four dispatch objects before global
        // buffers are allocated. They cannot be dispatched with these null args.
        let hashes = VARIANTS.map(|variant| HashKernel::new(&pq, variant));
        for variant in VARIANTS {
            println!(
                "\nSERIAL_LANE_KERNEL_CENSUS {}",
                serde_json::json!({
                    "kernel":variant.name(),"storage":hashes[variant.index()].census,
                    "before_global_buffer_allocation":true,
                    "local_byte_ceiling":selection::PAIR_LOCAL_BYTES,
                    "private_byte_ceiling_per_work_item":selection::PAIR_PRIVATE_BYTES_PER_LANE,
                    "physical_register_residency_measured":false,
                    "complete_driver_allocation_bound":false
                })
            );
        }
        let (rci, rcp, rcf, diagonal) = crate::gpu_constants::poseidon2_consts();
        let values = [rci, rcp, rcf, diagonal];
        assert_eq!(values.each_ref().map(|v| v.len()), [32, 22, 32, 8]);
        assert_eq!(BATCH_WORDS, 4096);
        assert_eq!(WORKSPACE_BYTES, 32800);
        assert_eq!(MAX_ALLOCATION_BYTES, 32768);
        let buffer = |length| {
            Buffer::<u64>::builder()
                .queue(pq.queue().clone())
                .len(length)
                .build()
                .unwrap()
        };
        let state = buffer(4);
        let scratch = buffer(BATCH_WORDS);
        let constants = values.each_ref().map(|values| {
            Buffer::<u64>::builder()
                .queue(pq.queue().clone())
                .len(values.len())
                .flags(ocl::flags::MEM_READ_ONLY)
                .copy_host_slice(values)
                .build()
                .unwrap()
        });
        for hash in &hashes {
            hash.kernel.set_arg(0, &state).unwrap();
            hash.kernel.set_arg(1, &scratch).unwrap();
            for (index, constant) in constants.iter().enumerate() {
                hash.kernel.set_arg(index + 6, constant).unwrap();
            }
        }
        let setup_ns = setup.elapsed().as_nanos();
        println!(
            "\nSERIAL_LANE_CONFIGURATION {}",
            serde_json::json!({
                "schema":"lattica-serial-lane-public-hash-v1",
                "device":identity,"nvidia_shuffle":true,"gpu_tuning_compiled":true,
                "prefix_sha3_256":source_digest(prefix),
                "arithmetic_source_sha3_256":source_digest(crate::gpu::KERNEL_SRC),
                "public_hash_source_sha3_256":source_digest(KERNEL_SRC),
                "probe_source_sha3_256":source_digest(SOURCE),
                "combined_source_sha3_256":combined_source_sha3,"source_bytes":source_bytes,
                "setup_ns":setup_ns,"program_queue_setup_ns":program_queue_setup_ns,
                "setup_in_timed_hashes":false,"global_workspace_bytes":WORKSPACE_BYTES,
                "constant_buffer_bytes":CONSTANT_BYTES,
                "total_global_buffer_bytes":WORKSPACE_BYTES + CONSTANT_BYTES,
                "max_allocation_bytes":MAX_ALLOCATION_BYTES,"kernel_objects":4,
                "maximum_fixture_requested_bytes":FIELDS * 8,
                "hash_host_staging_bytes":BATCH_WORDS * 8,
                "memory_peak_measured_by_probe":false,"opaque_driver_bound_established":false,
                "retained_kernels_and_constants_reused":true,"production_selector_available":false,
                "gpu_required_preprocessing_satisfied":false,"gpu_identity_receipt_minted":false,
                "complete_workflow_measurement":false
            })
        );
        Self {
            hashes,
            state,
            scratch,
            _constants: constants,
            pq,
        }
    }

    fn hash(&self, domain: u64, fields: &[u64], variant: Variant) -> Sample {
        assert!(fields.len() <= FIELDS);
        let length = validate(domain, fields).unwrap();
        let kernel = &self.hashes[variant.index()].kernel;
        kernel.set_arg(2, domain).unwrap();
        kernel.set_arg(3, length).unwrap();
        let mut device_ns = 0u64;
        let mut dispatches = 0usize;
        let mut uploaded_bytes = 0usize;
        batches(
            fields.len(),
            &mut |emit| {
                for &field in fields {
                    emit(field)?;
                }
                Ok(())
            },
            |words, first| {
                assert!(words.len() <= BATCH_WORDS);
                if !words.is_empty() {
                    self.scratch.write(words).enq().unwrap();
                    uploaded_bytes = uploaded_bytes.checked_add(words.len() * 8).unwrap();
                }
                kernel.set_arg(4, u32::from(first)).unwrap();
                kernel
                    .set_arg(5, u32::try_from(words.len()).unwrap())
                    .unwrap();
                let mut event = Event::empty();
                // SAFETY: one exact workgroup of 1/8/16 items, checked compiled
                // geometry, valid 4-word state and <=4096-word scratch; synchronous
                // completion before reuse. No uninspected or mismatched entry point.
                unsafe {
                    kernel.cmd().enew(&mut event).enq().unwrap();
                }
                self.pq.queue().finish().unwrap();
                let ProfilingInfoResult::Start(start) =
                    event.profiling_info(ProfilingInfo::Start).unwrap()
                else {
                    panic!("event start")
                };
                let ProfilingInfoResult::End(end) =
                    event.profiling_info(ProfilingInfo::End).unwrap()
                else {
                    panic!("event end")
                };
                device_ns = device_ns
                    .checked_add(end.checked_sub(start).unwrap())
                    .unwrap();
                dispatches += 1;
                Ok(())
            },
        )
        .unwrap();
        let mut digest = [0u64; 4];
        self.state.read(&mut digest[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        assert_eq!(dispatches, fields.len().div_ceil(BATCH_WORDS).max(1));
        assert_eq!(uploaded_bytes, fields.len() * 8);
        assert!(digest.iter().all(|&word| word < GOLDILOCKS_MODULUS));
        Sample {
            digest,
            device_ns,
            dispatches,
            uploaded_bytes,
        }
    }
}

#[test]
fn serial_lane_fixture_and_scalar_cpu_oracle_match_a005() {
    let fields = fixture(FIELDS);
    assert_eq!(workload_digest(&fields), INPUT_SHA3);
    let scalar =
        commitment::stream::hash_fields(DOMAIN, fields.len(), fields.iter().copied()).unwrap();
    assert_eq!(scalar, CPU_REFERENCE);
    assert_eq!(
        commitment::hash_fields(DOMAIN, &fields).unwrap(),
        CPU_REFERENCE
    );
}

#[test]
#[ignore = "disconnected component probe; coordinator must use serialized GPU resource guard"]
fn gpu_serial_lane_cpu_parity_and_alternating_timing() {
    let component_start = Instant::now();
    let harness = Harness::new();
    let correctness_start = Instant::now();
    let mut correctness_calls = 0;
    for domain in [0, DOMAIN, GOLDILOCKS_MODULUS - 1] {
        for length in [0usize, 1, 3, 4, 5, 63, 64, 65, 4095, 4096, 4097, 8195] {
            let fields: Vec<_> = (0..length)
                .map(|i| match i % 5 {
                    0 => 0,
                    1 => 1,
                    2 => GOLDILOCKS_MODULUS - 1,
                    3 => GOLDILOCKS_MODULUS - 2,
                    _ => (i as u64).wrapping_mul(MULTIPLIER) % GOLDILOCKS_MODULUS,
                })
                .collect();
            let scalar =
                commitment::stream::hash_fields(domain, length, fields.iter().copied()).unwrap();
            assert_eq!(commitment::hash_fields(domain, &fields).unwrap(), scalar);
            for variant in VARIANTS {
                assert_eq!(
                    harness.hash(domain, &fields, variant).digest,
                    scalar,
                    "domain={domain} length={length} variant={variant:?}"
                );
                correctness_calls += 1;
            }
        }
    }
    assert_eq!(correctness_calls, 144);
    let correctness_ns = correctness_start.elapsed().as_nanos();
    let input_start = Instant::now();
    let fields = fixture(FIELDS);
    let fixture_creation_ns = input_start.elapsed().as_nanos();
    let identity_start = Instant::now();
    let input_digest = workload_digest(&fields);
    let input_sha3_ns = identity_start.elapsed().as_nanos();
    assert_eq!(input_digest, INPUT_SHA3);
    let cpu_start = Instant::now();
    let expected = commitment::stream::hash_fields(DOMAIN, FIELDS, fields.iter().copied()).unwrap();
    let scalar_cpu_oracle_ns = cpu_start.elapsed().as_nanos();
    assert_eq!(expected, CPU_REFERENCE);
    assert_eq!(
        commitment::hash_fields(DOMAIN, &fields).unwrap(),
        CPU_REFERENCE
    );
    println!(
        "\nSERIAL_LANE_INPUT {}",
        serde_json::json!({
            "fixture":"a005_exact_small_synthetic","fields":FIELDS,"domain":DOMAIN,
            "input_encoding":INPUT_ENCODING,"input_sha3_256":input_digest,
            "cpu_reference_digest":expected,"scalar_cpu_oracle_ns":scalar_cpu_oracle_ns,
            "fixture_creation_ns":fixture_creation_ns,"input_sha3_ns":input_sha3_ns,
            "cpu_oracle_in_gpu_timing":false,"fixture_generation_in_gpu_timing":false,
            "captured_registration_input":false,"sponge_permutations":FIELDS.div_ceil(4),
            "fixture_requested_bytes":FIELDS * 8,"fixture_capacity_bytes":fields.capacity() * 8
        })
    );
    let mut timed_calls = 0;
    for round in 0..3 {
        let order = if round % 2 == 0 {
            VARIANTS
        } else {
            [
                Variant::NamedSerial,
                Variant::ExistingSerial,
                Variant::SboxPair,
                Variant::Cooperative,
            ]
        };
        for (position, variant) in order.into_iter().enumerate() {
            let start = Instant::now();
            let sample = harness.hash(DOMAIN, &fields, variant);
            let wall_ns = start.elapsed().as_nanos();
            assert_eq!(sample.digest, expected);
            assert!(sample.device_ns > 0 && u128::from(sample.device_ns) <= wall_ns);
            println!(
                "\nSERIAL_LANE_COMPONENT_TIMING {}",
                serde_json::json!({
                    "round":round,"position":position,"kernel":variant.name(),
                    "fields":FIELDS,"domain":DOMAIN,"input_sha3_256":input_digest,
                    "expected_digest":expected,"actual_digest":sample.digest,
                    "device_ns":sample.device_ns,"wall_ns":wall_ns,
                    "dispatches":sample.dispatches,"uploaded_bytes":sample.uploaded_bytes,
                    "downloaded_bytes":32,"sponge_permutations":FIELDS.div_ceil(4),
                    "storage":harness.hashes[variant.index()].census,
                    "includes_canonical_validation":true,"includes_transfer_and_wait":true,
                    "includes_program_queue_setup":false,"includes_fixture_generation":false,
                    "includes_cpu_oracle":false,"includes_input_sha3":false,
                    "kernels_and_constants_reused":true,"fresh_sponge_state":true,
                    "scalar_cpu_oracle_equal":true,"gpu_execution":true,
                    "production_selector_available":false,"captured_registration_input":false,
                    "gpu_required_preprocessing_satisfied":false,"gpu_identity_receipt_minted":false,
                    "fresh_proof_qualification":false,"complete_workflow_measurement":false
                })
            );
            timed_calls += 1;
        }
    }
    assert_eq!(timed_calls, 12);
    // Finish and release all retained OpenCL owners before the completion record.
    harness.pq.queue().finish().unwrap();
    drop(harness);
    let component_wall_ns = component_start.elapsed().as_nanos();
    println!(
        "\nSERIAL_LANE_VALIDATION {}",
        serde_json::json!({
            "correctness_cases_per_kernel":36,"correctness_hash_calls":correctness_calls,
            "timed_hash_calls":timed_calls,"kernels":4,"repetitions_per_kernel":3,
            "correctness_ns":correctness_ns,"component_wall_ns":component_wall_ns,
            "component_wall_excludes_final_record":true,
            "scalar_cpu_oracle_equal":true,"slice_cpu_oracle_equal":true,
            "pinned_a005_input_and_digest_equal":true,"all_queues_finished":true,
            "opencl_owners_dropped":true,"terminal_cleanup_audit_performed_by_probe":false,
            "physical_register_residency_measured":false,"actual_registration_metadata_hashed":false,
            "complete_workflow_measurement":false,"fresh_proof_qualification":false,
            "gpu_identity_receipt_minted":false,"gpu_required_preprocessing_satisfied":false,
            "native_proofs_created":0,"recursive_proofs_created":0,"transactions_created":0,
            "faithful_ringct_performance_qualified":false
        })
    );
}
