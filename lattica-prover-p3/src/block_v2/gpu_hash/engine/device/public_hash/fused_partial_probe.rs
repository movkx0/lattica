//! Standalone, unhooked experiment. A coordinator may later add a test module
//! declaration under all(test,gpu,gpu-tuning); this file grants no selection,
//! production dispatch, or complete-workflow qualification.
use super::*;
use ocl::{
    Buffer, Event, Kernel, ProQue,
    enums::{KernelWorkGroupInfo, KernelWorkGroupInfoResult, ProfilingInfo, ProfilingInfoResult},
};

const DOMAIN: u64 = 0x4c42563210;
const SOURCE: &str = include_str!("fused_partial_probe.cl");
const CONSTANT_WORDS: usize = 32 + 22 + 32 + 8;
const CONSTANT_BYTES: u64 = CONSTANT_WORDS as u64 * 8;

#[derive(Clone, Copy, Debug)]
enum Variant {
    Baseline,
    SboxPair,
    FusedPartial,
}
impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "device_public_hash_cooperative",
            Self::SboxPair => "device_public_hash_sbox_pair",
            Self::FusedPartial => "device_public_hash_fused_partial_probe",
        }
    }
    fn lanes(self) -> usize {
        if matches!(self, Self::Baseline) {
            8
        } else {
            16
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Baseline => 0,
            Self::SboxPair => 1,
            Self::FusedPartial => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Census {
    lanes: usize,
    compiled_geometry: [usize; 3],
    local_bytes: u64,
    private_bytes_per_lane: u64,
}
impl Census {
    fn inspect(pq: &ProQue, kernel: &Kernel, lanes: usize) -> Self {
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
        assert_eq!(geometry, [lanes, 1, 1]);
        assert!(maximum >= lanes);
        assert!(local <= selection::PAIR_LOCAL_BYTES);
        assert!(private <= selection::PAIR_PRIVATE_BYTES_PER_LANE);
        Self {
            lanes,
            compiled_geometry: geometry,
            local_bytes: local,
            private_bytes_per_lane: private,
        }
    }
}

struct Sample {
    digest: [u64; 4],
    device_ns: u64,
    census: Census,
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
        let census = Census::inspect(pq, &kernel, variant.lanes());
        Self { kernel, census }
    }
}

struct Harness {
    // Kernel arguments retain OpenCL memory objects. Drop those references
    // before the explicit buffer owners and finally the program/queue.
    raw: Kernel,
    hashes: [HashKernel; 3],
    state: Buffer<u64>,
    scratch: Buffer<u64>,
    _constants: [Buffer<u64>; 4],
    diagonal: [u64; 8],
    pq: ProQue,
}
impl Harness {
    fn new() -> Self {
        assert!(cfg!(feature = "gpu-tuning"));
        let (platform, device, _) = crate::gpu_device::select().unwrap();
        selection::Selection::SboxPairV1
            .require_device(device)
            .unwrap();
        let source = format!(
            "{}\n{}\n{}\n{}",
            nvidia::source_prefix(device),
            crate::gpu::KERNEL_SRC,
            KERNEL_SRC,
            SOURCE
        );
        let pq = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(source)
            .queue_properties(ocl::flags::QUEUE_PROFILING_ENABLE)
            .dims(1)
            .build()
            .unwrap();
        // Inspect the exact kernels which will be dispatched before allocating
        // any global buffers. No kernel may be launched with these null args.
        let raw = pq
            .kernel_builder("public_hash_fused_partial_raw_probe")
            .global_work_size(16usize)
            .local_work_size(16usize)
            .arg(None::<&Buffer<u64>>)
            .arg(None::<&Buffer<u64>>)
            .arg(0u64)
            .build()
            .unwrap();
        let raw_census = Census::inspect(&pq, &raw, 16);
        let hashes = [Variant::Baseline, Variant::SboxPair, Variant::FusedPartial]
            .map(|variant| HashKernel::new(&pq, variant));
        for (kernel, census) in [
            ("public_hash_fused_partial_raw_probe", raw_census),
            (Variant::Baseline.name(), hashes[0].census),
            (Variant::SboxPair.name(), hashes[1].census),
            (Variant::FusedPartial.name(), hashes[2].census),
        ] {
            println!(
                "\nFUSED_PARTIAL_KERNEL_CENSUS {}",
                serde_json::json!({
                    "kernel":kernel, "storage":census,
                    "gpu_tuning_compiled":cfg!(feature="gpu-tuning"),
                    "nvidia_supported":!nvidia::source_prefix(device).is_empty(),
                    "global_workspace_bytes":WORKSPACE_BYTES,"max_allocation_bytes":MAX_ALLOCATION_BYTES,
                    "constant_buffer_bytes":CONSTANT_BYTES,
                    "total_global_buffer_bytes":WORKSPACE_BYTES + CONSTANT_BYTES,
                    "before_global_buffer_allocation":true,
                    "standalone_probe":true,"experimental_production_selector_available":false
                })
            );
        }
        let (rci, rcp, rcf, diagonal) = crate::gpu_constants::poseidon2_consts();
        let exact: [u64; 8] = diagonal.as_slice().try_into().unwrap();
        assert_eq!(
            exact,
            [
                GOLDILOCKS_MODULUS - 2,
                1,
                2,
                0x7fffffff80000001,
                3,
                0x7fffffff80000000,
                GOLDILOCKS_MODULUS - 3,
                GOLDILOCKS_MODULUS - 4
            ]
        );
        let constant_values = [rci, rcp, rcf, diagonal];
        assert_eq!(constant_values.each_ref().map(|v| v.len()), [32, 22, 32, 8]);
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
        let constants = constant_values.each_ref().map(|values| {
            Buffer::<u64>::builder()
                .queue(pq.queue().clone())
                .len(values.len())
                .flags(ocl::flags::MEM_READ_ONLY)
                .copy_host_slice(values)
                .build()
                .unwrap()
        });
        raw.set_arg(0, &scratch).unwrap();
        raw.set_arg(1, &constants[3]).unwrap();
        for hash in &hashes {
            hash.kernel.set_arg(0, &state).unwrap();
            hash.kernel.set_arg(1, &scratch).unwrap();
            for (index, constant) in constants.iter().enumerate() {
                hash.kernel.set_arg(index + 6, constant).unwrap();
            }
        }
        Self {
            raw,
            hashes,
            state,
            scratch,
            _constants: constants,
            diagonal: exact,
            pq,
        }
    }

    fn raw(&self, values: [u64; 8], round_constant: u64) {
        self.scratch.write(&values[..]).enq().unwrap();
        self.raw.set_arg(2, round_constant).unwrap();
        // SAFETY: one 16-lane group, uniform exchanges, input[0..8] and
        // four output ranges[8..72] disjoint inside the fixed 4096-word buffer.
        unsafe {
            self.raw.cmd().enq().unwrap();
        }
        let mut output = [0u64; 72];
        self.scratch.read(&mut output[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        let modulus = u128::from(GOLDILOCKS_MODULUS);
        let mut updated = values.map(|v| u128::from(v) % modulus);
        let input = (updated[0] + u128::from(round_constant)) % modulus;
        updated[0] = (0..7).fold(1u128, |product, _| product * input % modulus);
        let sum = updated.iter().sum::<u128>() % modulus;
        for lane in 0..8 {
            let expected = (updated[lane] * u128::from(self.diagonal[lane]) + sum) % modulus;
            let expected_neg2 = (u128::from(values[lane]) * (modulus - 2)) % modulus;
            assert_eq!(output[8 + 2 * lane], output[9 + 2 * lane]);
            for role in 0..2 {
                let physical = 2 * lane + role;
                let candidate = output[8 + physical];
                let baseline = output[24 + physical];
                assert_eq!(
                    candidate, baseline,
                    "raw partial-round lane={lane} rc={round_constant:#x}"
                );
                assert_eq!(u128::from(candidate) % modulus, expected);
                let candidate_neg2 = output[40 + physical];
                let baseline_neg2 = output[56 + physical];
                assert_eq!(
                    candidate_neg2, baseline_neg2,
                    "raw -2 product input={:#x}",
                    values[lane]
                );
                assert_eq!(u128::from(candidate_neg2) % modulus, expected_neg2);
            }
        }
    }

    fn hash(&self, domain: u64, fields: &[u64], variant: Variant) -> Sample {
        let length = validate(domain, fields).unwrap();
        let hash = &self.hashes[variant.index()];
        let kernel = &hash.kernel;
        kernel.set_arg(2, domain).unwrap();
        kernel.set_arg(3, length).unwrap();
        let mut device_ns = 0u64;
        batches(
            fields.len(),
            &mut |emit| {
                for &field in fields {
                    emit(field)?;
                }
                Ok(())
            },
            |words, first| {
                if !words.is_empty() {
                    self.scratch.write(words).enq().unwrap();
                }
                kernel.set_arg(4, u32::from(first)).unwrap();
                kernel.set_arg(5, words.len() as u32).unwrap();
                let mut event = Event::empty();
                // SAFETY: exact compiled geometry, fixed state/scratch, count<=4096.
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
                Ok(())
            },
        )
        .unwrap();
        let mut digest = [0u64; 4];
        self.state.read(&mut digest[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        Sample {
            digest,
            device_ns,
            census: hash.census,
        }
    }
}

#[test]
#[ignore = "unhooked source-only fused partial-round probe; coordinator must authorize serialized GPU guard"]
fn gpu_fused_partial_raw_canonical_parity_and_timing() {
    let harness = Harness::new();
    let edge = [
        0,
        1,
        GOLDILOCKS_MODULUS - 2,
        GOLDILOCKS_MODULUS - 1,
        GOLDILOCKS_MODULUS,
        GOLDILOCKS_MODULUS + 1,
        1 << 63,
        u64::MAX,
    ];
    let constants = [0, 1, GOLDILOCKS_MODULUS - 1, u64::MAX];
    for shift in 0..8 {
        let values = std::array::from_fn(|lane| edge[(lane + shift) % 8]);
        for rc in constants {
            harness.raw(values, rc);
        }
    }
    // Cross every selected high/low limb corner, including noncanonical words.
    let limbs = [
        0u64, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffd, 0xfffffffe, 0xffffffff,
    ];
    for high in limbs {
        let values = limbs.map(|low| (high << 32) | low);
        for rc in constants {
            harness.raw(values, rc);
        }
    }
    let mut random = 0x8a5cd789635d2dffu64;
    for _ in 0..128 {
        let values = std::array::from_fn(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        });
        for rc in constants {
            harness.raw(values, rc);
        }
    }
    for domain in [0, DOMAIN, GOLDILOCKS_MODULUS - 1] {
        for length in [0usize, 1, 3, 4, 5, 63, 64, 65, 4095, 4096, 4097, 8195] {
            let fields: Vec<_> = (0..length)
                .map(|i| match i % 5 {
                    0 => 0,
                    1 => 1,
                    2 => GOLDILOCKS_MODULUS - 1,
                    3 => GOLDILOCKS_MODULUS - 2,
                    _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS,
                })
                .collect();
            let expected = commitment::hash_fields(domain, &fields).unwrap();
            for variant in [Variant::Baseline, Variant::SboxPair, Variant::FusedPartial] {
                assert_eq!(
                    harness.hash(domain, &fields, variant).digest,
                    expected,
                    "domain={domain} length={length} variant={variant:?}"
                );
            }
        }
    }
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(DOMAIN, &fields).unwrap();
    for round in 0..3 {
        let variants = if round % 2 == 0 {
            [Variant::Baseline, Variant::SboxPair, Variant::FusedPartial]
        } else {
            [Variant::FusedPartial, Variant::SboxPair, Variant::Baseline]
        };
        for variant in variants {
            let start = std::time::Instant::now();
            let sample = harness.hash(DOMAIN, &fields, variant);
            let wall_ns = start.elapsed().as_nanos();
            assert_eq!(sample.digest, expected);
            assert!(sample.device_ns > 0 && u128::from(sample.device_ns) <= wall_ns);
            println!(
                "\nFUSED_PARTIAL_COMPONENT_TIMING {}",
                serde_json::json!({
                    "round":round,"kernel":variant.name(),"fields":fields.len(),
                    "device_ns":sample.device_ns,"wall_ns":wall_ns,"cpu_oracle_equal":true,
                    "raw_partial_round_oracle_equal":true,"raw_negative_two_oracle_equal":true,
                    "gpu_tuning_compiled":cfg!(feature="gpu-tuning"),
                    "nvidia_supported":!nvidia::source_prefix(harness.pq.device()).is_empty(),
                    "global_workspace_bytes":WORKSPACE_BYTES,"max_allocation_bytes":MAX_ALLOCATION_BYTES,
                    "constant_buffer_bytes":CONSTANT_BYTES,
                    "total_global_buffer_bytes":WORKSPACE_BYTES + CONSTANT_BYTES,
                    "storage":sample.census,"all_kernels_reused":true,
                    "standalone_probe":true,"experimental_production_selector_available":false,
                    "complete_workflow_measurement":false
                })
            );
        }
    }
}
