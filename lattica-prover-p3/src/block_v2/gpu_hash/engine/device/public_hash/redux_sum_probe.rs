//! Standalone, unhooked experiment. A coordinator may later add a test module
//! declaration under all(test,gpu,gpu-tuning); this file grants no selection,
//! production dispatch, or complete-workflow qualification.
use super::*;
use sha3::Digest as _;
use ocl::{
    Buffer, Event, Kernel, ProQue,
    enums::{KernelWorkGroupInfo, KernelWorkGroupInfoResult, ProfilingInfo, ProfilingInfoResult},
};

const DOMAIN: u64 = 0x4c42563210;
const SOURCE: &str = include_str!("redux_sum_probe.cl");
const CONSTANT_WORDS: usize = 32 + 22 + 32 + 8;
const CONSTANT_BYTES: u64 = CONSTANT_WORDS as u64 * 8;

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Capability {
    vendor_id: u32,
    compute_major: u32,
    compute_minor: u32,
    warp_size: u32,
}
impl Capability {
    fn from_words(
        vendor: Option<u32>, major: Option<u32>, minor: Option<u32>, warp: Option<u32>,
    ) -> Result<Self, &'static str> {
        match (vendor, major, minor, warp) {
            (Some(0x10de), Some(major), Some(minor), Some(32)) if major >= 8 => Ok(Self {
                vendor_id: 0x10de, compute_major: major, compute_minor: minor, warp_size: 32,
            }),
            _ => Err("redux probe requires reported NVIDIA SM80+ and 32-lane warps"),
        }
    }
    fn inspect(device: ocl::Device) -> Result<Self, &'static str> {
        use ocl::core::{DeviceInfo, DeviceInfoResult};
        let vendor = match device.info(DeviceInfo::VendorId) {
            Ok(DeviceInfoResult::VendorId(value)) => Some(value),
            _ => None,
        };
        let word = |parameter| {
            ocl::core::get_device_info_raw(device, parameter)
                .ok()
                .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
                .map(u32::from_ne_bytes)
        };
        // NVIDIA extension: capability major, minor, and warp size.
        Self::from_words(vendor, word(0x4000), word(0x4001), word(0x4003))
    }
}

fn workload_digest(domain: u64, fields: &[u64]) -> [u8; 32] {
    let mut hash = sha3::Sha3_256::new();
    hash.update(b"lattica-redux-sum-input-v1");
    hash.update(domain.to_le_bytes());
    hash.update(u64::try_from(fields.len()).unwrap().to_le_bytes());
    for field in fields {
        hash.update(field.to_le_bytes());
    }
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    Baseline,
    SboxPair,
    ReduxSum,
}
impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "device_public_hash_cooperative",
            Self::SboxPair => "device_public_hash_sbox_pair",
            Self::ReduxSum => "device_public_hash_redux_sum_probe",
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
            Self::ReduxSum => 2,
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
    capability: Capability,
    pq: ProQue,
}
impl Harness {
    fn new() -> Self {
        assert!(cfg!(feature = "gpu-tuning"));
        let (platform, device, _) = crate::gpu_device::select().unwrap();
        // Reject SM7/missing capability before program or global-buffer creation.
        let capability = Capability::inspect(device).unwrap();
        selection::Selection::SboxPairV1
            .require_device(device)
            .unwrap();
        let source = format!(
            "{}\n#define LATTICA_PUBLIC_HASH_NVIDIA_REDUX_PROBE 1\n{}\n{}\n{}",
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
            .kernel_builder("public_hash_redux_sum_raw_probe")
            .global_work_size(16usize)
            .local_work_size(16usize)
            .arg(None::<&Buffer<u64>>)
            .arg(None::<&Buffer<u64>>)
            .arg(0u64)
            .build()
            .unwrap();
        let raw_census = Census::inspect(&pq, &raw, 16);
        let hashes = [Variant::Baseline, Variant::SboxPair, Variant::ReduxSum]
            .map(|variant| HashKernel::new(&pq, variant));
        for (kernel, census) in [
            ("public_hash_redux_sum_raw_probe", raw_census),
            (Variant::Baseline.name(), hashes[0].census),
            (Variant::SboxPair.name(), hashes[1].census),
            (Variant::ReduxSum.name(), hashes[2].census),
        ] {
            println!(
                "\nREDUX_SUM_KERNEL_CENSUS {}",
                serde_json::json!({
                    "kernel":kernel, "storage":census,
                    "gpu_tuning_compiled":cfg!(feature="gpu-tuning"),
                    "nvidia_supported":!nvidia::source_prefix(device).is_empty(),
                    "redux_supported":true,"capability":capability,
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
            capability,
            pq,
        }
    }

    fn raw(&self, values: [u64; 8], round_constant: u64) -> u64 {
        self.scratch.write(&values[..]).enq().unwrap();
        self.raw.set_arg(2, round_constant).unwrap();
        // SAFETY: one compiled 16-lane group with complete disjoint redux masks;
        // input[0..8] and six output ranges[8..104] fit the 4096-word buffer.
        unsafe {
            self.raw.cmd().enq().unwrap();
        }
        let mut output = [0u64; 104];
        self.scratch.read(&mut output[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        let modulus = u128::from(GOLDILOCKS_MODULUS);
        let initial = values.map(|v| u128::from(v) % modulus);
        let sum = initial.iter().sum::<u128>() % modulus;
        let linear: [u128; 8] = std::array::from_fn(|lane| {
            (initial[lane] * u128::from(self.diagonal[lane]) + sum) % modulus
        });
        let mut chained = initial;
        for _ in 0..22 {
            let input = (chained[0] + u128::from(round_constant)) % modulus;
            chained[0] = (0..7).fold(1u128, |product, _| product * input % modulus);
            let sum = chained.iter().sum::<u128>() % modulus;
            chained = std::array::from_fn(|lane| {
                (chained[lane] * u128::from(self.diagonal[lane]) + sum) % modulus
            });
        }
        let mut raw_differences = 0;
        for lane in 0..8 {
            // A changed representative is permitted between candidate and
            // reference, but exact pair equality is required within each path.
            for base in [8, 24, 40, 56, 72, 88] {
                assert_eq!(output[base + 2 * lane], output[base + 2 * lane + 1]);
            }
            for role in 0..2 {
                let physical = 2 * lane + role;
                for (candidate_base, baseline_base, expected) in [
                    (8, 24, sum), (40, 56, linear[lane]), (72, 88, chained[lane]),
                ] {
                    let candidate = output[candidate_base + physical];
                    let baseline = output[baseline_base + physical];
                    assert_eq!(u128::from(candidate) % modulus, expected);
                    assert_eq!(u128::from(baseline) % modulus, expected);
                    raw_differences += u64::from(candidate != baseline);
                }
            }
        }
        raw_differences
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
fn redux_eligibility_requires_complete_sm80_capabilities() {
    for major in [8, 9, 12] {
        assert!(Capability::from_words(Some(0x10de), Some(major), Some(0), Some(32)).is_ok());
    }
    for (vendor, major, minor, warp) in [
        (None, Some(8), Some(0), Some(32)),
        (Some(0x1002), Some(8), Some(0), Some(32)),
        (Some(0x10de), None, Some(0), Some(32)),
        (Some(0x10de), Some(7), Some(9), Some(32)),
        (Some(0x10de), Some(8), None, Some(32)),
        (Some(0x10de), Some(8), Some(0), None),
        (Some(0x10de), Some(8), Some(0), Some(64)),
    ] {
        assert!(Capability::from_words(vendor, major, minor, warp).is_err());
    }
}

#[test]
#[ignore = "unhooked SM80 redux probe; coordinator must authorize serialized GPU guard"]
fn gpu_redux_sum_raw_canonical_parity_and_timing() {
    let harness = Harness::new();
    let edge = [
        0, 1, GOLDILOCKS_MODULUS - 2, GOLDILOCKS_MODULUS - 1,
        GOLDILOCKS_MODULUS, GOLDILOCKS_MODULUS + 1, 1 << 63, u64::MAX,
    ];
    let constants = [0, 1, GOLDILOCKS_MODULUS - 1, u64::MAX];
    let mut raw_cases = 0u64;
    let mut raw_differences = 0u64;
    let mut check = |values, rc| {
        raw_differences += harness.raw(values, rc);
        raw_cases += 1;
    };
    // Uniform maximum inputs exercise every limb total and the top carry of 7.
    for value in edge {
        for rc in constants {
            check([value; 8], rc);
        }
    }
    for shift in 0..8 {
        let values = std::array::from_fn(|lane| edge[(lane + shift) % 8]);
        for rc in constants {
            check(values, rc);
        }
    }
    let limbs = [
        0u64, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffd, 0xfffffffe, 0xffffffff,
    ];
    for high in limbs {
        let values = limbs.map(|low| (high << 32) | low);
        for rc in constants {
            check(values, rc);
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
            check(values, rc);
        }
    }
    assert_eq!(raw_cases, 608);
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
            for variant in [Variant::Baseline, Variant::SboxPair, Variant::ReduxSum] {
                assert_eq!(
                    harness.hash(domain, &fields, variant).digest,
                    expected,
                    "domain={domain} length={length} variant={variant:?}"
                );
            }
        }
    }
    println!(
        "\nREDUX_SUM_COMPONENT_VALIDATION {}",
        serde_json::json!({
            "raw_cases":raw_cases,"compared_raw_words":raw_cases * 48,
            "different_raw_words":raw_differences,"raw_field_equivalent":true,
            "exact_pair_representatives_equal":true,"chained_partial_rounds":22,
            "complete_sponge_cases_per_kernel":36,"cpu_oracle_equal":true,
            "standalone_probe":true,"complete_workflow_measurement":false
        })
    );
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(DOMAIN, &fields).unwrap();
    let input_digest = workload_digest(DOMAIN, &fields);
    for round in 0..3 {
        let variants = if round % 2 == 0 {
            [Variant::Baseline, Variant::SboxPair, Variant::ReduxSum]
        } else {
            [Variant::ReduxSum, Variant::SboxPair, Variant::Baseline]
        };
        for variant in variants {
            let start = std::time::Instant::now();
            let sample = harness.hash(DOMAIN, &fields, variant);
            let wall_ns = start.elapsed().as_nanos();
            assert_eq!(sample.digest, expected);
            assert!(sample.device_ns > 0 && u128::from(sample.device_ns) <= wall_ns);
            println!(
                "\nREDUX_SUM_COMPONENT_TIMING {}",
                serde_json::json!({
                    "round":round,"kernel":variant.name(),"fields":fields.len(),"domain":DOMAIN,
                    "input_sha3_256":input_digest,"expected_digest":expected,"actual_digest":sample.digest,
                    "input_encoding":"lattica-redux-sum-input-v1/domain-u64le/length-u64le/fields-u64le",
                    "device_ns":sample.device_ns,"wall_ns":wall_ns,"cpu_oracle_equal":true,
                    "raw_sum_oracle_equal":true,"raw_internal_oracle_equal":true,
                    "chained_partial_round_oracle_equal":true,"exact_pair_representatives_equal":true,
                    "gpu_tuning_compiled":cfg!(feature="gpu-tuning"),
                    "nvidia_supported":!nvidia::source_prefix(harness.pq.device()).is_empty(),
                    "redux_supported":true,"capability":harness.capability,
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
