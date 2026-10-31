//! One compiled program, one fixed scratch allocation, exact CPU comparison.
//! These tests are ignored: the coordinator owns the serialized GPU guard.
use super::*;
use ocl::{
    Buffer, Event, Kernel, ProQue,
    enums::{ProfilingInfo, ProfilingInfoResult},
};

const DOMAIN: u64 = 0x4c42563210;
const PROBE: &str = r#"
__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void public_hash_pair_probe(__global ulong *scratch) {
    uint physical = get_local_id(0);
    ulong value = scratch[physical >> 1];
    // Read and write ranges do not overlap. Both roles expose their raw
    // representatives so canonicalization cannot hide a pair disagreement.
    scratch[8u + physical] = public_hash_pair_pow7(value, physical);
    scratch[24u + physical] = gl_pow7(value);
}
"#;

struct Harness {
    pq: ProQue,
    state: Buffer<u64>,
    input: Buffer<u64>,
    constants: Vec<Buffer<u64>>,
}

impl Harness {
    fn new() -> Self {
        let (platform, device, _) = crate::gpu_device::select().unwrap();
        selection::Selection::SboxPairV1
            .require_device(device)
            .unwrap();
        let source = format!(
            "{}\n{}\n{}\n{}",
            nvidia::source_prefix(device),
            crate::gpu::KERNEL_SRC,
            KERNEL_SRC,
            PROBE
        );
        let pq = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(source)
            .queue_properties(ocl::flags::QUEUE_PROFILING_ENABLE)
            .dims(1)
            .build()
            .unwrap();
        let buffer = |length| {
            Buffer::<u64>::builder()
                .queue(pq.queue().clone())
                .len(length)
                .build()
                .unwrap()
        };
        let state = buffer(4);
        let input = buffer(BATCH_WORDS);
        let (rci, rcp, rcf, diagonal) = crate::gpu_constants::poseidon2_consts();
        let constants = [rci, rcp, rcf, diagonal]
            .iter()
            .map(|values| {
                Buffer::<u64>::builder()
                    .queue(pq.queue().clone())
                    .len(values.len())
                    .flags(ocl::flags::MEM_READ_ONLY)
                    .copy_host_slice(values)
                    .build()
                    .unwrap()
            })
            .collect();
        Self {
            pq,
            state,
            input,
            constants,
        }
    }

    fn kernel(&self, name: &str, lanes: usize, domain: u64, length: usize) -> Kernel {
        let mut builder = self.pq.kernel_builder(name);
        builder
            .global_work_size(lanes)
            .local_work_size(lanes)
            .arg(&self.state)
            .arg(&self.input)
            .arg(domain)
            .arg(length as u64)
            .arg(0u32)
            .arg(0u32);
        for constant in &self.constants {
            builder.arg(constant);
        }
        builder.build().unwrap()
    }

    fn hash(
        &self,
        domain: u64,
        fields: &[u64],
        paired: bool,
    ) -> ([u64; 4], u64, u64, u64, report::PublicHashExecution) {
        validate(domain, fields).unwrap();
        let (name, lanes) = if paired {
            ("device_public_hash_sbox_pair", selection::PAIR_LANES)
        } else {
            ("device_public_hash_cooperative", HASH_LANES)
        };
        let kernel = self.kernel(name, lanes, domain, fields.len());
        let execution = report::PublicHashExecution::validated_kernel(
            name,
            !nvidia::source_prefix(self.pq.device()).is_empty(),
        )
        .unwrap();
        let (local, private) = if paired {
            selection::inspect_kernel(&kernel, self.pq.device()).unwrap()
        } else {
            use ocl::enums::{KernelWorkGroupInfo as Info, KernelWorkGroupInfoResult as Result};
            let Result::LocalMemSize(local) = kernel
                .wg_info(self.pq.device(), Info::LocalMemSize)
                .unwrap()
            else {
                panic!("missing baseline local memory");
            };
            let Result::PrivateMemSize(private) = kernel
                .wg_info(self.pq.device(), Info::PrivateMemSize)
                .unwrap()
            else {
                panic!("missing baseline private memory");
            };
            (local, private)
        };
        let mut total = 0u64;
        // Use production batching, including its mandatory empty-input launch.
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
                    self.input.write(words).enq().unwrap();
                }
                kernel.set_arg(4, u32::from(first)).unwrap();
                kernel.set_arg(5, words.len() as u32).unwrap();
                let mut event = Event::empty();
                // SAFETY: one exact-size workgroup; fixed four-word state and
                // <=4096 input words; all exchanges have uniform membership.
                unsafe {
                    kernel.cmd().enew(&mut event).enq().unwrap();
                }
                self.pq.queue().finish().unwrap();
                let ProfilingInfoResult::Start(start) =
                    event.profiling_info(ProfilingInfo::Start).unwrap()
                else {
                    panic!("missing event start");
                };
                let ProfilingInfoResult::End(end) =
                    event.profiling_info(ProfilingInfo::End).unwrap()
                else {
                    panic!("missing event end");
                };
                total = total.checked_add(end.checked_sub(start).unwrap()).unwrap();
                Ok(())
            },
        )
        .unwrap();
        let mut digest = [0u64; 4];
        self.state.read(&mut digest[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        (digest, total, local, private, execution)
    }

    fn sbox_probe(&self, values: [u64; 8]) {
        self.input.write(&values[..]).enq().unwrap();
        let kernel = self
            .pq
            .kernel_builder("public_hash_pair_probe")
            .global_work_size(16usize)
            .local_work_size(16usize)
            .arg(&self.input)
            .build()
            .unwrap();
        selection::inspect_kernel(&kernel, self.pq.device()).unwrap();
        // SAFETY: input[0..8], pair[8..24], baseline[24..40] are disjoint
        // ranges within the existing 4096-word scratch. All 16 lanes exchange.
        unsafe {
            kernel.cmd().enq().unwrap();
        }
        let mut output = [0u64; 40];
        self.input.read(&mut output[..]).enq().unwrap();
        self.pq.queue().finish().unwrap();
        for (logical, &value) in values.iter().enumerate() {
            let expected = (0..7).fold(1u128, |product, _| {
                product * u128::from(value) % u128::from(GOLDILOCKS_MODULUS)
            }) as u64;
            assert_eq!(output[8 + 2 * logical], output[9 + 2 * logical]);
            for role in 0..2 {
                let paired = output[8 + 2 * logical + role];
                let baseline = output[24 + 2 * logical + role];
                assert_eq!(paired, baseline, "raw representative for {value:#x}");
                assert_eq!(paired % GOLDILOCKS_MODULUS, expected);
            }
        }
    }
}

#[test]
#[ignore = "NVIDIA SM7+ OpenCL GPU; coordinator serialized zero-swap guard"]
fn gpu_sbox_pair_matches_cpu_baseline_and_timing() {
    let harness = Harness::new();
    harness.sbox_probe([
        0,
        1,
        GOLDILOCKS_MODULUS - 2,
        GOLDILOCKS_MODULUS - 1,
        GOLDILOCKS_MODULUS,
        GOLDILOCKS_MODULUS + 1,
        1u64 << 63,
        u64::MAX,
    ]);
    let mut random = 0x51b04a7d918e378du64;
    for _ in 0..32 {
        let words = std::array::from_fn(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        });
        harness.sbox_probe(words);
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
            for paired in [false, true] {
                assert_eq!(
                    harness.hash(domain, &fields, paired).0,
                    expected,
                    "domain={domain} length={length} paired={paired}"
                );
            }
        }
    }
    for paired in [false, true] {
        assert_ne!(
            harness.hash(7, &[1], paired).0,
            harness.hash(7, &[1, 0], paired).0
        );
        assert_ne!(
            harness.hash(7, &[1], paired).0,
            harness.hash(8, &[1], paired).0
        );
    }
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(DOMAIN, &fields).unwrap();
    let mut candidate_execution = None;
    for round in 0..3 {
        for paired in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let start = std::time::Instant::now();
            let (digest, device_ns, local, private, execution) =
                harness.hash(DOMAIN, &fields, paired);
            let wall_ns = start.elapsed().as_nanos();
            assert_eq!(digest, expected);
            assert!(device_ns > 0 && u128::from(device_ns) <= wall_ns);
            if paired {
                candidate_execution = Some(execution);
            }
            println!(
                "PUBLIC_HASH_COMPONENT_TIMING {}",
                serde_json::json!({
                    "public_hash_execution":execution,
                    "round":round,"selection":if paired {"sbox-pair-v1"} else {"baseline"},
                    "gpu_tuning":cfg!(feature="gpu-tuning"),"fields":fields.len(),
                    "device_ns":device_ns,"wall_ns":wall_ns,"cpu_oracle_equal":true,
                    "global_workspace_bytes":WORKSPACE_BYTES,"max_allocation_bytes":MAX_ALLOCATION_BYTES,
                    "physical_lanes":if paired {16} else {8},"driver_local_bytes":local,
                    "driver_private_bytes_per_lane":private,"shared_program":true,
                    "baseline_batch_kernel_reuse":true,"complete_workflow_measurement":false
                })
            );
        }
    }
    // The guard's selected-execution evidence names only the explicit
    // candidate tested here. Baseline comparison rows use the separate prefix.
    println!(
        "PUBLIC_HASH_EXECUTION {}",
        serde_json::to_string(&candidate_execution.unwrap()).unwrap()
    );
}

#[test]
#[ignore = "NVIDIA SM7+ OpenCL GPU; coordinator serialized zero-swap guard"]
fn gpu_sbox_pair_stream_receipts_and_cleanup() {
    let _shutdown = super::super::super::TestShutdownGuard;
    super::tests::initialize();
    let session = DeviceSession::new().unwrap();
    assert_eq!(
        crate::block_v2::gpu_hash::engine::public_hash_execution().unwrap(),
        None
    );
    let live = super::tests::live(&session);
    let fields = vec![GOLDILOCKS_MODULUS - 1; BATCH_WORDS + 3];
    let before = session.stats();
    let mut completed = 0;
    let mut device_ns = 0;
    assert!(
        session
            .hash_public_stream_selected(
                7,
                |emit| {
                    for &field in &fields {
                        emit(field)?;
                    }
                    Ok(())
                },
                |ns| {
                    completed += 1;
                    device_ns += ns;
                    Err("reject after first completed candidate batch".into())
                },
                true,
                selection::Selection::SboxPairV1
            )
            .is_err()
    );
    let failed = session.stats();
    assert_eq!(completed, 1);
    assert!(device_ns > 0);
    assert_eq!(failed.public_hash_batches - before.public_hash_batches, 1);
    assert_eq!(
        failed.public_hash_device_ns - before.public_hash_device_ns,
        device_ns
    );
    assert_eq!(failed.public_hash_calls, before.public_hash_calls);
    assert_eq!(failed.downloaded_bytes, before.downloaded_bytes);
    assert_eq!(super::tests::live(&session), live);
    // The interrupted proof still completed one candidate batch. Observation
    // is independent of success and remains available without a live buffer.
    let observed = crate::block_v2::gpu_hash::engine::public_hash_execution()
        .unwrap()
        .unwrap();
    assert_eq!(observed.kernel(), "sbox-pair-v1");
    assert!(observed.gpu_tuning_compiled() && observed.nvidia_supported());
    for tail in [3, 5] {
        let fields = vec![tail as u64; BATCH_WORDS + tail];
        let digest = session
            .hash_public_stream_selected(
                7,
                |emit| {
                    for &field in &fields {
                        emit(field)?;
                    }
                    Ok(())
                },
                |_| Ok(()),
                true,
                selection::Selection::SboxPairV1,
            )
            .unwrap();
        assert_eq!(digest, commitment::hash_fields(7, &fields).unwrap());
        assert_eq!(super::tests::live(&session), live);
    }
    let observed = crate::block_v2::gpu_hash::engine::public_hash_execution()
        .unwrap()
        .unwrap();
    println!(
        "PUBLIC_HASH_EXECUTION {}",
        serde_json::to_string(&observed).unwrap()
    );
}
