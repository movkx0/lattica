//! Compare the selected NVIDIA kernel with the portable kernel and CPU protocol.
use super::*;
use ocl::{
    enums::{ProfilingInfo, ProfilingInfoResult},
    Buffer, Event, ProQue,
};

pub(super) struct HashKernel {
    pub(super) pq: ProQue,
    state: Buffer<u64>,
    input: Buffer<u64>,
    constants: Vec<Buffer<u64>>,
}
impl HashKernel {
    pub(super) fn new(candidate: bool) -> Self {
        Self::build(candidate, KERNEL_SRC)
    }
    pub(super) fn for_kernels(kernels: &str) -> Self {
        Self::build(true, kernels)
    }
    fn build(candidate: bool, kernels: &str) -> Self {
        let (platform, device, identity) = crate::gpu_device::select().unwrap();
        assert!(identity.name.contains("NVIDIA"));
        let prefix = nvidia::source_prefix(device);
        assert!(
            !prefix.is_empty(),
            "requires NVIDIA SM >= 7 and 32-lane warps"
        );
        let source = format!(
            "{}\n{}\n{kernels}",
            if candidate { prefix } else { "" },
            crate::gpu::KERNEL_SRC
        );
        let pq = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(source)
            .queue_properties(ocl::flags::QUEUE_PROFILING_ENABLE)
            .dims(1)
            .build()
            .unwrap();
        let buffer = |len| {
            Buffer::<u64>::builder()
                .queue(pq.queue().clone())
                .len(len)
                .build()
                .unwrap()
        };
        let state = buffer(4);
        let input = buffer(BATCH_WORDS);
        let (rci, rcp, rcf, diag) = crate::gpu_constants::poseidon2_consts();
        assert_eq!(
            diag,
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
        let constants = [rci, rcp, rcf, diag]
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
    pub(super) fn hash(&self, fields: &[u64], cooperative: bool) -> ([u64; 4], u64, u64) {
        let name = if cooperative {
            "device_public_hash_cooperative"
        } else {
            "device_public_hash"
        };
        let lanes = if cooperative { 8 } else { 1 };
        let mut builder = self.pq.kernel_builder(name);
        builder
            .global_work_size(lanes)
            .local_work_size(lanes)
            .arg(&self.state)
            .arg(&self.input)
            .arg(0x4c42563210u64)
            .arg(fields.len() as u64)
            .arg(0u32)
            .arg(0u32);
        for constant in &self.constants {
            builder.arg(constant);
        }
        let kernel = builder.build().unwrap();
        let ocl::enums::KernelWorkGroupInfoResult::LocalMemSize(local_bytes) = kernel
            .wg_info(
                self.pq.queue().device(),
                ocl::enums::KernelWorkGroupInfo::LocalMemSize,
            )
            .unwrap()
        else {
            panic!("missing local memory")
        };
        // The driver includes implementation storage: on RTX 5080 the portable
        // scalar/cooperative kernels report 1/72 bytes for 0/64 source bytes.
        let ocl::core::DeviceInfoResult::LocalMemSize(local_limit) = self
            .pq
            .queue()
            .device()
            .info(ocl::core::DeviceInfo::LocalMemSize)
            .unwrap()
        else {
            panic!("missing device local memory")
        };
        assert!(local_bytes <= local_limit);
        let mut total = 0;
        for (i, chunk) in fields.chunks(BATCH_WORDS).enumerate() {
            self.input.write(chunk).enq().unwrap();
            kernel.set_arg(4, u32::from(i == 0)).unwrap();
            kernel.set_arg(5, chunk.len() as u32).unwrap();
            let mut event = Event::empty();
            // SAFETY: identical production launch geometry, constants, fixed scratch,
            // and count <=4096; this in-order queue finishes each chunk before reuse.
            unsafe {
                kernel.cmd().enew(&mut event).enq().unwrap();
            }
            self.pq.queue().finish().unwrap();
            let ProfilingInfoResult::Start(start) =
                event.profiling_info(ProfilingInfo::Start).unwrap()
            else {
                panic!("start")
            };
            let ProfilingInfoResult::End(end) = event.profiling_info(ProfilingInfo::End).unwrap()
            else {
                panic!("end")
            };
            total += end.checked_sub(start).unwrap();
        }
        let mut output = [0u64; 4];
        self.state.read(&mut output[..]).enq().unwrap();
        (output, total, local_bytes)
    }
}

#[test]
#[ignore = "NVIDIA OpenCL GPU; serial <=3 GiB zero-swap service"]
fn gpu_shuffle_matches_cpu_and_portable_hash_timing() {
    let baseline = HashKernel::new(false);
    let candidate = HashKernel::new(true);
    for length in [1usize, 3, 4, 5, 63, 64, 65, 4095, 4096, 4097, 4161] {
        let fields: Vec<_> = (0..length)
            .map(|i| [0, 1, GOLDILOCKS_MODULUS - 2, GOLDILOCKS_MODULUS - 1][i % 4])
            .collect();
        let expected = commitment::hash_fields(0x4c42563210, &fields).unwrap();
        for implementation in [&baseline, &candidate] {
            for cooperative in [false, true] {
                assert_eq!(implementation.hash(&fields, cooperative).0, expected);
            }
        }
    }
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(0x4c42563210, &fields).unwrap();
    for round in 0..3 {
        for is_candidate in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let implementation = if is_candidate { &candidate } else { &baseline };
            for cooperative in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = std::time::Instant::now();
                let (digest, device_ns, local_bytes) = implementation.hash(&fields, cooperative);
                let wall_ns = start.elapsed().as_nanos();
                assert_eq!(digest, expected);
                assert!(device_ns > 0 && device_ns as u128 <= wall_ns);
                println!(
                    "shuffle_hash_comparison {}",
                    serde_json::json!({
                    "round":round,"candidate":is_candidate,"cooperative":cooperative,
                    "fields":fields.len(),"device_ns":device_ns,"wall_ns":wall_ns,
                    "cpu_oracle_equal":true,"global_workspace_bytes":WORKSPACE_BYTES,
                    "source_local_bytes":if cooperative {64} else {0},
                    "driver_local_bytes":local_bytes})
                );
            }
        }
    }
}
