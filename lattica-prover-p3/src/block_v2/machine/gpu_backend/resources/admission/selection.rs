//! Capture physical identity and every memory-affecting selection before
//! source geometry admission. Enumeration creates no OpenCL context or queue.
use super::*;
#[cfg(feature = "gpu")]
use crate::block_v2::gpu_hash::engine::device::public_hash::PublicHashSelection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExecutionSelection {
    pub device_index: usize,
    pub uuid: [u8; 16],
    pub physical_global_bytes: u64,
    pub physical_max_allocation_bytes: u64,
    pub managed_bytes: u64,
    pub context_bytes: u64,
    host_output_bytes: usize,
    #[cfg(feature = "gpu")]
    public_hash: PublicHashSelection,
    pub transform_allowance: usize,
    pub slots: usize,
    required_switches: u32,
    lde_workspace_bytes: usize,
    opening_denominator_cache: bool,
    shared_preprocessing: bool,
    worker_assignment: bool,
}

const REQUIRED: [&str; 18] = [
    "LATTICA_V2_GPU_HASH",
    "LATTICA_V2_GPU_RETAIN_TREES",
    "LATTICA_V2_GPU_QUERY_GATHER",
    "LATTICA_V2_GPU_RESIDENT_LDE",
    "LATTICA_V2_GPU_OPENINGS",
    "LATTICA_V2_QUOTIENT_FUSION",
    "LATTICA_V2_GPU_QUOTIENT_LDE",
    "LATTICA_V2_GPU_QUOTIENT_EVAL",
    "LATTICA_V2_GPU_QUOTIENT_RESIDENT",
    "LATTICA_V2_GPU_LOOKUP",
    "LATTICA_V2_GPU_OPENING_EVAL",
    "LATTICA_V2_GPU_FRI_RESIDENT",
    "LATTICA_V2_GPU_PCS_DEVICE_ONLY",
    "LATTICA_V2_GPU_WITNESS",
    "LATTICA_V2_GPU_RANDOMNESS",
    "LATTICA_V2_GPU_TRANSCRIPT",
    "LATTICA_V2_GPU_FRI_FOLD",
    "LATTICA_PROVING_REPORT",
];

fn switch(name: &str) -> Result<bool, String> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => Err(format!("{name} must be 0 or 1")),
    }
}

fn bytes(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Ok(value) => value
            .parse()
            .map_err(|_| format!("invalid {name} byte allowance")),
        _ => Err(format!("invalid {name} byte allowance")),
    }
}

fn host_output_bytes() -> Result<usize, String> {
    crate::block_v2::resident_pcs::try_host_output_budget()
}

fn uuid(value: &str) -> Result<[u8; 16], String> {
    let value = value
        .strip_prefix("GPU-")
        .ok_or("registered GPU UUID prefix")?;
    if value.len() != 36
        || [8, 13, 18, 23]
            .into_iter()
            .any(|at| value.as_bytes()[at] != b'-')
    {
        return Err("registered GPU UUID format".into());
    }
    let mut digits = value.bytes().filter(|&byte| byte != b'-');
    let mut result = [0; 16];
    let hex = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    for byte in &mut result {
        let high = digits
            .next()
            .and_then(hex)
            .ok_or("registered GPU UUID digit")?;
        let low = digits
            .next()
            .and_then(hex)
            .ok_or("registered GPU UUID digit")?;
        *byte = 16 * high + low;
    }
    if digits.next().is_some() {
        return Err("registered GPU UUID length".into());
    }
    Ok(result)
}

impl ExecutionSelection {
    #[cfg(feature = "gpu")]
    pub(super) fn capture() -> Result<Self, String> {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            feature = "gpu-bounded-info"
        ))]
        let (
            device,
            device_index,
            physical_uuid,
            physical_global_bytes,
            physical_max_allocation_bytes,
        ) = {
            use crate::gpu_device::bounded::{fixed, Request, Scratch};
            // The owned RingCT entry holds its original runtime/preflight
            // reservation and immutable bounded environment through every
            // planner/dispatch recheck. This fixed scanner does not construct
            // a Vec of per-device Identity strings or create a context.
            let index = std::env::var("LATTICA_V2_GPU_DEVICE")
                .map_err(|_| "bounded registered GPU requires an explicit index")?;
            let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID")
                .map_err(|_| "bounded registered GPU requires an explicit UUID")?;
            let request = Request::parse(&index, &uuid)
                .map_err(|_| "bounded registered GPU selector refused")?;
            let mut scratch = Scratch::new();
            let selected = fixed::capture(request, &mut scratch)
                .map_err(|_| "bounded registered GPU physical selection refused")?;
            (
                selected.device(),
                selected.index(),
                selected.uuid(),
                selected.global_bytes(),
                selected.max_allocation_bytes(),
            )
        };
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            feature = "gpu-bounded-info"
        )))]
        let (_, device, physical) = crate::gpu_device::select()?;
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            feature = "gpu-bounded-info"
        )))]
        let (device_index, physical_uuid, physical_global_bytes, physical_max_allocation_bytes) = (
            physical.opencl_index,
            uuid(
                physical
                    .uuid
                    .as_deref()
                    .ok_or("registered GPU requires a physical UUID")?,
            )?,
            physical.global_bytes,
            physical.max_allocation_bytes,
        );
        // Qualify the effective typed policy against this selected device
        // before any context/queue exists. Equality at the dispatch boundary
        // then rejects selector drift rather than silently changing kernels.
        let public_hash = PublicHashSelection::from_env()?;
        public_hash.require_device(device)?;
        let mut required_switches = 0;
        for (bit, name) in REQUIRED.into_iter().enumerate() {
            required_switches |= u32::from(switch(name)?) << bit;
        }
        let transform_allowance = bytes(
            &crate::block_v2::worker_memory::env_name("LDE_SCRATCH_BYTES"),
            usize::MAX,
        )?;
        if transform_allowance != usize::MAX
            && (transform_allowance < 16 || transform_allowance % 16 != 0)
        {
            return Err("invalid registered LDE scratch allowance".into());
        }
        Ok(Self {
            device_index,
            uuid: physical_uuid,
            physical_global_bytes,
            physical_max_allocation_bytes,
            managed_bytes: bytes("LATTICA_V2_GPU_MANAGED_BYTES", DEVICE_LIMIT as usize)? as u64,
            context_bytes: bytes("LATTICA_V2_GPU_CONTEXT_BYTES", CONTEXT_RESERVE as usize)? as u64,
            host_output_bytes: host_output_bytes()?,
            public_hash,
            transform_allowance,
            slots: if switch("LATTICA_V2_GPU_PIPELINE")? {
                2
            } else {
                1
            },
            required_switches,
            lde_workspace_bytes: bytes("LATTICA_V2_GPU_LDE_WORKSPACE_BYTES", 0)?,
            opening_denominator_cache: switch("LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE")?,
            shared_preprocessing: std::env::var_os(crate::block_v2::worker_memory::env_name(
                "SHARED_PREPROCESSING_DIR",
            ))
            .is_some(),
            worker_assignment: std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some(),
        })
    }

    #[cfg(not(feature = "gpu"))]
    pub(super) fn capture() -> Result<Self, String> {
        Err("registered full-GPU admission requires OpenCL".into())
    }

    pub(super) fn qualify(self, limits: RegisteredGpuLimits) -> Result<(), String> {
        if self.required_switches != (1 << REQUIRED.len()) - 1
            || self.lde_workspace_bytes != 0
            || self.opening_denominator_cache
            || self.shared_preprocessing
            || self.worker_assignment
            || self.managed_bytes != limits.device_bytes
            || self.context_bytes != limits.context_bytes
            || self.physical_max_allocation_bytes == 0
            || add(self.managed_bytes, self.context_bytes)? > self.physical_global_bytes
        {
            return Err(
                "registered one-shot GPU selection differs from its qualified memory schedule"
                    .into(),
            );
        }
        Ok(())
    }

    /// Registration clamps its host budget to this effective PCS selection.
    /// Refuse an unsupported clamp before planning or creating a GPU context;
    /// do not silently change the registered backend/runtime partition.
    pub(super) fn qualify_host_output(self, backend_host_bytes: u64) -> Result<(), String> {
        if (self.host_output_bytes as u64) < backend_host_bytes {
            return Err(
                "registered GPU host output ceiling is below the planned backend allowance".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_output(bytes: usize) -> ExecutionSelection {
        ExecutionSelection {
            device_index: 0,
            uuid: [0; 16],
            physical_global_bytes: 16 << 30,
            physical_max_allocation_bytes: 4 << 30,
            managed_bytes: DEVICE_LIMIT,
            context_bytes: CONTEXT_RESERVE,
            host_output_bytes: bytes,
            #[cfg(feature = "gpu")]
            public_hash: PublicHashSelection::Baseline,
            transform_allowance: usize::MAX,
            slots: 1,
            required_switches: (1 << REQUIRED.len()) - 1,
            lde_workspace_bytes: 0,
            opening_denominator_cache: false,
            shared_preprocessing: false,
            worker_assignment: false,
        }
    }

    #[test]
    fn host_output_clamp_refuses_before_backend_partition_and_binds_selection() {
        let required = 24u64 << 30;
        let selected = selected_output(required as usize);
        assert!(selected.qualify_host_output(required).is_ok());
        assert!(selected_output(required as usize + 1)
            .qualify_host_output(required)
            .is_ok());
        let reduced = selected_output(required as usize - 1);
        assert!(reduced.qualify_host_output(required).is_err());
        assert_ne!(selected, reduced);
        assert!(selected_output(0).qualify_host_output(required).is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn effective_public_hash_policy_participates_in_exact_execution_selection() {
        let baseline = selected_output(24 << 30);
        let mut candidate = baseline;
        candidate.public_hash = PublicHashSelection::SboxPairV1;
        assert_ne!(baseline, candidate);
        candidate.public_hash = PublicHashSelection::Baseline;
        assert_eq!(baseline, candidate);
    }

    #[test]
    fn host_output_selection_uses_effective_runtime_parser_without_device_work() {
        const CHILD: &str = "LATTICA_REGISTERED_HOST_OUTPUT_TEST_CHILD";
        const OUTPUT: &str = "LATTICA_V2_HOST_OUTPUT_BYTES";
        if let Ok(case) = std::env::var(CHILD) {
            let output = host_output_bytes();
            match case.as_str() {
                "low" => {
                    let output = output.unwrap();
                    assert_eq!(output, 4095);
                    assert!(selected_output(output).qualify_host_output(4096).is_err());
                }
                "exact" => {
                    let output = output.unwrap();
                    assert_eq!(output, 4096);
                    assert!(selected_output(output).qualify_host_output(4096).is_ok());
                }
                "invalid" => assert!(output.is_err()),
                _ => panic!("invalid isolated host-output test case"),
            }
            eprintln!("registered_host_output_parser_test case={case} no_device_work=true");
            return;
        }
        let test = concat!(
            module_path!(),
            "::host_output_selection_uses_effective_runtime_parser_without_device_work"
        );
        let test = test.split_once("::").expect("crate-qualified test path").1;
        for (case, value) in [("low", "4095"), ("exact", "4096"), ("invalid", "invalid")] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env(CHILD, case)
                .env(OUTPUT, value)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated case {case}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stderr).contains(&format!(
                "registered_host_output_parser_test case={case} no_device_work=true"
            )));
        }
    }

    #[test]
    fn physical_uuid_is_fixed_size_and_canonical() {
        let a = uuid("GPU-01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(a, uuid("GPU-01234567-89AB-CDEF-0123-456789ABCDEF").unwrap());
        for invalid in [
            "",
            "GPU-0123456789ab-cdef-0123-456789abcdef",
            "GPU-g1234567-89ab-cdef-0123-456789abcdef",
        ] {
            assert!(uuid(invalid).is_err());
        }
    }
}
