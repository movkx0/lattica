//! OpenCL preparation of the shared public AIR specialization.
use super::super::Engine;
#[cfg(test)]
use crate::block_v2::quotient_program::specialize::{
    MAX_INSTRUCTIONS, MAX_REGISTERS, MAX_SOURCE_BYTES,
};
use crate::block_v2::quotient_program::{
    specialize::{self, Backend, OPENCL_BLOCK as BLOCK},
    Program,
};
use sha3::{Digest, Sha3_256};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
const REQUIRED_DRIVER_RESERVE: usize = 4 << 30;
const MAX_PRIVATE_BYTES: usize = 512;
fn required_driver_reserve(qualified_aggregation: bool) -> usize {
    if qualified_aggregation { 2 << 30 } else { REQUIRED_DRIVER_RESERVE }
}

// The aggregation worker independently checks the source/executable/device
// qualification and exact program geometry before entering this backend.
// Keep the original reserve for every other caller and malformed selection.
fn qualified_aggregation_reserve(engine: &Engine, reserve: usize) -> bool {
    if std::env::var("LATTICA_V2_GPU_AGGREGATION_V4").as_deref() != Ok("1") {
        return false;
    }
    let Some(value) = std::env::var("LATTICA_V2_GPU_AGGREGATION_MEMORY").ok()
        .filter(|s| s.len() <= 16 * 1024)
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()) else { return false; };
    value["context_bytes"].as_u64() == Some(reserve as u64)
        && value["managed_bytes"].as_u64() == Some(engine.limits.managed_bytes as u64)
        && value["qualification_sha256"].as_str().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        && value["qualified_geometries"].as_array().is_some_and(|g| !g.is_empty())
}

#[test]
fn smaller_reserve_preserves_specialization_only_after_aggregation_qualification() {
    assert!(2 << 30 < required_driver_reserve(false));
    assert!(3 << 30 < required_driver_reserve(false));
    assert_eq!(required_driver_reserve(false), 4 << 30);
    assert_eq!(required_driver_reserve(true), 2 << 30);
    assert!(128 << 20 < required_driver_reserve(true) - (512 << 20));
}
fn source(program: &Program) -> Result<Option<String>, String> {
    specialize::source(program, Backend::OpenCl)
}

pub(in crate::block_v2::gpu_hash::engine) struct Compiled {
    pub program: ocl::Program,
    pub private_bytes: usize,
    checked_execution: AtomicBool,
}

/// Engine-local LRU. Keys cover exact source bytes and the fixed compiler option;
/// the enclosing Engine fixes both device and context. No code, arguments,
/// private witness, challenge or device allocation is shared between engines.
pub(in crate::block_v2::gpu_hash::engine) struct Cache {
    entries: [Option<([u8; 32], Option<Arc<Compiled>>)>; 8],
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}
impl Default for Cache {
    fn default() -> Self { Self { entries: std::array::from_fn(|_| None), hits: 0, misses: 0, evictions: 0 } }
}
impl Cache {
    fn get(&mut self, key: &[u8; 32]) -> Option<Option<Arc<Compiled>>> {
        if let Some(index) = self.entries.iter().position(|entry| entry.as_ref().is_some_and(|entry| &entry.0 == key)) {
            self.entries[..=index].rotate_right(1);
            self.hits += 1;
            return Some(self.entries[0].as_ref().unwrap().1.clone());
        }
        self.misses += 1;
        None
    }
    fn insert(&mut self, key: [u8; 32], value: Option<Arc<Compiled>>) {
        self.evictions += u64::from(self.entries[7].is_some());
        self.entries.rotate_right(1);
        self.entries[0] = Some((key, value));
    }
    pub(in crate::block_v2::gpu_hash::engine) fn retained_host_bytes(&self) -> usize {
        // Inline keys/slots are already included in size_of::<Engine>().
        self.entries.iter().filter(|entry| entry.as_ref().is_some_and(|entry| entry.1.is_some())).count()
            * (std::mem::size_of::<Compiled>() + 2 * std::mem::size_of::<usize>() + std::mem::align_of::<Compiled>())
    }
}
impl Compiled {
    pub fn check_execution(&self, engine: &mut Engine) -> Result<(), String> {
        if !self.checked_execution.load(Ordering::Relaxed) {
            engine.context_checkpoint("specialized quotient execution")?;
            eprintln!(
                "bounded_gpu_quotient_specialized_execution private_bytes={} context_checkpoint_complete=true",
                self.private_bytes
            );
            self.checked_execution.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

/// Opaque code and private backing stay inside the existing driver reservation.
/// This is a bounded NVIDIA optimization; all other shapes retain the GPU IR.
pub(in crate::block_v2::gpu_hash::engine) fn prepare(
    engine: &mut Engine,
    program: &Program,
) -> Result<Option<Arc<Compiled>>, String> {
    use ocl::core::{DeviceInfo, DeviceInfoResult, KernelWorkGroupInfo, KernelWorkGroupInfoResult};
    let device = engine.pq.device();
    let reserve = super::super::env_bytes("LATTICA_V2_GPU_CONTEXT_BYTES", super::super::DRIVER_RESERVE_BYTES)?;
    let required_reserve = required_driver_reserve(qualified_aggregation_reserve(engine, reserve));
    if super::row_workgroup(device, 32).is_none()
        || reserve < required_reserve
    {
        return Ok(None);
    }
    let word = |key| {
        ocl::core::get_device_info_raw(device, key)
            .ok()
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
            .map(u32::from_ne_bytes)
    };
    let units = match device.info(DeviceInfo::MaxComputeUnits) {
        Ok(DeviceInfoResult::MaxComputeUnits(units)) if (1..=128).contains(&units) => {
            units as usize
        }
        _ => return Ok(None),
    };
    // These supported NVIDIA generations have at most 2,048 resident threads
    // per SM. Unknown devices retain the interpreter rather than guessing.
    if !word(0x4000).is_some_and(|major| (7..=12).contains(&major)) || word(0x4003) != Some(32) {
        return Ok(None);
    }
    let Some(source) = source(program)? else {
        return Ok(None);
    };
    // Diagnostic only: distinguish repeated compiler inputs from merely equal
    // byte lengths. This digest grants no cache, quota or execution authority.
    let source_hash = Sha3_256::digest(source.as_bytes());
    let mut key_hash = Sha3_256::new();
    key_hash.update(b"opencl-specialized-program-v1\0-cl-std=CL1.2\0");
    key_hash.update(source.as_bytes());
    let key: [u8; 32] = key_hash.finalize().into();
    if engine.tuning.programs {
        if let Some(compiled) = engine.specialized_programs.get(&key) {
            eprintln!("bounded_gpu_quotient_program_cache hit=true selected={} source_sha3={source_hash:x} hits={} misses={} evictions={}",
                compiled.is_some(), engine.specialized_programs.hits, engine.specialized_programs.misses, engine.specialized_programs.evictions);
            return Ok(compiled);
        }
    }
    let started = std::time::Instant::now();
    let compiled = ocl::Program::builder()
        .devices(device)
        .src(&source)
        .cmplr_opt("-cl-std=CL1.2")
        .build(engine.pq.context())
        .map_err(|e| e.to_string())?;
    let kernel = ocl::core::create_kernel(compiled.as_core(), "specialized_quotient")
        .map_err(|e| e.to_string())?;
    let private_bytes = match ocl::core::get_kernel_work_group_info(
        &kernel,
        device,
        KernelWorkGroupInfo::PrivateMemSize,
    )
    .map_err(|e| e.to_string())?
    {
        KernelWorkGroupInfoResult::PrivateMemSize(bytes) => {
            usize::try_from(bytes).map_err(|_| "GPU private size overflow")?
        }
        _ => return Err("GPU private size response".into()),
    };
    // Allow at most 128 MiB of rounded resident private backing within the
    // the selected opaque driver allowance; no managed workspace is borrowed.
    if private_bytes > MAX_PRIVATE_BYTES {
        eprintln!("bounded_gpu_quotient_specialization selected=false degree={} instructions={} registers={} source_bytes={} private_bytes={private_bytes} limit_bytes={MAX_PRIVATE_BYTES} source_sha3={source_hash:x} build_ns={}",
            program.extension.degree(), program.instruction_count(), program.registers, source.len(), started.elapsed().as_nanos());
        if engine.tuning.programs {
            engine.fence().finish()?;
            engine.specialized_programs.insert(key, None);
        }
        return Ok(None);
    }
    let private_backing = units * 2048 * private_bytes.div_ceil(256) * 256;
    assert!(private_backing <= 128 << 20);
    engine.context_checkpoint("specialized quotient compilation")?;
    eprintln!("bounded_gpu_quotient_specialization selected=true degree={} instructions={} registers={} blocks={} source_bytes={} source_capacity={} private_bytes={private_bytes} resident_private_bound_bytes={private_backing} driver_reserve_bytes={reserve} source_sha3={source_hash:x} build_ns={}",
        program.extension.degree(), program.instruction_count(), program.registers, program.instruction_count().div_ceil(BLOCK), source.len(), source.capacity(), started.elapsed().as_nanos());
    let compiled = Arc::new(Compiled {
        program: compiled,
        private_bytes,
        checked_execution: AtomicBool::new(false),
    });
    if engine.tuning.programs {
        engine.fence().finish()?;
        engine.specialized_programs.insert(key, Some(Arc::clone(&compiled)));
        super::super::host_storage::admit(engine)?;
        eprintln!("bounded_gpu_quotient_program_cache hit=false selected=true source_sha3={source_hash:x} hits={} misses={} evictions={} retained_host_bytes={}",
            engine.specialized_programs.hits, engine.specialized_programs.misses, engine.specialized_programs.evictions, engine.specialized_programs.retained_host_bytes());
    }
    Ok(Some(compiled))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires OpenCL GPU; run serially under the zero-swap resource guard"]
    fn gpu_specialized_cache_reuses_exact_source_and_retires_with_context() {
        use crate::block_v2::gpu_hash::{self as gpu, Limits};
        let _shutdown=gpu::TestShutdownGuard;
        let initialize=||gpu::initialize_quotient_test_engine(Limits {
            managed_bytes:64<<20,tile_bytes:1<<20,staging_bytes:64<<10,
        }).unwrap();
        initialize();
        {
            let mut slot=super::super::super::ENGINE.get().unwrap().lock().unwrap();
            let engine=slot.as_mut().unwrap();engine.tuning.programs=true;
            let mut program=super::super::tests::program();
            program.instructions=vec![0,0,13,17,19,16,0,0,0,0];
            let first=prepare(engine,&program).unwrap().expect("supported specialization");
            program.instructions[2..5].copy_from_slice(&[97,101,103]);
            let same=prepare(engine,&program).unwrap().unwrap();
            assert!(Arc::ptr_eq(&first,&same));
            assert_eq!(engine.specialized_programs.hits,1);
            program.instructions[2]=1;
            let changed=prepare(engine,&program).unwrap().unwrap();
            assert!(!Arc::ptr_eq(&first,&changed));
            assert_eq!(engine.specialized_programs.misses,2);
            assert!(engine.specialized_programs.retained_host_bytes()<32<<20);
        }
        gpu::shutdown().unwrap();initialize();
        let slot=super::super::super::ENGINE.get().unwrap().lock().unwrap();
        let cache=&slot.as_ref().unwrap().specialized_programs;
        assert_eq!(cache.hits,0);assert_eq!(cache.misses,0);
        assert!(cache.entries.iter().all(Option::is_none));
    }

    #[test]
    fn program_cache_is_bounded_lru_and_remembers_rejected_sources() {
        let mut cache = Cache::default();
        for key in 0..8 { cache.insert([key; 32], None); }
        assert!(matches!(cache.get(&[0;32]), Some(None)));
        cache.insert([8;32], None);
        assert!(cache.get(&[1;32]).is_none());
        assert!(matches!(cache.get(&[0;32]), Some(None)));
        assert_eq!(cache.evictions, 1);
        assert_eq!(cache.entries.iter().flatten().count(), 8);
        assert_eq!(cache.retained_host_bytes(), 0);
        assert!(cache.get(&[99;32]).is_none());
    }

    #[test]
    fn compiler_source_reuses_nontrivial_constants_and_keeps_global_code_offsets() {
        let mut program = super::super::tests::program();
        program.instructions = vec![0, 0, 13, 17, 19, 16, 0, 0, 0, 0];
        let first = source(&program).unwrap().unwrap();
        program.instructions[2..5].copy_from_slice(&[97, 101, 103]);
        assert_eq!(source(&program).unwrap().unwrap(), first);
        for word in 2..5 {
            assert!(first.contains(&format!("code[{word}UL]")));
        }
        program.instructions[2] = 1;
        assert_ne!(source(&program).unwrap().unwrap(), first);
        program.instructions = vec![0, 0, 13, 17, 19];
        for _ in 1..BLOCK {
            program.instructions.extend_from_slice(&[10, 0, 0, 0, 0]);
        }
        program.instructions.extend_from_slice(&[0, 0, 29, 31, 37, 16, 0, 0, 0, 0]);
        let wide = source(&program).unwrap().unwrap();
        for word in BLOCK * 5 + 2..BLOCK * 5 + 5 {
            assert!(wide.contains(&format!("code[{word}UL]")));
        }
    }

    #[test]
    fn invalid_bytecode_is_rejected_before_compilation_or_device_access() {
        let base = super::super::tests::program;
        for instructions in [
            vec![18, 0, 0, 0, 0],
            vec![0, 1, 0, 0, 0],
            vec![1, 0, 2, 0, 0],
            vec![2, 0, 0, 0, 0],
            vec![3, 0, 0, 0, 0],
            vec![4, 0, u64::MAX, 0, 0],
            vec![8, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 16, 0, 0, 1, 0],
            vec![0, 0, 1, 0],
        ] {
            let mut program = base();
            program.instructions = instructions;
            assert!(source(&program).is_err());
        }
    }

    #[test]
    fn source_storage_and_supported_shape_limits_are_bounded() {
        let mut program = super::super::tests::program();
        assert!(source(&program).unwrap().unwrap().capacity() <= MAX_SOURCE_BYTES);
        program.extension = crate::block_v2::gpu_hash::device::Extension::Quadratic;
        assert!(source(&program).unwrap().unwrap().capacity() <= MAX_SOURCE_BYTES);
        program.registers = MAX_REGISTERS + 1;
        assert!(source(&program).unwrap().is_none());
        program.registers = 1;
        program.instructions = vec![0; (MAX_INSTRUCTIONS + 1) * 5];
        assert!(source(&program).unwrap().is_none());
        // Many reused destinations cross block boundaries without growing the
        // liveness representation or source beyond their fixed envelopes.
        program.instructions = vec![0, 0, 7, 0, 0];
        for _ in 1..MAX_INSTRUCTIONS - 1 {
            program.instructions.extend_from_slice(&[10, 0, 0, 0, 0]);
        }
        program.instructions.extend_from_slice(&[16, 0, 0, 0, 0]);
        if let Some(generated) = source(&program).unwrap() {
            assert!(
                generated.len() <= MAX_SOURCE_BYTES && generated.capacity() <= MAX_SOURCE_BYTES
            );
        }
    }
}
