//! OpenCL preparation of the shared public AIR specialization.
use super::super::Engine;
#[cfg(test)]
use crate::block_v2::quotient_program::specialize::{
    MAX_INSTRUCTIONS, MAX_REGISTERS, MAX_SOURCE_BYTES,
};
use crate::block_v2::quotient_program::{
    specialize::{self, Backend, BLOCK},
    Program,
};
use std::sync::atomic::{AtomicBool, Ordering};
const REQUIRED_DRIVER_RESERVE: usize = 4 << 30;
const MAX_PRIVATE_BYTES: usize = 512;
fn source(program: &Program) -> Result<Option<String>, String> {
    specialize::source(program, Backend::OpenCl)
}

pub(in crate::block_v2::gpu_hash::engine) struct Compiled {
    pub program: ocl::Program,
    pub private_bytes: usize,
    checked_execution: AtomicBool,
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
) -> Result<Option<Compiled>, String> {
    use ocl::core::{DeviceInfo, DeviceInfoResult, KernelWorkGroupInfo, KernelWorkGroupInfoResult};
    let device = engine.pq.device();
    if super::row_workgroup(device, 32).is_none()
        || super::super::env_bytes(
            "LATTICA_V2_GPU_CONTEXT_BYTES",
            super::super::DRIVER_RESERVE_BYTES,
        )? < REQUIRED_DRIVER_RESERVE
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
    // 4 GiB opaque driver allowance; no managed workspace is borrowed.
    if private_bytes > MAX_PRIVATE_BYTES {
        eprintln!("bounded_gpu_quotient_specialization selected=false private_bytes={private_bytes} limit_bytes={MAX_PRIVATE_BYTES}");
        return Ok(None);
    }
    let private_backing = units * 2048 * private_bytes.div_ceil(256) * 256;
    assert!(private_backing <= 128 << 20);
    engine.context_checkpoint("specialized quotient compilation")?;
    eprintln!("bounded_gpu_quotient_specialization selected=true degree={} instructions={} blocks={} source_bytes={} source_capacity={} private_bytes={private_bytes} resident_private_bound_bytes={private_backing} driver_reserve_bytes={REQUIRED_DRIVER_RESERVE} build_ns={}",
        program.extension.degree(), program.instruction_count(), program.instruction_count().div_ceil(BLOCK), source.len(), source.capacity(), started.elapsed().as_nanos());
    Ok(Some(Compiled {
        program: compiled,
        private_bytes,
        checked_execution: AtomicBool::new(false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
