//! Bounded specialization of public AIR bytecode. Witnesses remain GPU inputs.
use super::super::Engine;
use crate::block_v2::gpu_quotient_prover::program::Program;
use std::{
    fmt::Write,
    sync::atomic::{AtomicBool, Ordering},
};

const BLOCK: usize = 64;
const MAX_INSTRUCTIONS: usize = 8192;
const MAX_REGISTERS: usize = 512;
const MAX_SOURCE_BYTES: usize = 2 << 20;
const REQUIRED_DRIVER_RESERVE: usize = 4 << 30;
const MAX_PRIVATE_BYTES: usize = 512;

#[derive(Clone, Copy, Default)]
struct Slots([u64; 8]);
impl Slots {
    fn contains(self, slot: usize) -> bool {
        self.0[slot / 64] & (1 << (slot % 64)) != 0
    }
    fn insert(&mut self, slot: usize) {
        self.0[slot / 64] |= 1 << (slot % 64);
    }
    fn remove(&mut self, slot: usize) {
        self.0[slot / 64] &= !(1 << (slot % 64));
    }
    fn read(&mut self, instruction: &[u64]) {
        if instruction[0] >= 8 {
            self.insert(instruction[2] as usize);
        }
        if matches!(instruction[0], 8 | 9 | 10 | 12 | 13 | 14) {
            self.insert(instruction[3] as usize);
        }
    }
}

struct Source(String);
impl std::fmt::Write for Source {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if text.len() > MAX_SOURCE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::fmt::Error);
        }
        self.0.push_str(text);
        Ok(())
    }
}

fn validate(program: &Program) -> Result<bool, String> {
    let degree = program.extension.degree();
    if !matches!(degree, 2 | 3)
        || program.registers == 0
        || program.registers > MAX_REGISTERS
        || program.instructions.is_empty()
        || program.instructions.len() > MAX_INSTRUCTIONS * 5
        || program.constraints > MAX_INSTRUCTIONS
    {
        return Ok(false);
    }
    if program.instructions.len() % 5 != 0 {
        return Err("specialized quotient instruction width".into());
    }
    for instruction in program.instructions.chunks_exact(5) {
        let [op, dst, a, b, _] = <[u64; 5]>::try_from(instruction).unwrap();
        if op > 17
            || (op < 16 && dst >= program.registers as u64)
            || (op >= 8 && a >= program.registers as u64)
            || (matches!(op, 8 | 9 | 10 | 12 | 13 | 14) && b >= program.registers as u64)
            || (op >= 16 && b >= program.constraints as u64)
        {
            return Err("specialized quotient opcode or register bound".into());
        }
        if matches!(op, 1 | 2 | 3 | 4) {
            let width = if matches!(op, 1 | 3) {
                1
            } else {
                degree as u64
            };
            let limit = if op <= 2 {
                program.row_words
            } else {
                program.parameter_words
            };
            if a.checked_add(width).is_none_or(|end| end > limit as u64) {
                return Err("specialized quotient input or parameter bound".into());
            }
        }
    }
    Ok(true)
}

/// Returns None for shapes outside this optimization's fixed compiler envelope.
fn source(program: &Program) -> Result<Option<String>, String> {
    if !validate(program)? {
        return Ok(None);
    }
    let degree = program.extension.degree();
    let count = program.instructions.len() / 5;
    let blocks = count.div_ceil(BLOCK);
    // Only block boundaries survive. At most 129 fixed 64-byte bitmaps.
    let mut boundaries = vec![Slots::default(); blocks + 1];
    let mut live = Slots::default();
    for pc in (0..count).rev() {
        let instruction = &program.instructions[pc * 5..pc * 5 + 5];
        if instruction[0] < 16 {
            live.remove(instruction[1] as usize);
        }
        live.read(instruction);
        if pc % BLOCK == 0 {
            boundaries[pc / BLOCK] = live;
        }
    }
    if live.0.iter().any(|word| *word != 0) {
        return Err("specialized quotient reads an uninitialized register".into());
    }
    let mut output = String::new();
    output
        .try_reserve_exact(MAX_SOURCE_BYTES)
        .map_err(|_| "specialized quotient source allocation failed")?;
    let mut output = Source(output);
    let emitted = (|| -> std::fmt::Result {
        output.write_str(crate::gpu::KERNEL_SRC)?;
        output.write_str(include_str!("../extension_multiply.cl"))?;
        writeln!(output, "\n#define QUOTIENT_DEGREE {degree}")?;
        writeln!(
            output,
            "#define QUOTIENT_MUL opening_{}_mul",
            if degree == 2 { "quadratic" } else { "cubic" }
        )?;
        for block in 0..blocks {
            let first = block * BLOCK;
            let end = (first + BLOCK).min(count);
            let chunk = &program.instructions[first * 5..end * 5];
            let mut used = Slots::default();
            let mut written = Slots::default();
            for instruction in chunk.chunks_exact(5) {
                used.read(instruction);
                if instruction[0] < 16 {
                    written.insert(instruction[1] as usize);
                }
            }
            writeln!(
                output,
                "__attribute__((noinline)) void quotient_block_{block}("
            )?;
            output.write_str("__global const ulong *input, uint width, __global const ulong *parameters,\n__global const ulong *weights, __global ulong *scratch, uint rows, uint row,\nulong first, ulong last, ulong transition, __private ulong *accumulator) {\n")?;
            writeln!(output, "ulong value[{degree}];")?;
            for slot in 0..program.registers {
                if used.contains(slot) || written.contains(slot) {
                    writeln!(output, "ulong reg_{slot}[{degree}];")?;
                }
                if used.contains(slot) && boundaries[block].contains(slot) {
                    for j in 0..degree {
                        writeln!(
                            output,
                            "reg_{slot}[{j}] = scratch[{}UL * rows + row];",
                            slot * degree + j
                        )?;
                    }
                }
            }
            for instruction in chunk.chunks_exact(5) {
                let [op, dst, a, b, c] = <[u64; 5]>::try_from(instruction).unwrap();
                if op == 14 {
                    writeln!(output, "QUOTIENT_MUL(reg_{a}, reg_{b}, value);")?;
                } else if op == 17 {
                    writeln!(output, "{{ ulong weight[{degree}];")?;
                    for j in 0..degree {
                        writeln!(
                            output,
                            "weight[{j}] = weights[{}UL];",
                            b * degree as u64 + j as u64
                        )?;
                    }
                    writeln!(output, "QUOTIENT_MUL(reg_{a}, weight, value); }}")?;
                } else {
                    for j in 0..degree {
                        write!(output, "value[{j}] = ")?;
                        match op {
                            0 => write!(output, "{}UL", [a, b, c][j])?,
                            1 | 2 if op == 2 || j == 0 => {
                                write!(output, "input[(size_t)row * width + {}UL]", a + j as u64)?
                            }
                            3 | 4 if op == 4 || j == 0 => {
                                write!(output, "parameters[{}UL]", a + j as u64)?
                            }
                            5..=7 if j == 0 => output
                                .write_str(["first", "last", "transition"][(op - 5) as usize])?,
                            8..=10 | 12 | 13 if op >= 12 || j == 0 => {
                                let name = match op {
                                    8 | 12 => "gl_add",
                                    9 | 13 => "gl_sub",
                                    _ => "gl_mul",
                                };
                                write!(output, "{name}(reg_{a}[{j}], reg_{b}[{j}])")?;
                            }
                            11 | 15 if op == 15 || j == 0 => {
                                write!(output, "gl_neg(reg_{a}[{j}])")?
                            }
                            16 => write!(
                                output,
                                "gl_mul(reg_{a}[0], weights[{}UL])",
                                b * degree as u64 + j as u64
                            )?,
                            _ => output.write_str("0UL")?,
                        }
                        output.write_str(";\n")?;
                    }
                }
                for j in 0..degree {
                    if op >= 16 {
                        writeln!(
                            output,
                            "accumulator[{j}] = gl_add(accumulator[{j}], value[{j}]);"
                        )?;
                    } else {
                        // All operand reads precede a reused destination's writes.
                        writeln!(output, "reg_{dst}[{j}] = value[{j}];")?;
                    }
                }
            }
            for slot in 0..program.registers {
                if written.contains(slot) && boundaries[block + 1].contains(slot) {
                    for j in 0..degree {
                        writeln!(
                            output,
                            "scratch[{}UL * rows + row] = reg_{slot}[{j}];",
                            slot * degree + j
                        )?;
                    }
                }
            }
            output.write_str("}\n")?;
        }
        // OpenCL C 1.2 does not support variadic macros.
        const ARGUMENTS: &str = "input, width, parameters, weights, scratch, rows, row, first, last, transition, accumulator";
        writeln!(output, "#define QUOTIENT_SPECIALIZED({ARGUMENTS}) \\")?;
        for block in 0..blocks {
            writeln!(output, "quotient_block_{block}({ARGUMENTS}); \\")?;
        }
        output.write_str("\n#define QUOTIENT_ALPHA specialized_alpha\n#define QUOTIENT_EVALUATE specialized_quotient\n")?;
        output.write_str(include_str!("../quotient_kernels.cl"))?;
        Ok(())
    })();
    Ok(emitted.ok().map(|_| output.0))
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
    let _span = tracing::info_span!(target: "lattica_block_v2_perf", "specialized OpenCL compilation").entered();
    let mut builder = ocl::Program::builder();
    builder.devices(device).src(&source).cmplr_opt("-cl-std=CL1.2");
    if super::super::switch("LATTICA_PROFILE_TIMELINE")? {
        builder.cmplr_opt("-cl-nv-verbose");
    }
    let compiled = builder.build(engine.pq.context())
        .map_err(|e| e.to_string())?;
    super::super::profiling::program(&compiled, device)?;
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
