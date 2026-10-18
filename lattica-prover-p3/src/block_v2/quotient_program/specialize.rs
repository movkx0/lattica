//! Shared 64-instruction specialization and liveness analysis for public AIRs.
use super::Program;
use std::fmt::Write;

pub(crate) const BLOCK: usize = 64;
pub(crate) const MAX_INSTRUCTIONS: usize = 8192;
pub(crate) const MAX_REGISTERS: usize = 512;
pub(crate) const MAX_SOURCE_BYTES: usize = 2 << 20;

#[derive(Clone, Copy)]
pub(crate) enum Backend {
    #[cfg(feature = "gpu")]
    OpenCl,
    #[cfg(feature = "gpu-cuda")]
    Cuda,
}
impl Backend {
    fn prelude(self) -> &'static str {
        match self {
            #[cfg(feature = "gpu")]
            Self::OpenCl => crate::gpu::KERNEL_SRC,
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda => concat!(
                include_str!("../../cuda_compute/field.cuh"),
                "\n#define ulong u64\n#define uint u32\n#define __global\n#define __private\n"
            ),
        }
    }
    fn multiply(self, degree: usize) -> String {
        match self {
            #[cfg(feature = "gpu")]
            Self::OpenCl => format!(
                "opening_{}_mul",
                if degree == 2 { "quadratic" } else { "cubic" }
            ),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda => format!("fe_mul<{degree}>"),
        }
    }
    fn noinline(self) -> &'static str {
        match self {
            #[cfg(feature = "gpu")]
            Self::OpenCl => "__attribute__((noinline))",
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda => "__device__ __noinline__",
        }
    }
    fn evaluator(self) -> &'static str {
        match self {
            #[cfg(feature = "gpu")]
            Self::OpenCl => include_str!("../gpu_hash/engine/quotient_kernels.cl"),
            #[cfg(feature = "gpu-cuda")]
            Self::Cuda => include_str!("../../cuda_compute/quotient.cu"),
        }
    }
}

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
pub(crate) fn source(program: &Program, backend: Backend) -> Result<Option<String>, String> {
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
        output.write_str(backend.prelude())?;
        #[cfg(feature = "gpu")]
        output.write_str(include_str!("../gpu_hash/engine/extension_multiply.cl"))?;
        writeln!(output, "\n#define QUOTIENT_DEGREE {degree}")?;
        writeln!(output, "#define QUOTIENT_MUL {}", backend.multiply(degree))?;
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
                "{} void quotient_block_{block}(",
                backend.noinline()
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
        output.write_str(backend.evaluator())?;
        Ok(())
    })();
    Ok(emitted.ok().map(|_| output.0))
}
