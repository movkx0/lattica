//! Tiled native CUDA interpolation/LDE, with all field work on the device.
//! The same geometry, roots and query budgets are shared with OpenCL.
use super::{Argument, Buffer, Kernel, Launch, Limits, Matrix, Result, Runtime};
use crate::gpu_matrix::{roots, MatrixSpec, MemoryPlan, RowOrder, GOLDILOCKS_MODULUS};
use std::sync::Arc;

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("transform.cu"));

#[derive(Clone, Debug)]
struct NttGroup {
    first: u32,
    stages: u32,
    log_columns: u32,
    launch: Launch,
}

fn ntt_groups(log_rows: u32, width: usize, shared_bytes: u32) -> Result<Vec<NttGroup>> {
    if !(1..=31).contains(&log_rows)
        || width == 0
        || width > u32::MAX as usize
        || shared_bytes < 8192
    {
        return Err("unsupported CUDA transform geometry".into());
    }
    let tile_bits = (shared_bytes as usize / 8).ilog2().min(12);
    let column_bits = width
        .checked_next_power_of_two()
        .ok_or("CUDA transform width overflow")?
        .trailing_zeros()
        .min(4);
    let cap = (tile_bits - column_bits).min(log_rows);
    let groups = log_rows.div_ceil(cap);
    let (base, extra) = (log_rows / groups, log_rows % groups);
    let mut first = 0;
    (0..groups)
        .map(|group| {
            let stages = base + u32::from(group < extra);
            let elements = 1usize << (stages + column_bits);
            let blocks = (1usize << (log_rows - stages))
                .checked_mul(width.div_ceil(1usize << column_bits))
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("CUDA transform grid overflow")?;
            let result = NttGroup {
                first,
                stages,
                log_columns: column_bits,
                launch: Launch {
                    blocks,
                    threads: (elements / 2).clamp(32, 256) as u32,
                    shared_bytes: (elements * 8) as u32,
                },
            };
            first += stages;
            Ok(result)
        })
        .collect()
}

fn geometry(
    input: MatrixSpec,
    log_rows: u32,
    shift: u64,
    order: RowOrder,
) -> Result<(MatrixSpec, usize, usize)> {
    if log_rows < input.log_rows || log_rows > 31 {
        return Err("CUDA LDE requires a nonshrinking domain below 2^32 rows".into());
    }
    let output = MatrixSpec::new(log_rows, input.columns, input.extension, order, shift)?;
    let width = input
        .columns
        .checked_mul(input.extension.degree())
        .filter(|n| *n <= u32::MAX as usize)
        .ok_or("CUDA transform width overflow")?;
    Ok((
        output,
        width,
        (input.log_rows.max(1) + log_rows.max(1) + 2) as usize,
    ))
}

pub(super) fn storage_plan(
    input: MatrixSpec,
    log_rows: u32,
    live: usize,
    limits: Limits,
) -> Result<MemoryPlan> {
    let (output, _, auxiliary) = geometry(input, log_rows, 1, RowOrder::Natural)?;
    if input.log_rows.max(log_rows).max(2) as usize * 8 > limits.max_allocation_bytes {
        return Err("CUDA transform constants exceed allocation limit".into());
    }
    MemoryPlan::new(
        &[output, output],
        live.checked_add(auxiliary * 8)
            .ok_or("CUDA transform memory overflow")?,
        limits.managed_bytes,
        limits.max_allocation_bytes,
    )
}

#[derive(Clone)]
pub(crate) struct Transforms {
    pub(super) runtime: Runtime,
    ntt: Kernel,
    parameters: Kernel,
    scale: Kernel,
    pub(super) prefix: Kernel,
    pub(super) gather: Kernel,
}

impl Transforms {
    /// Reuse loaded functions while attributing final coefficient work to its
    /// protocol stage. Query reconstruction keeps its own attribution.
    pub(super) fn for_final_polynomial(&self) -> Self {
        let mut result = self.clone();
        result.ntt = result
            .ntt
            .with_stage(crate::proving::Stage::FinalPolynomial);
        result.parameters = result
            .parameters
            .with_stage(crate::proving::Stage::FinalPolynomial);
        result.scale = result
            .scale
            .with_stage(crate::proving::Stage::FinalPolynomial);
        result
    }

    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        Ok(Self {
            runtime: runtime.clone(),
            ntt: module.kernel_for_stage("ntt_tile", crate::proving::Stage::Transform)?,
            parameters: module
                .kernel_for_stage("transform_parameters", crate::proving::Stage::Transform)?,
            scale: module.kernel_for_stage("transform_scale", crate::proving::Stage::Transform)?,
            prefix: module.kernel_for_stage("query_prefix", crate::proving::Stage::FriQuery)?,
            gather: module.kernel_for_stage("gather_rows", crate::proving::Stage::FriQuery)?,
        })
    }

    pub(super) fn check_owner(&self, matrix: &Matrix) -> Result<()> {
        if !Arc::ptr_eq(&self.runtime.state, matrix.buffer.owner()) {
            return Err("CUDA matrix belongs to another runtime".into());
        }
        Ok(())
    }

    pub(super) fn roots(&self, log_rows: u32, inverse: bool) -> Result<Buffer> {
        if log_rows > 32 {
            return Err("unsupported CUDA root domain".into());
        }
        let words: Vec<_> = (1..=log_rows.max(1))
            .map(if inverse {
                roots::inverse_root
            } else {
                roots::root
            })
            .collect();
        let buffer = self.runtime.allocate(words.len())?;
        buffer.write(0, &words)?;
        Ok(buffer)
    }

    pub(super) fn parameters(&self, input: MatrixSpec, output_shift: u64) -> Result<Buffer> {
        if input.log_rows > 31 || output_shift == 0 || output_shift >= GOLDILOCKS_MODULUS {
            return Err("invalid CUDA transform parameters".into());
        }
        let parameters = self.runtime.allocate(2)?;
        // Exactly one thread writes the two allocated parameter words. All
        // inversion and coset-ratio arithmetic occurs in the CUDA kernel.
        unsafe {
            self.parameters.launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&parameters),
                    Argument::U32(input.rows() as u32),
                    Argument::U64(input.shift),
                    Argument::U64(output_shift),
                ],
            )?
        }
        .finish()?;
        Ok(parameters)
    }

    /// Raw, unnormalized NTT. Buffers must be distinct. The first group reads
    /// source and writes scratch; a final bit-reversed store may write source.
    /// Natural output leaves source unchanged, including for inverse transforms.
    pub(super) fn ntt(
        &self,
        source: &Buffer,
        scratch: &Buffer,
        roots: &Buffer,
        log_rows: u32,
        width: usize,
        input_order: RowOrder,
        output_order: RowOrder,
    ) -> Result<bool> {
        let groups = ntt_groups(log_rows, width, self.runtime.identity().shared_bytes)?;
        let words = (1usize << log_rows)
            .checked_mul(width)
            .ok_or("CUDA transform size overflow")?;
        if source.pointer() == scratch.pointer()
            || words > source.len()
            || words > scratch.len()
            || roots.len() < log_rows as usize
        {
            return Err("CUDA transform buffer bounds or aliasing".into());
        }
        let mut in_scratch = true;
        for (i, group) in groups.iter().enumerate() {
            let first = i == 0;
            let reverse = i + 1 == groups.len() && output_order == RowOrder::BitReversed;
            let (input, output) = if first {
                (source, scratch)
            } else if reverse {
                (scratch, source)
            } else {
                (scratch, scratch)
            };
            in_scratch = output.pointer() == scratch.pointer();
            // The tile planner partitions complete rows/columns into disjoint
            // blocks. First/last permutations use distinct storage; middle
            // stages access only their block's own tile. Shared bytes match
            // 2^(stages+log_columns) u64 words and roots cover every stage.
            unsafe {
                self.ntt.launch(
                    group.launch,
                    &[
                        Argument::Buffer(input),
                        Argument::Buffer(output),
                        Argument::U32(width as u32),
                        Argument::U32(1u32 << log_rows),
                        Argument::U32(group.first),
                        Argument::U32(group.stages),
                        Argument::U32(group.log_columns),
                        Argument::U32(u32::from(first && input_order == RowOrder::Natural)),
                        Argument::U32(log_rows),
                        Argument::U32(u32::from(reverse)),
                        Argument::Buffer(roots),
                    ],
                )?
            }
            .finish()?;
        }
        Ok(in_scratch)
    }

    pub(super) fn scale(
        &self,
        source: &Buffer,
        output: &Buffer,
        parameters: &Buffer,
        width: usize,
        input_rows: usize,
        output_rows: usize,
    ) -> Result<()> {
        let words = output_rows
            .checked_mul(width)
            .ok_or("CUDA scale size overflow")?;
        if width == 0
            || width > u32::MAX as usize
            || input_rows == 0
            || output_rows > u32::MAX as usize
            || input_rows > output_rows
            || input_rows
                .checked_mul(width)
                .is_none_or(|n| n > source.len())
            || words > output.len()
            || parameters.len() < 2
        {
            return Err("CUDA scale buffer bounds".into());
        }
        // One lane per output word; padded rows never read source. An exact
        // in-place source/output alias is safe because each lane reads itself.
        unsafe {
            self.scale.launch(
                linear_launch(words)?,
                &[
                    Argument::Buffer(source),
                    Argument::Buffer(output),
                    Argument::Buffer(parameters),
                    Argument::U32(width as u32),
                    Argument::U32(input_rows as u32),
                    Argument::U32(output_rows as u32),
                ],
            )?
        }
        .finish()?;
        Ok(())
    }

    /// Interpolate on the input coset and evaluate on a same-size or larger
    /// output coset. Base and extension coefficients stay on device throughout.
    pub(crate) fn lde(
        &self,
        input: &Matrix,
        log_rows: u32,
        shift: u64,
        order: RowOrder,
    ) -> Result<Matrix> {
        self.check_owner(input)?;
        let (spec, width, _) = geometry(input.spec, log_rows, shift, order)?;
        let _plan = storage_plan(
            input.spec,
            log_rows,
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        let a = self.runtime.allocate(spec.words())?;
        let b = self.runtime.allocate(spec.words())?;
        let inverse = self.roots(input.spec.log_rows, true)?;
        let forward = self.roots(log_rows, false)?;
        let parameters = self.parameters(input.spec, shift)?;
        let coefficients = if input.spec.rows() > 1 {
            self.ntt(
                &input.buffer,
                &b,
                &inverse,
                input.spec.log_rows,
                width,
                input.spec.order,
                RowOrder::Natural,
            )?;
            &b
        } else {
            &input.buffer
        };
        self.scale(
            coefficients,
            &a,
            &parameters,
            width,
            input.spec.rows(),
            spec.rows(),
        )?;
        let in_b = spec.rows() > 1
            && self.ntt(&a, &b, &forward, log_rows, width, RowOrder::Natural, order)?;
        Ok(Matrix {
            spec,
            buffer: if in_b { b } else { a },
        })
    }
}

pub(super) fn linear_launch(words: usize) -> Result<Launch> {
    if words == 0 {
        return Err("empty CUDA operation".into());
    }
    Ok(Launch {
        blocks: words
            .div_ceil(256)
            .try_into()
            .map_err(|_| "CUDA launch grid overflow")?,
        threads: 256,
        shared_bytes: 0,
    })
}

#[cfg(test)]
mod tests;
