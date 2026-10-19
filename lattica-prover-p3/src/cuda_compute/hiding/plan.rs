use super::*;

/// Prepared inputs bind the maximum column tile and output domain before any
/// random draws. Sampling and transforming are separate admitted stage peaks.
#[derive(Clone, Copy, Debug)]
pub(in crate::cuda_compute) struct TilePlan {
    pub input_log: u32,
    pub output_log: u32,
    pub width: usize,
    pub columns: usize,
    pub quotient: bool,
}
impl TilePlan {
    pub fn new(
        input_log: u32,
        width: usize,
        output_log: u32,
        columns: usize,
        quotient: bool,
    ) -> Result<Self> {
        if input_log == 0
            || input_log > 31
            || output_log > 31
            || output_log < input_log + u32::from(quotient)
            || columns == 0
            || columns > width
            || width > u32::MAX as usize
        {
            return Err("unsupported CUDA hiding tile geometry".into());
        }
        let plan = Self {
            input_log,
            output_log,
            width,
            columns,
            quotient,
        };
        plan.output(columns, RowOrder::Natural)?;
        Ok(plan)
    }
    pub fn output(self, columns: usize, order: RowOrder) -> Result<MatrixSpec> {
        MatrixSpec::new(self.output_log, columns, Extension::Base, order, GENERATOR)
    }
    pub fn tile(self, first: usize, columns: usize) -> Result<Self> {
        if columns == 0
            || columns > self.columns
            || first
                .checked_add(columns)
                .is_none_or(|end| end > self.width)
        {
            return Err("CUDA hiding tile is outside prepared columns".into());
        }
        Ok(Self { columns, ..self })
    }
    pub fn scratch(self) -> Result<[usize; 5]> {
        let words = self.output(self.columns, RowOrder::Natural)?.words();
        Ok([
            words,
            words,
            self.input_log as usize,
            self.output_log as usize,
            if self.quotient { 0 } else { 2 },
        ])
    }
    pub fn admit(self, runtime: &Runtime, retained: &[usize]) -> Result<()> {
        admit(
            retained.iter().copied().chain(self.scratch()?),
            runtime.snapshot(),
            runtime.state.budget.limits,
        )
    }
}

pub(super) fn admit(
    words: impl IntoIterator<Item = usize>,
    state: super::super::Snapshot,
    limits: super::super::Limits,
) -> Result<()> {
    let mut live = state.live_bytes;
    let mut allocations = state.allocations;
    for words in words.into_iter().filter(|&n| n != 0) {
        let bytes = words
            .checked_mul(8)
            .ok_or("CUDA hiding allocation overflow")?;
        live = live.checked_add(bytes).ok_or("CUDA hiding peak overflow")?;
        allocations = allocations
            .checked_add(1)
            .ok_or("CUDA hiding allocation count overflow")?;
        if bytes > limits.max_allocation_bytes
            || live > limits.managed_bytes
            || allocations > limits.max_allocations
        {
            return Err("CUDA hiding exceeds admitted storage".into());
        }
    }
    Ok(())
}
