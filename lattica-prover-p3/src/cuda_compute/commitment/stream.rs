//! Bounded column streaming and mixed-height binary MMCS construction.
use super::*;

pub(in crate::cuda_compute) struct StreamPlan {
    pub words: [usize; 2], // Retained tree and largest row-sponge workspace.
    layout: Layout,
    order: Vec<usize>,
}
impl StreamPlan {
    pub(in crate::cuda_compute) fn new(specs: &[MatrixSpec], cap_height: usize) -> Result<Self> {
        if specs.is_empty() || specs.len() > MAX_FRAGMENTS {
            return Err("CUDA streamed commitment requires 1..256 matrices".into());
        }
        for spec in specs {
            if spec.log_rows > 31
                || spec.words() / spec.rows() > u32::MAX as usize
                || MatrixSpec::new(
                    spec.log_rows,
                    spec.columns,
                    spec.extension,
                    spec.order,
                    spec.shift,
                )? != *spec
            {
                return Err("invalid CUDA streamed commitment geometry".into());
            }
        }
        // Stable ordering preserves the original order within each height.
        // Salt generation is a separate consumer responsibility and must keep
        // original matrix order, not this Merkle construction order.
        let mut order: Vec<_> = (0..specs.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(specs[i].log_rows));
        let layout = Layout::new(specs[order[0]].log_rows, cap_height)?;
        Ok(Self {
            words: [layout.words, layout.height * 8],
            layout,
            order,
        })
    }
}

/// One matrix's columns in order. The sponge position is shared with the next
/// matrix of the same height, exactly as in upstream concatenated row hashing.
/// A failed or panicking launch makes the sink unusable even if a producer
/// catches the error; no partial tree can then be published.
pub(crate) struct ColumnSink<'a> {
    engine: &'a Commitments,
    states: &'a Buffer,
    pending: &'a mut u32,
    spec: MatrixSpec,
    consumed: usize,
    failed: bool,
}
impl ColumnSink<'_> {
    pub(crate) fn append(&mut self, first: usize, fragment: &Matrix) -> Result<()> {
        if self.failed {
            return Err("CUDA column sink retired after a failed launch".into());
        }
        self.engine.check_owner(&fragment.buffer)?;
        let spec = fragment.spec;
        let width = spec.words() / spec.rows();
        if first != self.consumed
            || spec.log_rows != self.spec.log_rows
            || spec.order != self.spec.order
            || spec.shift != self.spec.shift
            || width == 0
            || width > u32::MAX as usize
            || fragment.buffer.len() < spec.words()
            || self
                .consumed
                .checked_add(width)
                .is_none_or(|n| n > self.spec.words() / self.spec.rows())
        {
            return Err("CUDA streamed columns do not match the declared matrix".into());
        }
        self.failed = true;
        // States are a private workspace allocated by the engine, distinct
        // from the producer's fragment. Every row is owned by one thread.
        unsafe {
            self.engine.absorb.launch(
                launch(self.spec.rows())?,
                &[
                    Argument::Buffer(&fragment.buffer),
                    Argument::Buffer(self.states),
                    Argument::U32(self.spec.rows() as u32),
                    Argument::U32(width as u32),
                    Argument::U32(*self.pending),
                    Argument::Buffer(&self.engine.constants),
                ],
            )?
        }
        .finish()?;
        *self.pending = (*self.pending + (width % 4) as u32) % 4;
        self.consumed += width;
        self.failed = false;
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        if self.failed || self.consumed != self.spec.words() / self.spec.rows() {
            return Err("CUDA streamed matrix is incomplete or retired".into());
        }
        Ok(())
    }
}

impl Commitments {
    pub(in crate::cuda_compute) fn stream_plan(
        &self,
        runtime: &Runtime,
        specs: &[MatrixSpec],
        cap_height: usize,
    ) -> Result<StreamPlan> {
        self.check_runtime(runtime)?;
        StreamPlan::new(specs, cap_height)
    }

    /// The producer is called once per original matrix index, in stable height
    /// order. It may release each column tile immediately after append. The
    /// caller admits its own production scratch in addition to stream_plan.
    pub(crate) fn commit_streamed(
        &self,
        specs: &[MatrixSpec],
        cap_height: usize,
        mut produce: impl FnMut(usize, &mut ColumnSink<'_>) -> Result<()>,
    ) -> Result<RetainedTree> {
        let plan = self.stream_plan(&self.runtime, specs, cap_height)?;
        let state = self.runtime.snapshot();
        if state
            .allocations
            .checked_add(2)
            .is_none_or(|n| n > self.runtime.state.budget.limits.max_allocations)
        {
            return Err("CUDA streamed commitment exceeds allocation count".into());
        }
        admit(
            &plan.words,
            state.live_bytes,
            self.runtime.state.budget.limits,
        )?;
        let tree = self.runtime.allocate(plan.layout.words)?;
        let mut rows = plan.layout.height;
        let mut first = 0;
        let mut next_matrix = 0;
        while next_matrix < plan.order.len() {
            let height = specs[plan.order[next_matrix]].rows();
            while rows > height {
                first = self.compress_stream_level(&tree, first, rows)?;
                rows /= 2;
            }
            // Fresh zeroed storage avoids retaining sponge state across height
            // groups. Only one group's state exists at a time.
            let states = self.runtime.allocate(height * 8)?;
            let mut pending = 0;
            while next_matrix < plan.order.len() && specs[plan.order[next_matrix]].rows() == height
            {
                let index = plan.order[next_matrix];
                let mut sink = ColumnSink {
                    engine: self,
                    states: &states,
                    pending: &mut pending,
                    spec: specs[index],
                    consumed: 0,
                    failed: false,
                };
                produce(index, &mut sink)?;
                sink.complete()?;
                next_matrix += 1;
            }
            // Smaller matrices enter as compress(parent_digest, hash(rows)),
            // after child compression, matching the upstream binary MMCS.
            unsafe {
                self.finalize_at.launch(
                    launch(height)?,
                    &[
                        Argument::Buffer(&states),
                        Argument::Buffer(&tree),
                        Argument::U64(first as u64),
                        Argument::U32(height as u32),
                        Argument::U32(pending),
                        Argument::U32(u32::from(height != plan.layout.height)),
                        Argument::Buffer(&self.constants),
                    ],
                )?
            }
            .finish()?;
        }
        while rows > 1 {
            first = self.compress_stream_level(&tree, first, rows)?;
            rows /= 2;
        }
        Ok(RetainedTree {
            storage: tree,
            layout: plan.layout,
        })
    }

    fn compress_stream_level(&self, tree: &Buffer, first: usize, rows: usize) -> Result<usize> {
        let next = first + rows * 4;
        // The checked full-tree allocation contains disjoint consecutive
        // levels. Each parent consumes two children and writes four words.
        unsafe {
            self.compress.launch(
                launch(rows / 2)?,
                &[
                    Argument::Buffer(tree),
                    Argument::U64(first as u64),
                    Argument::U64(next as u64),
                    Argument::U32((rows / 2) as u32),
                    Argument::Buffer(&self.constants),
                ],
            )?
        }
        .finish()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
