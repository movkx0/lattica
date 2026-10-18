//! Reconstruct queried rows from device prefixes with two reusable tiles.
use super::{transform::linear_launch, Argument, Matrix, Result, Transforms};
use crate::gpu_matrix::{
    query::{geometry, QueryPlan},
    RowOrder, GOLDILOCKS_MODULUS,
};

pub(crate) struct QueryRows {
    pub values: Vec<u64>,
    pub tiles: usize,
    pub workspace_bytes: usize,
}

fn zeroed_words(count: usize) -> Result<Vec<u64>> {
    let mut words = Vec::new();
    words.try_reserve_exact(count).map_err(super::error)?;
    words.resize(count, 0);
    Ok(words)
}

impl Transforms {
    /// Preserve the requested order and duplicates. Only immutable public roots,
    /// indices and the final queried values cross the host/device boundary.
    pub(crate) fn query_rows(
        &self,
        input: &Matrix,
        log_rows: u32,
        indices: &[usize],
        host_allowance: usize,
    ) -> Result<QueryRows> {
        self.check_owner(input)?;
        geometry(input.spec, log_rows, indices)?;
        let limits = self.runtime.state.budget.limits;
        let remaining = limits
            .managed_bytes
            .checked_sub(self.runtime.snapshot().live_bytes)
            .ok_or("CUDA query has no managed memory allowance")?;
        let plan = QueryPlan::new(
            input.spec,
            log_rows,
            indices.len(),
            remaining,
            limits.max_allocation_bytes,
            host_allowance,
        )?;
        let mut values = zeroed_words(indices.len() * input.spec.columns)?;
        let mut tile = zeroed_words(indices.len() * plan.columns)?;
        let a = self.runtime.allocate(plan.height * plan.columns)?;
        let b = self.runtime.allocate(plan.height * plan.columns)?;
        let inverse = self.roots(input.spec.log_rows, true)?;
        let forward = self.roots(log_rows, false)?;
        let parameters = self.parameters(input.spec, input.spec.shift)?;
        let queries = self.runtime.allocate(indices.len())?;
        queries.write(0, &indices.iter().map(|i| *i as u64).collect::<Vec<_>>())?;
        let gathered = self.runtime.allocate(indices.len() * plan.columns)?;
        let mut tiles = 0;
        for first in (0..input.spec.columns).step_by(plan.columns) {
            let width = plan.columns.min(input.spec.columns - first);
            // Checked prefix geometry, column interval and complete destination
            // tile. Reversal permutes only the input's own rows.
            unsafe {
                self.prefix.launch(
                    linear_launch(input.spec.rows() * width)?,
                    &[
                        Argument::Buffer(&input.buffer),
                        Argument::Buffer(&a),
                        Argument::U32(input.spec.columns as u32),
                        Argument::U32(first as u32),
                        Argument::U32(width as u32),
                        Argument::U32(input.spec.rows() as u32),
                        Argument::U32(input.spec.log_rows),
                    ],
                )?
            }
            .finish()?;
            let coefficients = if input.spec.rows() > 1 {
                self.ntt(
                    &a,
                    &b,
                    &inverse,
                    input.spec.log_rows,
                    width,
                    RowOrder::Natural,
                    RowOrder::Natural,
                )?;
                &b
            } else {
                &a
            };
            self.scale(
                coefficients,
                &a,
                &parameters,
                width,
                input.spec.rows(),
                plan.height,
            )?;
            let in_b = plan.height > 1
                && self.ntt(
                    &a,
                    &b,
                    &forward,
                    log_rows,
                    width,
                    RowOrder::Natural,
                    RowOrder::BitReversed,
                )?;
            let output = if in_b { &b } else { &a };
            // Each public index is inside the expanded domain. The gather
            // allocation covers every requested row and the tile's full width.
            unsafe {
                self.gather.launch(
                    linear_launch(indices.len() * width)?,
                    &[
                        Argument::Buffer(output),
                        Argument::Buffer(&queries),
                        Argument::Buffer(&gathered),
                        Argument::U32(width as u32),
                        Argument::U32(indices.len() as u32),
                    ],
                )?
            }
            .finish()?;
            let words = &mut tile[..indices.len() * width];
            gathered.read(0, words)?;
            if words.iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                return Err("CUDA query returned a noncanonical field value".into());
            }
            for (query, row) in words.chunks_exact(width).enumerate() {
                let at = query * input.spec.columns + first;
                values[at..at + width].copy_from_slice(row);
            }
            tiles += 1;
        }
        Ok(QueryRows {
            values,
            tiles,
            workspace_bytes: plan.workspace_bytes,
        })
    }
}
