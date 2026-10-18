//! Shared bounded query reconstruction planner for native GPU backends.
use super::{Extension, MatrixSpec, RowOrder};

#[cfg(test)]
mod tests;

// Fit sixteen columns of two 2^23-row transform buffers, plus roots, indices
// and gathered rows. A strict 2 GiB cap loses one column to that bookkeeping
// and misses the existing sixteen-column NVIDIA NTT geometry. All workspace
// bytes remain charged; tiles shrink to the managed/allocation allowance.
pub(crate) const PREFERRED_SCRATCH: usize = (2 << 30) + (64 << 10);
const HOST_METADATA: usize = 8 << 10;

#[derive(Debug)]
pub(crate) struct QueryPlan {
    pub(crate) height: usize,
    pub(crate) columns: usize,
    pub(crate) inverse_words: usize,
    pub(crate) forward_words: usize,
    pub(crate) workspace_bytes: usize,
    pub(crate) host_peak_bytes: usize,
}

pub(crate) fn geometry(input: MatrixSpec, log_rows: u32, indices: &[usize]) -> Result<(), String> {
    if input.extension != Extension::Base
        || input.order != RowOrder::BitReversed
        || input.columns > 4096
        || log_rows < input.log_rows
        || log_rows > 25
        || indices.is_empty()
        || indices.len() > 256
        || indices.iter().any(|i| *i >= 1usize << log_rows)
    {
        return Err(
            "owned query requires a bounded bit-reversed base-field prefix and query indices"
                .into(),
        );
    }
    Ok(())
}

impl QueryPlan {
    pub(crate) fn new(
        input: MatrixSpec,
        log_rows: u32,
        queries: usize,
        remaining: usize,
        max_allocation: usize,
        host_allowance: usize,
    ) -> Result<Self, String> {
        // These checks also make all arithmetic below fit usize on supported
        // 64-bit hosts, even when the caller supplies overflowing allowances.
        geometry(input, log_rows, &[0])?;
        if queries == 0 || queries > 256 {
            return Err("owned query count exceeds its bound".into());
        }
        let height = 1usize << log_rows;
        let inverse_words = input.log_rows.max(1) as usize;
        let forward_words = log_rows.max(1) as usize;
        let fixed = (inverse_words + forward_words + 2 + queries) * 8;
        if [inverse_words, forward_words, 2, queries]
            .into_iter()
            .any(|words| words * 8 > max_allocation)
        {
            return Err("owned query constants/indices exceed allocation limit".into());
        }
        let per_column = (2 * height + queries) * 8;
        let scratch_limit = PREFERRED_SCRATCH.max(fixed + per_column);
        let available = remaining
            .min(scratch_limit)
            .checked_sub(fixed)
            .ok_or("owned query has no scratch allowance")?;
        let columns = input
            .columns
            .min(available / per_column)
            .min(max_allocation / (height * 8))
            .min(max_allocation / (queries * 8))
            .min(u32::MAX as usize / height);
        if columns == 0 {
            return Err("no owned query transform column fits GPU allowance".into());
        }
        let host_peak_bytes = queries * (input.columns + columns) * 8 + HOST_METADATA;
        if host_peak_bytes > host_allowance {
            return Err("owned query result and staging exceed host allowance".into());
        }
        Ok(Self {
            height,
            columns,
            inverse_words,
            forward_words,
            workspace_bytes: fixed + columns * per_column,
            host_peak_bytes,
        })
    }
}
