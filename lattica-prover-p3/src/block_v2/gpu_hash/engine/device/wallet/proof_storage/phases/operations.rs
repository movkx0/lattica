//! Reuse runtime planners with conservative request lifetimes. Their chosen
//! tiles/columns are admission snapshots; runtime still adapts to actual live
//! buffers. Per-operation host output checks do not reserve caller lifetimes.
use super::*;

#[derive(Debug)]
pub(super) struct OperationPlan {
    pub(super) name: &'static str,
    pub(super) chunks: usize,
    pub(super) rows: Option<usize>,
    pub(super) columns: Option<usize>,
    pub(super) peak: usize,
    pub(super) host_buffer_bytes: usize,
    pub(super) query_count: usize,
}

impl OperationPlan {
    pub(super) fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name, "quotient_chunks": self.chunks,
            "tile_rows_at_bound": self.rows, "tile_columns_at_bound": self.columns,
            "managed_bytes_at_bound": self.peak,
            "host_buffer_bytes_at_bound": self.host_buffer_bytes,
            "query_count": self.query_count,
        })
    }
}

impl Plan {
    pub(super) fn admit_openings(
        &mut self,
        prefix: MatrixSpec,
        log_rows: u32,
        chunks: usize,
        extension: Extension,
        live: usize,
        limits: Limits,
        host_allowance: usize,
    ) -> Result<(), String> {
        // A uni wallet opens its main matrix at at most two points; all other
        // matrices use one. The widest prefix and two points bound every call.
        // `live` already includes all retained claims, even the current one;
        // counting its output again here is deliberately conservative.
        let degree = extension.degree();
        let host_buffer_bytes = 2 * prefix.columns() * degree * 8;
        if host_buffer_bytes > host_allowance {
            return Err("wallet opening values exceed host allowance".into());
        }
        let evaluation =
            opening::EvaluationPlan::new(prefix, 2, degree, live, limits, self.max_allocation)?;
        self.operations.push(OperationPlan {
            name: "opening_evaluation",
            chunks,
            rows: Some(evaluation.rows),
            columns: None,
            peak: evaluation.peak,
            host_buffer_bytes,
            query_count: 0,
        });
        // Reduction retains the full accumulator and its alpha allocation.
        let accumulator = MatrixSpec::new(log_rows, 1, extension, RowOrder::BitReversed, 1)?;
        let reduction = opening::ReductionPlan::new(
            prefix,
            log_rows,
            2,
            degree,
            sum(&[live, accumulator.bytes(), degree * 8])?,
            limits,
            self.max_allocation,
        )?;
        self.operations.push(OperationPlan {
            name: "opening_reduction",
            chunks,
            rows: Some(reduction.rows),
            columns: None,
            peak: reduction.peak,
            host_buffer_bytes: 0,
            query_count: 0,
        });
        Ok(())
    }

    pub(super) fn admit_queries(
        &mut self,
        prefix: MatrixSpec,
        log_rows: u32,
        chunks: usize,
        queries: usize,
        live: usize,
        host_allowance: usize,
    ) -> Result<(), String> {
        let remaining = self
            .ceiling
            .checked_sub(live)
            .ok_or("wallet query live storage exceeds capacity")?;
        // Actual live storage may be smaller and allow more columns than the
        // conservative admission snapshot. Check host output against that
        // largest possible tile as well, so adaptation cannot invalidate it.
        let largest_tile = query::QueryPlan::new(
            prefix,
            log_rows,
            queries,
            usize::MAX,
            self.max_allocation,
            host_allowance,
        )?;
        let query = query::QueryPlan::new(
            prefix,
            log_rows,
            queries,
            remaining,
            self.max_allocation,
            host_allowance,
        )?;
        self.operations.push(OperationPlan {
            name: "pcs_query_reconstruction",
            chunks,
            rows: None,
            columns: Some(query.columns),
            peak: sum(&[live, query.workspace_bytes])?,
            host_buffer_bytes: largest_tile.host_peak_bytes,
            query_count: queries,
        });
        Ok(())
    }
}
