//! Shared FRI operation checks for the wallet's single input height. Fold
//! outputs are already included in the geometric retained-vector bound.
use super::super::super::super::fri::storage::{self, FinalShape, GatherShape, StoragePlan};
use super::*;
use crate::block_v2::pcs_field::PcsField;

#[derive(Debug)]
pub(super) struct FriPlan {
    name: &'static str,
    chunks: usize,
    log_arity: usize,
    query_count: usize,
    storage: StoragePlan,
}
impl FriPlan {
    pub(super) fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name, "quotient_chunks": self.chunks, "log_arity": self.log_arity,
            "query_count": self.query_count, "managed_bytes_at_bound": self.storage.peak_bytes,
            "max_allocation_bytes": self.storage.max_allocation_bytes,
            "host_output_bytes_at_bound": self.storage.host_output_bytes,
            "host_temporary_bytes_at_bound": self.storage.host_temporary_bytes,
        })
    }
}
fn max_arity(extension: Extension) -> Result<usize, String> {
    match extension {
        Extension::Quadratic => Ok(crate::config::Challenge::MAX_LOG_ARITY),
        Extension::Cubic => Ok(profile::Challenge::MAX_LOG_ARITY),
        Extension::Base => Err("wallet FRI requires an extension field".into()),
    }
}
impl Plan {
    pub(super) fn admit_fri_final(
        &mut self,
        input: MatrixSpec,
        chunks: usize,
        live: usize,
        host_allowance: usize,
    ) -> Result<usize, String> {
        for log_arity in 1..=max_arity(input.extension())? {
            let output = storage::fold_output(input, log_arity)?;
            // All committed vectors plus the new fold total <2 full inputs.
            // Keep that entire envelope while checking the largest output of
            // each supported arity. Smaller layers cannot exceed either bound.
            let before_output = live
                .checked_sub(output.bytes())
                .ok_or("FRI live bound omits fold output")?;
            let storage =
                storage::vector_output(output, before_output, self.ceiling, self.max_allocation)?;
            self.fri.push(FriPlan {
                name: "fri_fold",
                chunks,
                log_arity,
                query_count: 0,
                storage,
            });
        }
        let parameters = profile::fri(());
        let final_input = MatrixSpec::new(
            (parameters.log_blowup + parameters.log_final_poly_len) as u32,
            1,
            input.extension(),
            RowOrder::BitReversed,
            1,
        )?;
        let final_shape = FinalShape::new(
            final_input,
            parameters.log_blowup,
            parameters.log_final_poly_len,
            host_allowance,
        )?;
        // Final egress adds its output/index or interpolation buffers. They
        // are separate from the retained-vector envelope, even at length one.
        let storage = final_shape.plan(live, self.ceiling, self.max_allocation)?;
        self.fri.push(FriPlan {
            name: "fri_final_polynomial",
            chunks,
            log_arity: 0,
            query_count: 1,
            storage,
        });
        Ok(storage.peak_bytes)
    }
    pub(super) fn admit_fri_queries(
        &mut self,
        input: MatrixSpec,
        chunks: usize,
        queries: usize,
        live: usize,
        host_allowance: usize,
    ) -> Result<usize, String> {
        let mut peak = live;
        for log_arity in 1..=max_arity(input.extension())? {
            let leaves = storage::leaves(input, log_arity)?;
            let storage = GatherShape::new(leaves, queries, host_allowance.min(1 << 20))?.plan(
                live,
                self.ceiling,
                self.max_allocation,
            )?;
            peak = peak.max(storage.peak_bytes);
            self.fri.push(FriPlan {
                name: "fri_query_values",
                chunks,
                log_arity,
                query_count: queries,
                storage,
            });
        }
        let salts = MatrixSpec::new(
            input.rows().ilog2() - 1,
            4,
            Extension::Base,
            RowOrder::BitReversed,
            1,
        )?;
        let storage = GatherShape::new(salts, queries, host_allowance.min(1 << 20))?.plan(
            live,
            self.ceiling,
            self.max_allocation,
        )?;
        peak = peak.max(storage.peak_bytes);
        self.fri.push(FriPlan {
            name: "fri_query_salts",
            chunks,
            log_arity: 0,
            query_count: queries,
            storage,
        });
        Ok(peak)
    }
}
