//! The original serial-worker ledger is shared with the feature-gated core
//! producer so every payload can retain the same concrete reservation. Numeric
//! receipts remain observations, never replacement ownership or dispatch.
pub(crate) use lattica_prover_p3::ringct_research_quota::*;

/// Shared helper/frame scratch for source-only outer backend planning. This
/// fixed bound grants neither a worker allowance nor dispatch authority.
pub(crate) const OUTER_PLANNING_HOST_BYTES: u64 = 1 << 20;
