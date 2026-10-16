//! One ceiling for simultaneous System requests and full spill backing. This
//! deliberately charges even nonresident disk-backed spill pages. Foreign
//! allocations, allocator overhead and other direct mappings are not included.
use super::system_budget::{Budget, Snapshot};

pub(super) static HOST: Budget = Budget::new();

pub(crate) fn snapshot() -> Snapshot {
    HOST.snapshot()
}

/// Install before Rayon/GPU initialization. Shares the System budget's atomic
/// activation/reservation protocol, including requests predating installation.
pub(crate) fn admit_worker(limit: usize) -> Result<(), &'static str> {
    HOST.install(limit)
        .map_err(|_| "invalid combined host request budget or existing ownership")?;
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_host_requests {}",
            serde_json::json!({
                "schema": "lattica-host-request-budget-v1", "pid": std::process::id(),
                "boundary": "before_rayon", "snapshot": snapshot(),
                "includes_in_flight": true, "reserves_before_allocation": true,
                "charges_full_spill_backing": true, "immutable_until_exit": true,
                "is_rss_bound": false, "is_complete_allocator_bound": false,
            })
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
