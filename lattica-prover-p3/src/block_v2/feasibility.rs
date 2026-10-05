//! Checked lower-bound accounting for trace commitment. NOT a scheduler or a
//! peak-RSS/VRAM guarantee: quotient, Merkle, FRI, staging, concurrent jobs and OS
//! overhead still need measurement after a bounded recursive circuit exists.

use super::profile::{LOG_BLOWUP, NUM_RANDOM_CODEWORDS};

pub const RAM_BUDGET_BYTES: u64 = 48 << 30;
pub const VRAM_BUDGET_BYTES: u64 = 12 << 30;
pub const SCRATCH_BUDGET_BYTES: u64 = 128 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    InvalidGeometry,
    Overflow,
    ScratchExceeded { required: u64, budget: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitFootprint {
    pub trace_bytes: u64,
    pub randomized_trace_bytes: u64,
    pub committed_lde_bytes: u64,
    pub trace_commit_peak_bytes: u64,
}

impl CommitFootprint {
    /// Current owned-store algorithm: release natural trace before committing LDE,
    /// but randomized trace and committed LDE coexist. No allocation is performed.
    pub fn for_geometry(height: u64, width: u64) -> Result<Self, ResourceError> {
        if !height.is_power_of_two() || width == 0 {
            return Err(ResourceError::InvalidGeometry);
        }
        let mul = |a: u64, b: u64| a.checked_mul(b).ok_or(ResourceError::Overflow);
        let add = |a: u64, b: u64| a.checked_add(b).ok_or(ResourceError::Overflow);
        let trace_bytes = mul(mul(height, width)?, 8)?;
        let randomized_trace_bytes = mul(
            mul(mul(height, 2)?, add(width, NUM_RANDOM_CODEWORDS as u64)?)?,
            8,
        )?;
        let committed_lde_bytes = mul(randomized_trace_bytes, 1 << LOG_BLOWUP)?;
        let trace_commit_peak_bytes = add(trace_bytes, randomized_trace_bytes)?
            .max(add(randomized_trace_bytes, committed_lde_bytes)?);
        Ok(Self {
            trace_bytes,
            randomized_trace_bytes,
            committed_lde_bytes,
            trace_commit_peak_bytes,
        })
    }

    /// Rejection is decisive; acceptance of this lower bound is NOT admission of a job.
    pub fn check_scratch_lower_bound(&self, budget: u64) -> Result<(), ResourceError> {
        if self.trace_commit_peak_bytes > budget {
            return Err(ResourceError::ScratchExceeded {
                required: self.trace_commit_peak_bytes,
                budget,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_monolith_exceeds_workstation_budget_before_allocation() {
        // Regression geometry, independently recomputed by block-v2-feasibility
        // from real q96 K=2 proofs. NOT a measurement of the proposed v2 AIR.
        let footprint = CommitFootprint::for_geometry(2_097_152, 5_885).unwrap();
        assert_eq!(footprint.trace_bytes, 98_733_916_160);
        assert_eq!(footprint.randomized_trace_bytes, 197_602_050_048);
        assert_eq!(footprint.committed_lde_bytes, 3_161_632_800_768);
        assert_eq!(footprint.trace_commit_peak_bytes, 3_359_234_850_816);
        assert!(matches!(
            footprint.check_scratch_lower_bound(SCRATCH_BUDGET_BYTES),
            Err(ResourceError::ScratchExceeded { .. })
        ));
    }

    #[test]
    fn boundaries_fail_closed() {
        assert_eq!(
            CommitFootprint::for_geometry(0, 1),
            Err(ResourceError::InvalidGeometry)
        );
        assert_eq!(
            CommitFootprint::for_geometry(3, 1),
            Err(ResourceError::InvalidGeometry)
        );
        assert_eq!(
            CommitFootprint::for_geometry(4, 0),
            Err(ResourceError::InvalidGeometry)
        );
        assert_eq!(
            CommitFootprint::for_geometry(1 << 63, 2),
            Err(ResourceError::Overflow)
        );
        assert_eq!(
            CommitFootprint::for_geometry(1, u64::MAX),
            Err(ResourceError::Overflow)
        );
        let fp = CommitFootprint::for_geometry(4096, 19).unwrap();
        assert_eq!(
            fp.check_scratch_lower_bound(fp.trace_commit_peak_bytes),
            Ok(())
        );
        assert!(fp
            .check_scratch_lower_bound(fp.trace_commit_peak_bytes - 1)
            .is_err());
    }
}
