//! Allocation-free geometry of existing wide AIRs compared with the serial
//! partition. This is planning evidence only: no wide proof is produced, no
//! request/graph obligation is discharged, and no peak memory is measured.
use super::*;

#[derive(Clone, Copy, Debug)]
pub struct LayoutGeometry {
    pub width: usize,
    pub height: usize,
    pub raw_trace_bytes: u64,
    /// Main trace LDE only, including the profile's one hiding bit and FRI
    /// blowup. Excludes quotient/FRI matrices, hashes, openings and workspaces.
    pub retained_main_lde_bytes: u64,
    /// Same heuristic as the serial planner. It has not been calibrated on
    /// these wide AIRs and does not guarantee that a process fits its budget.
    pub uncalibrated_peak_estimate_bytes: u64,
}
impl LayoutGeometry {
    pub(super) fn new(width: usize, height: usize) -> Result<Self> {
        let estimate = super::estimate(0, 1, width, height)?;
        let lde_factor = 1u64
            .checked_shl((profile::LOG_BLOWUP + 1) as u32)
            .ok_or_else(|| Error("crypto layout LDE factor overflow".into()))?;
        let retained_main_lde_bytes = estimate
            .raw_trace_bytes
            .checked_mul(lde_factor)
            .ok_or_else(|| Error("crypto layout LDE size overflow".into()))?;
        Ok(Self {
            width,
            height,
            raw_trace_bytes: estimate.raw_trace_bytes,
            retained_main_lde_bytes,
            uncalibrated_peak_estimate_bytes: estimate.estimated_peak_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct WideShakePartitionEstimate {
    pub maximum_permutations: usize,
    pub segments: Vec<LayoutGeometry>,
}
#[derive(Clone, Debug)]
pub struct LayoutComparison {
    pub wide_whole_request: LayoutGeometry,
    pub serial_segments: Vec<LayoutGeometry>,
    /// These use the original segmented ShakeAir constructor, which already
    /// represents exact absorb/padding/squeeze phases. A component-tree
    /// adapter for wide children is separate from these estimates. This
    /// comparison never produces proofs or selects a proving path implicitly.
    pub wide_shake_partitions: Vec<WideShakePartitionEstimate>,
}
impl Request {
    pub fn layout_comparison(&self) -> Result<LayoutComparison> {
        let serial_segments = self
            .segments
            .iter()
            .map(|s| LayoutGeometry::new(s.width, s.height))
            .collect::<Result<Vec<_>>>()?;
        let mut wide_shake_partitions = Vec::new();
        let wide_whole_request = match self.descriptor {
            RequestDescriptor::Aes(descriptor) => {
                let air = crate::aes_air::AesAir::new(descriptor).map_err(err)?;
                LayoutGeometry::new(air.width(), air.height)?
            }
            RequestDescriptor::Shake(descriptor) => {
                let air = shake_air::ShakeAir::whole(descriptor).map_err(err)?;
                for maximum in [64, 128, 256, 512, 1024] {
                    let mut first = 0;
                    let mut segments = Vec::new();
                    while first < air.permutations {
                        let count = (air.permutations - first).min(maximum);
                        let segment =
                            shake_air::ShakeAir::new(descriptor, first, count).map_err(err)?;
                        segments.push(LayoutGeometry::new(segment.width(), segment.height)?);
                        first += count;
                    }
                    wide_shake_partitions.push(WideShakePartitionEstimate {
                        maximum_permutations: maximum,
                        segments,
                    });
                }
                LayoutGeometry::new(air.width(), air.height)?
            }
        };
        Ok(LayoutComparison {
            wide_whole_request,
            serial_segments,
            wide_shake_partitions,
        })
    }
}
