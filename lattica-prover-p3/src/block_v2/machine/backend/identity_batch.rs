//! Opt-in preprocessing schedule. These options change execution, not identities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityHashSchedule {
    #[default]
    Serial,
    BatchedV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct IdentityBatchLimits {
    pub schedule: IdentityHashSchedule,
    max_streams: usize,
}
impl Default for IdentityBatchLimits {
    fn default() -> Self { Self { schedule: IdentityHashSchedule::Serial, max_streams: 1 } }
}
impl IdentityBatchLimits {
    pub fn batched(max_streams: usize) -> Result<Self, &'static str> {
        if !matches!(max_streams, 1 | 2 | 4 | 8 | 16) { return Err("identity batch ceiling must be 1, 2, 4, 8 or 16"); }
        Ok(Self { schedule: IdentityHashSchedule::BatchedV1, max_streams })
    }
    pub fn max_streams(self) -> usize { self.max_streams }
    pub fn parse(schedule: &str, max_streams: Option<usize>) -> Result<Self, &'static str> {
        match (schedule, max_streams) {
            ("serial", None | Some(1)) => Ok(Self::default()),
            ("batched-v1", ceiling) => Self::batched(ceiling.unwrap_or(8)),
            _ => Err("invalid identity hash schedule or serial batch ceiling"),
        }
    }
}

#[cfg(feature = "gpu-tuning")]
mod gpu;
#[cfg(feature = "gpu-tuning")]
pub use gpu::{IdentityBatchContext, IdentityBatchPlan, PendingIdentityBatch, CompletedIdentityPrefix, IdentityBatchFootprint, IdentityBatchReport, IDENTITY_PREFIX_HOST_BYTES};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_batch_selection_is_explicit_and_bounded() {
        assert_eq!(IdentityBatchLimits::default().schedule, IdentityHashSchedule::Serial);
        assert_eq!(IdentityBatchLimits::parse("batched-v1", None).unwrap().max_streams(), 8);
        for n in [0, 3, 5, 9, 17, usize::MAX] { assert!(IdentityBatchLimits::batched(n).is_err()); }
        assert!(IdentityBatchLimits::parse("serial", Some(8)).is_err());
        assert!(IdentityBatchLimits::parse("auto", None).is_err());
    }
}
