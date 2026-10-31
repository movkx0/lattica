//! Staged private-note GPU research admission for the unchanged join-split AIR.
//! Preparation records public metadata only. There is deliberately no proof,
//! configuration, or dispatch entry point until the complete producer lifetime
//! has an independently reviewed reservation and an exclusive runtime owner.
mod config;
mod geometry;
mod opening;
mod preparation;
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
mod preopening;
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
pub(crate) use preopening::PreopeningHostResources;
mod randomness;
mod resources;
mod selection;

pub use config::ConfigurationCensus;
pub(crate) use config::WorkerPolicyAbsent;
pub use geometry::Geometry;
pub use opening::OpeningHostResources;
pub use preparation::{Diagnostics, PreparationPlan, PreparedNote};
pub use randomness::{RandomnessBounds, StreamBounds};
pub use resources::PreparationResources;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    Geometry,
    Overflow,
    ResourceLimit,
    Randomness,
    Statement,
    Preparation,
    Configuration,
    WorkerPolicy,
    EntropyUnavailable,
    IncompleteLifetimeAdmission,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Overflow)
}

#[cfg(all(any(test, feature = "note-gpu-proving-experiment"), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info"))]
mod runtime;
#[cfg(all(feature = "note-gpu-proving-experiment", target_os = "linux", target_arch = "x86_64"))]
pub use runtime::OwnedEncodedNote;
