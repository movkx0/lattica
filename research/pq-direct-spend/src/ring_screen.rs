//! Guarded, research-only seven-statement screen. No aggregate or production API.
//! The parent hook is release/test/gpu-proving/Linux/x86_64 only.
mod bounds;
mod fixtures;
#[cfg(feature = "gpu-identity-reuse-experiment")]
mod identity_experiment;
mod io;
mod workflow;

#[cfg(feature = "ring-direct-aggregate-experiment")]
pub(crate) fn aggregate_fixture(case: usize) -> std::result::Result<(ring::Statement, ring::Witness), Error> {
    fixtures::generate(case)
}
#[cfg(feature = "ring-direct-aggregate-experiment")]
pub(crate) fn aggregate_fixture_staging_bytes() -> Result<usize> {
    Ok(bounds::Staging::new()?.required_host_bytes)
}

use crate::{ring, ring_circuit, Context, Error, Profile};
use ring_circuit::{
    CompilerCapacityProfile, CompilerMemoryProfile, CompilerRepresentation, CompilerWireProfile,
};

const CASES: usize = 7;
const CONTEXT: Context = Context([0x73; 32]);
const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;
const CAPACITY: CompilerCapacityProfile = CompilerCapacityProfile::new(
    CompilerMemoryProfile::Program2GiB,
    CompilerWireProfile::Research16M,
);
const WORKER_HOST_BYTES: usize = 32 << 30;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
mod tests;
