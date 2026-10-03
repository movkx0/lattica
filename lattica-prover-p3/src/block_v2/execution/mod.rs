//! Local candidate execution contracts. Research only; no production C ABI.
//!
//! Job identities are operational metadata, not new recursive public inputs.
//! Proof validity does not establish current host-chain transaction eligibility.
//! The in-memory DAG owns candidate/attempt fences and aggregate reservations.
//! Linux snapshot recovery is available. OS/device enforcement and worker/host
//! lifecycle integration remain separate requirements, not implied by the adapter.

pub mod dag;
pub mod job;
pub mod resources;
pub mod selection;
pub mod worker;
pub mod workspace;

// The bounded local filesystem implementation uses Linux directory descriptors.
// Other platforms retain the in-memory contracts, not an unqualified fallback.
#[cfg(target_os = "linux")]
pub mod artifact_store;

#[cfg(target_os = "linux")]
pub mod journal;

#[cfg(target_os = "linux")]
pub mod launch;

#[cfg(target_os = "linux")]
pub mod transport;

#[cfg(target_os = "linux")]
pub mod os_worker;

#[cfg(all(target_os = "linux", feature = "stream"))]
pub mod process;
#[cfg(all(target_os = "linux", feature = "stream"))]
pub mod supervisor;

#[cfg(test)]
mod dag_tests;

#[cfg(all(test, target_os = "linux"))]
mod test_fixture;
