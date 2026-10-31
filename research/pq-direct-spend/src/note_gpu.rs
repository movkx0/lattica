//! Admission-first private-note research. Production acceptance is unchanged.
//! The default inspection/preparation paths do not dispatch. The separate
//! note-gpu-proving-experiment feature admits one fixed owned native proof,
//! original-ledger PQNOTE1 handoff and independent CPU verification under the
//! dedicated external guard. It claims no complete RingCT workflow or speedup.
mod admission;
mod codec;
pub mod fixtures;
mod quota;
mod shape;
mod verification;

#[cfg(all(feature = "note-gpu-proving-experiment", target_os = "linux", target_arch = "x86_64"))]
pub mod workflow;
#[cfg(feature = "note-gpu-preparation")]
mod proving;
#[cfg(feature = "note-gpu-preparation")]
pub use proving::{PreparedNote, PreparationReceipt, PreparationError};
#[cfg(all(feature = "note-gpu-proving-experiment", target_os = "linux", target_arch = "x86_64"))]
pub use proving::ProducedNote;

pub use admission::{diagnose, AdmissionDiagnostic, Geometry, Limits, MissingBound};
pub use codec::{decode_required_bytes, DecodeReceipt, DecodeSession, DecodedArtifact};
pub use quota::QuotaSnapshot;
pub use verification::{
    VerificationError, VerificationPlan, VerificationReceipt, VerifiedArtifact,
};

use lattica_prover_p3::config::{Challenge, ChallengeMmcs, MyConfig, Val, ValMmcs};
use serde::Serialize;

pub const SCHEMA: &str = "lattica-private-note-gpu-admission-v1";
pub const MAX_PROOF_BYTES: usize = 64 << 20;
pub const ARTIFACT_HEADER_BYTES: usize = 48 + 8 * 26;
pub const MAGIC: &[u8; 8] = b"PQNOTE1\0";
const WORKER_HOST_BYTES: usize = 32 << 30;
const MANAGED_DEVICE_BYTES: usize = 8 << 30;
const CONTEXT_DEVICE_BYTES: usize = 4 << 30;
const NATIVE_HOST_BYTES: usize = 24 << 30;
const PROCESS_HOST_BYTES: usize = 47 << 30;
const MAX_ROWS: usize = 1 << 20;

type Proof = p3_uni_stark::Proof<MyConfig>;
type Cap = p3_symmetric::MerkleCap<Val, [Val; 4]>;
type Opening = p3_commit::BatchOpening<Val, ValMmcs>;
type Fri = p3_fri::FriProof<Challenge, ChallengeMmcs, Val, Vec<Opening>>;
type Query = p3_fri::QueryProof<Challenge, ChallengeMmcs, Vec<Opening>>;
type Step = p3_fri::CommitPhaseProofStep<Challenge, ChallengeMmcs>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    Profile,
    Context,
    Statement,
    NonCanonical,
    Geometry,
    ResourceLimit,
    MalformedArtifact,
    IncompleteLifetimeAdmission,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::ResourceLimit)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::ResourceLimit)
}

#[cfg(test)]
mod tests;
