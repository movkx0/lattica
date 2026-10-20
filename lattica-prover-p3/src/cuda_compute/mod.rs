//! Native CUDA primitives for the bounded prover. No OpenCL dependency and no
//! CPU kernel fallback. Proof-stage integration must explicitly select these
//! primitives; compiling this feature alone does not claim CUDA proof coverage.
#[cfg(feature = "block-v2")]
mod batch_stark;
mod budget;
mod buffer;
mod commitment;
mod compiler;
mod device;
mod events;
mod field;
mod fri;
#[cfg(feature = "block-v2")]
mod hiding;
mod kernel;
#[cfg(feature = "block-v2")]
mod lookup;
mod matrix;
mod opening;
#[cfg(feature = "block-v2")]
mod pcs;
#[cfg(feature = "block-v2")]
mod public;
mod query;
#[cfg(feature = "block-v2")]
mod quotient;
mod random;
mod reporting;
mod scalars;
#[cfg(feature = "block-v2")]
mod stark;
mod storage;
#[cfg(test)]
mod tests;
mod transcript;
mod transform;
#[cfg(feature = "block-v2")]
pub(crate) mod wallet;
#[cfg(feature = "block-v2")]
mod witness;

#[cfg(feature = "block-v2")]
pub(crate) use batch_stark::{
    BatchStarks, MachineInputs, NativeBatchProof, PreparedBatch, ProofPlan, RegisteredKey,
    RegisteredMachine, RegisteredProof,
};
pub(crate) use budget::Limits;
pub use budget::Snapshot;
pub(crate) use buffer::Buffer;
pub(crate) use commitment::{ColumnSink, Commitments, RetainedTree};
pub use device::Identity;
pub(crate) use device::{inventory, Runtime};
pub(crate) use field::{FieldOperation, FieldProgram, FieldSpan};
pub(crate) use fri::{FinalPolynomial, Fri, FriLayer, FriLayerOpenings, FriRound, FriVector};
#[cfg(feature = "block-v2")]
pub(crate) use fri::{FriField, FriParameters, NativeFriProof};
#[cfg(feature = "block-v2")]
pub(crate) use hiding::{
    HiddenCommitment, HiddenOpenings, Hiding, HidingInput, QuotientHidingInput, RandomizationInput,
    TraceHidingInput,
};
pub(crate) use kernel::{Argument, Completion, Kernel, Launch, Module};
#[cfg(feature = "block-v2")]
pub(crate) use lookup::{LookupWitness, Lookups, PreparedLookup};
pub(crate) use matrix::Matrix;
pub(crate) use opening::{DeviceOpening, OpeningAccumulator, Openings};
#[cfg(feature = "block-v2")]
pub(crate) use pcs::{NativeHidingProof, OpeningPoints, OpeningRound, PcsOpenings};
#[cfg(feature = "block-v2")]
pub(crate) use public::PublicArithmetic;
pub(crate) use query::QueryRows;
#[cfg(feature = "block-v2")]
pub(crate) use quotient::{
    CacheLimits, CacheSnapshot, PreparedQuotient, QuotientInputs, Quotients, Specialization,
};
pub(crate) use random::{DeviceRandom, RandomWords, Randoms, ReplaySalts};
pub(crate) use scalars::{DomainValues, Scalars};
#[cfg(feature = "block-v2")]
pub(crate) use stark::{
    NativeStarkConfig, NativeStarkProof, PreparedStark, StarkField, StarkRandomness, Starks,
};
pub(crate) use transcript::{Transcript, TranscriptAttempt, Transcripts};
pub(crate) use transform::Transforms;

type Result<T> = std::result::Result<T, String>;

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn cleanup(result: Result<()>, operation: &str) {
    if let Err(error) = result {
        eprintln!("fatal CUDA cleanup failure operation={operation}: {error}");
        std::process::abort();
    }
}

#[cfg(feature = "block-v2")]
pub(crate) use wallet::{NativeWalletTrace, Wallets};
#[cfg(feature = "block-v2")]
pub(crate) use witness::{ExecutionTrace, PreparedWitness, PreprocessingTrace, Witnesses};
