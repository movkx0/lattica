//! Native CUDA primitives for the bounded prover. No OpenCL dependency and no
//! CPU kernel fallback. Proof-stage integration must explicitly select these
//! primitives; compiling this feature alone does not claim CUDA proof coverage.
mod budget;
mod buffer;
mod commitment;
mod compiler;
mod device;
mod field;
#[cfg(feature = "block-v2")]
mod hiding;
mod kernel;
mod matrix;
mod query;
mod random;
mod scalars;
#[cfg(feature = "block-v2")]
mod quotient;
#[cfg(test)]
mod tests;
mod transcript;
mod transform;

pub(crate) use budget::{Limits, Snapshot};
pub(crate) use buffer::Buffer;
pub(crate) use commitment::{ColumnSink, Commitments, RetainedTree};
pub(crate) use device::{inventory, Identity, Runtime};
pub(crate) use field::{FieldOperation, FieldProgram, FieldSpan};
#[cfg(feature = "block-v2")]
pub(crate) use hiding::{HiddenCommitment, HiddenOpenings, Hiding, HidingInput, QuotientHidingInput, TraceHidingInput};
pub(crate) use kernel::{Argument, Completion, Kernel, Launch, Module};
pub(crate) use matrix::Matrix;
pub(crate) use query::QueryRows;
pub(crate) use random::{DeviceRandom, Randoms, RandomWords, ReplaySalts};
pub(crate) use scalars::{DomainValues, Scalars};
#[cfg(feature = "block-v2")]
pub(crate) use quotient::{
    CacheLimits, CacheSnapshot, PreparedQuotient, QuotientInputs, Quotients, Specialization,
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
