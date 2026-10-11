//! Maximum exact-capacity backing produced by the concrete wallet decoder.
//!
//! This describes envelope-admitted shapes, not arbitrary caller-owned Vec
//! capacities. The decoder separately caps every request, including malformed
//! shapes, before allocation. Canonical re-encoding ends before it returns.

use super::{profile, Envelope, Val, MAX_DEGREE_BITS, ROUNDS};
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use crate::block_v2::gpu_hash::CandidateMmcs as ValMmcs;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::config::ValMmcs;

type Ext = profile::Challenge;
type Cap = p3_symmetric::MerkleCap<Val, [Val; 4]>;
type Opening = p3_commit::BatchOpening<Val, ValMmcs>;
type Query = p3_fri::QueryProof<Ext, profile::ChallengeMmcs, Vec<Opening>>;
type Step = p3_fri::CommitPhaseProofStep<Ext, profile::ChallengeMmcs>;

pub(crate) const STORAGE_LIMIT: usize = 8 << 20;
const ERROR: &str = "wallet decoded storage profile";

pub(super) fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b).ok_or(ERROR)
}
fn mul(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_mul(b).ok_or(ERROR)
}

#[derive(Default)]
struct Bytes(usize);
impl Bytes {
    fn exact<T>(&mut self, count: usize) -> Result<(), &'static str> {
        self.0 = add(self.0, mul(count, core::mem::size_of::<T>())?)?;
        Ok(())
    }
    fn repeat(&mut self, bytes: Self, count: usize) -> Result<(), &'static str> {
        self.0 = add(self.0, mul(bytes.0, count)?)?;
        Ok(())
    }
    fn cap(&mut self, log_height: usize) -> Result<(), &'static str> {
        self.exact::<[Val; 4]>(1 << log_height.min(profile::CAP_HEIGHT))
    }
    fn authentication(&mut self, matrices: usize, log_height: usize) -> Result<(), &'static str> {
        self.exact::<Vec<Val>>(matrices)?;
        self.exact::<Val>(mul(matrices, 4)?)?;
        self.exact::<[Val; 4]>(log_height.saturating_sub(profile::CAP_HEIGHT))
    }
}

pub(crate) fn backing_bytes(degree: usize, htlc: bool) -> Result<usize, &'static str> {
    let shape = Envelope::new(degree, htlc)?;
    let mut bytes = Bytes::default();
    bytes.exact::<Val>(if htlc {
        crate::htlc_air::N_PUBLIC
    } else {
        crate::joinsplit_air::N_PUBLIC
    })?;
    for _ in 0..3 {
        bytes.cap(shape.log_lde)?;
    }
    bytes.exact::<Ext>(add(mul(2, shape.widths[1])?, 3)?)?;
    bytes.exact::<Vec<Ext>>(shape.matrices[2])?;
    bytes.exact::<Ext>(mul(3, shape.matrices[2])?)?;
    // Optional preprocessing rows must be empty; they allocate no backing.
    bytes.exact::<Vec<Vec<Vec<Ext>>>>(ROUNDS)?;
    for (round, points) in [1, 2, 1].into_iter().enumerate() {
        let matrices = shape.matrices[round];
        bytes.exact::<Vec<Vec<Ext>>>(matrices)?;
        bytes.exact::<Vec<Ext>>(mul(matrices, points)?)?;
        bytes.exact::<Ext>(mul(mul(matrices, points)?, profile::NUM_RANDOM_CODEWORDS)?)?;
    }
    bytes.exact::<Cap>(degree)?;
    for layer in 0..degree {
        bytes.cap(shape.log_lde - layer - 1)?;
    }
    bytes.exact::<Val>(degree)?;
    bytes.exact::<Ext>(1)?;
    bytes.exact::<Query>(profile::NUM_QUERIES)?;
    let mut query = Bytes::default();
    query.exact::<Opening>(ROUNDS)?;
    for round in 0..ROUNDS {
        let matrices = shape.matrices[round];
        query.exact::<Vec<Val>>(matrices)?;
        query.exact::<Val>(mul(
            matrices,
            add(shape.widths[round], profile::NUM_RANDOM_CODEWORDS)?,
        )?)?;
        query.authentication(matrices, shape.log_lde)?;
    }
    query.exact::<Step>(degree)?;
    for layer in 0..degree {
        query.exact::<Ext>(1)?;
        query.authentication(1, shape.log_lde - layer - 1)?;
    }
    bytes.repeat(query, profile::NUM_QUERIES)?;
    Ok(bytes.0)
}

pub(crate) fn storage_limit() -> Result<usize, &'static str> {
    // Every term is nondecreasing in degree: caps saturate, paths and the
    // number of FRI layers grow. Check both AIR widths at the largest degree.
    let maximum = backing_bytes(MAX_DEGREE_BITS, false)?.max(backing_bytes(MAX_DEGREE_BITS, true)?);
    if add(maximum, profile::MAX_PROOF_BYTES)? > STORAGE_LIMIT {
        return Err(ERROR);
    }
    Ok(STORAGE_LIMIT)
}

#[cfg(all(test, feature = "stream"))]
#[path = "decoded/tests.rs"]
mod tests;
