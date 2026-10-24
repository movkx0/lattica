//! Ordered recursion over complete standalone MatRiCT relations.
//!
//! A graph child must carry a complete, source-trusted graph verifier key. An
//! aggregate child carries a key derived from this crate's checked compilation
//! and actual program registration. Every parent emits both full verifiers.
//! Native verification is admission, never a replacement for those constraints.
//!
//! Positions authenticate ordered relation instances, not unique ledger spends.
//! Repeated statements at different positions are permitted. Membership,
//! nullifier uniqueness, state transitions, fees and data availability remain
//! outside this relation.
//!
//! Canonical shape pairs adjacent entries left-to-right and carries an odd tail
//! unchanged. Equivalently, an internal interval of count n splits at the largest
//! power of two strictly smaller than n. A singleton is its complete graph proof;
//! no synthetic empty child or extra singleton wrapper proof is introduced.

mod contract;
#[cfg(feature = "opencl")]
pub mod opencl;
#[cfg(test)]
mod tests;
mod tree;

pub use contract::{
    Plan, BATCH_MODE, CONTEXT, COUNT, FIRST, LEAF_DOMAIN, LEVEL, MODE, NODE_DOMAIN, PUBLIC_VALUES,
    ROOT, TOTAL,
};
pub use lattica_pq_ringct_research::graph_tree::Geometry;
pub use tree::{
    compile_merge, BatchKey, BatchNode, BatchProof, Child, CompiledNode, GraphChild, PreparedNode,
    RecursiveWitnessCheck,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

fn err(value: impl std::fmt::Debug) -> Error {
    Error(format!("{value:?}"))
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
