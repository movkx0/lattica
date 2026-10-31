//! Original graph storage retained across native callback completion.
//!
//! The live GPU entry uses `inputs::FixedInputs` before importing anything.
//! The ownership constructor is test-only until the remaining constructor
//! runtime, error/report and downstream lifetimes have admission.
//! Tests lower the actual relation after reserving decoded inputs, graph vectors
//! and symbolic/memo/dependency/raw-adapter scratch; no function accepts an already-built
//! graph or arbitrary callback. This is not complete native-producer authority.
pub(super) mod bounds;
pub(super) mod inputs;

pub(super) mod collections;
mod footprint;
#[cfg(test)]
mod owned;
mod raw_adapters;
mod symbolic;
pub(crate) use footprint::{CheckedInitialGraph, InitialSourceFootprint};
#[cfg(test)]
pub(crate) use owned::{Construction, OwnedGraph, PendingGraph};
