//! Experimental transaction framing for compact post-quantum RingCT research.
//!
//! Decoding and body binding do not verify a proof, authorize a spend, or establish
//! privacy. Cryptographic fields remain opaque until a real scheme verifies them.
//! This crate is not connected to Lattica's production transaction acceptance.

pub mod codec;
pub mod cost;
#[cfg(feature = "opencl")]
pub mod opencl;
pub mod error;
#[cfg(feature = "native-matrict")]
pub mod native;
pub mod native_packet;
pub mod transaction;
pub mod rust_verify;
#[cfg(feature = "recursive")]
pub mod recursive_aggregation;
#[cfg(feature = "recursive")]
pub mod shake_air;
#[cfg(feature = "recursive")]
pub mod aes_air;
#[cfg(feature = "recursive")]
pub mod crypto_join;
#[cfg(feature = "recursive")]
pub mod ntt_air;
#[cfg(feature = "recursive")]
pub mod poly_air;
#[cfg(feature = "recursive")]
pub mod affine_air;
#[cfg(feature = "recursive")]
pub mod permutation_air;
#[cfg(feature = "recursive")]
pub mod linear_map_air;
#[cfg(feature = "recursive")]
pub mod statement_air;
#[cfg(feature = "recursive")]
pub mod proof_air;
#[cfg(feature = "recursive")]
pub mod g_bound_air;
#[cfg(feature = "recursive")]
pub mod transcript_air;
#[cfg(feature = "recursive")]
pub mod aes_lane_air;
#[cfg(feature = "recursive")]
pub mod component_tree;
#[cfg(feature = "recursive")]
pub mod obligation_manifest;
#[cfg(feature = "recursive")]
pub mod sparse_air;
#[cfg(feature = "recursive")]
pub mod uniform_air;
#[cfg(feature = "recursive")]
pub mod sampler_bridge;
#[cfg(feature = "recursive")]
pub mod transcript_bridge;
#[cfg(feature = "recursive")]
pub mod graph_proofs;
#[cfg(feature = "recursive")]
pub mod request_bridge;
#[cfg(feature = "recursive")]
pub mod graph_tree;
#[cfg(feature = "recursive")]
pub mod producer_branch;

#[cfg(all(test, feature = "native-matrict", feature = "recursive"))]
pub(crate) mod native_test_fixture;
#[cfg(feature = "recursive")]
pub mod graph_crypto;
#[cfg(feature = "recursive")]
pub(crate) mod outer_cache;
#[cfg(feature = "recursive")]
pub mod graph_auxiliary;
#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod graph_algebra_candidates;
#[cfg(feature = "recursive")]
pub mod graph_sources;
#[cfg(feature = "recursive")]
pub mod spend_pipeline;
#[cfg(feature = "recursive")]
pub mod spend_pair;

pub use error::Error;
pub use transaction::{
    Input, Limits, Output, ProfileId, PublicTransaction, RingReference, Transaction,
};

#[cfg(feature = "recursive")]
pub mod execution;

#[cfg(feature = "recursive")]
pub mod proof_cache_policy;
