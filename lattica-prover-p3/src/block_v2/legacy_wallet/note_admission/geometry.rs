//! Allocation-free fixed legacy geometry; no caller chooses protocol parameters.
use super::Error;
use crate::block_v2::pcs_field::PcsField;
use crate::{config, joinsplit_air as js};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Geometry {
    pub inputs: usize,
    pub outputs: usize,
    pub value_bits: usize,
    pub membership_depth: usize,
    pub active_rows: usize,
    pub rows: usize,
    pub width: usize,
    pub periodic_columns: usize,
    pub public_values: usize,
    pub extension_degree: usize,
    pub log_blowup: usize,
    pub queries: usize,
    pub max_log_arity: usize,
    pub cap_height: usize,
    pub random_codewords: usize,
    pub query_pow_bits: usize,
    pub quotient_chunks: usize,
}

impl Geometry {
    pub fn pinned() -> Result<Self, Error> {
        if cfg!(debug_assertions)
            || !cfg!(target_arch = "x86_64")
            || !cfg!(all(feature = "gpu", feature = "stream"))
            || core::mem::size_of::<usize>() != 8
            || (js::N_IN, js::M_OUT, js::BITS, js::DEPTH) != (2, 2, 52, 32)
            || (js::HEIGHT, js::WIDTH, js::N_PERIODIC, js::N_PUBLIC) != (4096, 19, 33, 26)
            || (config::LOG_BLOWUP, config::NUM_QUERIES, config::CAP_HEIGHT) != (4, 96, 6)
            || (config::NUM_RANDOM_CODEWORDS, config::QUERY_POW_BITS) != (4, 16)
            || <config::Challenge as PcsField>::MAX_LOG_ARITY != 4
            || <config::Challenge as PcsField>::NUM_QUERIES != 96
            || core::mem::size_of::<config::Val>() != 8
            || core::mem::size_of::<config::Challenge>() != 16
        {
            return Err(Error::Geometry);
        }
        Ok(Self {
            inputs: 2,
            outputs: 2,
            value_bits: 52,
            membership_depth: 32,
            active_rows: (2 * (4 + 32) + 2 * 2 + 2 + 2) * 32,
            rows: js::HEIGHT,
            width: js::WIDTH,
            periodic_columns: js::N_PERIODIC,
            public_values: js::N_PUBLIC,
            extension_degree: 2,
            log_blowup: config::LOG_BLOWUP,
            queries: config::NUM_QUERIES,
            max_log_arity: 4,
            cap_height: config::CAP_HEIGHT,
            random_codewords: config::NUM_RANDOM_CODEWORDS,
            query_pow_bits: config::QUERY_POW_BITS,
            // The reviewed degree-eight legacy AIR with hiding has 16 chunks.
            // The eventual producer must also compare compiled degree metadata.
            quotient_chunks: 16,
        })
    }

    pub(super) fn check(self) -> Result<(), Error> {
        if self != Self::pinned()? {
            return Err(Error::Geometry);
        }
        Ok(())
    }
}
