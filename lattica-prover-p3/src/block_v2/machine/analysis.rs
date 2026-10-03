//! Pre-allocation geometry checks and partial security accounting. A successful
//! check is NOT a peak-memory guarantee or a recursive soundness certificate.
use super::program::Val;
use super::{MachineAir, WIDTH};
use crate::block_v2::{feasibility, profile};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks, get_max_constraint_degree,
};
use p3_lookup::{LogUpGadget, Lookups};
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Overflow,
    MultiplicityBound,
    QuotientDegree,
    RamLowerBound { required: u64, budget: u64 },
}

#[derive(Clone, Debug)]
pub struct MachineAnalysis {
    pub height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub permutation_width_base: usize,
    pub quotient_chunks: usize,
    pub constraints: usize,
    pub max_constraint_degree: usize,
    pub query_multiplicity_bound: u64,
    /// Retained LDE payloads alone. Excludes Merkle trees, natural matrices,
    /// transcript/compiler storage, temporary buffers, allocator and OS overhead.
    pub retained_lde_bytes: u64,
    /// FRI/ALI estimate only. LogUp and composition require separate accounting.
    pub fri_ali_bits: usize,
}

pub fn analyze(air: &MachineAir) -> Result<MachineAnalysis, AdmissionError> {
    let layout = AirLayout::from_air::<Val>(air);
    let gadget = LogUpGadget::new();
    let unpacked = Lookups::<Val>::from_air::<profile::Challenge, _>(air);
    let log_chunks = get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
        air, layout, &unpacked, 1, &gadget,
    );
    if log_chunks > profile::LOG_BLOWUP {
        return Err(AdmissionError::QuotientDegree);
    }
    let lookups = unpacked.pack_same_bus(&gadget, 1 << log_chunks);
    let constraints =
        get_constraint_layout::<Val, profile::Challenge, _, _>(air, layout, &lookups, &gadget)
            .total_constraints();
    let degree =
        get_max_constraint_degree::<Val, profile::Challenge, _, _>(air, layout, &lookups, &gadget);
    let height = air.program().height();
    let preprocessed_width = air.preprocessed_width();
    let permutation_width_base = (lookups.len() + 1) * 3;
    let quotient_chunks = 1usize << (log_chunks + 1);
    let query_multiplicity_bound = lookups
        .total_count_weight()
        .checked_mul(height as u64)
        .ok_or(AdmissionError::Overflow)?;
    if query_multiplicity_bound >= crate::block_v2::commitment::MODULUS {
        return Err(AdmissionError::MultiplicityBound);
    }
    // Hiding doubles each committed domain. Preprocessing has no random
    // codeword columns; main, permutation, quotient chunks and random round do.
    let random_cw = profile::NUM_RANDOM_CODEWORDS;
    let columns = WIDTH
        + random_cw
        + preprocessed_width
        + permutation_width_base
        + random_cw
        + quotient_chunks * (3 + random_cw)
        + 3
        + random_cw;
    let retained_lde_bytes = (height as u64)
        .checked_mul(2 << profile::LOG_BLOWUP)
        .and_then(|n| n.checked_mul(columns as u64))
        .and_then(|n| n.checked_mul(8))
        .ok_or(AdmissionError::Overflow)?;
    let params = StarkSecurityParams {
        fri_log_blowup: profile::LOG_BLOWUP,
        fri_log_final_poly_len: 0,
        fri_max_log_arity: 1,
        fri_num_queries: profile::NUM_QUERIES,
        fri_commit_proof_of_work_bits: 0,
        fri_query_proof_of_work_bits: profile::QUERY_POW_BITS,
        num_modulus_bits: profile::CHALLENGE_FIELD_BITS,
        collision_resistance: profile::HASH_COLLISION_BITS,
        num_constraints: constraints,
        air_max_constraint_degree: degree,
        max_combo: 2,
    };
    let fri_ali_bits =
        ProvenSecurity::compute_from_proof(height.ilog2() as usize + 1, &params).security_bits();
    Ok(MachineAnalysis {
        height,
        main_width: WIDTH,
        preprocessed_width,
        permutation_width_base,
        quotient_chunks,
        constraints,
        max_constraint_degree: degree,
        query_multiplicity_bound,
        retained_lde_bytes,
        fri_ali_bits,
    })
}

impl MachineAnalysis {
    pub fn check_ram_lower_bound(&self) -> Result<(), AdmissionError> {
        if self.retained_lde_bytes > feasibility::RAM_BUDGET_BYTES {
            return Err(AdmissionError::RamLowerBound {
                required: self.retained_lde_bytes,
                budget: feasibility::RAM_BUDGET_BYTES,
            });
        }
        Ok(())
    }
}
