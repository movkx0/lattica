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
    /// Retained matrix payload at the two compact-storage lifetime boundaries.
    ///
    /// Before quotient evaluation, preprocessing, main and permutation data
    /// retain half of their logical LDE rows. Afterwards main/permutation are
    /// reduced to degree prefixes, quotient chunks and the random round retain
    /// degree prefixes, and preprocessing keeps its half-LDE prefix for reuse.
    /// See resident_pcs, gpu_hash::compact_data and gpu_quotient_prover.
    ///
    /// This excludes salts, Merkle trees, natural matrices, compiler storage,
    /// temporary buffers and driver overhead. It is a necessary payload bound,
    /// not complete lifetime or peak-memory admission.
    pub fn compact_retained_lde_lower_bound(&self) -> Result<u64, AdmissionError> {
        if self.quotient_chunks > (1 << profile::LOG_BLOWUP) {
            return Err(AdmissionError::QuotientDegree);
        }
        let random = profile::NUM_RANDOM_CODEWORDS as u64;
        let main = (self.main_width as u64)
            .checked_add(random)
            .ok_or(AdmissionError::Overflow)?;
        let permutation = (self.permutation_width_base as u64)
            .checked_add(random)
            .ok_or(AdmissionError::Overflow)?;
        let preprocessing = self.preprocessed_width as u64;
        let random_round = 3u64.checked_add(random).ok_or(AdmissionError::Overflow)?;
        let quotient = (self.quotient_chunks as u64)
            .checked_mul(random_round)
            .ok_or(AdmissionError::Overflow)?;
        let degree_rows = (self.height as u64)
            .checked_mul(2)
            .ok_or(AdmissionError::Overflow)?;
        let lde_rows = degree_rows
            .checked_mul(1 << profile::LOG_BLOWUP)
            .ok_or(AdmissionError::Overflow)?;
        let evaluation_cells = preprocessing
            .checked_add(main)
            .and_then(|n| n.checked_add(permutation))
            .and_then(|n| n.checked_mul(lde_rows / 2))
            .ok_or(AdmissionError::Overflow)?;
        let opening_cells = main
            .checked_add(permutation)
            .and_then(|n| n.checked_add(quotient))
            .and_then(|n| n.checked_add(random_round))
            .and_then(|n| n.checked_mul(degree_rows))
            .and_then(|n| preprocessing.checked_mul(lde_rows / 2)?.checked_add(n))
            .ok_or(AdmissionError::Overflow)?;
        evaluation_cells
            .max(opening_cells)
            .checked_mul(8)
            .ok_or(AdmissionError::Overflow)
    }

    /// Only valid when the active PCS actually uses compact prefixes.
    /// A separate phase-aware RAM/spill/GPU model is still required.
    pub fn check_compact_ram_lower_bound_with_budget(
        &self,
        budget: u64,
    ) -> Result<(), AdmissionError> {
        let required = self.compact_retained_lde_lower_bound()?;
        if required > budget {
            return Err(AdmissionError::RamLowerBound { required, budget });
        }
        Ok(())
    }

    pub fn check_ram_lower_bound(&self) -> Result<(), AdmissionError> {
        self.check_ram_lower_bound_with_budget(feasibility::RAM_BUDGET_BYTES)
    }

    /// A necessary lower bound, not complete lifetime resource admission.
    pub fn check_ram_lower_bound_with_budget(&self, budget: u64) -> Result<(), AdmissionError> {
        if self.retained_lde_bytes > budget {
            return Err(AdmissionError::RamLowerBound {
                required: self.retained_lde_bytes,
                budget,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod compact_admission_tests {
    use super::*;

    #[test]
    fn compact_layout_has_its_own_boundary_without_relaxing_full_storage() {
        let air = super::super::programs::shape(262144).unwrap();
        let analysis = analyze(&air).unwrap();
        let compact = analysis.compact_retained_lde_lower_bound().unwrap();
        // The wide controller admits an upper bound of 98 main columns,
        // 200 preprocessing columns and 55 permutation columns. Check the
        // compiled AIR against that bound, including the hiding codewords.
        #[cfg(feature = "block-v2-wide-lanes")]
        {
            assert_eq!(analysis.main_width, 94);
            assert_eq!(analysis.preprocessed_width, 200);
            assert!(analysis.permutation_width_base + 4 <= 55);
            assert_eq!(analysis.quotient_chunks, 16);
            assert!(analysis.retained_lde_bytes <= 31_675_383_808);
            let mut upper = analysis.clone();
            upper.permutation_width_base = 51;
            assert_eq!(upper.compact_retained_lde_lower_bound(), Ok(11_844_714_496));
            assert!(compact <= 11_844_714_496);
        }
        assert!(compact < analysis.retained_lde_bytes);
        assert!(analysis.check_ram_lower_bound_with_budget(compact).is_err());
        assert_eq!(
            analysis.check_compact_ram_lower_bound_with_budget(compact),
            Ok(())
        );
        assert_eq!(
            analysis.check_compact_ram_lower_bound_with_budget(compact - 1),
            Err(AdmissionError::RamLowerBound {
                required: compact,
                budget: compact - 1
            })
        );
        assert_eq!(
            analysis.check_ram_lower_bound_with_budget(analysis.retained_lde_bytes),
            Ok(())
        );
    }

    #[test]
    fn compact_admission_rejects_unsupported_domains_and_overflow() {
        let mut analysis = analyze(&super::super::programs::shape(16).unwrap()).unwrap();
        analysis.quotient_chunks = 2 << profile::LOG_BLOWUP;
        assert_eq!(
            analysis.compact_retained_lde_lower_bound(),
            Err(AdmissionError::QuotientDegree)
        );
        analysis.quotient_chunks = 1 << profile::LOG_BLOWUP;
        analysis.height = usize::MAX;
        analysis.main_width = usize::MAX;
        assert_eq!(
            analysis.compact_retained_lde_lower_bound(),
            Err(AdmissionError::Overflow)
        );
    }
}
