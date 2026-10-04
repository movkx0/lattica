//! Version-separated, UNFROZEN candidate parameters. No reduced-security fallback.

use p3_air::{symbolic::SymbolicAirBuilder, Air};
use p3_commit::ExtensionMmcs;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_uni_stark::{AirLayout, ProvenSecurity, StarkConfig, StarkSecurityParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[cfg(feature = "gpu")]
use super::gpu_hash::CandidateMmcs as ValMmcs;
#[cfg(feature = "stream")]
use super::normalization_workspace::HeapNormalizedDft as Dft;
#[cfg(not(feature = "stream"))]
use crate::config::Dft;
#[cfg(not(feature = "gpu"))]
use crate::config::ValMmcs;
use crate::config::{Challenger, MyCompress, MyHash, Val};

/// Research namespace, NOT a reviewed verifier/program identity or activation ID.
/// Freeze a new identity after the recursive program and complete profile are reviewed.
pub const CANDIDATE_PROFILE_ID: [u8; 32] = *b"LATTICA-BLOCK-V2-CANDIDATE-00001";
pub const MAX_TRANSACTIONS: usize = 64;
pub const TREE_DEPTH: usize = 6;
pub const BLOCK_INTERVAL_SECS: u64 = 12 * 60;
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
// Research node transport only. Wallets keep their existing encoding/profile.
// The wide registry and program manifest bind this revision explicitly.
#[cfg(not(feature = "block-v2-wide-lanes"))]
pub const NODE_CODEC_REVISION: u64 = 1;
#[cfg(feature = "block-v2-wide-lanes")]
pub const NODE_CODEC_REVISION: u64 = 2;
pub const LOG_BLOWUP: usize = 4;
pub const NUM_QUERIES: usize = 128;
pub const CAP_HEIGHT: usize = 6;
pub const NUM_RANDOM_CODEWORDS: usize = 4;
pub const QUERY_POW_BITS: usize = 16;
/// floor(log2(p^3)), not 3 * floor(log2(p)). Goldilocks p = 2^64 - 2^32 + 1.
pub const CHALLENGE_FIELD_BITS: usize = 191;
/// Conservative floor for birthday collision resistance of four Goldilocks elements.
pub const HASH_COLLISION_BITS: usize = 127;
pub const MIN_TREE_SECURITY_BITS: usize = 100;
/// 64 wallet proofs + 64 leaf/empty wrappers + 63 binary merge proofs.
/// This is an accounting assumption, not evidence that those recursive proofs exist.
pub const MAX_TREE_PROOF_STATEMENTS: usize = 3 * MAX_TRANSACTIONS - 1;

pub type Challenge = CubicTrinomialExtensionField<Val>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Pcs = super::quotient_pcs::CandidatePcs;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub fn fri<M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs,
    }
}

/// Independent, fresh 256-bit CSPRNG seeds for salts and hiding codewords.
/// No public seed-from-u64 or deterministic proving entry point.
pub fn make_config() -> Config {
    config_with_rngs(
        ChaCha20Rng::from_rng(&mut rand::rng()),
        ChaCha20Rng::from_rng(&mut rand::rng()),
        None,
        false,
    )
}

/// Candidate execution proving only. Default verification and wallet proving
/// never consult these switches. Each proof receives independent full-entropy
/// seeds; optional quotient fusion draws a third seed, never cloning the inner
/// PCS seed. Resident commitments share the existing hiding/salt streams.
pub(crate) fn make_proving_config() -> Config {
    let fusion = super::quotient_pcs::research_enabled();
    let resident = resident_research_enabled();
    if !fusion && !resident {
        return make_config();
    }
    config_with_rngs(
        ChaCha20Rng::from_rng(&mut rand::rng()),
        ChaCha20Rng::from_rng(&mut rand::rng()),
        fusion.then(|| ChaCha20Rng::from_rng(&mut rand::rng())),
        resident,
    )
}

/// ONLY for committing immutable, public preprocessing. Never prove a witness
/// with this config: deterministic salts/random codewords are not zero knowledge.
pub(crate) fn preprocessing_config() -> Config {
    config_with_rngs(
        ChaCha20Rng::from_seed([0; 32]),
        ChaCha20Rng::from_seed([0; 32]),
        None,
        resident_research_enabled(),
    )
}

fn resident_research_enabled() -> bool {
    #[cfg(feature = "gpu")]
    {
        super::resident_pcs::research_enabled()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

fn config_with_rngs(
    salt_rng: ChaCha20Rng,
    hiding_rng: ChaCha20Rng,
    quotient_rng: Option<ChaCha20Rng>,
    resident: bool,
) -> Config {
    let perm = default_goldilocks_poseidon2_8();
    let val_mmcs = ValMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm.clone()),
        CAP_HEIGHT,
        salt_rng,
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let pcs = if resident {
        #[cfg(feature = "gpu")]
        {
            Pcs::new_resident(
                Dft::default(),
                val_mmcs,
                fri(challenge_mmcs),
                NUM_RANDOM_CODEWORDS,
                hiding_rng,
                super::resident_pcs::host_output_budget(),
            )
            .expect("resident PCS configuration failed; no silent fallback")
        }
        #[cfg(not(feature = "gpu"))]
        {
            panic!("resident PCS requires the gpu feature")
        }
    } else {
        Pcs::new(
            Dft::default(),
            val_mmcs,
            fri(challenge_mmcs),
            NUM_RANDOM_CODEWORDS,
            hiding_rng,
        )
    };
    #[cfg(feature = "gpu")]
    let pcs = if resident && super::resident_pcs::research_openings_enabled() {
        pcs.with_gpu_openings()
            .expect("GPU opening selection failed; no silent fallback")
    } else {
        pcs
    };
    let pcs = match quotient_rng {
        Some(rng) => pcs.with_fused_quotients(rng),
        None => pcs,
    };
    Config::new(pcs, Challenger::new(perm))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    InvalidHeight,
    QuotientDoesNotFit,
    EmptyComposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AirSecurity {
    pub constraints: usize,
    pub max_constraint_degree: usize,
    pub hiding_degree_bits: u32,
    pub proven_bits: usize,
}

/// Only for the base-only candidate AIRs: a future lookup/permutation AIR must
/// supply its complete layout and redo this calculation. Height is exact, not rounded.
pub(crate) fn base_air_security<A>(air: &A, height: usize) -> Result<AirSecurity, SecurityError>
where
    A: Air<SymbolicAirBuilder<Val, Challenge>> + Air<SymbolicAirBuilder<Val>>,
{
    // Hiding doubles the trace domain; blowup must also fit Goldilocks' 2-adicity.
    if !height.is_power_of_two() || height.trailing_zeros() as usize + 1 + LOG_BLOWUP > 32 {
        return Err(SecurityError::InvalidHeight);
    }
    let perm = default_goldilocks_poseidon2_8();
    // Security calculation never produces commitments; its salts are unused.
    let mmcs = ValMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm),
        CAP_HEIGHT,
        ChaCha20Rng::from_seed([0; 32]),
    );
    let params = StarkSecurityParams::from_air::<Val, Challenge, A, ChallengeMmcs>(
        &fri(ChallengeMmcs::new(mmcs)),
        air,
        AirLayout::from_air::<Val>(air),
        CHALLENGE_FIELD_BITS,
        HASH_COLLISION_BITS,
        2,
    );
    // Match P3's quotient-chunk calculation, including hiding's extra factor.
    let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, A>(
        air,
        AirLayout::from_air::<Val>(air),
        1,
    );
    if log_chunks > LOG_BLOWUP || params.air_max_constraint_degree > (1 << LOG_BLOWUP) + 1 {
        return Err(SecurityError::QuotientDoesNotFit);
    }
    Ok(AirSecurity {
        constraints: params.num_constraints,
        max_constraint_degree: params.air_max_constraint_degree,
        hiding_degree_bits: height.trailing_zeros() + 1,
        proven_bits: ProvenSecurity::compute(&params, height * 2).security_bits(),
    })
}

/// Conservative union-bound arithmetic: min(individual bits) - ceil(log2(count)).
/// Caller MUST include wallet, wrapper, empty and merge proofs, with their actual
/// AIR-derived bounds. Passing only the leaf bound is NOT a complete-tree analysis.
pub fn composition_bits(
    min_individual_bits: usize,
    proof_count: usize,
) -> Result<usize, SecurityError> {
    if proof_count == 0 {
        return Err(SecurityError::EmptyComposition);
    }
    let loss = usize::BITS - (proof_count - 1).leading_zeros();
    Ok(min_individual_bits.saturating_sub(loss as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_extension_is_cubic_trinomial() {
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

        assert_eq!(<Challenge as BasedVectorSpace<Val>>::DIMENSION, 3);
        let x =
            Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO]).unwrap();
        assert_eq!(x * x * x, x + Challenge::ONE, "candidate uses X^3 - X - 1");
        assert_eq!(CANDIDATE_PROFILE_ID.len(), 32);
        assert_eq!(MAX_TRANSACTIONS, 1 << TREE_DEPTH);
        assert_eq!(CHALLENGE_FIELD_BITS, 191);
    }

    #[test]
    fn composition_charges_all_proofs_not_just_depth() {
        assert_eq!(composition_bits(127, 1), Ok(127));
        assert_eq!(composition_bits(127, 2), Ok(126));
        assert_eq!(composition_bits(127, 3), Ok(125));
        assert_eq!(composition_bits(127, MAX_TREE_PROOF_STATEMENTS), Ok(119));
        assert_eq!(composition_bits(3, 191), Ok(0));
        assert_eq!(
            composition_bits(127, 0),
            Err(SecurityError::EmptyComposition)
        );
        assert_eq!(
            composition_bits(127, usize::MAX),
            Ok(127 - usize::BITS as usize)
        );
    }
}
