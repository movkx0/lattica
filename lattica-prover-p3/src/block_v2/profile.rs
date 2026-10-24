//! Version-separated, UNFROZEN candidate parameters. No reduced-security fallback.

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::extension_mmcs::CandidateExtensionMmcs as ExtensionMmcs;
use p3_air::{symbolic::SymbolicAirBuilder, Air};
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use p3_commit::ExtensionMmcs;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_fri::FriParameters;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_uni_stark::{AirLayout, ProvenSecurity, StarkConfig, StarkSecurityParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub use super::challenger::CandidateChallenger as Challenger;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::gpu_hash::CandidateMmcs as ValMmcs;
#[cfg(feature = "stream")]
use super::normalization_workspace::HeapNormalizedDft as Dft;
#[cfg(not(feature = "stream"))]
use crate::config::Dft;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::config::ValMmcs;
use crate::config::{MyCompress, MyHash, Val};

/// Research namespace, NOT a reviewed verifier/program identity or activation ID.
/// Freeze a new identity after the recursive program and complete profile are reviewed.
#[cfg(not(feature = "block-v2-capacity-128"))]
pub const CANDIDATE_PROFILE_ID: [u8; 32] = *b"LATTICA-BLOCK-V2-CANDIDATE-00001";
#[cfg(feature = "block-v2-capacity-128")]
pub const CANDIDATE_PROFILE_ID: [u8; 32] = *b"LATTICA-BLOCK-V2-CANDIDATE-00128";
pub const MAX_TRANSACTIONS: usize = if cfg!(feature = "block-v2-capacity-128") {
    128
} else {
    64
};
pub const TREE_DEPTH: usize = MAX_TRANSACTIONS.ilog2() as usize;
pub const ROOT_FILE: &str = if cfg!(feature = "block-v2-capacity-128") {
    "node.7.0"
} else {
    "node.6.0"
};
/// Planning only: these sizes require wider count codecs and fresh qualification.
pub const PLANNED_CAPACITIES: [usize; 2] = [256, 512];
/// A full reference DAG has one wrapper per leaf and one node per merge.
pub const MAX_DAG_NODES: usize = 2 * MAX_TRANSACTIONS - 1;
pub const BLOCK_INTERVAL_SECS: u64 = 12 * 60;
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
// Research node transport only. Wallets keep their existing encoding/profile.
// The wide registry and program manifest bind this revision explicitly.
#[cfg(not(feature = "block-v2-wide-lanes"))]
pub const NODE_CODEC_REVISION: u64 = 1;
#[cfg(feature = "block-v2-wide-lanes")]
pub const NODE_CODEC_REVISION: u64 = 2;
pub const LOG_BLOWUP: usize = 4;
/// Canonical quotient partitions supported by the GPU compiler and PCS. This
/// bound is independent of the per-chunk LDE blowup; batch AIRs need 32 chunks.
pub(crate) const MAX_QUOTIENT_CHUNKS: usize = 32;
pub const NUM_QUERIES: usize = 128;
pub const CAP_HEIGHT: usize = 6;
pub const NUM_RANDOM_CODEWORDS: usize = 4;
pub const QUERY_POW_BITS: usize = 16;
/// floor(log2(p^3)), not 3 * floor(log2(p)). Goldilocks p = 2^64 - 2^32 + 1.
pub const CHALLENGE_FIELD_BITS: usize = 191;
/// Conservative floor for birthday collision resistance of four Goldilocks elements.
pub const HASH_COLLISION_BITS: usize = 127;
pub const MIN_TREE_SECURITY_BITS: usize = 100;
/// N wallet proofs + N leaf/empty wrappers + (N - 1) binary merge proofs.
/// This is an accounting assumption, not evidence that those recursive proofs exist.
pub const MAX_TREE_PROOF_STATEMENTS: usize = 3 * MAX_TRANSACTIONS - 1;

pub type Challenge = CubicTrinomialExtensionField<Val>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Pcs = super::quotient_pcs::CandidatePcs;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub(crate) mod verification;

/// Inventory the selected path, not the features compiled into this binary.
/// Existing GPU stages still perform host arithmetic/materialization around
/// their kernels, so Mixed is intentional and cannot admit GpuRequired.
pub(crate) fn proving_capabilities(recursive: bool) -> crate::proving::Capabilities {
    use crate::proving::{Capabilities, Profile};
    let capabilities = Capabilities::cpu(Profile::BlockV2Cubic, recursive, recursive);
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    {
        use crate::proving::{Backend, Stage};
        let mut capabilities = capabilities;
        if super::gpu_hash::is_enabled() {
            capabilities.set(Stage::Commitment, Backend::Mixed);
            capabilities.set(Stage::FriQuery, Backend::Mixed);
            if recursive {
                capabilities.set(Stage::Preprocessing, Backend::Mixed);
            }
            if recursive && resident_research_enabled() {
                capabilities.set(Stage::Transform, Backend::Mixed);
                if super::resident_pcs::research_openings_enabled() {
                    capabilities.set(Stage::Opening, Backend::Mixed);
                    capabilities.set(Stage::FriFold, Backend::Unknown);
                    if super::quotient_pcs::gpu_fri_resident_enabled() {
                        capabilities.set(Stage::FriFold, Backend::OpenCl);
                        capabilities.set(Stage::FinalPolynomial, Backend::OpenCl);
                    }
                }
            }
            if recursive && super::quotient_pcs::gpu_quotient_eval_enabled() {
                capabilities.set(Stage::Quotient, Backend::OpenCl);
            }
            if recursive && super::quotient_pcs::gpu_lookup_enabled() {
                capabilities.set(Stage::Lookup, Backend::OpenCl);
            }
            if recursive && super::quotient_pcs::gpu_witness_enabled() {
                // Registered statement hashes, constant folding and symbolic AIR
                // construction have GPU implementations. Keep this capability
                // mixed until every public-value path has measured coverage.
                capabilities.set(Stage::PublicValues, Backend::Mixed);
                capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
                // Registered construction, public salts and transforms use GPU
                // arithmetic. Keep admission conservative until operation-level
                // coverage and fallback rejection cover every entry point.
                capabilities.set(Stage::Preprocessing, Backend::Mixed);
            }
            if recursive && super::quotient_pcs::gpu_randomness_enabled() {
                capabilities.set(Stage::Randomness, Backend::OpenCl);
                capabilities.set(Stage::Hiding, Backend::OpenCl);
            }
            if recursive && super::quotient_pcs::gpu_quotient_resident_enabled() {
                capabilities.set(Stage::Scalar, Backend::Mixed);
            }
            if recursive && super::quotient_pcs::gpu_transcript_enabled() {
                capabilities.set(Stage::Transcript, Backend::OpenCl);
                capabilities.set(Stage::Grinding, Backend::OpenCl);
                capabilities.set(Stage::Scalar, Backend::OpenCl);
            }
        }
        capabilities
    }
    #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
    capabilities
}

/// A public derivation or compilation scope, not an entire recursive request.
pub(crate) fn public_scope_capabilities(
    stage: crate::proving::Stage,
) -> crate::proving::Capabilities {
    use crate::proving::{CoverageScope, Stage};
    let scope = match stage {
        Stage::PublicValues => CoverageScope::Statement,
        Stage::Preprocessing => CoverageScope::RegistryCompilation,
        _ => panic!("invalid public arithmetic scope"),
    };
    let capabilities =
        crate::proving::Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, true)
            .scoped(scope, &[stage]);
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let capabilities = {
        let mut capabilities = capabilities;
        if super::quotient_pcs::gpu_witness_enabled() {
            capabilities.set(stage, crate::proving::Backend::OpenCl);
        }
        capabilities
    };
    capabilities
}

pub(crate) fn recursive_request_capabilities() -> crate::proving::Capabilities {
    use crate::proving::{Capabilities, Profile, Stage};
    let capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    #[cfg(debug_assertions)]
    let capabilities = capabilities.with_constraint_audit();
    let mut capabilities = capabilities;
    for stage in registered_proof_capabilities().stages() {
        capabilities.set(stage.stage, stage.backend);
    }
    let public = public_scope_capabilities(Stage::PublicValues);
    capabilities.set(Stage::PublicValues, public.stages()[0].backend);
    capabilities
}

pub(crate) fn preprocessing_capabilities() -> crate::proving::Capabilities {
    use crate::proving::{CoverageScope, Stage};
    let stages = [
        Stage::Preprocessing,
        Stage::Randomness,
        Stage::Transform,
        Stage::Commitment,
    ];
    let capabilities = proving_capabilities(true).scoped(CoverageScope::Preprocessing, &stages);
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let capabilities = {
        let mut capabilities = capabilities;
        // Witness selection owns public trace construction and commitment.
        // Public salts follow the randomness switch in preprocessing_config;
        // retain that inherited backend so partial selection cannot be admitted.
        if super::quotient_pcs::gpu_witness_enabled() {
            for stage in [Stage::Preprocessing, Stage::Transform, Stage::Commitment] {
                capabilities.set(stage, crate::proving::Backend::OpenCl);
            }
        }
        capabilities
    };
    capabilities
}

/// Public values and the registered circuit are already inputs to this API.
/// Cached preprocessing must still belong to the selected witness backend.
pub(crate) fn registered_proof_capabilities() -> crate::proving::Capabilities {
    use crate::proving::{CoverageScope, Stage};
    let stages: Vec<_> = Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::PublicValues)
        .collect();
    let capabilities = proving_capabilities(true).scoped(CoverageScope::RegisteredProof, &stages);
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let capabilities = {
        let mut capabilities = capabilities;
        if super::quotient_pcs::gpu_witness_enabled() {
            // Witness admission requires the owned PCS interface. Its transforms,
            // commitments, opening reductions and query reconstruction have no
            // host matrix facade or small-input CPU fallback.
            for stage in [
                Stage::Preprocessing,
                Stage::Transform,
                Stage::Commitment,
                Stage::Opening,
                Stage::FriQuery,
            ] {
                capabilities.set(stage, crate::proving::Backend::OpenCl);
            }
        }
        capabilities
    };
    #[cfg(debug_assertions)]
    let capabilities = capabilities.with_constraint_audit();
    capabilities
}

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
        false,
    )
}

/// Explicit reference-native execution while an unrelated owned GPU session
/// is live. Proof parameters and fresh entropy match `make_config`; only this
/// configuration's commitment backend is forced to CPU. No global switches.
pub fn make_cpu_config() -> Config {
    config_with_cpu_selection(
        ChaCha20Rng::from_rng(&mut rand::rng()),
        ChaCha20Rng::from_rng(&mut rand::rng()),
        None,
        false,
        false,
        None,
        true,
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
        false,
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
        true,
    )
}

/// Fresh per-proof entropy for an explicitly selected owned GPU wallet path.
#[cfg(feature = "gpu")]
pub(crate) fn make_gpu_proving_config<E: super::pcs_field::PcsField>(
    assigned_host_bytes: usize,
) -> Result<super::pcs_field::ProvingConfig<E>, crate::proving::Error> {
    if !resident_research_enabled() || !super::quotient_pcs::research_enabled() {
        return Err(crate::proving::Error::ComponentRejected);
    }
    let budget = host_budget::selected_budget(assigned_host_bytes)?;
    if budget != assigned_host_bytes {
        return Err(crate::proving::Error::ComponentRejected);
    }
    Ok(config_with_rngs_and_host_budget(
        ChaCha20Rng::from_rng(&mut rand::rng()),
        ChaCha20Rng::from_rng(&mut rand::rng()),
        Some(ChaCha20Rng::from_rng(&mut rand::rng())),
        true,
        false,
        Some(budget),
    ))
}

fn resident_research_enabled() -> bool {
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    {
        super::resident_pcs::research_enabled()
    }
    #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
    {
        false
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
#[path = "profile_host_budget.rs"]
mod host_budget;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) use host_budget::{
    make_proving_config_with_host_budget, preprocessing_config_with_host_budget,
};

fn config_with_rngs<E: super::pcs_field::PcsField>(
    salt_rng: ChaCha20Rng,
    hiding_rng: ChaCha20Rng,
    quotient_rng: Option<ChaCha20Rng>,
    resident: bool,
    public_preprocessing: bool,
) -> super::pcs_field::ProvingConfig<E> {
    config_with_rngs_and_host_budget(
        salt_rng,
        hiding_rng,
        quotient_rng,
        resident,
        public_preprocessing,
        None,
    )
}

fn config_with_rngs_and_host_budget<E: super::pcs_field::PcsField>(
    salt_rng: ChaCha20Rng,
    hiding_rng: ChaCha20Rng,
    quotient_rng: Option<ChaCha20Rng>,
    resident: bool,
    public_preprocessing: bool,
    _host_budget: Option<usize>,
) -> super::pcs_field::ProvingConfig<E> {
    config_with_cpu_selection(
        salt_rng,
        hiding_rng,
        quotient_rng,
        resident,
        public_preprocessing,
        _host_budget,
        false,
    )
}

fn config_with_cpu_selection<E: super::pcs_field::PcsField>(
    salt_rng: ChaCha20Rng,
    hiding_rng: ChaCha20Rng,
    quotient_rng: Option<ChaCha20Rng>,
    resident: bool,
    public_preprocessing: bool,
    _host_budget: Option<usize>,
    force_cpu: bool,
) -> super::pcs_field::ProvingConfig<E> {
    assert!(!force_cpu || (!resident && quotient_rng.is_none() && !public_preprocessing));
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    if resident {
        super::challenger::resources::check_worker(super::quotient_pcs::gpu_transcript_enabled())
            .expect("GPU transcript worker admission failed before configuration");
    }
    let perm = default_goldilocks_poseidon2_8();
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let val_mmcs = if public_preprocessing {
        ValMmcs::new_public_preprocessing(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            CAP_HEIGHT,
        )
    } else {
        ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            CAP_HEIGHT,
            salt_rng,
        )
    };
    #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
    let _ = public_preprocessing;
    #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
    let val_mmcs = ValMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm.clone()),
        CAP_HEIGHT,
        salt_rng,
    );
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let val_mmcs = if force_cpu {
        val_mmcs.cpu_only()
    } else {
        val_mmcs
    };
    let challenge_mmcs = ExtensionMmcs::<Val, E, ValMmcs>::new(val_mmcs.clone());
    let mut parameters = fri(challenge_mmcs);
    parameters.max_log_arity = E::MAX_LOG_ARITY;
    parameters.num_queries = E::NUM_QUERIES;
    let pcs = if resident {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        {
            super::quotient_pcs::CandidatePcs::<E>::new_resident(
                Dft::default(),
                val_mmcs,
                parameters,
                NUM_RANDOM_CODEWORDS,
                hiding_rng,
                _host_budget.unwrap_or_else(super::resident_pcs::host_output_budget),
            )
            .expect("resident PCS configuration failed; no silent fallback")
        }
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        {
            panic!("resident PCS requires the gpu feature")
        }
    } else {
        super::quotient_pcs::CandidatePcs::<E>::new(
            Dft::default(),
            val_mmcs,
            parameters,
            NUM_RANDOM_CODEWORDS,
            hiding_rng,
        )
    };
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
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
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    let pcs = if resident && super::quotient_pcs::gpu_randomness_enabled() {
        if public_preprocessing {
            pcs.with_gpu_preprocessing_salts()
                .expect("GPU public randomness selection failed; no silent fallback")
        } else {
            pcs.with_gpu_randomness()
                .expect("GPU private randomness selection failed; no silent fallback")
        }
    } else {
        pcs
    };
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    if resident && !public_preprocessing && super::quotient_pcs::gpu_transcript_enabled() {
        let challenger = pcs
            .registered_gpu_challenger()
            .expect("registered GPU transcript selection failed; no fallback");
        return super::pcs_field::ProvingConfig::<E>::new(pcs, challenger);
    }
    super::pcs_field::ProvingConfig::<E>::new(pcs, Challenger::new(perm))
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
        assert_eq!(
            composition_bits(127, MAX_TREE_PROOF_STATEMENTS),
            Ok(127 - (TREE_DEPTH + 2))
        );
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
