//! Independent CPU verification with an enclosing temporary payload owner.
//! Numerical verification uses the unchanged quadratic P3 verifier and the
//! original join-split constraints. Process/thread/runtime admission is external.
use super::*;
use lattica_prover_p3::config;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

pub(super) mod air;
mod plan;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationError {
    UnsupportedHost,
    ResourceLimit,
    Geometry,
    EntropyUnavailable,
    ProofRejected,
}
impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VerificationError {}

/// Conservative cumulative requested backing. Reserving all allocations until
/// verification ends covers every possible overlap, including Rayon workers.
/// Native stacks, allocator overhead, entropy-provider internals, and tracing
/// subscribers are outside this payload model and remain campaign obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationPlan {
    configuration_bytes: usize,
    uni_stark_bytes: usize,
    transcript_bytes: usize,
    air_bytes: usize,
    fri_bytes: usize,
    periodic_construction_bytes: usize,
    periodic_retained_bytes: usize,
    periodic_evaluation_peak_bytes: usize,
    periodic_evaluation_cumulative_bytes: usize,
    cumulative_requested_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct VerificationReceipt {
    pub profile: &'static str,
    pub proof_profile: &'static str,
    pub verifier: &'static str,
    pub reserved_temporary_bytes: usize,
    pub cpu_verification_ns: u128,
    pub public_values: usize,
    pub independent_cpu_verification: bool,
    pub gpu_work_performed: bool,
    pub production_acceptance: bool,
}

/// Successful numerical verification borrows the immutable decoded artifact.
/// Membership-root approval and the spent-nullifier ledger remain external.
pub struct VerifiedArtifact<'a> {
    artifact: &'a DecodedArtifact,
    receipt: VerificationReceipt,
}
impl VerifiedArtifact<'_> {
    pub fn artifact(&self) -> &DecodedArtifact {
        self.artifact
    }
    pub fn receipt(&self) -> VerificationReceipt {
        self.receipt
    }
}

impl VerificationPlan {
    /// Allocation-free; debug's symbolic degree cross-check is not admitted.
    pub fn new() -> Result<Self, VerificationError> {
        if cfg!(debug_assertions) || !cfg!(target_arch = "x86_64") {
            return Err(VerificationError::UnsupportedHost);
        }
        Geometry::pinned().map_err(|_| VerificationError::Geometry)?;
        plan::build().map_err(|_| VerificationError::ResourceLimit)
    }
    pub fn required_temporary_bytes(&self) -> usize {
        self.cumulative_requested_bytes
    }

    pub fn verify<'a>(
        &self,
        artifact: &'a DecodedArtifact,
    ) -> Result<VerifiedArtifact<'a>, VerificationError> {
        // Private fields prevent a caller from lowering this plan. The proof is
        // immutable and the decoder has already admitted its exact geometry.
        let _reservation = artifact
            .reserve_scratch(self.cumulative_requested_bytes)
            .map_err(|_| VerificationError::ResourceLimit)?;
        let started = Instant::now();
        let config = fresh_config()?;
        p3_uni_stark::verify(
            &config,
            &air::VerifierAir,
            artifact.proof(),
            artifact.public(),
        )
        .map_err(|_| VerificationError::ProofRejected)?;
        Ok(VerifiedArtifact {
            artifact,
            receipt: VerificationReceipt {
                profile: crate::Profile::PrivateNoteDirectV1.tag(),
                proof_profile: "legacy_quadratic",
                verifier: "p3_uni_stark_original_joinsplit_constraints",
                reserved_temporary_bytes: self.cumulative_requested_bytes,
                cpu_verification_ns: started.elapsed().as_nanos(),
                public_values: 26,
                independent_cpu_verification: true,
                gpu_work_performed: false,
                production_acceptance: false,
            },
        })
    }
}

pub(super) fn fresh_config() -> Result<MyConfig, VerificationError> {
    // Exactly config::make_config's types, hashes, hiding and FRI parameters.
    // Fresh SysRng seeds avoid an unaccounted rand thread-local initialization.
    let salt = ChaCha20Rng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| VerificationError::EntropyUnavailable)?;
    let hiding = ChaCha20Rng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| VerificationError::EntropyUnavailable)?;
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(
        config::MyHash::new(perm.clone()),
        config::MyCompress::new(perm.clone()),
        config::CAP_HEIGHT,
        salt,
    );
    let parameters = config::production_fri(ChallengeMmcs::new(mmcs.clone()));
    if parameters.log_blowup != 4
        || parameters.log_final_poly_len != 0
        || parameters.max_log_arity != 4
        || parameters.num_queries != 96
        || parameters.commit_proof_of_work_bits != 0
        || parameters.query_proof_of_work_bits != 16
        || config::NUM_RANDOM_CODEWORDS != 4
        || config::CAP_HEIGHT != 6
    {
        return Err(VerificationError::Geometry);
    }
    let pcs = config::MyPcs::new(
        config::Dft::default(),
        mmcs,
        parameters,
        config::NUM_RANDOM_CODEWORDS,
        hiding,
    );
    Ok(MyConfig::new(pcs, config::Challenger::new(perm)))
}
