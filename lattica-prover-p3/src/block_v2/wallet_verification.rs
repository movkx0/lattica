//! Admission for caller-owned wallet proof inputs and release x86_64 numerical
//! payload lifetimes. Enclosing runtime and physical reservations are separate.
use super::{profile, WalletProof};
use crate::config::Val;
use p3_field::PrimeCharacteristicRing;

#[path = "wallet_verification/air.rs"]
pub(crate) mod air;
#[path = "wallet_verification/decoded.rs"]
pub(crate) mod decoded;
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
#[path = "wallet_verification/intake.rs"]
pub(crate) mod intake;
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
#[path = "wallet_verification/scratch.rs"]
pub(crate) mod scratch;
#[path = "wallet_verification/storage.rs"]
mod storage;
pub(crate) const PROOF_BACKING_LIMIT: usize = 64 << 20;
const MAX_PUBLIC: usize = crate::htlc_air::N_PUBLIC;
const MAX_DEGREE_BITS: usize = 32 - profile::LOG_BLOWUP;
const ROUNDS: usize = 3;

pub(crate) struct Inputs {
    public: [Val; MAX_PUBLIC + 16],
    len: usize,
    pub(crate) proof_backing_bytes: usize,
}

impl Inputs {
    pub(crate) fn public(&self) -> &[Val] {
        &self.public[..self.len]
    }
}

pub(crate) fn inputs(wallet: &WalletProof, htlc: bool) -> Result<Inputs, &'static str> {
    let count = if htlc {
        crate::htlc_air::N_PUBLIC
    } else {
        crate::joinsplit_air::N_PUBLIC
    };
    if count > MAX_PUBLIC || wallet.public.len() != count {
        return Err("wallet verification public shape");
    }
    Envelope::new(wallet.proof.degree_bits, htlc)?.check(&wallet.proof)?;
    let proof_backing_bytes = storage::proof_bytes(wallet)?;
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    scratch::Plan::new(wallet.proof.degree_bits, htlc)?.admit(scratch::TEMPORARY_LIMIT_BYTES)?;
    let mut public = [Val::ZERO; MAX_PUBLIC + 16];
    public[..count].copy_from_slice(&wallet.public);
    let context = super::super::commitment::Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: wallet.chain,
    };
    for (slot, value) in public[count..count + 16]
        .iter_mut()
        .zip(context.to_fields())
    {
        *slot = Val::from_u64(value);
    }
    Ok(Inputs {
        public,
        len: count + 16,
        proof_backing_bytes,
    })
}

struct Envelope {
    degree: usize,
    log_lde: usize,
    widths: [usize; ROUNDS],
    matrices: [usize; ROUNDS],
}

impl Envelope {
    fn new(degree: usize, htlc: bool) -> Result<Self, &'static str> {
        // Goldilocks 2-adicity and the fixed blowup bound all shifts and loops.
        if !(1..=MAX_DEGREE_BITS).contains(&degree) {
            return Err("wallet verification degree envelope");
        }
        Ok(Self {
            degree,
            log_lde: degree + profile::LOG_BLOWUP,
            widths: [
                3,
                if htlc {
                    crate::htlc_air::WIDTH
                } else {
                    crate::joinsplit_air::WIDTH
                },
                3,
            ],
            matrices: [1, 1, profile::MAX_QUOTIENT_CHUNKS],
        })
    }

    fn check(&self, proof: &p3_uni_stark::Proof<profile::Config>) -> Result<(), &'static str> {
        let error = "wallet verification proof exceeds profile envelope";
        let cap_fits = |cap: &p3_symmetric::MerkleCap<Val, [Val; 4]>, log: usize| {
            // Derived deserialization can bypass MerkleCap::new's invariant.
            // Require nonempty, power-of-two roots before handing caps upstream.
            let roots = cap.roots().len();
            roots.is_power_of_two() && roots <= 1usize << log.min(profile::CAP_HEIGHT)
        };
        let optional_fits = |values: &Option<Vec<profile::Challenge>>, width: usize| {
            values.as_ref().is_none_or(|v| v.len() <= width)
        };
        let commits = &proof.commitments;
        if !cap_fits(&commits.trace, self.log_lde)
            || !cap_fits(&commits.quotient_chunks, self.log_lde)
            || commits
                .random
                .as_ref()
                .is_some_and(|cap| !cap_fits(cap, self.log_lde))
        {
            return Err(error);
        }
        let values = &proof.opened_values;
        if values.trace_local.len() > self.widths[1]
            || !optional_fits(&values.trace_next, self.widths[1])
            || !optional_fits(&values.preprocessed_local, 0)
            || !optional_fits(&values.preprocessed_next, 0)
            || !optional_fits(&values.random, 3)
            || values.quotient_chunks.len() > self.matrices[2]
            || values.quotient_chunks.iter().any(|row| row.len() > 3)
        {
            return Err(error);
        }
        let (hiding, fri) = &proof.opening_proof;
        if hiding.len() > ROUNDS
            || fri.commit_phase_commits.len() > self.degree
            || fri.commit_pow_witnesses.len() > self.degree
            || fri.final_poly.len() > 1
            || fri.query_proofs.len() > profile::NUM_QUERIES
        {
            return Err(error);
        }
        for (round, matrices) in hiding.iter().enumerate() {
            let points = if round == 1 { 2 } else { 1 };
            if matrices.len() > self.matrices[round]
                || matrices.iter().any(|matrix| {
                    matrix.len() > points
                        || matrix
                            .iter()
                            .any(|row| row.len() > profile::NUM_RANDOM_CODEWORDS)
                })
            {
                return Err(error);
            }
        }
        for (layer, cap) in fri.commit_phase_commits.iter().enumerate() {
            if !cap_fits(cap, self.log_lde - layer - 1) {
                return Err(error);
            }
        }
        for query in &fri.query_proofs {
            if query.input_proof.len() > ROUNDS || query.commit_phase_openings.len() > self.degree {
                return Err(error);
            }
            for (round, opening) in query.input_proof.iter().enumerate() {
                if opening.opened_values.len() > self.matrices[round]
                    || opening
                        .opened_values
                        .iter()
                        .any(|row| row.len() > self.widths[round] + profile::NUM_RANDOM_CODEWORDS)
                    || !authentication_fits(
                        &opening.opening_proof,
                        self.matrices[round],
                        self.log_lde,
                    )
                {
                    return Err(error);
                }
            }
            for (layer, opening) in query.commit_phase_openings.iter().enumerate() {
                if opening.log_arity != 1
                    || opening.sibling_values.len() > 1
                    || !authentication_fits(&opening.opening_proof, 1, self.log_lde - layer - 1)
                {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

fn authentication_fits(
    proof: &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    matrices: usize,
    log_height: usize,
) -> bool {
    proof.0.len() <= matrices
        && proof.0.iter().all(|row| row.len() <= 4)
        && proof.1.len() <= log_height.saturating_sub(profile::CAP_HEIGHT)
}

pub(crate) fn error(label: &'static str, error: &impl core::fmt::Debug) -> super::Error {
    struct Labeled<'a, T> {
        label: &'static str,
        error: &'a T,
    }
    impl<T: core::fmt::Debug> core::fmt::Debug for Labeled<'_, T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}: {:?}", self.label, self.error)
        }
    }
    super::super::machine::backend::verification_error(&Labeled { label, error }).into()
}

#[cfg(all(test, feature = "stream"))]
#[path = "wallet_verification/tests.rs"]
mod tests;
