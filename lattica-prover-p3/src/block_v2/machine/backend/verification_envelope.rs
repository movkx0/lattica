//! Allocation-free length admission for the pinned single-machine verifier.
//!
//! All bounds come from trusted machine/lookup geometry and the cubic binary
//! FRI profile. No proof field chooses its own bound. Underfilled or otherwise
//! invalid proofs still need the unchanged upstream numerical verifier.
//!
//! This bounds data that upstream may clone or extend. It does not account for
//! caller-owned spare capacities, all numerical scratch, allocator overhead,
//! or the upstream debug-only symbolic degree assertion.

use super::{profile, BatchProof, Config, MachineAir};
use p3_air::BaseAir;

const EXTENSION_DEGREE: usize = 3;
const SALT_ELEMENTS: usize = 4;
const ROUNDS: usize = 5;
const POINTS: [usize; ROUNDS] = [1, 1, 1, 1, 2];

#[derive(Clone, Copy, Debug)]
pub(super) struct Envelope {
    pub(super) degree: usize,
    pub(super) log_lde: usize,
    pub(super) matrices: [usize; ROUNDS],
    pub(super) widths: [usize; ROUNDS],
}

impl Envelope {
    pub(super) fn new(
        air: &MachineAir,
        common: &p3_batch_stark::CommonData<Config>,
        quotient_chunks: usize,
    ) -> Result<Self, &'static str> {
        if common.lookups.len() != 1
            || quotient_chunks == 0
            || quotient_chunks > profile::MAX_QUOTIENT_CHUNKS
        {
            return Err("native verifier trusted geometry");
        }
        let permutation = common.lookups[0]
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(EXTENSION_DEGREE))
            .ok_or("native verifier trusted geometry")?;
        let degree = air.program().height().ilog2() as usize + 1;
        Ok(Self {
            degree,
            log_lde: degree + profile::LOG_BLOWUP,
            matrices: [1, 1, quotient_chunks, 1, 1],
            widths: [
                EXTENSION_DEGREE,
                air.width(),
                EXTENSION_DEGREE,
                air.preprocessed_width(),
                permutation,
            ],
        })
    }

    fn check(&self, proof: &BatchProof<Config>) -> Result<(), &'static str> {
        let error = "native verifier proof exceeds registered envelope";
        let cap_fits = |cap: &p3_batch_stark::Commitment<Config>, log_height: usize| {
            // Derived deserialization need not pass through MerkleCap::new.
            let roots = cap.roots().len();
            roots.is_power_of_two() && roots <= 1usize << log_height.min(profile::CAP_HEIGHT)
        };
        let optional_fits = |row: &Option<Vec<profile::Challenge>>, width| {
            row.as_ref().is_none_or(|r| r.len() <= width)
        };
        let commitments = &proof.commitments;
        if !cap_fits(&commitments.main, self.log_lde)
            || !cap_fits(&commitments.quotient_chunks, self.log_lde)
            || commitments
                .random
                .as_ref()
                .is_some_and(|c| !cap_fits(c, self.log_lde))
            || commitments
                .permutation
                .as_ref()
                .is_some_and(|c| !cap_fits(c, self.log_lde))
            || proof.opened_values.instances.len() != 1
        {
            return Err(error);
        }
        let instance = &proof.opened_values.instances[0];
        let values = &instance.base_opened_values;
        if values.trace_local.len() > self.widths[1]
            || values.trace_next.is_some()
            || !optional_fits(&values.preprocessed_local, self.widths[3])
            // MachineAir has no next-row columns. In particular, Some([])
            // passes upstream's preprocessing length check but would panic
            // when its numerical verifier constructs unequal-width rows.
            || values.preprocessed_next.is_some()
            || !optional_fits(&values.random, EXTENSION_DEGREE)
            || values.quotient_chunks.len() > self.matrices[2]
            || values
                .quotient_chunks
                .iter()
                .any(|row| row.len() > EXTENSION_DEGREE)
            || instance.permutation_local.len() > self.widths[4]
            || instance.permutation_next.len() > self.widths[4]
        {
            return Err(error);
        }

        let (random, fri) = &proof.opening_proof;
        if random.len() > ROUNDS
            || fri.commit_phase_commits.len() > self.degree
            || fri.commit_pow_witnesses.len() > self.degree
            || fri.final_poly.len() > 1
            || fri.query_proofs.len() > profile::NUM_QUERIES
        {
            return Err(error);
        }
        for (round, matrices) in random.iter().enumerate() {
            if matrices.len() > self.matrices[round]
                || matrices.iter().any(|points| {
                    points.len() > POINTS[round]
                        || points.iter().any(|row| row.len() > hiding_width(round))
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
                        .any(|row| row.len() > self.widths[round] + hiding_width(round))
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

fn hiding_width(round: usize) -> usize {
    // Public preprocessing has salts but no hiding codewords.
    if round == 3 {
        0
    } else {
        profile::NUM_RANDOM_CODEWORDS
    }
}

fn authentication_fits(
    (salts, path): &(Vec<Vec<super::Val>>, Vec<[super::Val; 4]>),
    matrices: usize,
    log_height: usize,
) -> bool {
    salts.len() <= matrices
        && salts.iter().all(|row| row.len() <= SALT_ELEMENTS)
        && path.len() <= log_height.saturating_sub(profile::CAP_HEIGHT)
}

pub(super) fn check(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    quotient_chunks: usize,
    proof: &BatchProof<Config>,
) -> Result<(), &'static str> {
    Envelope::new(air, common, quotient_chunks)?.check(proof)
}

#[cfg(test)]
mod tests;
