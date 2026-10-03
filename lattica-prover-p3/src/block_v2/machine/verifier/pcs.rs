//! Complete binary FRI/hiding PCS verifier for fixed-shape equal-height batches.
//! All query locations and folding challenges come from the constrained transcript.
use super::super::circuit::Extension;
use super::super::merkle::Digest;
use super::super::program::Val;
use super::super::transcript::Transcript;
use super::super::{ProgramBuilder, Wire};
use super::{ext_base, observe_cap, CompileError, ProofInputs};
use crate::block_v2::profile::{self, Config};
use p3_field::{Field, PrimeCharacteristicRing};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Point {
    pub point: Extension,
    pub values: Vec<Extension>,
}
#[derive(Clone)]
pub struct Round {
    pub commitment: Vec<Digest>,
    /// Size of the committed domain before FRI blowup (already doubled for hiding).
    pub log_domain: usize,
    /// All matrices in this commitment have the same height.
    pub matrices: Vec<Vec<Point>>,
    pub preprocessing: bool,
}

fn salted_authentication(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    cap: &[Digest],
    bits: &[Wire],
    rows: &[Vec<Wire>],
    salts: &[Vec<Val>],
    siblings: &[[Val; 4]],
) -> Result<(), CompileError> {
    if salts.len() != rows.len()
        || salts.iter().any(|s| s.len() != 4)
        || siblings.len() != bits.len().saturating_sub(profile::CAP_HEIGHT)
    {
        return Err(CompileError::Shape("salted MMCS proof"));
    }
    let salts: Vec<_> = salts
        .iter()
        .map(|s| core::array::from_fn(|i| inputs.base(b, s[i])))
        .collect();
    let siblings: Vec<_> = siblings.iter().map(|d| inputs.digest(b, d)).collect();
    b.authenticate_equal_height_mmcs(cap, bits, rows, &salts, &siblings)
        .map_err(|_| CompileError::Shape("MMCS geometry"))
}

pub fn verify(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    transcript: &mut Transcript,
    mut rounds: Vec<Round>,
    proof: &p3_batch_stark::PcsProof<Config>,
) -> Result<(), CompileError> {
    if rounds.is_empty()
        || rounds
            .iter()
            .any(|r| r.matrices.is_empty() || r.matrices.iter().any(Vec::is_empty))
    {
        return Err(CompileError::Shape("empty PCS round"));
    }
    let (random_openings, fri) = proof;
    if random_openings.len() != rounds.len() {
        return Err(CompileError::Shape("random opening rounds"));
    }
    for (round, randomness) in rounds.iter_mut().zip(random_openings) {
        if round.log_domain + profile::LOG_BLOWUP > 32
            || round.log_domain == 0
            || randomness.len() != round.matrices.len()
        {
            return Err(CompileError::Shape("PCS matrix geometry"));
        }
        if round.commitment.len()
            != 1 << (round.log_domain + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT)
        {
            return Err(CompileError::Shape("PCS cap shape"));
        }
        for (matrix, rand_matrix) in round.matrices.iter_mut().zip(randomness) {
            if matrix.len() != rand_matrix.len() {
                return Err(CompileError::Shape("random opening points"));
            }
            for (point, rand_point) in matrix.iter_mut().zip(rand_matrix) {
                let random_width = if round.preprocessing {
                    0
                } else {
                    profile::NUM_RANDOM_CODEWORDS
                };
                if rand_point.len() != random_width {
                    return Err(CompileError::Shape("random codeword width"));
                }
                point.values.extend(inputs.extensions(b, rand_point));
                // The inner TwoAdicFriPcs observes all reconstructed claimed values.
                for value in &point.values {
                    transcript.observe_slice(b, value);
                }
            }
            if matrix
                .iter()
                .any(|p| p.values.len() != matrix[0].values.len())
            {
                return Err(CompileError::Shape("unequal point widths"));
            }
        }
    }
    let log_global = rounds
        .iter()
        .map(|r| r.log_domain + profile::LOG_BLOWUP)
        .max()
        .unwrap();
    let folds = log_global - profile::LOG_BLOWUP;
    if fri.commit_phase_commits.len() != folds
        || fri.commit_pow_witnesses.len() != folds
        || fri.final_poly.len() != 1
        || fri.query_proofs.len() != profile::NUM_QUERIES
    {
        return Err(CompileError::Shape("FRI profile"));
    }
    for query in &fri.query_proofs {
        if query.input_proof.len() != rounds.len()
            || query.commit_phase_openings.len() != folds
            || query
                .commit_phase_openings
                .iter()
                .any(|p| p.log_arity != 1 || p.sibling_values.len() != 1)
        {
            return Err(CompileError::Shape("binary FRI query shape"));
        }
    }
    let alpha = transcript.sample_ext(b);
    let mut caps = Vec::new();
    let mut betas = Vec::new();
    for (i, cap) in fri.commit_phase_commits.iter().enumerate() {
        let cap = inputs.cap(b, cap, log_global - i - 1)?;
        observe_cap(transcript, b, &cap);
        caps.push(cap);
        // Commit PoW is zero in this pinned profile, so native check_witness
        // neither absorbs nor constrains its unused witness.
        betas.push(transcript.sample_ext(b));
    }
    let final_value = inputs.extension(b, fri.final_poly[0]);
    transcript.observe_slice(b, &final_value);
    let one_base = b.constant(Val::ONE);
    for _ in 0..folds {
        transcript.observe(b, one_base);
    }
    let pow = inputs.base(b, fri.query_pow_witness);
    transcript.check_pow(b, profile::QUERY_POW_BITS, pow);
    let zero_ext = b.ext_constant([Val::ZERO; 3]);
    let one_ext = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let coset = b.constant(Val::GENERATOR);
    for query in &fri.query_proofs {
        let bits = transcript.sample_bits(b, log_global);
        // Each height has its own alpha power, continued across commitments,
        // matrices and points in their protocol order.
        let mut reductions: BTreeMap<usize, (Extension, Extension)> = BTreeMap::new();
        for (round, opening) in rounds.iter().zip(&query.input_proof) {
            if opening.opened_values.len() != round.matrices.len() {
                return Err(CompileError::Shape("opened matrix count"));
            }
            let log_height = round.log_domain + profile::LOG_BLOWUP;
            let reduced_bits = &bits[log_global - log_height..];
            let mut rows = Vec::new();
            for (values, points) in opening.opened_values.iter().zip(&round.matrices) {
                if values.len() != points[0].values.len() {
                    return Err(CompileError::Shape("opened matrix width"));
                }
                rows.push(inputs.bases(b, values));
            }
            salted_authentication(
                b,
                inputs,
                &round.commitment,
                reduced_bits,
                &rows,
                &opening.opening_proof.0,
                &opening.opening_proof.1,
            )?;
            let x = b
                .subgroup_point(reduced_bits, log_height)
                .map_err(|_| CompileError::Shape("query point"))?;
            let x = b.mul(x, coset);
            let x_ext = ext_base(b, x);
            let (mut power, mut reduced) = reductions
                .remove(&log_height)
                .unwrap_or((one_ext, zero_ext));
            for (row, points) in rows.iter().zip(&round.matrices) {
                // Linearity separates the query-dependent base-field row from the
                // OOD extension openings. The latter and alpha powers are shared
                // across every query by SSA CSE, and a row is shared by both points.
                let mut row_sum = zero_ext;
                let mut row_power = one_ext;
                for &value in row {
                    let term = b.ext_scale(row_power, value);
                    row_sum = b.ext_add(row_sum, term);
                    row_power = b.ext_mul(row_power, alpha);
                }
                for point in points {
                    let denominator = b.ext_sub(point.point, x_ext);
                    let inv = b.ext_inverse(denominator);
                    let mut claimed_sum = zero_ext;
                    let mut claimed_power = one_ext;
                    for &claimed in &point.values {
                        let term = b.ext_mul(claimed_power, claimed);
                        claimed_sum = b.ext_add(claimed_sum, term);
                        claimed_power = b.ext_mul(claimed_power, alpha);
                    }
                    let delta = b.ext_sub(claimed_sum, row_sum);
                    let weighted = b.ext_mul(power, delta);
                    let contribution = b.ext_mul(weighted, inv);
                    reduced = b.ext_add(reduced, contribution);
                    power = b.ext_mul(power, row_power);
                }
            }
            reductions.insert(log_height, (power, reduced));
        }
        if let Some((_, value)) = reductions.remove(&profile::LOG_BLOWUP) {
            b.ext_assert_equal(value, zero_ext);
        }
        let (_, mut folded) = reductions
            .remove(&log_global)
            .ok_or(CompileError::Shape("initial reduced opening"))?;
        for (r, step) in query.commit_phase_openings.iter().enumerate() {
            let sibling = inputs.extension(b, step.sibling_values[0]);
            let even = b.ext_select(bits[r], folded, sibling);
            let odd = b.ext_select(bits[r], sibling, folded);
            let row: Vec<_> = even.into_iter().chain(odd).collect();
            salted_authentication(
                b,
                inputs,
                &caps[r],
                &bits[r + 1..],
                &[row],
                &step.opening_proof.0,
                &step.opening_proof.1,
            )?;
            let x = b
                .subgroup_point(&bits[r + 1..], log_global - r)
                .map_err(|_| CompileError::Shape("fold point"))?;
            folded = b.binary_fri_fold(even, odd, betas[r], x);
            if let Some((_, reduced)) = reductions.remove(&(log_global - r - 1)) {
                let beta_squared = b.ext_mul(betas[r], betas[r]);
                let contribution = b.ext_mul(beta_squared, reduced);
                folded = b.ext_add(folded, contribution);
            }
        }
        if !reductions.is_empty() {
            return Err(CompileError::Shape("unconsumed reduced opening"));
        }
        b.ext_assert_equal(folded, final_value);
    }
    Ok(())
}
