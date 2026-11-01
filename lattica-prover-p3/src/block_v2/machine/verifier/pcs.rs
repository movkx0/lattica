//! Complete binary FRI/hiding PCS verifier for fixed-shape equal-height batches.
//! All query locations and folding challenges come from the constrained transcript.
use super::super::circuit::Extension;
use super::super::merkle::Digest;
use super::super::program::ScopedProgramBuilder as ProgramBuilder;
use super::super::program::Val;
use super::super::transcript::Transcript;
use super::super::Wire;
use super::{ext_base, observe_cap, CompileError, ProofInputs};
use crate::block_v2::profile::{self, Config};
use p3_field::{Field, PrimeCharacteristicRing};

// These are the shapes emitted by the supported uni/batch verifier compilers.
// Fixed descriptors and random suffixes never grow with untrusted proof data.
const MAX_ROUNDS: usize = 5;
pub(super) const MAX_MATRICES: usize = 1 << (profile::LOG_BLOWUP + 1);
const MAX_POINTS: usize = 2;
const MAX_LOG: usize = 32;
type RandomSuffix = [Extension; profile::NUM_RANDOM_CODEWORDS];

#[derive(Clone, Copy)]
pub struct Point<'a> {
    pub point: Extension,
    pub values: &'a [Extension],
}
#[derive(Clone, Copy)]
pub struct Round<'a> {
    pub commitment: &'a [Digest],
    /// Size of the committed domain before FRI blowup (already doubled for hiding).
    pub log_domain: usize,
    /// All matrices in this commitment have the same height.
    pub matrices: &'a [&'a [Point<'a>]],
    pub preprocessing: bool,
}

fn salted_authentication<R: AsRef<[Wire]>>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    cap: &[Digest],
    bits: &[Wire],
    rows: &[R],
    salts: Option<&[Vec<Val>]>,
    siblings: Option<&[[Val; 4]]>,
) -> Result<(), CompileError> {
    if rows.len() > MAX_MATRICES
        || bits.len() > MAX_LOG
        || salts.is_some() != siblings.is_some()
        || salts
            .is_some_and(|salts| salts.len() != rows.len() || salts.iter().any(|s| s.len() != 4))
        || siblings.is_some_and(|siblings| {
            siblings.len() != bits.len().saturating_sub(profile::CAP_HEIGHT)
        })
    {
        return Err(CompileError::Shape("salted MMCS proof"));
    }
    if salts.is_none() {
        inputs.require_geometry(b)?;
    }
    let mut salt_wires = [[Wire(0); 4]; MAX_MATRICES];
    for (index, out) in salt_wires[..rows.len()].iter_mut().enumerate() {
        *out = core::array::from_fn(|i| inputs.base(b, salts.map_or(Val::ZERO, |s| s[index][i])));
    }
    let sibling_count = bits.len().saturating_sub(profile::CAP_HEIGHT);
    let mut sibling_wires = [[Wire(0); 4]; MAX_LOG];
    for (index, out) in sibling_wires[..sibling_count].iter_mut().enumerate() {
        *out = inputs.digest(b, siblings.map_or(&[Val::ZERO; 4], |s| &s[index]));
    }
    check_resources(b)?;
    b.authenticate_equal_height_mmcs(
        cap,
        bits,
        rows,
        &salt_wires[..rows.len()],
        &sibling_wires[..sibling_count],
    )
    .map_err(|_| CompileError::Shape("MMCS geometry"))
}

fn check_resources(b: &ProgramBuilder) -> Result<(), CompileError> {
    if let Some(error) = b.resource_failure() {
        return Err(CompileError::from_builder_admission(
            error,
            "PCS compiler resource allowance",
        ));
    }
    Ok(())
}

pub fn verify(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    transcript: &mut Transcript,
    rounds: &[Round<'_>],
    proof: &p3_batch_stark::PcsProof<Config>,
) -> Result<(), CompileError> {
    verify_view(b, inputs, transcript, rounds, Some(proof), None)
}

/// Geometry-only openings are accepted exclusively by the non-proving numeric
/// sink. Actual proof callers retain every original shape and value check.
pub(super) fn verify_view(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    transcript: &mut Transcript,
    rounds: &[Round<'_>],
    proof: Option<&p3_batch_stark::PcsProof<Config>>,
    mut timings: Option<&mut super::uni::shape::NativeLoweringTimings>,
) -> Result<(), CompileError> {
    let started = timings.as_ref().map(|_| std::time::Instant::now());
    if proof.is_none() {
        inputs.require_geometry(b)?;
    }
    if rounds.is_empty()
        || rounds.len() > MAX_ROUNDS
        || rounds.iter().any(|r| {
            r.matrices.is_empty()
                || r.matrices.len() > MAX_MATRICES
                || r.matrices
                    .iter()
                    .any(|m| m.is_empty() || m.len() > MAX_POINTS)
        })
    {
        return Err(CompileError::Shape("PCS descriptor geometry"));
    }
    let random_openings = proof.map(|p| &p.0);
    let fri = proof.map(|p| &p.1);
    if random_openings.is_some_and(|random| random.len() != rounds.len()) {
        return Err(CompileError::Shape("random opening rounds"));
    }
    let mut random_wires: [[[RandomSuffix; MAX_POINTS]; MAX_MATRICES]; MAX_ROUNDS] =
        [[[[[Wire(0); 3]; profile::NUM_RANDOM_CODEWORDS]; MAX_POINTS]; MAX_MATRICES]; MAX_ROUNDS];
    for (round_index, (round, random_round)) in rounds.iter().zip(&mut random_wires).enumerate() {
        let randomness = random_openings.map(|random| &random[round_index]);
        if round.log_domain > MAX_LOG - profile::LOG_BLOWUP
            || round.log_domain == 0
            || randomness.is_some_and(|r| r.len() != round.matrices.len())
        {
            return Err(CompileError::Shape("PCS matrix geometry"));
        }
        if round.commitment.len()
            != 1 << (round.log_domain + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT)
        {
            return Err(CompileError::Shape("PCS cap shape"));
        }
        for (matrix_index, (matrix, random_matrix)) in
            round.matrices.iter().zip(random_round).enumerate()
        {
            let rand_matrix = randomness.map(|r| &r[matrix_index]);
            if rand_matrix.is_some_and(|r| matrix.len() != r.len()) {
                return Err(CompileError::Shape("random opening points"));
            }
            for (point_index, (point, random_point)) in matrix.iter().zip(random_matrix).enumerate()
            {
                let rand_point = rand_matrix.map(|r| &r[point_index]);
                let random_width = if round.preprocessing {
                    0
                } else {
                    profile::NUM_RANDOM_CODEWORDS
                };
                if rand_point.is_some_and(|r| r.len() != random_width) {
                    return Err(CompileError::Shape("random codeword width"));
                }
                for (index, out) in random_point[..random_width].iter_mut().enumerate() {
                    *out = inputs
                        .extension(b, rand_point.map_or(profile::Challenge::ZERO, |p| p[index]));
                }
                check_resources(b)?;
                // The inner TwoAdicFriPcs observes all reconstructed claimed values.
                for value in point.values.iter().chain(&random_point[..random_width]) {
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
    if let Some(fri) = fri {
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
    }
    let alpha = transcript.sample_ext(b);
    let mut caps: [Vec<Digest>; MAX_LOG] = core::array::from_fn(|_| Vec::new());
    let mut betas = [[Wire(0); 3]; MAX_LOG];
    for i in 0..folds {
        let cap = inputs.cap_view(
            b,
            fri.map(|f| &f.commit_phase_commits[i]),
            log_global - i - 1,
        )?;
        observe_cap(transcript, b, &cap);
        caps[i] = cap;
        // Commit PoW is zero in this pinned profile, so native check_witness
        // neither absorbs nor constrains its unused witness.
        betas[i] = transcript.sample_ext(b);
    }
    let final_value =
        inputs.extension(b, fri.map_or(profile::Challenge::ZERO, |f| f.final_poly[0]));
    transcript.observe_slice(b, &final_value);
    let one_base = b.constant(Val::ONE);
    for _ in 0..folds {
        transcript.observe(b, one_base);
    }
    let pow = inputs.base(b, fri.map_or(Val::ZERO, |f| f.query_pow_witness));
    transcript.check_pow(b, profile::QUERY_POW_BITS, pow);
    let zero_ext = b.ext_constant([Val::ZERO; 3]);
    let one_ext = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let coset = b.constant(Val::GENERATOR);
    // Alpha powers and reduced OOD openings are query-independent. Populate
    // their slots during the first query to preserve the exact SSA/input order,
    // then reuse wires instead of repeating thousands of CSE table lookups.
    // This backing shares the enforced compiler allowance, including counting.
    let mut offsets = [[0usize; MAX_MATRICES]; MAX_ROUNDS];
    let mut scratch_count = 0usize;
    for (r, round) in rounds.iter().enumerate() {
        let random_width = if round.preprocessing {
            0
        } else {
            profile::NUM_RANDOM_CODEWORDS
        };
        for (m, points) in round.matrices.iter().enumerate() {
            offsets[r][m] = scratch_count;
            scratch_count = scratch_count
                .checked_add(points[0].values.len())
                .and_then(|n| n.checked_add(random_width + 1 + points.len()))
                .ok_or(CompileError::Shape("PCS reduction scratch overflow"))?;
        }
    }
    if let Some(t) = timings.as_deref_mut() {
        t.pcs_setup_ns = started.unwrap().elapsed().as_nanos();
    }
    b.with_compiler_scratch("PCS reductions", scratch_count, zero_ext, |b, reusable| {
        for query_index in 0..profile::NUM_QUERIES {
            let started = timings.as_ref().map(|_| std::time::Instant::now());
            let query = fri.map(|f| &f.query_proofs[query_index]);
            let bits = transcript.sample_bits(b, log_global);
            // Each height has its own alpha power, continued across commitments,
            // matrices and points in their protocol order.
            let mut reductions = [None; MAX_LOG + 1];
            if let Some(t) = timings.as_deref_mut() {
                t.pcs_query_ns += started.unwrap().elapsed().as_nanos();
            }
            for (round_index, (round, random_round)) in rounds.iter().zip(&random_wires).enumerate()
            {
                let started = timings.as_ref().map(|_| std::time::Instant::now());
                let opening = query.map(|q| &q.input_proof[round_index]);
                if opening.is_some_and(|o| o.opened_values.len() != round.matrices.len()) {
                    return Err(CompileError::Shape("opened matrix count"));
                }
                let log_height = round.log_domain + profile::LOG_BLOWUP;
                let reduced_bits = &bits[log_global - log_height..];
                let random_width = if round.preprocessing {
                    0
                } else {
                    profile::NUM_RANDOM_CODEWORDS
                };
                let mut row_storage: [Vec<Wire>; MAX_MATRICES] =
                    core::array::from_fn(|_| Vec::new());
                let rows = &mut row_storage[..round.matrices.len()];
                for (matrix_index, (points, row)) in
                    round.matrices.iter().zip(rows.iter_mut()).enumerate()
                {
                    let width = points[0]
                        .values
                        .len()
                        .checked_add(random_width)
                        .ok_or(CompileError::Shape("opened matrix width"))?;
                    let values = opening.map(|o| o.opened_values[matrix_index].as_slice());
                    if values.is_some_and(|v| v.len() != width) {
                        return Err(CompileError::Shape("opened matrix width"));
                    }
                    *row = inputs.bases_view(b, values, width)?;
                }
                salted_authentication(
                    b,
                    inputs,
                    &round.commitment,
                    reduced_bits,
                    &rows,
                    opening.map(|o| o.opening_proof.0.as_slice()),
                    opening.map(|o| o.opening_proof.1.as_slice()),
                )?;
                if let Some(t) = timings.as_deref_mut() {
                    t.pcs_opening_ns += started.unwrap().elapsed().as_nanos();
                }
                let started = timings.as_ref().map(|_| std::time::Instant::now());
                let x = b
                    .subgroup_point(reduced_bits, log_height)
                    .map_err(|_| CompileError::Shape("query point"))?;
                let x = b.mul(x, coset);
                let x_ext = ext_base(b, x);
                let (mut power, mut reduced) =
                    reductions[log_height].take().unwrap_or((one_ext, zero_ext));
                for (matrix_index, ((row, points), random_matrix)) in rows
                    .iter()
                    .zip(round.matrices)
                    .zip(random_round)
                    .enumerate()
                {
                    // Linearity separates the query-dependent base-field row from the
                    // OOD extension openings. The latter and alpha powers are shared
                    // across every query by SSA CSE, and a row is shared by both points.
                    let mut row_sum = zero_ext;
                    let mut row_power = one_ext;
                    let offset = offsets[round_index][matrix_index];
                    for (index, &value) in row.iter().enumerate() {
                        if query_index == 0 {
                            reusable[offset + index] = row_power;
                        } else {
                            row_power = reusable[offset + index];
                        }
                        let term = b.ext_scale(row_power, value);
                        row_sum = b.ext_add(row_sum, term);
                        if query_index == 0 {
                            row_power = b.ext_mul(row_power, alpha);
                        }
                    }
                    if query_index == 0 {
                        reusable[offset + row.len()] = row_power;
                    } else {
                        row_power = reusable[offset + row.len()];
                    }
                    for (point_index, (point, random_point)) in
                        points.iter().zip(random_matrix).enumerate()
                    {
                        let denominator = b.ext_sub(point.point, x_ext);
                        let inv = b.ext_inverse(denominator);
                        let slot = offset + row.len() + 1 + point_index;
                        let claimed_sum = if query_index == 0 {
                            let mut sum = zero_ext;
                            let mut power = one_ext;
                            for &claimed in point.values.iter().chain(&random_point[..random_width])
                            {
                                let term = b.ext_mul(power, claimed);
                                sum = b.ext_add(sum, term);
                                power = b.ext_mul(power, alpha);
                            }
                            reusable[slot] = sum;
                            sum
                        } else {
                            reusable[slot]
                        };
                        let delta = b.ext_sub(claimed_sum, row_sum);
                        let weighted = b.ext_mul(power, delta);
                        let contribution = b.ext_mul(weighted, inv);
                        reduced = b.ext_add(reduced, contribution);
                        power = b.ext_mul(power, row_power);
                    }
                }
                reductions[log_height] = Some((power, reduced));
                if let Some(t) = timings.as_deref_mut() {
                    t.pcs_reduction_ns += started.unwrap().elapsed().as_nanos();
                }
            }
            let started = timings.as_ref().map(|_| std::time::Instant::now());
            if let Some((_, value)) = reductions[profile::LOG_BLOWUP].take() {
                b.ext_assert_equal(value, zero_ext);
            }
            let (_, mut folded) = reductions[log_global]
                .take()
                .ok_or(CompileError::Shape("initial reduced opening"))?;
            for r in 0..folds {
                let step = query.map(|q| &q.commit_phase_openings[r]);
                let sibling = inputs.extension(
                    b,
                    step.map_or(profile::Challenge::ZERO, |s| s.sibling_values[0]),
                );
                let ordered = b.select_lanes(
                    bits[r],
                    [
                        folded[0], folded[1], folded[2], sibling[0], sibling[1], sibling[2],
                    ],
                    [
                        sibling[0], sibling[1], sibling[2], folded[0], folded[1], folded[2],
                    ],
                );
                let even = [ordered[0], ordered[1], ordered[2]];
                let odd = [ordered[3], ordered[4], ordered[5]];
                let row = [even[0], even[1], even[2], odd[0], odd[1], odd[2]];
                salted_authentication(
                    b,
                    inputs,
                    &caps[r],
                    &bits[r + 1..],
                    &[row],
                    step.map(|s| s.opening_proof.0.as_slice()),
                    step.map(|s| s.opening_proof.1.as_slice()),
                )?;
                let x = b
                    .subgroup_point(&bits[r + 1..], log_global - r)
                    .map_err(|_| CompileError::Shape("fold point"))?;
                folded = b.binary_fri_fold(even, odd, betas[r], x);
                if let Some((_, reduced)) = reductions[log_global - r - 1].take() {
                    let beta_squared = b.ext_mul(betas[r], betas[r]);
                    let contribution = b.ext_mul(beta_squared, reduced);
                    folded = b.ext_add(folded, contribution);
                }
            }
            if reductions.iter().any(Option::is_some) {
                return Err(CompileError::Shape("unconsumed reduced opening"));
            }
            b.ext_assert_equal(folded, final_value);
            if let Some(t) = timings.as_deref_mut() {
                t.pcs_folding_ns += started.unwrap().elapsed().as_nanos();
            }
        }
        check_resources(b)
    })
}

#[cfg(test)]
mod tests;
