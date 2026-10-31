//! Allocation-free shape checks for the unchanged quadratic single-note AIR.
//! Shape admission is not cryptographic verification or transaction acceptance.
use super::*;

#[derive(Default)]
struct Bytes(usize);
impl Bytes {
    fn exact<T>(&mut self, count: usize) -> Result<(), Error> {
        self.0 = add(self.0, mul(count, core::mem::size_of::<T>())?)?;
        Ok(())
    }
    fn repeat(&mut self, other: Self, count: usize) -> Result<(), Error> {
        self.0 = add(self.0, mul(other.0, count)?)?;
        Ok(())
    }
    fn cap(&mut self, count: usize) -> Result<(), Error> {
        self.exact::<[Val; 4]>(count)
    }
    fn auth(&mut self, matrices: usize, path: usize) -> Result<(), Error> {
        self.exact::<Vec<Val>>(matrices)?;
        self.exact::<Val>(mul(matrices, 4)?)?;
        self.exact::<[Val; 4]>(path)
    }
}

pub(super) fn backing_ceiling(g: Geometry) -> Result<usize, Error> {
    let roots = 1usize << g.cap_height;
    let path = g.degree_bits + g.log_blowup - g.cap_height;
    let matrices = [1, 1, g.quotient_chunks];
    let widths = [g.challenge_degree, g.trace_columns, g.challenge_degree];
    let mut bytes = Bytes::default();
    bytes.cap(3 * roots)?;
    bytes.exact::<Challenge>(2 * g.trace_columns + g.challenge_degree)?;
    bytes.exact::<Vec<Challenge>>(g.quotient_chunks)?;
    bytes.exact::<Challenge>(g.quotient_chunks * g.challenge_degree)?;
    bytes.exact::<Vec<Vec<Vec<Challenge>>>>(3)?;
    for (round, points) in [1, 2, 1].into_iter().enumerate() {
        bytes.exact::<Vec<Vec<Challenge>>>(matrices[round])?;
        bytes.exact::<Vec<Challenge>>(matrices[round] * points)?;
        bytes.exact::<Challenge>(matrices[round] * points * g.random_codewords)?;
    }
    // Any admitted arity schedule has at most degree_bits folds. Using the
    // maximum cap/path/arity for each overcounts and covers every such schedule.
    bytes.exact::<Cap>(g.degree_bits)?;
    bytes.cap(g.degree_bits * roots)?;
    bytes.exact::<Val>(g.degree_bits)?;
    bytes.exact::<Challenge>(1)?;
    bytes.exact::<Query>(g.queries)?;
    let mut query = Bytes::default();
    query.exact::<Opening>(3)?;
    for round in 0..3 {
        query.exact::<Vec<Val>>(matrices[round])?;
        query.exact::<Val>(matrices[round] * (widths[round] + g.random_codewords))?;
        query.auth(matrices[round], path)?;
    }
    query.exact::<Step>(g.degree_bits)?;
    let mut step = Bytes::default();
    step.exact::<Challenge>((1 << g.max_log_fri_arity) - 1)?;
    step.auth(1, path)?;
    query.repeat(step, g.degree_bits)?;
    bytes.repeat(query, g.queries)?;
    Ok(bytes.0)
}

fn authentication(
    proof: &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    matrices: usize,
    log_height: usize,
    cap_height: usize,
) -> bool {
    proof.0.len() == matrices
        && proof.0.iter().all(|row| row.len() == 4)
        && proof.1.len() == log_height.saturating_sub(cap_height)
}

pub(super) fn check(proof: &Proof, g: Geometry) -> Result<(), Error> {
    let error = Error::Geometry;
    let log_lde = g.degree_bits + g.log_blowup;
    let cap = |value: &Cap, log: usize| value.roots().len() == 1usize << log.min(g.cap_height);
    if proof.degree_bits != g.degree_bits
        || !cap(&proof.commitments.trace, log_lde)
        || !cap(&proof.commitments.quotient_chunks, log_lde)
        || !proof
            .commitments
            .random
            .as_ref()
            .is_some_and(|value| cap(value, log_lde))
    {
        return Err(error);
    }
    let values = &proof.opened_values;
    if values.trace_local.len() != g.trace_columns
        || values.trace_next.as_ref().map(Vec::len) != Some(g.trace_columns)
        || values.preprocessed_local.is_some()
        || values.preprocessed_next.is_some()
        || values.quotient_chunks.len() != g.quotient_chunks
        || values
            .quotient_chunks
            .iter()
            .any(|row| row.len() != g.challenge_degree)
        || values.random.as_ref().map(Vec::len) != Some(g.challenge_degree)
    {
        return Err(error);
    }
    let matrices = [1, 1, g.quotient_chunks];
    let widths = [g.challenge_degree, g.trace_columns, g.challenge_degree];
    let (hiding, fri) = &proof.opening_proof;
    if hiding.len() != 3 {
        return Err(error);
    }
    for (round, points) in [1, 2, 1].into_iter().enumerate() {
        if hiding[round].len() != matrices[round]
            || hiding[round].iter().any(|matrix| {
                matrix.len() != points || matrix.iter().any(|row| row.len() != g.random_codewords)
            })
        {
            return Err(error);
        }
    }
    let folds = fri.commit_phase_commits.len();
    if !(1..=g.degree_bits).contains(&folds)
        || fri.commit_pow_witnesses.len() != folds
        || fri.query_proofs.len() != g.queries
        || fri.final_poly.len() != 1
        || fri.query_proofs[0].commit_phase_openings.len() != folds
    {
        return Err(error);
    }
    let mut arities = [0usize; 13];
    let mut heights = [0usize; 13];
    let mut height = log_lde;
    for (i, opening) in fri.query_proofs[0].commit_phase_openings.iter().enumerate() {
        let arity = opening.log_arity as usize;
        if !(1..=g.max_log_fri_arity).contains(&arity) {
            return Err(error);
        }
        height = height.checked_sub(arity).ok_or(error)?;
        if height < g.log_blowup || !cap(&fri.commit_phase_commits[i], height) {
            return Err(error);
        }
        arities[i] = arity;
        heights[i] = height;
    }
    if height != g.log_blowup {
        return Err(error);
    }
    for query in &fri.query_proofs {
        if query.input_proof.len() != 3 || query.commit_phase_openings.len() != folds {
            return Err(error);
        }
        for (round, opening) in query.input_proof.iter().enumerate() {
            if opening.opened_values.len() != matrices[round]
                || opening
                    .opened_values
                    .iter()
                    .any(|row| row.len() != widths[round] + g.random_codewords)
                || !authentication(
                    &opening.opening_proof,
                    matrices[round],
                    log_lde,
                    g.cap_height,
                )
            {
                return Err(error);
            }
        }
        for (i, opening) in query.commit_phase_openings.iter().enumerate() {
            if opening.log_arity as usize != arities[i]
                || opening.sibling_values.len() != (1usize << arities[i]) - 1
                || !authentication(&opening.opening_proof, 1, heights[i], g.cap_height)
            {
                return Err(error);
            }
        }
    }
    Ok(())
}
