//! Structural binding for an immutable, previously compiled recursive program.
//! No proofs, witnesses, or randomness are retained here. The session owns the
//! registry/program identity and completed compilation provenance.

use super::*;
use p3_field::BasedVectorSpace;

pub(crate) const MAX_INPUT_BYTES: usize = 64 << 20;
const ERROR: CompileError = CompileError::Shape("recursive input binding");

#[derive(Clone, Copy, Debug)]
pub(crate) struct Shape {
    degree: usize,
    widths: [usize; 5],
    matrices: [usize; 5],
}

impl Shape {
    // Trusted AIR geometry, not lengths selected by an incoming proof.
    pub(crate) fn from_prefix(
        prefix: &RegistryPrefix<'_>,
        height: usize,
        keys: usize,
    ) -> Result<Self, CompileError> {
        prefix.fields(height, keys)?;
        let air = shape(height)?;
        let prepared =
            super::super::symbolic::prepare_machine(&air, compiler_constants(Some(prefix)))?;
        let analysis =
            super::super::analysis::analyze_prepared(&air, &prepared).map_err(|_| ERROR)?;
        use p3_air::BaseAir;
        Ok(Self {
            degree: height.ilog2() as usize + 1,
            widths: [
                3,
                air.width(),
                3,
                air.preprocessed_width(),
                analysis.permutation_width_base,
            ],
            matrices: [1, 1, analysis.quotient_chunks, 1, 1],
        })
    }

    #[cfg(test)]
    pub(crate) fn new(height: usize) -> Result<Self, CompileError> {
        let prefix = RegistryPrefix::with_hash(height, 12, &mut |d, f| {
            commitment::hash_fields(d, f).map_err(|_| ERROR)
        })?;
        Self::from_prefix(&prefix, height, 12)
    }

    pub(super) fn walk(
        &self,
        proof: &BatchProof<Config>,
        mut emit: impl FnMut(&[Val]) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        let log_lde = self.degree + profile::LOG_BLOWUP;
        if proof.degree_bits != [self.degree]
            || proof.opened_values.instances.len() != 1
            || proof.lookup_terminals.len() != 1
            || proof.lookup_terminals[0].is_none()
        {
            return Err(ERROR);
        }
        let inst = &proof.opened_values.instances[0];
        let opened = &inst.base_opened_values;
        let pre = opened.preprocessed_local.as_ref().ok_or(ERROR)?;
        let random = opened.random.as_ref().ok_or(ERROR)?;
        if opened.trace_local.len() != self.widths[1]
            || opened.trace_next.is_some()
            || opened.preprocessed_next.is_some()
            || pre.len() != self.widths[3]
            || random.len() != 3
            || opened.quotient_chunks.len() != self.matrices[2]
            || opened.quotient_chunks.iter().any(|v| v.len() != 3)
            || inst.permutation_local.len() != self.widths[4]
            || inst.permutation_next.len() != self.widths[4]
        {
            return Err(ERROR);
        }
        for cap in [
            &proof.commitments.main,
            &proof.commitments.quotient_chunks,
            proof.commitments.random.as_ref().ok_or(ERROR)?,
            proof.commitments.permutation.as_ref().ok_or(ERROR)?,
        ] {
            cap_values(cap, log_lde, &mut emit)?;
        }
        emit(
            proof.lookup_terminals[0]
                .as_ref()
                .unwrap()
                .0
                .as_basis_coefficients_slice(),
        )?;
        for values in [&opened.trace_local, pre, random] {
            extensions(values, &mut emit)?;
        }
        for values in &opened.quotient_chunks {
            extensions(values, &mut emit)?;
        }
        extensions(&inst.permutation_local, &mut emit)?;
        extensions(&inst.permutation_next, &mut emit)?;

        let (random_openings, fri) = &proof.opening_proof;
        if random_openings.len() != 5
            || fri.commit_phase_commits.len() != self.degree
            || fri.commit_pow_witnesses.len() != self.degree
            || fri.final_poly.len() != 1
            || fri.query_proofs.len() != profile::NUM_QUERIES
        {
            return Err(ERROR);
        }
        for (round, matrices) in random_openings.iter().enumerate() {
            if matrices.len() != self.matrices[round] {
                return Err(ERROR);
            }
            for points in matrices {
                if points.len() != if round == 4 { 2 } else { 1 } {
                    return Err(ERROR);
                }
                for values in points {
                    if values.len() != hiding(round) {
                        return Err(ERROR);
                    }
                    extensions(values, &mut emit)?;
                }
            }
        }
        for (layer, cap) in fri.commit_phase_commits.iter().enumerate() {
            cap_values(cap, log_lde - layer - 1, &mut emit)?;
        }
        // Commit PoW witnesses are unused by the pinned zero-commit-PoW
        // compiler. Preserve its input sequence rather than adding them.
        extensions(&fri.final_poly, &mut emit)?;
        emit(&[fri.query_pow_witness])?;
        for query in &fri.query_proofs {
            if query.input_proof.len() != 5 || query.commit_phase_openings.len() != self.degree {
                return Err(ERROR);
            }
            for (round, opening) in query.input_proof.iter().enumerate() {
                if opening.opened_values.len() != self.matrices[round] {
                    return Err(ERROR);
                }
                for values in &opening.opened_values {
                    if values.len() != self.widths[round] + hiding(round) {
                        return Err(ERROR);
                    }
                    emit(values)?;
                }
                authentication(
                    &opening.opening_proof,
                    self.matrices[round],
                    log_lde,
                    &mut emit,
                )?;
            }
            for (layer, step) in query.commit_phase_openings.iter().enumerate() {
                if step.log_arity != 1 || step.sibling_values.len() != 1 {
                    return Err(ERROR);
                }
                extensions(&step.sibling_values, &mut emit)?;
                authentication(&step.opening_proof, 1, log_lde - layer - 1, &mut emit)?;
            }
        }
        Ok(())
    }
}

fn hiding(round: usize) -> usize {
    if round == 3 {
        0
    } else {
        profile::NUM_RANDOM_CODEWORDS
    }
}

pub(super) fn extensions(
    values: &[profile::Challenge],
    emit: &mut impl FnMut(&[Val]) -> Result<(), CompileError>,
) -> Result<(), CompileError> {
    for value in values {
        emit(value.as_basis_coefficients_slice())?;
    }
    Ok(())
}

pub(super) fn cap_values(
    cap: &p3_batch_stark::Commitment<Config>,
    log: usize,
    emit: &mut impl FnMut(&[Val]) -> Result<(), CompileError>,
) -> Result<(), CompileError> {
    if cap.roots().len() != 1 << log.min(profile::CAP_HEIGHT) {
        return Err(ERROR);
    }
    for digest in cap.roots() {
        emit(digest)?;
    }
    Ok(())
}

pub(super) fn authentication(
    proof: &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    matrices: usize,
    log: usize,
    emit: &mut impl FnMut(&[Val]) -> Result<(), CompileError>,
) -> Result<(), CompileError> {
    if proof.0.len() != matrices
        || proof.0.iter().any(|salt| salt.len() != 4)
        || proof.1.len() != log.saturating_sub(profile::CAP_HEIGHT)
    {
        return Err(ERROR);
    }
    for salt in &proof.0 {
        emit(salt)?;
    }
    for sibling in &proof.1 {
        emit(sibling)?;
    }
    Ok(())
}

pub(crate) fn bind<const N: usize>(
    shape: &Shape,
    caps: &Caps<N>,
    children: &[(&[Val; PUBLIC_VALUES], &BatchProof<Config>)],
    expected_values: usize,
    limit_bytes: usize,
) -> Result<Vec<Val>, CompileError> {
    if !matches!(N, 5 | 6 | 12) || !matches!(children.len(), 1 | 2) {
        return Err(ERROR);
    }
    check_caps(caps)?;
    let mut count = 0usize;
    visit(shape, caps, children, &mut |values| {
        count = count.checked_add(values.len()).ok_or(ERROR)?;
        if count > expected_values {
            return Err(ERROR);
        }
        Ok(())
    })?;
    if count != expected_values
        || count
            .checked_mul(core::mem::size_of::<Val>())
            .ok_or(ERROR)?
            > limit_bytes.min(MAX_INPUT_BYTES)
    {
        return Err(ERROR);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| ERROR)?;
    if output.capacity() != count {
        return Err(ERROR);
    }
    visit(shape, caps, children, &mut |values| {
        if output.len().checked_add(values.len()).ok_or(ERROR)? > count {
            return Err(ERROR);
        }
        output.extend_from_slice(values);
        Ok(())
    })?;
    if output.len() != count {
        return Err(ERROR);
    }
    Ok(output)
}

fn visit<const N: usize>(
    shape: &Shape,
    caps: &Caps<N>,
    children: &[(&[Val; PUBLIC_VALUES], &BatchProof<Config>)],
    emit: &mut dyn FnMut(&[Val]) -> Result<(), CompileError>,
) -> Result<(), CompileError> {
    for digest in caps.iter().flatten() {
        emit(digest)?;
    }
    for (public, proof) in children {
        emit(*public)?;
        shape.walk(proof, &mut *emit)?;
    }
    Ok(())
}

/// Compare against the cold compiler without allocating a second witness vector.
/// This establishes the input ordering before a plan can enter the program cache.
pub(crate) fn check_witness<const N: usize>(
    shape: &Shape,
    caps: &Caps<N>,
    children: &[(&[Val; PUBLIC_VALUES], &BatchProof<Config>)],
    witness: &[Val],
    limit_bytes: usize,
) -> Result<(), CompileError> {
    if !matches!(N, 5 | 6 | 12)
        || !matches!(children.len(), 1 | 2)
        || witness
            .len()
            .checked_mul(core::mem::size_of::<Val>())
            .ok_or(ERROR)?
            > limit_bytes.min(MAX_INPUT_BYTES)
    {
        return Err(ERROR);
    }
    check_caps(caps)?;
    let mut offset = 0usize;
    visit(shape, caps, children, &mut |values| {
        let end = offset.checked_add(values.len()).ok_or(ERROR)?;
        if witness.get(offset..end) != Some(values) {
            return Err(ERROR);
        }
        offset = end;
        Ok(())
    })?;
    if offset != witness.len() {
        return Err(ERROR);
    }
    Ok(())
}
