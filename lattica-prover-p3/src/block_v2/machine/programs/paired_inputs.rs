//! Fresh uni-STARK inputs for immutable, previously authenticated paired programs.
//! The selected registry compiler supplies geometry; wallet proofs supply values.
use super::super::{symbolic, typed_pairs, typed_programs};
use super::recursive_inputs::{authentication, cap_values, extensions, MAX_INPUT_BYTES};
use super::*;
use crate::block_v2::typed_leaf::ContextAir;
use crate::htlc_air as htlc;
use p3_air::{Air, BaseAir};

const ERROR: CompileError = CompileError::Shape("paired input binding");
pub(crate) type Wallet<'a> = (&'a [Val], &'a Proof<Config>);

#[derive(Clone, Copy, Debug)]
struct UniShape {
    degree: usize,
    public_values: usize,
    width: usize,
    next: bool,
    chunks: usize,
}

impl UniShape {
    fn for_air<A>(
        air: &A,
        height: usize,
        public_values: usize,
        constants: Constants<'_>,
    ) -> Result<Self, CompileError>
    where
        A: BaseAir<Val> + Air<symbolic::Builder> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>>,
    {
        if !height.is_power_of_two()
            || height < 8
            || height.ilog2() as usize + 1 + profile::LOG_BLOWUP > 32
            || air.preprocessed_width() != 0
            || air.num_public_values() != public_values + 16
        {
            return Err(ERROR);
        }
        let (_, log_chunks) = symbolic::prepare_uni(air, constants)?;
        if log_chunks > profile::LOG_BLOWUP {
            return Err(ERROR);
        }
        Ok(Self {
            degree: height.ilog2() as usize + 1,
            public_values,
            width: air.width(),
            next: !air.main_next_row_columns().is_empty(),
            chunks: 1 << (log_chunks + 1),
        })
    }

    fn from_mode(mode: u64, constants: Constants<'_>) -> Result<Self, CompileError> {
        match mode {
            WRAPPER => Self::for_air(&ContextJoinSplitAir, js::HEIGHT, js::N_PUBLIC, constants),
            typed_programs::HTLC => Self::for_air(
                &ContextAir(htlc::HtlcAir),
                htlc::HEIGHT,
                htlc::N_PUBLIC,
                constants,
            ),
            typed_programs::ISSUANCE => Self::for_air(
                &ContextAir(js::JoinSplitAir),
                js::HEIGHT,
                js::N_PUBLIC,
                constants,
            ),
            _ => Err(ERROR),
        }
    }

    fn walk(
        &self,
        wallet: Wallet<'_>,
        emit: &mut impl FnMut(&[Val]) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        let (public, proof) = wallet;
        let opened = &proof.opened_values;
        if public.len() != self.public_values
            || proof.degree_bits != self.degree
            || opened.trace_local.len() != self.width
            || opened.trace_next.is_some() != self.next
            || opened
                .trace_next
                .as_ref()
                .is_some_and(|v| v.len() != self.width)
            || opened.preprocessed_local.is_some()
            || opened.preprocessed_next.is_some()
            || opened.quotient_chunks.len() != self.chunks
            || opened.quotient_chunks.iter().any(|v| v.len() != 3)
            || opened.random.as_ref().is_none_or(|v| v.len() != 3)
        {
            return Err(ERROR);
        }
        emit(public)?;
        let log_lde = self.degree + profile::LOG_BLOWUP;
        for cap in [
            &proof.commitments.trace,
            &proof.commitments.quotient_chunks,
            proof.commitments.random.as_ref().ok_or(ERROR)?,
        ] {
            cap_values(cap, log_lde, emit)?;
        }
        extensions(&opened.trace_local, emit)?;
        if let Some(next) = &opened.trace_next {
            extensions(next, emit)?;
        }
        extensions(opened.random.as_ref().ok_or(ERROR)?, emit)?;
        for chunk in &opened.quotient_chunks {
            extensions(chunk, emit)?;
        }
        let (random_openings, fri) = &proof.opening_proof;
        // The PCS rounds follow the compiler's random/trace/quotient order,
        // which differs from the commitment inputs above.
        let widths = [3, self.width, 3];
        let matrices = [1, 1, self.chunks];
        let points = [1, 1 + usize::from(self.next), 1];
        if random_openings.len() != 3
            || fri.commit_phase_commits.len() != self.degree
            || fri.commit_pow_witnesses.len() != self.degree
            || fri.final_poly.len() != 1
            || fri.query_proofs.len() != profile::NUM_QUERIES
        {
            return Err(ERROR);
        }
        for (round, opening) in random_openings.iter().enumerate() {
            if opening.len() != matrices[round] {
                return Err(ERROR);
            }
            for matrix in opening {
                if matrix.len() != points[round] {
                    return Err(ERROR);
                }
                for values in matrix {
                    if values.len() != profile::NUM_RANDOM_CODEWORDS {
                        return Err(ERROR);
                    }
                    extensions(values, emit)?;
                }
            }
        }
        for (layer, cap) in fri.commit_phase_commits.iter().enumerate() {
            cap_values(cap, log_lde - layer - 1, emit)?;
        }
        // The pinned zero-commit-PoW compiler checks vector length but consumes
        // no commit witnesses. Keep its actual input order, including query PoW.
        extensions(&fri.final_poly, emit)?;
        emit(&[fri.query_pow_witness])?;
        for query in &fri.query_proofs {
            if query.input_proof.len() != 3 || query.commit_phase_openings.len() != self.degree {
                return Err(ERROR);
            }
            for (round, opening) in query.input_proof.iter().enumerate() {
                if opening.opened_values.len() != matrices[round] {
                    return Err(ERROR);
                }
                for values in &opening.opened_values {
                    if values.len() != widths[round] + profile::NUM_RANDOM_CODEWORDS {
                        return Err(ERROR);
                    }
                    emit(values)?;
                }
                authentication(&opening.opening_proof, matrices[round], log_lde, emit)?;
            }
            for (layer, step) in query.commit_phase_openings.iter().enumerate() {
                if step.log_arity != 1 || step.sibling_values.len() != 1 {
                    return Err(ERROR);
                }
                extensions(&step.sibling_values, emit)?;
                authentication(&step.opening_proof, 1, log_lde - layer - 1, emit)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Shape {
    wallets: [UniShape; 2],
}

impl Shape {
    pub(crate) fn from_prefix(
        prefix: &RegistryPrefix<'_>,
        height: usize,
        mode: u64,
    ) -> Result<Self, CompileError> {
        prefix.fields(height, typed_pairs::KEY_COUNT)?;
        let modes = typed_pairs::leaf_modes(mode)?;
        let constants = compiler_constants(Some(prefix));
        Ok(Self {
            wallets: [
                UniShape::from_mode(modes[0], constants)?,
                UniShape::from_mode(modes[1], constants)?,
            ],
        })
    }
    fn visit(
        &self,
        caps: &typed_pairs::Caps,
        wallets: [Wallet<'_>; 2],
        emit: &mut impl FnMut(&[Val]) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        check_caps(caps)?;
        for digest in caps.iter().flatten() {
            emit(digest)?;
        }
        for (shape, wallet) in self.wallets.iter().zip(wallets) {
            shape.walk(wallet, emit)?;
        }
        Ok(())
    }
}

pub(crate) fn bind(
    shape: &Shape,
    caps: &typed_pairs::Caps,
    wallets: [Wallet<'_>; 2],
    expected_values: usize,
    limit_bytes: usize,
) -> Result<Vec<Val>, CompileError> {
    let limit = limit_bytes.min(MAX_INPUT_BYTES);
    if expected_values
        .checked_mul(core::mem::size_of::<Val>())
        .ok_or(ERROR)?
        > limit
    {
        return Err(ERROR);
    }
    let mut count = 0usize;
    shape.visit(caps, wallets, &mut |values| {
        count = count.checked_add(values.len()).ok_or(ERROR)?;
        if count > expected_values {
            return Err(ERROR);
        }
        Ok(())
    })?;
    if count != expected_values {
        return Err(ERROR);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| ERROR)?;
    if output
        .capacity()
        .checked_mul(core::mem::size_of::<Val>())
        .ok_or(ERROR)?
        > limit
    {
        return Err(ERROR);
    }
    shape.visit(caps, wallets, &mut |values| {
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

pub(crate) fn check_witness(
    shape: &Shape,
    caps: &typed_pairs::Caps,
    wallets: [Wallet<'_>; 2],
    witness: &[Val],
    limit_bytes: usize,
) -> Result<(), CompileError> {
    if witness
        .len()
        .checked_mul(core::mem::size_of::<Val>())
        .ok_or(ERROR)?
        > limit_bytes.min(MAX_INPUT_BYTES)
    {
        return Err(ERROR);
    }
    let mut offset = 0usize;
    shape.visit(caps, wallets, &mut |values| {
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

#[cfg(test)]
mod tests;
