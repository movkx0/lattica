//! DAG-memoized lowering of upstream symbolic constraints at the OOD point.
use super::super::circuit::Extension;
use super::super::compiler_constants::Constants;
use super::super::program::CompilerMemo;
use super::super::program::ScopedProgramBuilder as ProgramBuilder;
use super::super::program::Val;
use super::super::Wire;
use super::{ext_base, CompileError};
use crate::block_v2::profile::Challenge;
use p3_air::symbolic::{
    BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression, SymbolicExpressionExt,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

/// A borrowed row or a repeated pattern with the same checked indexing as a
/// materialized vector. Repetition creates no field operations or heap storage.
#[derive(Clone, Copy)]
pub enum Values<'a> {
    Slice(&'a [Extension]),
    Repeated {
        pattern: &'a [Extension],
        len: usize,
    },
}

impl<'a> Values<'a> {
    pub fn repeat(pattern: &'a [Extension], repetitions: usize) -> Result<Self, CompileError> {
        let len = pattern
            .len()
            .checked_mul(repetitions)
            .ok_or(CompileError::Shape("evaluation pattern length"))?;
        Ok(Self::Repeated { pattern, len })
    }

    pub fn get(&self, index: usize) -> Option<&Extension> {
        match self {
            Self::Slice(values) => values.get(index),
            Self::Repeated { pattern, len } => {
                if index >= *len {
                    return None;
                }
                pattern.get(index.checked_rem(pattern.len())?)
            }
        }
    }
}

pub struct Evaluation<'a> {
    pub main: [Values<'a>; 2],
    pub preprocessed: [Values<'a>; 2],
    pub periodic: &'a [Extension],
    pub public: &'a [Wire],
    pub permutation: [&'a [Extension]; 2],
    pub challenges: Values<'a>,
    pub terminals: &'a [Extension],
    pub first: Extension,
    pub last: Extension,
    pub transition: Extension,
}

pub struct Lowerer<'a, 'backend> {
    pub b: &'a mut ProgramBuilder<'backend>,
    pub values: Evaluation<'a>,
    base_cache: CompilerMemo<Extension>,
    extension_cache: CompilerMemo<Extension>,
}

impl Drop for Lowerer<'_, '_> {
    fn drop(&mut self) {
        self.base_cache.release(self.b, "base");
        self.extension_cache.release(self.b, "extension");
    }
}

impl<'a, 'backend> Lowerer<'a, 'backend> {
    pub fn new(b: &'a mut ProgramBuilder<'backend>, values: Evaluation<'a>) -> Self {
        Self {
            b,
            values,
            base_cache: CompilerMemo::new(),
            extension_cache: CompilerMemo::new(),
        }
    }
    pub fn base(&mut self, e: &SymbolicExpression<Val>) -> Result<Extension, CompileError> {
        if self.b.resource_failure().is_some() {
            return Err(CompileError::Shape("expression compiler host allowance"));
        }
        let key = e as *const _ as usize;
        if let Some(&value) = self.base_cache.get(&key) {
            return Ok(value);
        }
        let value = match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(v) => self.b.ext_constant([*v, Val::ZERO, Val::ZERO]),
                BaseLeaf::IsFirstRow => self.values.first,
                BaseLeaf::IsLastRow => self.values.last,
                BaseLeaf::IsTransition => self.values.transition,
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset } => *self
                        .values
                        .main
                        .get(offset)
                        .and_then(|m| m.get(v.index))
                        .ok_or(CompileError::Shape("main constraint index"))?,
                    BaseEntry::Preprocessed { offset } => *self
                        .values
                        .preprocessed
                        .get(offset)
                        .and_then(|m| m.get(v.index))
                        .ok_or(CompileError::Shape("preprocessing constraint index"))?,
                    BaseEntry::Periodic => *self
                        .values
                        .periodic
                        .get(v.index)
                        .ok_or(CompileError::Shape("periodic constraint index"))?,
                    BaseEntry::Public => ext_base(
                        self.b,
                        *self
                            .values
                            .public
                            .get(v.index)
                            .ok_or(CompileError::Shape("public constraint index"))?,
                    ),
                },
            },
            SymbolicExpr::Add { x, y, .. } => {
                let a = self.base(x)?;
                let c = self.base(y)?;
                self.b.ext_add(a, c)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.base(x)?;
                let c = self.base(y)?;
                self.b.ext_sub(a, c)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.base(x)?;
                let c = self.base(y)?;
                self.b.ext_mul(a, c)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.base(x)?;
                let zero = self.b.ext_constant([Val::ZERO; 3]);
                self.b.ext_sub(zero, a)
            }
        };
        self.base_cache.insert(key, value, self.b)?;
        Ok(value)
    }
    pub fn extension(
        &mut self,
        e: &SymbolicExpressionExt<Val, Challenge>,
    ) -> Result<Extension, CompileError> {
        if self.b.resource_failure().is_some() {
            return Err(CompileError::Shape("expression compiler host allowance"));
        }
        let key = e as *const _ as usize;
        if let Some(&value) = self.extension_cache.get(&key) {
            return Ok(value);
        }
        let value = match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(e) => self.base(e)?,
                ExtLeaf::ExtConstant(v) => self
                    .b
                    .ext_constant(v.as_basis_coefficients_slice().try_into().unwrap()),
                ExtLeaf::ExtVariable(v) => match v.entry {
                    ExtEntry::Permutation { offset } => *self
                        .values
                        .permutation
                        .get(offset)
                        .and_then(|m| m.get(v.index))
                        .ok_or(CompileError::Shape("permutation constraint index"))?,
                    ExtEntry::Challenge => *self
                        .values
                        .challenges
                        .get(v.index)
                        .ok_or(CompileError::Shape("lookup challenge index"))?,
                    ExtEntry::PermutationValue => *self
                        .values
                        .terminals
                        .get(v.index)
                        .ok_or(CompileError::Shape("lookup terminal index"))?,
                },
            },
            SymbolicExpr::Add { x, y, .. } => {
                let a = self.extension(x)?;
                let c = self.extension(y)?;
                self.b.ext_add(a, c)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.extension(x)?;
                let c = self.extension(y)?;
                self.b.ext_sub(a, c)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.extension(x)?;
                let c = self.extension(y)?;
                self.b.ext_mul(a, c)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.extension(x)?;
                let zero = self.b.ext_constant([Val::ZERO; 3]);
                self.b.ext_sub(zero, a)
            }
        };
        self.extension_cache.insert(key, value, self.b)?;
        Ok(value)
    }
}

pub fn selectors(
    b: &mut ProgramBuilder,
    zeta: Extension,
    log_height: usize,
) -> (Extension, Extension, Extension, Extension) {
    selectors_with_constants(b, zeta, log_height, Constants::cpu())
        .expect("valid compiler subgroup")
}

pub(crate) fn selectors_with_constants(
    b: &mut ProgramBuilder,
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
) -> Result<(Extension, Extension, Extension, Extension), CompileError> {
    let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let zn = b.ext_pow(zeta, 1 << log_height);
    let vanishing = b.ext_sub(zn, one);
    let first_den = b.ext_sub(zeta, one);
    let first_inv = b.ext_inverse(first_den);
    let first = b.ext_mul(vanishing, first_inv);
    let last_point = b.ext_constant([
        constants.inverse_generator(log_height)?,
        Val::ZERO,
        Val::ZERO,
    ]);
    let transition = b.ext_sub(zeta, last_point);
    let last_inv = b.ext_inverse(transition);
    let last = b.ext_mul(vanishing, last_inv);
    let inv_vanishing = b.ext_inverse(vanishing);
    Ok((first, last, transition, inv_vanishing))
}

/// Fixed public periodic columns are interpolated on their own subgroup, then
/// evaluated at zeta^(N / period). This matches p3-commit's shifted-free domain.
pub fn periodic_values(
    b: &mut ProgramBuilder,
    columns: &[Vec<Val>],
    zeta: Extension,
    log_height: usize,
) -> Result<Vec<Extension>, CompileError> {
    // Compatibility helper returns caller-owned CPU output. Registered
    // compilers provide an admitted slice to periodic_values_into instead.
    let mut values = Vec::new();
    values
        .try_reserve_exact(columns.len())
        .map_err(|_| CompileError::Shape("periodic output allocation"))?;
    values.resize(columns.len(), [Wire(0); 3]);
    periodic_values_into(b, columns, zeta, log_height, Constants::cpu(), &mut values)?;
    Ok(values)
}

pub(crate) fn periodic_values_into(
    b: &mut ProgramBuilder,
    columns: &[Vec<Val>],
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
    values: &mut [Extension],
) -> Result<(), CompileError> {
    if values.len() != columns.len() || log_height > 32 {
        return Err(CompileError::Shape("periodic output geometry"));
    }
    for (column, out) in columns.iter().zip(values) {
        *out = periodic_value(b, column, zeta, log_height, constants)?;
    }
    Ok(())
}

pub(super) fn periodic_value(
    b: &mut ProgramBuilder,
    column: &[Val],
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
) -> Result<Extension, CompileError> {
    let n = column.len();
    if log_height > 32 || !n.is_power_of_two() || n as u64 > 1u64 << log_height {
        return Err(CompileError::Shape("periodic column height"));
    }
    let value =
        b.with_compiler_scratch("periodic-coefficients", n, Val::ZERO, |b, coefficients| {
            constants.periodic_into(column, log_height, coefficients)?;
            let point = b.ext_pow(zeta, (1 << log_height) / n as u64);
            let mut value = b.ext_constant([Val::ZERO; 3]);
            for &coefficient in coefficients.iter().rev() {
                value = b.ext_mul(value, point);
                let term = b.ext_constant([coefficient, Val::ZERO, Val::ZERO]);
                value = b.ext_add(value, term);
            }
            Ok(value)
        })?;
    if b.resource_failure().is_some() {
        return Err(CompileError::Shape("periodic compiler allowance"));
    }
    Ok(value)
}

/// Recompose the hiding quotient chunks on disjoint cosets. The chunk domain
/// has the original (unmasked) trace height; committed chunks have double that.
pub fn quotient(
    b: &mut ProgramBuilder,
    chunks: &[Vec<Extension>],
    zeta: Extension,
    log_height: usize,
) -> Result<Extension, CompileError> {
    quotient_with_constants(b, chunks, zeta, log_height, Constants::cpu())
}

pub(crate) fn quotient_with_constants(
    b: &mut ProgramBuilder,
    chunks: &[Vec<Extension>],
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
) -> Result<Extension, CompileError> {
    if chunks.is_empty()
        || !chunks.len().is_power_of_two()
        || chunks.len() > super::pcs::MAX_MATRICES
        || chunks.iter().any(|c| c.len() != 3)
    {
        return Err(CompileError::Shape("quotient chunks"));
    }
    let count = super::super::compiler_constants::quotient_count(chunks.len(), log_height)?;
    b.with_compiler_scratch("quotient-constants", count, Val::ZERO, |b, output| {
        constants.quotient_into(chunks.len(), log_height, output)?;
        let (inverse_shifts, normalization) = output.split_at(chunks.len());
        let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
        let mut vanishing = [[Wire(0); 3]; super::pcs::MAX_MATRICES];
        for (out, &inverse) in vanishing.iter_mut().zip(inverse_shifts) {
            let inv = b.constant(inverse);
            let z = b.ext_scale(zeta, inv);
            let power = b.ext_pow(z, 1 << log_height);
            *out = b.ext_sub(power, one);
        }
        let basis = [
            b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]),
            b.ext_constant([Val::ZERO, Val::ONE, Val::ZERO]),
            b.ext_constant([Val::ZERO, Val::ZERO, Val::ONE]),
        ];
        let mut result = b.ext_constant([Val::ZERO; 3]);
        for (i, chunk) in chunks.iter().enumerate() {
            let mut coefficient = one;
            for j in 0..chunks.len() {
                if i != j {
                    let inv = b.constant(normalization[i * chunks.len() + j]);
                    let factor = b.ext_scale(vanishing[j], inv);
                    coefficient = b.ext_mul(coefficient, factor);
                }
            }
            let mut chunk_value = b.ext_constant([Val::ZERO; 3]);
            for k in 0..3 {
                let term = b.ext_mul(chunk[k], basis[k]);
                chunk_value = b.ext_add(chunk_value, term);
            }
            let term = b.ext_mul(coefficient, chunk_value);
            result = b.ext_add(result, term);
        }
        Ok(result)
    })
}

#[cfg(test)]
mod tests;
