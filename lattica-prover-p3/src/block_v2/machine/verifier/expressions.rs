//! DAG-memoized lowering of upstream symbolic constraints at the OOD point.
use super::super::circuit::Extension;
use super::super::program::Val;
use super::super::{ProgramBuilder, Wire};
use super::{ext_base, CompileError};
use crate::block_v2::profile::Challenge;
use p3_air::symbolic::{
    BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression, SymbolicExpressionExt,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField};
use std::collections::HashMap;

pub struct Evaluation {
    pub main: [Vec<Extension>; 2],
    pub preprocessed: [Vec<Extension>; 2],
    pub periodic: Vec<Extension>,
    pub public: Vec<Wire>,
    pub permutation: [Vec<Extension>; 2],
    pub challenges: Vec<Extension>,
    pub terminals: Vec<Extension>,
    pub first: Extension,
    pub last: Extension,
    pub transition: Extension,
}

pub struct Lowerer<'a> {
    pub b: &'a mut ProgramBuilder,
    pub values: Evaluation,
    base_cache: HashMap<usize, Extension>,
    extension_cache: HashMap<usize, Extension>,
}

impl<'a> Lowerer<'a> {
    pub fn new(b: &'a mut ProgramBuilder, values: Evaluation) -> Self {
        Self {
            b,
            values,
            base_cache: HashMap::new(),
            extension_cache: HashMap::new(),
        }
    }
    pub fn base(&mut self, e: &SymbolicExpression<Val>) -> Result<Extension, CompileError> {
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
        self.base_cache.insert(key, value);
        Ok(value)
    }
    pub fn extension(
        &mut self,
        e: &SymbolicExpressionExt<Val, Challenge>,
    ) -> Result<Extension, CompileError> {
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
        self.extension_cache.insert(key, value);
        Ok(value)
    }
}

pub fn selectors(
    b: &mut ProgramBuilder,
    zeta: Extension,
    log_height: usize,
) -> (Extension, Extension, Extension, Extension) {
    let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let zn = b.ext_pow(zeta, 1 << log_height);
    let vanishing = b.ext_sub(zn, one);
    let first_den = b.ext_sub(zeta, one);
    let first_inv = b.ext_inverse(first_den);
    let first = b.ext_mul(vanishing, first_inv);
    let last_point = b.ext_constant([
        Val::two_adic_generator(log_height).inverse(),
        Val::ZERO,
        Val::ZERO,
    ]);
    let transition = b.ext_sub(zeta, last_point);
    let last_inv = b.ext_inverse(transition);
    let last = b.ext_mul(vanishing, last_inv);
    let inv_vanishing = b.ext_inverse(vanishing);
    (first, last, transition, inv_vanishing)
}

/// Fixed public periodic columns are interpolated on their own subgroup, then
/// evaluated at zeta^(N / period). This matches p3-commit's shifted-free domain.
pub fn periodic_values(
    b: &mut ProgramBuilder,
    columns: &[Vec<Val>],
    zeta: Extension,
    log_height: usize,
) -> Result<Vec<Extension>, CompileError> {
    let mut values = Vec::new();
    for column in columns {
        let n = column.len();
        if !n.is_power_of_two() || n > 1 << log_height {
            return Err(CompileError::Shape("periodic column height"));
        }
        let generator_inv = Val::two_adic_generator(n.ilog2() as usize).inverse();
        let inv_n = Val::from_usize(n).inverse();
        let point = b.ext_pow(zeta, (1 << log_height) / n as u64);
        let mut coefficients = Vec::with_capacity(n);
        for k in 0..n {
            let step = generator_inv.exp_u64(k as u64);
            let mut power = Val::ONE;
            let mut sum = Val::ZERO;
            for &value in column {
                sum += power * value;
                power *= step;
            }
            coefficients.push(sum * inv_n);
        }
        let mut value = b.ext_constant([Val::ZERO; 3]);
        for coefficient in coefficients.into_iter().rev() {
            value = b.ext_mul(value, point);
            let term = b.ext_constant([coefficient, Val::ZERO, Val::ZERO]);
            value = b.ext_add(value, term);
        }
        values.push(value);
    }
    Ok(values)
}

/// Recompose the hiding quotient chunks on disjoint cosets. The chunk domain
/// has the original (unmasked) trace height; committed chunks have double that.
pub fn quotient(
    b: &mut ProgramBuilder,
    chunks: &[Vec<Extension>],
    zeta: Extension,
    log_height: usize,
) -> Result<Extension, CompileError> {
    if chunks.is_empty() || !chunks.len().is_power_of_two() || chunks.iter().any(|c| c.len() != 3) {
        return Err(CompileError::Shape("quotient chunks"));
    }
    let log_chunks = chunks.len().ilog2() as usize;
    let g = Val::two_adic_generator(log_height + log_chunks);
    let shifts: Vec<_> = (0..chunks.len())
        .map(|i| Val::GENERATOR * g.exp_u64(i as u64))
        .collect();
    let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let mut vanishing = Vec::new();
    for shift in &shifts {
        let inv = b.constant(shift.inverse());
        let z = b.ext_scale(zeta, inv);
        let power = b.ext_pow(z, 1 << log_height);
        vanishing.push(b.ext_sub(power, one));
    }
    let basis = [
        b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]),
        b.ext_constant([Val::ZERO, Val::ONE, Val::ZERO]),
        b.ext_constant([Val::ZERO, Val::ZERO, Val::ONE]),
    ];
    let mut result = b.ext_constant([Val::ZERO; 3]);
    for (i, chunk) in chunks.iter().enumerate() {
        let mut coefficient = one;
        for (j, &other) in shifts.iter().enumerate() {
            if i != j {
                let den = (shifts[i] / other).exp_u64(1 << log_height) - Val::ONE;
                let inv = b.constant(den.inverse());
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
}
