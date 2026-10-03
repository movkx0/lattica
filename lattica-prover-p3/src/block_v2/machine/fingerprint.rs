//! Canonical DAG encoding for symbolic AIR fingerprints. Never Debug-format a
//! symbolic expression tree: Poseidon linear layers share subexpressions and
//! expanding them as a tree can take exponential time and memory.
use super::program::Val;
use crate::block_v2::profile::Challenge;
use p3_air::symbolic::{
    BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt,
};
use p3_field::{BasedVectorSpace, PrimeField64};
use std::collections::HashMap;

#[derive(Default)]
struct Encoder {
    base: HashMap<usize, u64>,
    extension: HashMap<usize, u64>,
    nodes: u64,
    fields: Vec<u64>,
}

impl Encoder {
    fn node(&mut self, fields: &[u64]) -> u64 {
        let id = self.nodes;
        self.nodes += 1;
        self.fields.push(fields.len() as u64);
        self.fields.extend_from_slice(fields);
        id
    }
    fn base(&mut self, expr: &SymbolicExpression<Val>) -> u64 {
        let key = expr as *const _ as usize;
        if let Some(&id) = self.base.get(&key) {
            return id;
        }
        let id = match expr {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Variable(v) => {
                    let (tag, offset) = match v.entry {
                        BaseEntry::Preprocessed { offset } => (0, offset),
                        BaseEntry::Main { offset } => (1, offset),
                        BaseEntry::Periodic => (2, 0),
                        BaseEntry::Public => (3, 0),
                    };
                    self.node(&[0, tag, offset as u64, v.index as u64])
                }
                BaseLeaf::IsFirstRow => self.node(&[1]),
                BaseLeaf::IsLastRow => self.node(&[2]),
                BaseLeaf::IsTransition => self.node(&[3]),
                BaseLeaf::Constant(v) => self.node(&[4, v.as_canonical_u64()]),
            },
            SymbolicExpr::Add { x, y, .. } => {
                let a = self.base(x);
                let b = self.base(y);
                self.node(&[5, a, b])
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.base(x);
                let b = self.base(y);
                self.node(&[6, a, b])
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.base(x);
                let b = self.base(y);
                self.node(&[7, a, b])
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.base(x);
                self.node(&[8, a])
            }
        };
        self.base.insert(key, id);
        id
    }
    fn extension(&mut self, expr: &SymbolicExpressionExt<Val, Challenge>) -> u64 {
        let key = expr as *const _ as usize;
        if let Some(&id) = self.extension.get(&key) {
            return id;
        }
        let id = match expr {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(e) => {
                    let id = self.base(e);
                    self.node(&[9, id])
                }
                ExtLeaf::ExtConstant(v) => {
                    let mut fields = vec![10];
                    let coefficients: &[Val] = v.as_basis_coefficients_slice();
                    fields.extend(coefficients.iter().map(|v| v.as_canonical_u64()));
                    self.node(&fields)
                }
                ExtLeaf::ExtVariable(v) => {
                    let (tag, offset) = match v.entry {
                        ExtEntry::Permutation { offset } => (0, offset),
                        ExtEntry::Challenge => (1, 0),
                        ExtEntry::PermutationValue => (2, 0),
                    };
                    self.node(&[11, tag, offset as u64, v.index as u64])
                }
            },
            SymbolicExpr::Add { x, y, .. } => {
                let a = self.extension(x);
                let b = self.extension(y);
                self.node(&[12, a, b])
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.extension(x);
                let b = self.extension(y);
                self.node(&[13, a, b])
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.extension(x);
                let b = self.extension(y);
                self.node(&[14, a, b])
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.extension(x);
                self.node(&[15, a])
            }
        };
        self.extension.insert(key, id);
        id
    }
}

pub(super) fn encode(
    base: &[SymbolicExpression<Val>],
    extension: &[SymbolicExpressionExt<Val, Challenge>],
    layout: &ConstraintLayout,
) -> Vec<u64> {
    let mut encoder = Encoder::default();
    let base_roots: Vec<_> = base.iter().map(|e| encoder.base(e)).collect();
    let ext_roots: Vec<_> = extension.iter().map(|e| encoder.extension(e)).collect();
    let mut fields = vec![1, encoder.nodes, encoder.fields.len() as u64];
    fields.extend(encoder.fields);
    for values in [
        base_roots,
        ext_roots,
        layout.base_indices.iter().map(|&i| i as u64).collect(),
        layout.ext_indices.iter().map(|&i| i as u64).collect(),
    ] {
        fields.push(values.len() as u64);
        fields.extend(values);
    }
    fields
}
