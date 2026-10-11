//! Fixed allocation envelope for the GPU compiler's canonical symbolic DAG.
//! This is a sub-budget of symbolic::HOST_BYTES, not an extra worker allowance.
use super::*;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

pub(crate) const HOST_BYTES: usize = 32 << 20;
const MAX_NODES: usize = 1 << 17;
const MAX_DEPTH: usize = 512;
const SLOTS: usize = 2 * MAX_NODES;
const FIXED_BYTES: usize = 1 << 20; // stack traversal and fixed object overhead
const _: () = assert!(HOST_BYTES as u64 <= super::super::symbolic::HOST_BYTES - (64 << 20));

struct Memo {
    slots: Vec<Option<(usize, u64)>>,
    hash: RandomState,
}
impl Memo {
    fn new() -> Result<Self, String> {
        let mut slots = reserve(SLOTS)?;
        slots.resize(SLOTS, None);
        Ok(Self {
            slots,
            hash: RandomState::new(),
        })
    }
    fn index(&self, key: usize) -> usize {
        let mut hasher = self.hash.build_hasher();
        key.hash(&mut hasher);
        hasher.finish() as usize & (SLOTS - 1)
    }
    fn get(&self, key: usize) -> Option<u64> {
        let mut slot = self.index(key);
        loop {
            match self.slots[slot] {
                None => return None,
                Some((stored, id)) if stored == key => return Some(id),
                _ => slot = (slot + 1) & (SLOTS - 1),
            }
        }
    }
    fn insert(&mut self, key: usize, id: u64) {
        let mut slot = self.index(key);
        while self.slots[slot].is_some() {
            slot = (slot + 1) & (SLOTS - 1);
        }
        self.slots[slot] = Some((key, id));
    }
}

fn reserve<T>(length: usize) -> Result<Vec<T>, String> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| "fingerprint allocation failed")?;
    Ok(values)
}

fn allocation(roots: usize, layout: usize, allowance: usize) -> Result<usize, String> {
    if roots > MAX_NODES || layout > MAX_NODES {
        return Err("fingerprint root/layout bound".into());
    }
    // Five words per node (length + at most four payload words), seven
    // header/length words, both root arrays and both layout arrays.
    let fields = 7 + 5 * MAX_NODES + roots + layout;
    let bytes = FIXED_BYTES
        + 2 * SLOTS * std::mem::size_of::<Option<(usize, u64)>>()
        + (fields + roots) * std::mem::size_of::<u64>();
    if bytes > allowance {
        return Err("fingerprint host allowance".into());
    }
    Ok(fields)
}

struct Encoder {
    base: Memo,
    extension: Memo,
    nodes: u64,
    fields: Vec<u64>,
}

impl Encoder {
    fn node(&mut self, fields: &[u64]) -> Result<u64, String> {
        if self.nodes as usize == MAX_NODES || fields.len() > 4 {
            return Err("fingerprint node bound".into());
        }
        let id = self.nodes;
        self.nodes += 1;
        self.fields.push(fields.len() as u64);
        self.fields.extend_from_slice(fields);
        Ok(id)
    }
    fn base(&mut self, expr: &SymbolicExpression<Val>, depth: usize) -> Result<u64, String> {
        let key = expr as *const _ as usize;
        if let Some(id) = self.base.get(key) {
            return Ok(id);
        }
        if depth > MAX_DEPTH {
            return Err("fingerprint depth bound".into());
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
                let a = self.base(x, depth + 1)?;
                let b = self.base(y, depth + 1)?;
                self.node(&[5, a, b])
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.base(x, depth + 1)?;
                let b = self.base(y, depth + 1)?;
                self.node(&[6, a, b])
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.base(x, depth + 1)?;
                let b = self.base(y, depth + 1)?;
                self.node(&[7, a, b])
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.base(x, depth + 1)?;
                self.node(&[8, a])
            }
        }?;
        self.base.insert(key, id);
        Ok(id)
    }
    fn extension(
        &mut self,
        expr: &SymbolicExpressionExt<Val, Challenge>,
        depth: usize,
    ) -> Result<u64, String> {
        let key = expr as *const _ as usize;
        if let Some(id) = self.extension.get(key) {
            return Ok(id);
        }
        if depth > MAX_DEPTH {
            return Err("fingerprint depth bound".into());
        }
        let id = match expr {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(e) => {
                    let id = self.base(e, depth + 1)?;
                    self.node(&[9, id])
                }
                ExtLeaf::ExtConstant(v) => {
                    let coefficients: &[Val] = v.as_basis_coefficients_slice();
                    self.node(&[
                        10,
                        coefficients[0].as_canonical_u64(),
                        coefficients[1].as_canonical_u64(),
                        coefficients[2].as_canonical_u64(),
                    ])
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
                let a = self.extension(x, depth + 1)?;
                let b = self.extension(y, depth + 1)?;
                self.node(&[12, a, b])
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let a = self.extension(x, depth + 1)?;
                let b = self.extension(y, depth + 1)?;
                self.node(&[13, a, b])
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let a = self.extension(x, depth + 1)?;
                let b = self.extension(y, depth + 1)?;
                self.node(&[14, a, b])
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.extension(x, depth + 1)?;
                self.node(&[15, a])
            }
        }?;
        self.extension.insert(key, id);
        Ok(id)
    }
}

pub(crate) fn encode(
    base: &[SymbolicExpression<Val>],
    extension: &[SymbolicExpressionExt<Val, Challenge>],
    layout: &ConstraintLayout,
    allowance: usize,
) -> Result<Vec<u64>, String> {
    let roots_len = base
        .len()
        .checked_add(extension.len())
        .ok_or("fingerprint roots overflow")?;
    let layout_len = layout
        .base_indices
        .len()
        .checked_add(layout.ext_indices.len())
        .ok_or("fingerprint layout overflow")?;
    // Admit every backing array before allocating any of them. All subsequent
    // writes fit these capacities; no grow/realloc overlap or per-node vectors.
    let capacity = allocation(roots_len, layout_len, allowance)?;
    let mut fields = reserve(capacity)?;
    fields.extend([1, 0, 0]);
    let mut encoder = Encoder {
        base: Memo::new()?,
        extension: Memo::new()?,
        nodes: 0,
        fields,
    };
    let mut roots = reserve(roots_len)?;
    for expr in base {
        roots.push(encoder.base(expr, 0)?);
    }
    for expr in extension {
        roots.push(encoder.extension(expr, 0)?);
    }
    encoder.fields[1] = encoder.nodes;
    encoder.fields[2] = (encoder.fields.len() - 3) as u64;
    let Encoder {
        fields: mut fields,
        base: base_memo,
        extension: ext_memo,
        ..
    } = encoder;
    drop((base_memo, ext_memo));
    fields.push(base.len() as u64);
    fields.extend_from_slice(&roots[..base.len()]);
    fields.push(extension.len() as u64);
    fields.extend_from_slice(&roots[base.len()..]);
    drop(roots);
    for values in [&layout.base_indices, &layout.ext_indices] {
        fields.push(values.len() as u64);
        fields.extend(values.iter().map(|&index| index as u64));
    }
    Ok(fields)
}

#[cfg(test)]
mod tests;
