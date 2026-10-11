use super::{BaseExpr, Builder, ExtExpr, Val, MAX_NODES};
use crate::block_v2::machine::{
    compiler_constants::{Constants, FoldOperation, Folding},
    verifier::CompileError,
};
use p3_air::symbolic::{ExtLeaf, SymLeaf, SymbolicExpr};
use p3_field::PrimeCharacteristicRing;
use std::sync::Arc;
mod storage;
pub(super) use storage::{Map, Storage, HOST_BYTES};
#[cfg(test)]
pub(super) mod tests;

/// Check every recorded root, including unused interaction/constraint streams,
/// before any backend arithmetic. Input AIRs and layouts are trusted compiler
/// types; this does not admit arbitrary remote AIR code or unbounded evaluation.
pub(super) fn admit(builder: &Builder, storage: &Storage) -> Result<(), CompileError> {
    builder.check()?;
    enum Node<'a> {
        Base(&'a BaseExpr),
        Ext(&'a ExtExpr),
    }
    let mut stack = Vec::new();
    let mut root = |node| {
        if stack.len() >= MAX_NODES {
            return Err(CompileError::Shape("symbolic graph exceeds admission"));
        }
        storage.push(&mut stack, (node, 0))?;
        Ok(())
    };
    for e in &builder.base {
        root(Node::Base(e))?;
    }
    for e in &builder.extension {
        root(Node::Ext(e))?;
    }
    for i in &builder.global {
        root(Node::Base(&i.count))?;
        for e in &i.fields {
            root(Node::Base(e))?;
        }
    }
    for i in &builder.local {
        for (fields, count) in &i.tuples {
            root(Node::Base(count))?;
            for e in fields {
                root(Node::Base(e))?;
            }
        }
    }
    let mut seen = [Map::new(storage), Map::new(storage)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 512 {
            return Err(CompileError::Shape(
                "symbolic graph depth exceeds admission",
            ));
        }
        let key = match &node {
            Node::Base(e) => (0, *e as *const _ as usize),
            Node::Ext(e) => (1, *e as *const _ as usize),
        };
        // Revisit a shared node if reached along a longer path. A short path
        // must not hide an over-deep branch from the preflight.
        if seen[key.0].get(key.1).is_some_and(|&old| old >= depth) {
            continue;
        }
        if seen[key.0].get(key.1).is_none() && seen.iter().map(Map::len).sum::<usize>() >= MAX_NODES
        {
            return Err(CompileError::Shape("symbolic graph exceeds admission"));
        }
        seen[key.0].insert(key.1, depth)?;
        match node {
            Node::Base(e) => match e {
                SymbolicExpr::Leaf(_) => {}
                SymbolicExpr::Neg { x, .. } => {
                    storage.push(&mut stack, (Node::Base(x), depth + 1))?
                }
                SymbolicExpr::Add { x, y, .. }
                | SymbolicExpr::Sub { x, y, .. }
                | SymbolicExpr::Mul { x, y, .. } => {
                    storage.push(&mut stack, (Node::Base(x), depth + 1))?;
                    storage.push(&mut stack, (Node::Base(y), depth + 1))?;
                }
            },
            Node::Ext(e) => match e {
                SymbolicExpr::Leaf(ExtLeaf::Base(e)) => {
                    storage.push(&mut stack, (Node::Base(e), depth + 1))?
                }
                SymbolicExpr::Leaf(_) => {}
                SymbolicExpr::Neg { x, .. } => {
                    storage.push(&mut stack, (Node::Ext(x), depth + 1))?
                }
                SymbolicExpr::Add { x, y, .. }
                | SymbolicExpr::Sub { x, y, .. }
                | SymbolicExpr::Mul { x, y, .. } => {
                    storage.push(&mut stack, (Node::Ext(x), depth + 1))?;
                    storage.push(&mut stack, (Node::Ext(y), depth + 1))?;
                }
            },
        }
    }
    Ok(())
}

/// Maps *input Arc identity* to output Arc identity. Structural interning would
/// change the protocol's DAG fingerprint. The caller keeps every input root
/// alive until this entire pass has ended, so pointer keys cannot be reused.
pub(super) struct Normalizer<'a, 'b> {
    folding: Folding<'a>,
    storage: &'b Storage,
    base: Map<'b, Arc<BaseExpr>>,
    extension: Map<'b, Arc<ExtExpr>>,
    nodes: usize,
}

impl<'a, 'b> Normalizer<'a, 'b> {
    pub(super) fn new(constants: Constants<'a>, storage: &'b Storage) -> Self {
        Self {
            folding: Folding::new(constants),
            storage,
            base: Map::new(storage),
            extension: Map::new(storage),
            nodes: 0,
        }
    }
    fn admit(&mut self, depth: usize) -> Result<(), CompileError> {
        self.storage.check()?;
        if depth > 512 || self.nodes >= MAX_NODES {
            return Err(CompileError::Shape("symbolic graph exceeds admission"));
        }
        self.nodes += 1;
        Ok(())
    }
    fn fold(&mut self, op: FoldOperation, a: Val, b: Val) -> Result<Val, CompileError> {
        self.storage.check()?;
        let value = self
            .folding
            .fold(op, [a, Val::ZERO, Val::ZERO], [b, Val::ZERO, Val::ZERO]);
        if let Some(error) = self.folding.failure() {
            return Err(error.clone());
        }
        Ok(value.expect("addition and multiplication are total")[0])
    }
    fn neg<A: SymLeaf<F = Val>>(
        &mut self,
        x: Arc<SymbolicExpr<A>>,
    ) -> Result<SymbolicExpr<A>, CompileError> {
        if let SymbolicExpr::Leaf(a) = x.as_ref() {
            if let Some(&v) = a.as_const() {
                return Ok(SymbolicExpr::Leaf(A::from_const(self.fold(
                    FoldOperation::Mul,
                    v,
                    Val::NEG_ONE,
                )?)));
            }
        }
        Ok(SymbolicExpr::Neg {
            degree_multiple: x.degree_multiple(),
            x,
        })
    }
    fn binary<A: SymLeaf<F = Val>>(
        &mut self,
        tag: u8,
        x: Arc<SymbolicExpr<A>>,
        y: Arc<SymbolicExpr<A>>,
    ) -> Result<SymbolicExpr<A>, CompileError> {
        let known = |e: &SymbolicExpr<A>| match e {
            SymbolicExpr::Leaf(a) => a.as_const().copied(),
            _ => None,
        };
        let a = known(&x);
        let b = known(&y);
        if let (Some(a), Some(b)) = (a, b) {
            let value = match tag {
                0 => self.fold(FoldOperation::Add, a, b)?,
                1 => {
                    let negative = self.fold(FoldOperation::Mul, b, Val::NEG_ONE)?;
                    self.fold(FoldOperation::Add, a, negative)?
                }
                2 => self.fold(FoldOperation::Mul, a, b)?,
                _ => unreachable!(),
            };
            return Ok(SymbolicExpr::Leaf(A::from_const(value)));
        }
        // Preserve the pinned p3-air simplification order exactly, including
        // double negation (which upstream deliberately does not eliminate).
        match tag {
            0 if a == Some(Val::ZERO) => return Ok(y.as_ref().clone()),
            0 | 1 if b == Some(Val::ZERO) => return Ok(x.as_ref().clone()),
            1 if a == Some(Val::ZERO) => return self.neg(y),
            2 if a == Some(Val::ZERO) || b == Some(Val::ZERO) => {
                return Ok(SymbolicExpr::Leaf(A::ZERO))
            }
            2 if a == Some(Val::ONE) => return Ok(y.as_ref().clone()),
            2 if b == Some(Val::ONE) => return Ok(x.as_ref().clone()),
            _ => {}
        }
        let degree_multiple = if tag == 2 {
            x.degree_multiple()
                .checked_add(y.degree_multiple())
                .ok_or(CompileError::Shape("symbolic degree overflow"))?
        } else {
            x.degree_multiple().max(y.degree_multiple())
        };
        Ok(match tag {
            0 => SymbolicExpr::Add {
                x,
                y,
                degree_multiple,
            },
            1 => SymbolicExpr::Sub {
                x,
                y,
                degree_multiple,
            },
            2 => SymbolicExpr::Mul {
                x,
                y,
                degree_multiple,
            },
            _ => unreachable!(),
        })
    }
    fn base_arc(
        &mut self,
        input: &Arc<BaseExpr>,
        depth: usize,
    ) -> Result<Arc<BaseExpr>, CompileError> {
        let key = Arc::as_ptr(input) as usize;
        if let Some(value) = self.base.get(key) {
            return Ok(value.clone());
        }
        let value = self.storage.arc(|| self.base(input, depth))?;
        self.base.insert(key, value.clone())?;
        Ok(value)
    }
    fn ext_arc(
        &mut self,
        input: &Arc<ExtExpr>,
        depth: usize,
    ) -> Result<Arc<ExtExpr>, CompileError> {
        let key = Arc::as_ptr(input) as usize;
        if let Some(value) = self.extension.get(key) {
            return Ok(value.clone());
        }
        let value = self.storage.arc(|| self.extension(input, depth))?;
        self.extension.insert(key, value.clone())?;
        Ok(value)
    }
    pub(super) fn base(
        &mut self,
        input: &BaseExpr,
        depth: usize,
    ) -> Result<BaseExpr, CompileError> {
        self.admit(depth)?;
        let (tag, x, y) = match input {
            SymbolicExpr::Leaf(a) => return Ok(SymbolicExpr::Leaf(a.clone())),
            SymbolicExpr::Neg { x, .. } => {
                let x = self.base_arc(x, depth + 1)?;
                return self.neg(x);
            }
            SymbolicExpr::Add { x, y, .. } => (0, x, y),
            SymbolicExpr::Sub { x, y, .. } => (1, x, y),
            SymbolicExpr::Mul { x, y, .. } => (2, x, y),
        };
        let x = self.base_arc(x, depth + 1)?;
        let y = self.base_arc(y, depth + 1)?;
        self.binary(tag, x, y)
    }
    pub(super) fn extension(
        &mut self,
        input: &ExtExpr,
        depth: usize,
    ) -> Result<ExtExpr, CompileError> {
        self.admit(depth)?;
        let (tag, x, y) = match input {
            SymbolicExpr::Leaf(ExtLeaf::Base(b)) => {
                return Ok(SymbolicExpr::Leaf(ExtLeaf::Base(self.base(b, depth + 1)?)))
            }
            SymbolicExpr::Leaf(a) => return Ok(SymbolicExpr::Leaf(a.clone())),
            SymbolicExpr::Neg { x, .. } => {
                let x = self.ext_arc(x, depth + 1)?;
                return self.neg(x);
            }
            SymbolicExpr::Add { x, y, .. } => (0, x, y),
            SymbolicExpr::Sub { x, y, .. } => (1, x, y),
            SymbolicExpr::Mul { x, y, .. } => (2, x, y),
        };
        let x = self.ext_arc(x, depth + 1)?;
        let y = self.ext_arc(y, depth + 1)?;
        self.binary(tag, x, y)
    }
}
