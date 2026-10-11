use super::super::{ExecutionError, Program, Wire};
use super::*;
use crate::block_v2::machine::circuit::Extension;
use crate::block_v2::machine::program::{ScopedProgramBuilder as ProgramBuilder, Val};
use crate::block_v2::machine::verifier::expressions::{Evaluation, Lowerer, Values};
use crate::block_v2::machine::verifier::{ext_base, CompileError};
use crate::block_v2::profile::Challenge;
use p3_air::symbolic::{
    BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt, SymbolicVariable, SymbolicVariableExt,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use std::mem::size_of;

type B = SymbolicExpression<Val>;
type E = SymbolicExpressionExt<Val, Challenge>;

fn values() -> Evaluation<'static> {
    const VALUE: Extension = [Wire(0), Wire(1), Wire(2)];
    Evaluation {
        main: [Values::Slice(&[VALUE]); 2],
        preprocessed: [Values::Slice(&[VALUE]); 2],
        periodic: &[VALUE],
        public: &[Wire(0)],
        permutation: [&[VALUE]; 2],
        challenges: Values::Slice(&[VALUE]),
        terminals: &[VALUE],
        first: VALUE,
        last: VALUE,
        transition: VALUE,
    }
}

#[test]
fn expression_memos_admit_shared_growth_and_release_exact_storage() {
    let slot = size_of::<Option<(usize, Extension)>>();
    for limit in [32 * slot - 1, 32 * slot] {
        let mut b = ProgramBuilder::new(0).unwrap();
        b.memory.limit = Some(limit);
        let mut base = CompilerMemo::new();
        let mut extension = CompilerMemo::new();
        for key in 0..7 {
            base.insert(key, [Wire(key); 3], &mut b).unwrap();
            extension.insert(key, [Wire(key + 1); 3], &mut b).unwrap();
        }
        assert_eq!(b.memory.live, 16 * slot);
        let result = base.insert(7, [Wire(7); 3], &mut b);
        assert_eq!(result.is_ok(), limit == 32 * slot);
        for key in 0..7 {
            assert_eq!(base.get(&key), Some(&[Wire(key); 3]));
            assert_eq!(extension.get(&key), Some(&[Wire(key + 1); 3]));
        }
        if result.is_ok() {
            assert_eq!(b.memory.live, 24 * slot);
            assert_eq!(b.memory.peak, 32 * slot);
            base.insert(0, [Wire(99); 3], &mut b).unwrap();
            assert_eq!(base.get(&0), Some(&[Wire(99); 3]));
            assert_eq!(b.memory.live, 24 * slot);
        } else {
            assert_eq!(b.memory.live, 16 * slot);
            assert!(base.get(&7).is_none());
            assert_eq!(b.resource_failure(), Some(ExecutionError::TooLarge));
        }
        base.release(&mut b, "base-test");
        extension.release(&mut b, "extension-test");
        assert_eq!(b.memory.live, 0);
        assert!(base.get(&0).is_none());
    }
}

#[test]
fn lowerer_releases_memos_on_success_error_and_unwind() {
    let expr = B::Leaf(BaseLeaf::IsFirstRow);
    let ext = E::from(expr.clone());
    for mode in 0..3 {
        let mut b = ProgramBuilder::new(3).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut lowerer = Lowerer::new(&mut b, values());
            lowerer.base(&expr).unwrap();
            lowerer.extension(&ext).unwrap();
            let live = lowerer.b.memory.live;
            assert!(live > 0);
            // A memo hit creates neither additional instructions nor storage.
            lowerer.base(&expr).unwrap();
            lowerer.extension(&ext).unwrap();
            assert_eq!(lowerer.b.memory.live, live);
            if mode == 1 {
                let bad = B::Leaf(BaseLeaf::Variable(SymbolicVariable::new(
                    BaseEntry::Public,
                    9,
                )));
                assert!(lowerer.base(&bad).is_err());
            } else if mode == 2 {
                panic!("exercise scoped memo unwind");
            }
        }));
        assert_eq!(caught.is_err(), mode == 2);
        assert_eq!(b.memory.live, 0);
        assert!(b.memory.peak > 0);
        assert!(b.resource_failure().is_none());
    }
}

#[test]
fn lowerer_quota_failure_is_latched_and_blocks_cached_results() {
    let slot = size_of::<Option<(usize, Extension)>>();
    for limit in [8 * slot - 1, 16 * slot - 1] {
        let mut b = ProgramBuilder::new(3).unwrap();
        b.memory.limit = Some(limit);
        let expr = B::Leaf(BaseLeaf::IsFirstRow);
        let ext = E::from(expr.clone());
        {
            let mut lowerer = Lowerer::new(&mut b, values());
            let first = lowerer.base(&expr);
            assert_eq!(first.is_ok(), limit >= 8 * slot);
            assert!(lowerer.extension(&ext).is_err());
            let before = lowerer.b.memory.live;
            assert!(lowerer.base(&expr).is_err());
            assert_eq!(lowerer.b.memory.live, before);
            assert!(lowerer.b.memory.peak <= limit);
        }
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.finish(None).unwrap_err(), ExecutionError::TooLarge);
    }
}

fn compile(reference: bool, base: &[B], extension: &[E]) -> Program {
    let mut b = ProgramBuilder::new(3).unwrap();
    if reference {
        let mut lowerer = legacy::Lowerer::new(&mut b, legacy::values());
        for expr in base {
            lowerer.base(expr).unwrap();
        }
        for expr in extension {
            lowerer.extension(expr).unwrap();
        }
    } else {
        let mut lowerer = Lowerer::new(&mut b, values());
        for expr in base {
            lowerer.base(expr).unwrap();
        }
        for expr in extension {
            lowerer.extension(expr).unwrap();
        }
    }
    b.finish(None).unwrap()
}

#[test]
fn charged_lowering_matches_frozen_reference_for_shared_base_and_extension_dags() {
    let mut base = vec![
        B::Leaf(BaseLeaf::IsFirstRow),
        B::Leaf(BaseLeaf::IsLastRow),
        B::Leaf(BaseLeaf::IsTransition),
        B::from(Val::NEG_ONE),
    ];
    for entry in [
        BaseEntry::Main { offset: 0 },
        BaseEntry::Main { offset: 1 },
        BaseEntry::Preprocessed { offset: 0 },
        BaseEntry::Preprocessed { offset: 1 },
        BaseEntry::Periodic,
        BaseEntry::Public,
    ] {
        base.push(B::Leaf(BaseLeaf::Variable(SymbolicVariable::new(entry, 0))));
    }
    let shared = base[0].clone() + base[1].clone();
    base.extend([
        shared.clone(),
        shared.clone() * shared.clone(),
        shared.clone() - base[2].clone(),
        -shared,
    ]);
    let mut extension = vec![
        E::from(base[0].clone()),
        E::from(
            Challenge::from_basis_coefficients_slice(&[Val::ONE, Val::TWO, Val::NEG_ONE]).unwrap(),
        ),
    ];
    for entry in [
        ExtEntry::Permutation { offset: 0 },
        ExtEntry::Permutation { offset: 1 },
        ExtEntry::Challenge,
        ExtEntry::PermutationValue,
    ] {
        extension.push(E::Leaf(ExtLeaf::ExtVariable(SymbolicVariableExt::new(
            entry, 0,
        ))));
    }
    let shared = extension[0].clone() + extension[1].clone();
    extension.extend([
        shared.clone(),
        shared.clone() * shared.clone(),
        shared.clone() - extension[2].clone(),
        -shared,
    ]);
    let expected = compile(true, &base, &extension);
    let actual = compile(false, &base, &extension);
    assert_eq!(actual, expected);
    assert_eq!(actual.manifest_fields(), expected.manifest_fields());
    assert_eq!(
        actual
            .evaluate(&[Val::ONE, Val::TWO, Val::NEG_ONE], &[])
            .unwrap(),
        expected
            .evaluate(&[Val::ONE, Val::TWO, Val::NEG_ONE], &[])
            .unwrap()
    );
}

// Frozen reference from the previous checkpoint. Keep its independent
// HashMap implementation to check operation order, sharing and wire IDs.
mod legacy {
    use super::*;
    use std::collections::HashMap;
    // Keep the reference's owned-vector input representation independent.
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
    pub fn values() -> Evaluation {
        let value = [Wire(0), Wire(1), Wire(2)];
        Evaluation {
            main: [vec![value], vec![value]],
            preprocessed: [vec![value], vec![value]],
            periodic: vec![value],
            public: vec![Wire(0)],
            permutation: [vec![value], vec![value]],
            challenges: vec![value],
            terminals: vec![value],
            first: value,
            last: value,
            transition: value,
        }
    }
    pub struct Lowerer<'a, 'backend> {
        pub b: &'a mut ProgramBuilder<'backend>,
        pub values: Evaluation,
        base_cache: HashMap<usize, Extension>,
        extension_cache: HashMap<usize, Extension>,
    }

    impl<'a, 'backend> Lowerer<'a, 'backend> {
        pub fn new(b: &'a mut ProgramBuilder<'backend>, values: Evaluation) -> Self {
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
}
