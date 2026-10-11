//! Recording operators construct nodes only. Canonicalization is a separate,
//! fallible pass with an explicitly selected arithmetic backend.
use super::{recording, Challenge, Val};
use p3_air::symbolic::{
    BaseLeaf, ExtLeaf, SymLeaf, SymbolicExpr, SymbolicVariable, SymbolicVariableExt,
};
use p3_field::{Algebra, Dup, PrimeCharacteristicRing};
use std::{
    iter::{Product, Sum},
    ops,
    sync::Arc,
};

/// Depth of the pinned leaf representation of a base-field constant.
pub trait RecordingLeaf: SymLeaf<F = Val> {
    const CONSTANT_DEPTH: usize;
}
impl RecordingLeaf for BaseLeaf<Val> {
    const CONSTANT_DEPTH: usize = 0;
}
impl RecordingLeaf for ExtLeaf<Val, Challenge> {
    const CONSTANT_DEPTH: usize = 1;
}

#[derive(Clone, Debug)]
pub struct Expression<A: RecordingLeaf>(pub(super) SymbolicExpr<A>, pub(super) usize);
pub type Base = Expression<BaseLeaf<Val>>;
pub type Extension = Expression<ExtLeaf<Val, Challenge>>;

impl<A: RecordingLeaf> PrimeCharacteristicRing for Expression<A> {
    type PrimeSubfield = Val;
    const ZERO: Self = Self(SymbolicExpr::Leaf(A::ZERO), A::CONSTANT_DEPTH);
    const ONE: Self = Self(SymbolicExpr::Leaf(A::ONE), A::CONSTANT_DEPTH);
    const TWO: Self = Self(SymbolicExpr::Leaf(A::TWO), A::CONSTANT_DEPTH);
    const NEG_ONE: Self = Self(SymbolicExpr::Leaf(A::NEG_ONE), A::CONSTANT_DEPTH);
    fn from_prime_subfield(value: Val) -> Self {
        Self(SymbolicExpr::Leaf(A::from_const(value)), A::CONSTANT_DEPTH)
    }
}
impl<A: RecordingLeaf> Dup for Expression<A> {
    fn dup(&self) -> Self {
        self.clone()
    }
}
impl<A: RecordingLeaf> Default for Expression<A> {
    fn default() -> Self {
        Self::ZERO
    }
}
impl<A: RecordingLeaf> From<Val> for Expression<A> {
    fn from(value: Val) -> Self {
        Self::from_prime_subfield(value)
    }
}
impl<A: RecordingLeaf> Algebra<Val> for Expression<A> {}

macro_rules! binary {
    ($trait:ident, $method:ident, $variant:ident) => {
        impl<A: RecordingLeaf, T: Into<Self>> ops::$trait<T> for Expression<A> {
            type Output = Self;
            fn $method(self, rhs: T) -> Self {
                let rhs = rhs.into();
                let depth = self.1.max(rhs.1).saturating_add(1);
                if !recording::expression::<SymbolicExpr<A>>(2, depth) {
                    return Self::ZERO;
                }
                // The raw degree is deliberately unused. Only normalized trees
                // may supply a degree to admission, packing or fingerprints.
                Self(
                    SymbolicExpr::$variant {
                        x: Arc::new(self.0),
                        y: Arc::new(rhs.0),
                        degree_multiple: 0,
                    },
                    depth,
                )
            }
        }
    };
}
binary!(Add, add, Add);
binary!(Sub, sub, Sub);
binary!(Mul, mul, Mul);
impl<A: RecordingLeaf> ops::Neg for Expression<A> {
    type Output = Self;
    fn neg(self) -> Self {
        let depth = self.1.saturating_add(1);
        if !recording::expression::<SymbolicExpr<A>>(1, depth) {
            return Self::ZERO;
        }
        Self(
            SymbolicExpr::Neg {
                x: Arc::new(self.0),
                degree_multiple: 0,
            },
            depth,
        )
    }
}
macro_rules! assign {
    ($trait:ident, $method:ident, $op:tt) => {
        impl<A: RecordingLeaf, T: Into<Self>> ops::$trait<T> for Expression<A> {
            fn $method(&mut self, rhs: T) { *self = self.clone() $op rhs.into(); }
        }
    }
}
assign!(AddAssign, add_assign, +);
assign!(SubAssign, sub_assign, -);
assign!(MulAssign, mul_assign, *);
impl<A: RecordingLeaf, T: Into<Self>> Sum<T> for Expression<A> {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into)
            .reduce(|a, b| a + b)
            .unwrap_or(Self::ZERO)
    }
}
impl<A: RecordingLeaf, T: Into<Self>> Product<T> for Expression<A> {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into)
            .reduce(|a, b| a * b)
            .unwrap_or(Self::ONE)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Variable(pub(super) SymbolicVariable<Val>);
impl From<Variable> for Base {
    fn from(value: Variable) -> Self {
        Self(SymbolicExpr::Leaf(BaseLeaf::Variable(value.0)), 0)
    }
}
impl Algebra<Variable> for Base {}
macro_rules! variable_binary {
    ($trait:ident, $method:ident, $op:tt) => {
        impl<T: Into<Base>> ops::$trait<T> for Variable {
            type Output = Base;
            fn $method(self, rhs: T) -> Base { Base::from(self) $op rhs.into() }
        }
    }
}
variable_binary!(Add, add, +);
variable_binary!(Sub, sub, -);
variable_binary!(Mul, mul, *);
impl From<Base> for Extension {
    fn from(value: Base) -> Self {
        let depth = value.1.saturating_add(1);
        if !recording::expression::<SymbolicExpr<ExtLeaf<Val, Challenge>>>(0, depth) {
            return Self::ZERO;
        }
        Self(SymbolicExpr::Leaf(ExtLeaf::Base(value.0)), depth)
    }
}
impl From<Variable> for Extension {
    fn from(value: Variable) -> Self {
        Base::from(value).into()
    }
}
impl From<Challenge> for Extension {
    fn from(value: Challenge) -> Self {
        Self(SymbolicExpr::Leaf(ExtLeaf::ExtConstant(value)), 0)
    }
}
impl From<SymbolicVariableExt<Val, Challenge>> for Extension {
    fn from(value: SymbolicVariableExt<Val, Challenge>) -> Self {
        Self(SymbolicExpr::Leaf(ExtLeaf::ExtVariable(value)), 0)
    }
}
impl Algebra<Base> for Extension {}
impl Algebra<Variable> for Extension {}
impl Algebra<Challenge> for Extension {}
