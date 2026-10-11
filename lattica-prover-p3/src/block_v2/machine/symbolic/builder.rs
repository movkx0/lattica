use super::{
    expression::{Base, Expression, Extension, Variable},
    recording, Challenge, CompileError, Val,
};
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, SymbolicExpr, SymbolicVariable,
    SymbolicVariableExt,
};
use p3_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_lookup::{Count, InteractionBuilder, SymbolicInteraction, SymbolicLocalInteraction};
use std::sync::Arc;

/// Cloned AIR windows share the recorded variables instead of copying rows.
#[derive(Clone)]
pub struct Window<T> {
    values: Arc<Vec<T>>,
    width: usize,
}
impl<T> Window<T> {
    fn new(width: usize, mut value: impl FnMut(usize, usize) -> T) -> Result<Self, CompileError> {
        let count = width.checked_mul(2).ok_or_else(|| {
            recording::reject();
            recording::error()
        })?;
        let values = recording::vector(count, |i| value(i / width, i % width))?;
        Ok(Self {
            values: recording::shared(values)?,
            width,
        })
    }
}
impl<T> WindowAccess<T> for Window<T> {
    fn current_slice(&self) -> &[T] {
        &self.values[..self.width]
    }
    fn next_slice(&self) -> &[T] {
        &self.values[self.width..]
    }
}

/// Records the trusted AIR without running native field-expression operators.
/// Raw expressions never leave this module before fallible normalization.
pub struct Builder {
    main: Window<Variable>,
    preprocessed: Window<Variable>,
    public: Vec<Variable>,
    periodic: Vec<Variable>,
    permutation: Window<SymbolicVariableExt<Val, Challenge>>,
    challenges: Vec<SymbolicVariableExt<Val, Challenge>>,
    terminals: Vec<SymbolicVariableExt<Val, Challenge>>,
    pub(super) base: Vec<p3_air::symbolic::SymbolicExpression<Val>>,
    pub(super) extension: Vec<p3_air::symbolic::SymbolicExpressionExt<Val, Challenge>>,
    pub(super) order: ConstraintLayout,
    pub(super) global: Vec<SymbolicInteraction<Val>>,
    pub(super) local: Vec<SymbolicLocalInteraction<Val>>,
    failed: bool,
}

impl Builder {
    pub(super) fn new(layout: AirLayout) -> Result<Self, CompileError> {
        let window = |width, entry: fn(usize) -> BaseEntry| {
            Window::new(width, |offset, i| {
                Variable(SymbolicVariable::new(entry(offset), i))
            })
        };
        Ok(Self {
            main: window(layout.main_width, |offset| BaseEntry::Main { offset })?,
            preprocessed: window(layout.preprocessed_width, |offset| {
                BaseEntry::Preprocessed { offset }
            })?,
            public: recording::vector(layout.num_public_values, |i| {
                Variable(SymbolicVariable::new(BaseEntry::Public, i))
            })?,
            periodic: recording::vector(layout.num_periodic_columns, |i| {
                Variable(SymbolicVariable::new(BaseEntry::Periodic, i))
            })?,
            permutation: Window::new(layout.permutation_width, |offset, i| {
                SymbolicVariableExt::new(ExtEntry::Permutation { offset }, i)
            })?,
            challenges: recording::vector(layout.num_permutation_challenges, |i| {
                SymbolicVariableExt::new(ExtEntry::Challenge, i)
            })?,
            terminals: recording::vector(layout.num_permutation_values, |i| {
                SymbolicVariableExt::new(ExtEntry::PermutationValue, i)
            })?,
            base: vec![],
            extension: vec![],
            order: ConstraintLayout {
                base_indices: vec![],
                ext_indices: vec![],
            },
            global: vec![],
            local: vec![],
            failed: false,
        })
    }
    pub(super) fn check(&self) -> Result<(), CompileError> {
        if self.failed {
            Err(recording::error())
        } else {
            recording::check()
        }
    }
    fn record(&mut self, body: impl FnOnce(&mut Self) -> Result<(), CompileError>) {
        if self.check().is_err() || body(self).is_err() {
            self.failed = true;
            recording::reject();
        }
    }
}
impl AirBuilder for Builder {
    type F = Val;
    type Expr = Base;
    type Var = Variable;
    type MainWindow = Window<Variable>;
    type PreprocessedWindow = Window<Variable>;
    type PublicVar = Variable;
    type PeriodicVar = Variable;
    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }
    fn public_values(&self) -> &[Variable] {
        &self.public
    }
    fn periodic_values(&self) -> &[Variable] {
        &self.periodic
    }
    fn is_first_row(&self) -> Base {
        Expression(SymbolicExpr::Leaf(BaseLeaf::IsFirstRow), 0)
    }
    fn is_last_row(&self) -> Base {
        Expression(SymbolicExpr::Leaf(BaseLeaf::IsLastRow), 0)
    }
    fn is_transition(&self) -> Base {
        Expression(SymbolicExpr::Leaf(BaseLeaf::IsTransition), 0)
    }
    fn assert_zero<I: Into<Base>>(&mut self, value: I) {
        self.record(|this| {
            let index = this.order.total_constraints();
            recording::push(&mut this.order.base_indices, index)?;
            recording::push(&mut this.base, value.into().0)
        });
    }
}
impl ExtensionBuilder for Builder {
    type EF = Challenge;
    type ExprEF = Extension;
    type VarEF = SymbolicVariableExt<Val, Challenge>;
    fn assert_zero_ext<I: Into<Extension>>(&mut self, value: I) {
        self.record(|this| {
            let index = this.order.total_constraints();
            recording::push(&mut this.order.ext_indices, index)?;
            recording::push(&mut this.extension, value.into().0)
        });
    }
}
impl PermutationAirBuilder for Builder {
    type MP = Window<Self::VarEF>;
    type RandomVar = Self::VarEF;
    type PermutationVar = Self::VarEF;
    fn permutation(&self) -> Self::MP {
        self.permutation.clone()
    }
    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.challenges
    }
    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.terminals
    }
}
impl InteractionBuilder for Builder {
    fn push_interaction<E: Into<Base>>(
        &mut self,
        bus_name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Base>>,
    ) {
        self.record(|this| {
            let (count, count_weight) = count.into().into_parts();
            let bus_name = recording::string(bus_name)?;
            let fields = recording::collect(fields.into_iter().map(|v| v.into().0))?;
            recording::push(
                &mut this.global,
                SymbolicInteraction {
                    bus_name,
                    fields,
                    count: count.0,
                    count_weight,
                },
            )
        });
    }
    fn push_local_interaction(&mut self, tuples: impl IntoIterator<Item = (Vec<Base>, Base)>) {
        self.record(|this| {
            let mut recorded = Vec::new();
            for (fields, count) in tuples {
                // The incoming Vec belongs to the AIR; our output has its own
                // admitted allocation, independent of the input's capacity.
                let mut fields = fields.into_iter();
                let values = recording::vector(fields.len(), |_| fields.next().unwrap().0)?;
                recording::push(&mut recorded, (values, count.0))?;
            }
            recording::push(
                &mut this.local,
                SymbolicLocalInteraction { tuples: recorded },
            )
        });
    }
    fn num_global_interactions(&self) -> usize {
        self.global.len()
    }
    fn num_local_interactions(&self) -> usize {
        self.local.len()
    }
}
