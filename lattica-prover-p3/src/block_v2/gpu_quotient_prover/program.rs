//! Static constraint compilation for the pinned quadratic and cubic profiles. Plonky3's
//! symbolic builder supplies the constraints, including the LogUp gadget and
//! global emission order. No witness or challenge values enter this program.
use crate::{
    block_v2::{
        gpu_hash::{device::Extension, FriExtension},
        profile::Challenge,
    },
    config::Val,
};
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpression, SymbolicExpressionExt,
};
#[cfg(test)]
use p3_air::Air;
use p3_field::PrimeField64;
#[cfg(test)]
use p3_lookup::{InteractionSymbolicBuilder, Lookup, LookupProtocol};
use std::{collections::HashMap, sync::Arc};
mod shape;
pub(crate) use shape::ProgramShape;

pub(crate) const WORDS_PER_INSTRUCTION: usize = 5;
pub(crate) const MAX_NODES: usize = 1 << 18;
pub(crate) const MAX_CONSTRAINTS: usize = 1 << 16;
pub(crate) const MAX_ROW_WORDS: usize = 1 << 16;
const MAX_DEPTH: usize = 512;

// Instruction words: opcode, destination slot, a, b, c. All scratch slots
// contain three coefficients; base operations explicitly zero the other two.
pub(crate) const CONSTANT: u64 = 0;
pub(crate) const ROW_BASE: u64 = 1;
pub(crate) const ROW_EXT: u64 = 2;
pub(crate) const PARAM_BASE: u64 = 3;
pub(crate) const PARAM_EXT: u64 = 4;
pub(crate) const FIRST: u64 = 5;
pub(crate) const LAST: u64 = 6;
pub(crate) const TRANSITION: u64 = 7;
pub(crate) const ADD_BASE: u64 = 8;
pub(crate) const SUB_BASE: u64 = 9;
pub(crate) const MUL_BASE: u64 = 10;
pub(crate) const NEG_BASE: u64 = 11;
pub(crate) const ADD_EXT: u64 = 12;
pub(crate) const SUB_EXT: u64 = 13;
pub(crate) const MUL_EXT: u64 = 14;
pub(crate) const NEG_EXT: u64 = 15;
pub(crate) const FOLD_BASE: u64 = 16;
pub(crate) const FOLD_EXT: u64 = 17;
pub(crate) const STORE_BASE: u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Op {
    code: u64,
    a: u64,
    b: u64,
    c: u64,
}
impl Op {
    fn dependencies(self) -> [Option<usize>; 2] {
        match self.code {
            ADD_BASE | SUB_BASE | MUL_BASE | ADD_EXT | SUB_EXT | MUL_EXT => {
                [Some(self.a as usize), Some(self.b as usize)]
            }
            NEG_BASE | NEG_EXT | FOLD_BASE | FOLD_EXT | STORE_BASE => [Some(self.a as usize), None],
            _ => [None, None],
        }
    }
    fn extension(self) -> bool {
        matches!(
            self.code,
            ROW_EXT | PARAM_EXT | ADD_EXT | SUB_EXT | MUL_EXT | NEG_EXT
        ) || (self.code == CONSTANT && (self.b != 0 || self.c != 0))
    }
}

#[derive(Debug)]
pub(crate) struct Program {
    pub extension: Extension,
    pub instructions: Vec<u64>,
    pub registers: usize,
    pub constraints: usize,
    pub layout: AirLayout,
    pub row_words: usize,
    pub parameter_words: usize,
}

impl Program {
    pub(crate) fn shape(&self) -> ProgramShape {
        ProgramShape {
            extension: self.extension,
            instruction_words: self.instructions.len(),
            registers: self.registers,
            constraints: self.constraints,
            row_words: self.row_words,
            parameter_words: self.parameter_words,
        }
    }
    #[cfg(test)]
    pub fn compile<A, LG>(
        air: &A,
        layout: AirLayout,
        lookups: &[Lookup<Val>],
        gadget: &LG,
    ) -> Result<Self, String>
    where
        A: Air<InteractionSymbolicBuilder<Val, Challenge>>,
        LG: LookupProtocol,
    {
        let layout = AirLayout {
            permutation_width: if lookups.is_empty() {
                0
            } else {
                lookups
                    .len()
                    .checked_add(1)
                    .ok_or("quotient permutation width overflow")?
            },
            num_permutation_challenges: lookups
                .len()
                .checked_mul(gadget.num_challenges())
                .ok_or("quotient challenge count overflow")?,
            num_permutation_values: usize::from(!lookups.is_empty()),
            ..layout
        };
        Self::input_shape(layout)?;
        let mut builder = InteractionSymbolicBuilder::new(layout);
        gadget.eval_air_and_lookups(air, &mut builder, lookups);
        Self::from_constraints(
            layout,
            &crate::block_v2::machine::symbolic::Constraints {
                order: builder.constraint_layout(),
                base: builder.base_constraints(),
                extension: builder.extension_constraints(),
            },
        )
    }

    pub(super) fn from_constraints<F: FriExtension>(
        layout: AirLayout,
        constraints: &crate::block_v2::machine::symbolic::Constraints<F>,
    ) -> Result<Self, String> {
        Self::lower_constraints(layout, constraints, 0)
    }

    /// Periodic polynomials are evaluated as an uncommitted auxiliary input.
    /// This lowering never changes the AIR layout observed by the verifier.
    pub(super) fn from_periodic_constraints<F: FriExtension>(
        mut layout: AirLayout,
        constraints: &crate::block_v2::machine::symbolic::Constraints<F>,
    ) -> Result<Self, String> {
        if layout.preprocessed_width != 0 || layout.permutation_width != 0 {
            return Err(
                "periodic quotient lowering requires a single AIR without preprocessing or lookups"
                    .into(),
            );
        }
        let periodic_width = layout.num_periodic_columns;
        layout.num_periodic_columns = 0;
        layout.preprocessed_width = periodic_width;
        Self::lower_constraints(layout, constraints, periodic_width)
    }

    fn lower_constraints<F: FriExtension>(
        layout: AirLayout,
        constraints: &crate::block_v2::machine::symbolic::Constraints<F>,
        periodic_width: usize,
    ) -> Result<Self, String> {
        let (row_words, parameter_words) =
            Self::input_shape_extension(layout, F::DEVICE_EXTENSION)?;
        let order = &constraints.order;
        let base = &constraints.base;
        let ext = &constraints.extension;
        let total = order.total_constraints();
        if total == 0
            || total > MAX_CONSTRAINTS
            || order.base_indices.len() != base.len()
            || order.ext_indices.len() != ext.len()
        {
            return Err("quotient constraint layout exceeds bounded evaluator".into());
        }
        let mut roots = vec![None; total];
        for (index, expression) in order.base_indices.iter().zip(base) {
            if *index >= total || roots[*index].replace(Root::Base(expression)).is_some() {
                return Err("invalid base constraint order".into());
            }
        }
        for (index, expression) in order.ext_indices.iter().zip(ext) {
            if *index >= total || roots[*index].replace(Root::Ext(expression)).is_some() {
                return Err("invalid extension constraint order".into());
            }
        }
        let mut compiler = Compiler {
            degree: F::DIMENSION,
            layout,
            periodic_width,
            nodes: Vec::new(),
            schedule: Vec::new(),
            base_arcs: HashMap::new(),
            ext_arcs: HashMap::new(),
            interned: HashMap::new(),
        };
        for (index, root) in roots.into_iter().enumerate() {
            let node = match root.ok_or("missing constraint in global order")? {
                Root::Base(expression) => compiler.base(expression, 0)?,
                Root::Ext(expression) => compiler.ext(expression, 0)?,
            };
            compiler.schedule.push((
                None,
                Op {
                    code: if compiler.nodes[node].extension() {
                        FOLD_EXT
                    } else {
                        FOLD_BASE
                    },
                    a: node as u64,
                    b: index as u64,
                    c: 0,
                },
            ));
        }
        let (instructions, registers) = compiler.lower()?;
        Ok(Self {
            extension: F::DEVICE_EXTENSION,
            instructions,
            registers,
            constraints: total,
            layout,
            row_words,
            parameter_words,
        })
    }

    pub(super) fn input_shape(layout: AirLayout) -> Result<(usize, usize), String> {
        Self::input_shape_extension(layout, Extension::Cubic)
    }

    pub(super) fn input_shape_extension(
        layout: AirLayout,
        extension: Extension,
    ) -> Result<(usize, usize), String> {
        if extension == Extension::Base {
            return Err("GPU quotient requires a pinned challenge extension".into());
        }
        let degree = extension.degree();
        if layout.num_periodic_columns != 0 {
            return Err("GPU quotient requires periodic-column lowering".into());
        }
        let row_words = layout
            .main_width
            .checked_add(layout.preprocessed_width)
            .and_then(|n| {
                layout
                    .permutation_width
                    .checked_mul(degree)
                    .and_then(|p| n.checked_add(p))
            })
            .and_then(|n| n.checked_mul(2))
            .ok_or("quotient row width overflow")?;
        let parameter_words = layout
            .num_permutation_challenges
            .checked_add(layout.num_permutation_values)
            .and_then(|n| n.checked_mul(degree))
            .and_then(|n| n.checked_add(layout.num_public_values))
            .ok_or("quotient parameter count overflow")?;
        if row_words == 0 || row_words > MAX_ROW_WORDS || parameter_words > MAX_ROW_WORDS {
            return Err("quotient input layout exceeds bounded evaluator".into());
        }
        Ok((row_words, parameter_words))
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len() / WORDS_PER_INSTRUCTION
    }
}

#[derive(Clone, Copy)]
enum Root<'a, F: p3_field::ExtensionField<Val>> {
    Base(&'a SymbolicExpression<Val>),
    Ext(&'a SymbolicExpressionExt<Val, F>),
}
pub(super) struct Compiler {
    degree: usize,
    layout: AirLayout,
    periodic_width: usize,
    nodes: Vec<Op>,
    schedule: Vec<(Option<usize>, Op)>,
    base_arcs: HashMap<usize, usize>,
    ext_arcs: HashMap<usize, usize>,
    interned: HashMap<Op, usize>,
}

impl Compiler {
    pub(super) fn new(layout: AirLayout) -> Self {
        Self {
            degree: 3,
            layout,
            periodic_width: 0,
            nodes: Vec::new(),
            schedule: Vec::new(),
            base_arcs: HashMap::new(),
            ext_arcs: HashMap::new(),
            interned: HashMap::new(),
        }
    }

    pub(super) fn store_base(
        &mut self,
        expression: &SymbolicExpression<Val>,
        output: usize,
    ) -> Result<(), String> {
        let node = self.base(expression, 0)?;
        self.schedule.push((
            None,
            Op {
                code: STORE_BASE,
                a: node as u64,
                b: output as u64,
                c: 0,
            },
        ));
        Ok(())
    }
    fn intern(&mut self, op: Op) -> Result<usize, String> {
        if let Some(&id) = self.interned.get(&op) {
            return Ok(id);
        }
        if self.nodes.len() == MAX_NODES {
            return Err("quotient expression program exceeds node bound".into());
        }
        let id = self.nodes.len();
        self.nodes.push(op);
        self.schedule.push((Some(id), op));
        self.interned.insert(op, id);
        Ok(id)
    }
    fn load(
        &mut self,
        code: u64,
        index: usize,
        width: usize,
        offset: usize,
    ) -> Result<usize, String> {
        if index >= width {
            return Err("quotient symbolic input is outside its declared layout".into());
        }
        let stride = if code == ROW_EXT || code == PARAM_EXT {
            self.degree
        } else {
            1
        };
        self.intern(Op {
            code,
            a: (offset + index * stride) as u64,
            b: 0,
            c: 0,
        })
    }
    fn arithmetic(&mut self, code: u64, a: usize, b: usize) -> Result<usize, String> {
        let extension =
            self.nodes[a].extension() || (code != NEG_BASE && self.nodes[b].extension());
        self.intern(Op {
            code: code + if extension { 4 } else { 0 },
            a: a as u64,
            b: b as u64,
            c: 0,
        })
    }
    fn base_arc(
        &mut self,
        expr: &Arc<SymbolicExpression<Val>>,
        depth: usize,
    ) -> Result<usize, String> {
        let key = Arc::as_ptr(expr) as usize;
        if let Some(&id) = self.base_arcs.get(&key) {
            return Ok(id);
        }
        let id = self.base(expr, depth)?;
        self.base_arcs.insert(key, id);
        Ok(id)
    }
    fn ext_arc<F: FriExtension>(
        &mut self,
        expr: &Arc<SymbolicExpressionExt<Val, F>>,
        depth: usize,
    ) -> Result<usize, String> {
        let key = Arc::as_ptr(expr) as usize;
        if let Some(&id) = self.ext_arcs.get(&key) {
            return Ok(id);
        }
        let id = self.ext(expr, depth)?;
        self.ext_arcs.insert(key, id);
        Ok(id)
    }
    fn base(&mut self, expr: &SymbolicExpression<Val>, depth: usize) -> Result<usize, String> {
        if depth > MAX_DEPTH {
            return Err("quotient expression depth exceeds bound".into());
        }
        match expr {
            SymbolicExpression::Leaf(leaf) => match leaf {
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset } if offset < 2 => self.load(
                        ROW_BASE,
                        v.index,
                        self.layout.main_width,
                        offset * self.layout.main_width,
                    ),
                    BaseEntry::Preprocessed { offset }
                        if offset < 2 && self.periodic_width == 0 =>
                    {
                        self.load(
                            ROW_BASE,
                            v.index,
                            self.layout.preprocessed_width,
                            2 * self.layout.main_width + offset * self.layout.preprocessed_width,
                        )
                    }
                    BaseEntry::Public => {
                        self.load(PARAM_BASE, v.index, self.layout.num_public_values, 0)
                    }
                    BaseEntry::Periodic => self.load(
                        ROW_BASE,
                        v.index,
                        self.periodic_width,
                        2 * self.layout.main_width,
                    ),
                    _ => Err("unsupported quotient base input window".into()),
                },
                BaseLeaf::Constant(value) => self.intern(Op {
                    code: CONSTANT,
                    a: value.as_canonical_u64(),
                    b: 0,
                    c: 0,
                }),
                BaseLeaf::IsFirstRow => self.intern(Op {
                    code: FIRST,
                    a: 0,
                    b: 0,
                    c: 0,
                }),
                BaseLeaf::IsLastRow => self.intern(Op {
                    code: LAST,
                    a: 0,
                    b: 0,
                    c: 0,
                }),
                BaseLeaf::IsTransition => self.intern(Op {
                    code: TRANSITION,
                    a: 0,
                    b: 0,
                    c: 0,
                }),
            },
            SymbolicExpression::Add { x, y, .. }
            | SymbolicExpression::Sub { x, y, .. }
            | SymbolicExpression::Mul { x, y, .. } => {
                let a = self.base_arc(x, depth + 1)?;
                let b = self.base_arc(y, depth + 1)?;
                let code = match expr {
                    SymbolicExpression::Add { .. } => ADD_BASE,
                    SymbolicExpression::Sub { .. } => SUB_BASE,
                    _ => MUL_BASE,
                };
                self.arithmetic(code, a, b)
            }
            SymbolicExpression::Neg { x, .. } => {
                let a = self.base_arc(x, depth + 1)?;
                self.arithmetic(NEG_BASE, a, 0)
            }
        }
    }
    fn ext<F: FriExtension>(
        &mut self,
        expr: &SymbolicExpressionExt<Val, F>,
        depth: usize,
    ) -> Result<usize, String> {
        if depth > MAX_DEPTH {
            return Err("quotient expression depth exceeds bound".into());
        }
        match expr {
            SymbolicExpressionExt::Leaf(leaf) => match leaf {
                ExtLeaf::Base(expr) => self.base(expr, depth + 1),
                ExtLeaf::ExtConstant(value) => {
                    let c: &[Val] = value.as_basis_coefficients_slice();
                    self.intern(Op {
                        code: CONSTANT,
                        a: c[0].as_canonical_u64(),
                        b: c[1].as_canonical_u64(),
                        c: c.get(2).map_or(0, PrimeField64::as_canonical_u64),
                    })
                }
                ExtLeaf::ExtVariable(v) => match v.entry {
                    ExtEntry::Permutation { offset } if offset < 2 => self.load(
                        ROW_EXT,
                        v.index,
                        self.layout.permutation_width,
                        2 * (self.layout.main_width + self.layout.preprocessed_width)
                            + offset * self.degree * self.layout.permutation_width,
                    ),
                    ExtEntry::Challenge => self.load(
                        PARAM_EXT,
                        v.index,
                        self.layout.num_permutation_challenges,
                        self.layout.num_public_values,
                    ),
                    ExtEntry::PermutationValue => self.load(
                        PARAM_EXT,
                        v.index,
                        self.layout.num_permutation_values,
                        self.layout.num_public_values
                            + self.degree * self.layout.num_permutation_challenges,
                    ),
                    _ => Err("unsupported quotient extension input window".into()),
                },
            },
            SymbolicExpressionExt::Add { x, y, .. }
            | SymbolicExpressionExt::Sub { x, y, .. }
            | SymbolicExpressionExt::Mul { x, y, .. } => {
                let a = self.ext_arc(x, depth + 1)?;
                let b = self.ext_arc(y, depth + 1)?;
                let code = match expr {
                    SymbolicExpressionExt::Add { .. } => ADD_BASE,
                    SymbolicExpressionExt::Sub { .. } => SUB_BASE,
                    _ => MUL_BASE,
                };
                self.arithmetic(code, a, b)
            }
            SymbolicExpressionExt::Neg { x, .. } => {
                let a = self.ext_arc(x, depth + 1)?;
                self.arithmetic(NEG_BASE, a, 0)
            }
        }
    }

    /// Reuse slots after their last consumer, including folds in global emission
    /// order. This bounds scratch by simultaneously live expressions, not DAG size.
    pub(super) fn lower(self) -> Result<(Vec<u64>, usize), String> {
        let mut remaining = vec![0usize; self.nodes.len()];
        for (_, op) in &self.schedule {
            for source in op.dependencies().into_iter().flatten() {
                remaining[source] += 1;
            }
        }
        let mut slots = vec![None; self.nodes.len()];
        let mut free = Vec::new();
        let mut allocated = 0;
        let mut code = Vec::with_capacity(self.schedule.len() * WORDS_PER_INSTRUCTION);
        for (node, mut op) in self.schedule {
            let dependencies = op.dependencies();
            let source_slots = dependencies
                .map(|id| id.map(|id| slots[id].expect("topological constraint graph")));
            for source in dependencies.into_iter().flatten() {
                remaining[source] -= 1;
                if remaining[source] == 0 {
                    free.push(slots[source].take().unwrap());
                }
            }
            if let Some(a) = source_slots[0] {
                op.a = a as u64;
            }
            if let Some(b) = source_slots[1] {
                op.b = b as u64;
            }
            let destination = if let Some(node) = node {
                let slot = free.pop().unwrap_or_else(|| {
                    let slot = allocated;
                    allocated += 1;
                    slot
                });
                slots[node] = Some(slot);
                slot
            } else {
                0
            };
            code.extend_from_slice(&[op.code, destination as u64, op.a, op.b, op.c]);
        }
        if allocated == 0 || remaining.iter().any(|n| *n != 0) {
            return Err("invalid quotient register lifetimes".into());
        }
        Ok((code, allocated))
    }
}
