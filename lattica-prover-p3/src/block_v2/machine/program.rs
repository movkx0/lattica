//! Immutable SSA programs. Wire addresses, selectors and reference counts live
//! in the authenticated preprocessing, never in the prover's witness.

use super::compiler_constants::{Constants, FoldOperation, Folding};
use crate::block_v2::profile::Challenge;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;
mod compiler_memo;
mod compiler_scratch;
mod construction;
pub(super) use compiler_memo::CompilerMemo;
mod manifest;
mod proof_inputs;
use construction::{Budget as ConstructionBudget, Map as ConstructionMap, Set as ConstructionSet};
pub use proof_inputs::ProofInputs;

pub type Val = Goldilocks;
#[cfg(not(feature = "block-v2-wide-lanes"))]
pub const LANES: usize = 8;
#[cfg(feature = "block-v2-wide-lanes")]
pub const LANES: usize = 23;
pub const OPS: usize = 8;
pub const OPCODE_BITS: usize = 3;
// Keep the two-bank public statement mapping independent of arithmetic packing.
pub const PUBLICS_PER_ROW: usize = 32;
pub const EXT_LANES: usize = LANES / 3;
pub const MAX_PUBLIC_VALUES: usize = 64;
pub const MAX_WIRES: usize = 1 << 26;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wire(pub(crate) usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    InvalidWire,
    TooLarge,
    PublicInputCount,
    WitnessCount,
    Unsatisfied,
    InvalidHeight,
    NonCanonicalField,
    ProvingPolicy,
    GpuFailure,
    CompilerBackend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Input {
        index: usize,
        out: Wire,
    },
    // Witness-generation hint only. The caller must constrain reconstruction
    // and booleanity; no algebraic relation is claimed by this input opcode.
    Bit {
        source: Wire,
        bit: usize,
        out: Wire,
    },
    // Unconstrained path-generation hint. Only use with authenticated output checks.
    SelectHint {
        entries: Vec<Wire>,
        bits: Vec<Wire>,
        out: Wire,
    },
    Constant {
        value: Val,
        out: Wire,
    },
    Add {
        a: Wire,
        b: Wire,
        out: Wire,
    },
    Mul {
        a: Wire,
        b: Wire,
        out: Wire,
    },
    Equal {
        a: Wire,
        b: Wire,
    },
    Boolean {
        a: Wire,
    },
    Inverse {
        a: Wire,
        out: Wire,
    },
    Select {
        bit: Wire,
        a: Wire,
        b: Wire,
        out: Wire,
    },
    CubicMul {
        a: [Wire; 3],
        b: [Wire; 3],
        out: [Wire; 3],
    },
    CubicInverse {
        a: [Wire; 3],
        out: [Wire; 3],
    },
    Poseidon {
        input: [Wire; 8],
        output: [Wire; 8],
    },
}

impl Op {
    pub(crate) fn reads(&self) -> Vec<Wire> {
        match self {
            Self::Input { .. }
            | Self::Bit { .. }
            | Self::SelectHint { .. }
            | Self::Constant { .. } => vec![],
            Self::Add { a, b, .. } | Self::Mul { a, b, .. } | Self::Equal { a, b } => vec![*a, *b],
            Self::Boolean { a } | Self::Inverse { a, .. } => vec![*a],
            Self::Select { bit, a, b, .. } => vec![*a, *b, *bit],
            Self::CubicMul { a, b, .. } => a.iter().chain(b).copied().collect(),
            Self::CubicInverse { a, .. } => a.to_vec(),
            Self::Poseidon { input, .. } => input.to_vec(),
        }
    }
    pub(crate) fn writes(&self) -> Vec<Wire> {
        match self {
            Self::Input { out, .. }
            | Self::Bit { out, .. }
            | Self::SelectHint { out, .. }
            | Self::Constant { out, .. }
            | Self::Add { out, .. }
            | Self::Mul { out, .. }
            | Self::Inverse { out, .. }
            | Self::Select { out, .. } => vec![*out],
            Self::CubicMul { out, .. } | Self::CubicInverse { out, .. } => out.to_vec(),
            Self::Equal { .. } | Self::Boolean { .. } => vec![],
            Self::Poseidon { output, .. } => output.to_vec(),
        }
    }
    pub(crate) fn code(&self) -> usize {
        match self {
            Self::Input { .. } | Self::Bit { .. } | Self::SelectHint { .. } => 0,
            Self::Constant { .. } => 1,
            Self::Add { .. } => 2,
            Self::Mul { .. } => 3,
            Self::Equal { .. } => 4,
            Self::Boolean { .. } => 5,
            Self::Inverse { .. } => 6,
            Self::Select { .. } => 7,
            Self::Poseidon { .. } => 8,
            Self::CubicMul { .. } => 9,
            Self::CubicInverse { .. } => 10,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Row {
    Public(usize),
    Alu(Vec<Op>),
    Cubic(Vec<Op>),
    Poseidon { input: [Wire; 8], output: [Wire; 8] },
}

#[derive(Clone, Debug)]
pub struct Program {
    // Witness evaluation retains topological order; authenticated rows may be packed by opcode.
    pub(crate) operations: Vec<Op>,
    pub(crate) rows: Vec<Row>,
    pub(crate) references: Vec<u32>,
    pub(crate) publics: usize,
    pub(crate) witnesses: usize,
    pub(crate) height: usize,
    // Construction provenance is admission metadata, not program identity.
    // It must survive cloning/padding, but never enters manifest_fields.
    construction_host_bytes: usize,
}

impl PartialEq for Program {
    fn eq(&self, other: &Self) -> bool {
        self.operations == other.operations
            && self.rows == other.rows
            && self.references == other.references
            && self.publics == other.publics
            && self.witnesses == other.witnesses
            && self.height == other.height
    }
}
impl Eq for Program {}

impl Program {
    /// Peak requested builder storage, including packing and scoped scratch.
    /// This is not RSS and excludes separately reserved caller/compiler data.
    pub(crate) fn construction_host_bytes(&self) -> usize {
        self.construction_host_bytes
    }

    pub fn public_values(&self) -> usize {
        self.publics
    }
    pub fn witness_values(&self) -> usize {
        self.witnesses
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn active_rows(&self) -> usize {
        self.rows.len()
    }
    pub fn wire_count(&self) -> usize {
        self.references.len()
    }
    pub fn total_reads(&self) -> u64 {
        self.references.iter().map(|&v| u64::from(v)).sum()
    }

    /// Change only padding, before registration. Never accepts a proof-supplied height.
    pub fn pad_to(mut self, height: usize) -> Result<Self, ExecutionError> {
        if !height.is_power_of_two() || height < self.active_rows().max(8) || height > (1 << 24) {
            return Err(ExecutionError::InvalidHeight);
        }
        self.height = height;
        Ok(self)
    }

    /// Canonical public program encoding. It contains no witness values.
    pub fn manifest_fields(&self) -> Vec<u64> {
        let mut length = 0usize;
        self.emit_manifest(&mut |_| {
            length = length
                .checked_add(1)
                .ok_or("program manifest length overflow")?;
            Ok(())
        })
        .expect("program manifest length");
        let mut fields = Vec::with_capacity(length);
        self.emit_manifest(&mut |field| {
            fields.push(field);
            Ok(())
        })
        .expect("infallible manifest collection");
        fields
    }

    pub(crate) fn evaluate(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<Vec<Val>, ExecutionError> {
        if public.len() != self.publics {
            return Err(ExecutionError::PublicInputCount);
        }
        if witness.len() != self.witnesses {
            return Err(ExecutionError::WitnessCount);
        }
        let mut values = vec![Val::ZERO; self.references.len()];
        values[..self.publics].copy_from_slice(public);
        let mut execute = |op: &Op| -> Result<(), ExecutionError> {
            match op {
                Op::Input { index, out } => values[out.0] = witness[*index],
                Op::Bit { source, bit, out } => {
                    values[out.0] = Val::from_u64((values[source.0].as_canonical_u64() >> bit) & 1)
                }
                Op::SelectHint { entries, bits, out } => {
                    let mut index = 0;
                    for (i, bit) in bits.iter().enumerate() {
                        let bit = values[bit.0];
                        if bit != Val::ZERO && bit != Val::ONE {
                            return Err(ExecutionError::Unsatisfied);
                        }
                        index |= (bit.as_canonical_u64() as usize) << i;
                    }
                    values[out.0] = values[entries[index].0];
                }
                Op::Constant { value, out } => values[out.0] = *value,
                Op::Add { a, b, out } => values[out.0] = values[a.0] + values[b.0],
                Op::Mul { a, b, out } => values[out.0] = values[a.0] * values[b.0],
                Op::Equal { a, b } => {
                    if values[a.0] != values[b.0] {
                        return Err(ExecutionError::Unsatisfied);
                    }
                }
                Op::Boolean { a } => {
                    if values[a.0] != Val::ZERO && values[a.0] != Val::ONE {
                        return Err(ExecutionError::Unsatisfied);
                    }
                }
                Op::Inverse { a, out } => {
                    values[out.0] = values[a.0]
                        .try_inverse()
                        .ok_or(ExecutionError::Unsatisfied)?
                }
                Op::Select { bit, a, b, out } => {
                    let bit = values[bit.0];
                    if bit != Val::ZERO && bit != Val::ONE {
                        return Err(ExecutionError::Unsatisfied);
                    }
                    values[out.0] = values[a.0] + bit * (values[b.0] - values[a.0]);
                }
                Op::CubicMul { a, b, out } => {
                    let a =
                        Challenge::from_basis_coefficients_slice(&a.map(|w| values[w.0])).unwrap();
                    let b =
                        Challenge::from_basis_coefficients_slice(&b.map(|w| values[w.0])).unwrap();
                    for (w, &v) in out.iter().zip((a * b).as_basis_coefficients_slice()) {
                        values[w.0] = v;
                    }
                }
                Op::CubicInverse { a, out } => {
                    let a =
                        Challenge::from_basis_coefficients_slice(&a.map(|w| values[w.0])).unwrap();
                    let inverse = a.try_inverse().ok_or(ExecutionError::Unsatisfied)?;
                    for (w, &v) in out.iter().zip(inverse.as_basis_coefficients_slice()) {
                        values[w.0] = v;
                    }
                }
                Op::Poseidon { input, output } => {
                    let mut state = input.map(|w| values[w.0]);
                    default_goldilocks_poseidon2_8().permute_mut(&mut state);
                    for (w, v) in output.iter().zip(state) {
                        values[w.0] = v;
                    }
                }
            }
            Ok(())
        };
        for op in &self.operations {
            execute(op)?;
        }
        Ok(values)
    }
}

/// The existing public builder uses CPU reference arithmetic.
pub type ProgramBuilder = ScopedProgramBuilder<'static>;

/// Backend borrows live only while compiling, never in the immutable program.
pub struct ScopedProgramBuilder<'a> {
    folding: Folding<'a>,
    memory: ConstructionBudget,
    publics: usize,
    witnesses: usize,
    wires: usize,
    operations: Vec<Op>,
    constants: ConstructionMap<u64, Wire>,
    known: ConstructionMap<Wire, Val>,
    expressions: ConstructionMap<(u8, Wire, Wire), Wire>,
    booleans: ConstructionSet,
    cubic_expressions: ConstructionMap<(u8, [Wire; 3], [Wire; 3]), [Wire; 3]>,
    selections: ConstructionMap<(Wire, Wire, Wire), Wire>,
    permutations: ConstructionMap<[Wire; 8], [Wire; 8]>,
}

impl<'a> ScopedProgramBuilder<'a> {
    pub fn new(publics: usize) -> Result<Self, ExecutionError> {
        Self::with_constants(publics, Constants::cpu())
    }

    pub(crate) fn with_constants(
        publics: usize,
        constants: Constants<'a>,
    ) -> Result<Self, ExecutionError> {
        if publics > MAX_PUBLIC_VALUES {
            return Err(ExecutionError::TooLarge);
        }
        let memory = ConstructionBudget::new(constants, publics)?;
        Ok(Self {
            folding: Folding::new(constants),
            memory,
            publics,
            witnesses: 0,
            wires: publics,
            operations: vec![],
            constants: ConstructionMap::new(),
            known: ConstructionMap::new(),
            expressions: ConstructionMap::new(),
            booleans: ConstructionSet::new(),
            cubic_expressions: ConstructionMap::new(),
            selections: ConstructionMap::new(),
            permutations: ConstructionMap::new(),
        })
    }
    pub fn public(&self, index: usize) -> Result<Wire, ExecutionError> {
        if self.memory.failed {
            return Err(ExecutionError::TooLarge);
        }
        if index >= self.publics {
            return Err(ExecutionError::InvalidWire);
        }
        Ok(Wire(index))
    }
    fn allocate(&mut self) -> Wire {
        if self.memory.failed || self.wires >= self.memory.wire_limit {
            self.memory.reject();
            return Wire(0);
        }
        let w = Wire(self.wires);
        self.wires += 1;
        w
    }
    fn push_operation(&mut self, op: Op) {
        self.memory.push(&mut self.operations, op);
    }
    pub(crate) fn resource_failure(&self) -> Option<ExecutionError> {
        self.memory.failed.then_some(ExecutionError::TooLarge)
    }
    pub fn input(&mut self) -> Wire {
        if self.memory.failed || self.witnesses >= self.memory.input_limit {
            self.memory.reject();
            return Wire(0);
        }
        let out = self.allocate();
        if self.memory.failed {
            return out;
        }
        let index = self.witnesses;
        self.witnesses += 1;
        self.push_operation(Op::Input { index, out });
        out
    }
    pub fn constant(&mut self, value: Val) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        let key = value.as_canonical_u64();
        if let Some(w) = self.constants.get(&key) {
            return *w;
        }
        let out = self.allocate();
        self.push_operation(Op::Constant { value, out });
        self.constants.insert(key, out, &mut self.memory);
        self.known.insert(out, value, &mut self.memory);
        out
    }
    pub fn add(&mut self, a: Wire, b: Wire) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        if let (Some(&x), Some(&y)) = (self.known.get(&a), self.known.get(&b)) {
            let value = self
                .folding
                .fold(
                    FoldOperation::Add,
                    [x, Val::ZERO, Val::ZERO],
                    [y, Val::ZERO, Val::ZERO],
                )
                .unwrap();
            return self.constant(value[0]);
        }
        if self.known.get(&a) == Some(&Val::ZERO) {
            return b;
        }
        if self.known.get(&b) == Some(&Val::ZERO) {
            return a;
        }
        let key = (0, a.min(b), a.max(b));
        if let Some(&w) = self.expressions.get(&key) {
            return w;
        }
        let out = self.allocate();
        self.push_operation(Op::Add { a, b, out });
        self.expressions.insert(key, out, &mut self.memory);
        out
    }
    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        if let (Some(&x), Some(&y)) = (self.known.get(&a), self.known.get(&b)) {
            let value = self
                .folding
                .fold(
                    FoldOperation::Mul,
                    [x, Val::ZERO, Val::ZERO],
                    [y, Val::ZERO, Val::ZERO],
                )
                .unwrap();
            return self.constant(value[0]);
        }
        if self.known.get(&a) == Some(&Val::ONE) {
            return b;
        }
        if self.known.get(&b) == Some(&Val::ONE) {
            return a;
        }
        if self.known.get(&a) == Some(&Val::ZERO) || self.known.get(&b) == Some(&Val::ZERO) {
            return self.constant(Val::ZERO);
        }
        let key = (1, a.min(b), a.max(b));
        if let Some(&w) = self.expressions.get(&key) {
            return w;
        }
        let out = self.allocate();
        self.push_operation(Op::Mul { a, b, out });
        self.expressions.insert(key, out, &mut self.memory);
        out
    }
    pub fn inverse(&mut self, a: Wire) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        if let Some(&x) = self.known.get(&a) {
            if let Some(inv) = self.folding.fold(
                FoldOperation::Inverse,
                [x, Val::ZERO, Val::ZERO],
                [Val::ZERO; 3],
            ) {
                return self.constant(inv[0]);
            }
        }
        let key = (2, a, a);
        if let Some(&w) = self.expressions.get(&key) {
            return w;
        }
        let out = self.allocate();
        self.push_operation(Op::Inverse { a, out });
        self.expressions.insert(key, out, &mut self.memory);
        out
    }
    pub fn select(&mut self, bit: Wire, a: Wire, b: Wire) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        if self.known.get(&bit) == Some(&Val::ZERO) {
            return a;
        }
        if self.known.get(&bit) == Some(&Val::ONE) {
            return b;
        }
        if a == b {
            self.assert_bool(bit);
            return a;
        }
        let key = (bit, a, b);
        if let Some(&out) = self.selections.get(&key) {
            return out;
        }
        let out = self.allocate();
        self.push_operation(Op::Select { bit, a, b, out });
        self.booleans.insert(bit, &mut self.memory); // Select itself enforces booleanity.
        self.selections.insert(key, out, &mut self.memory);
        out
    }
    pub(crate) fn cubic_mul(&mut self, a: [Wire; 3], b: [Wire; 3]) -> [Wire; 3] {
        if self.memory.failed {
            return [Wire(0); 3];
        }
        // Preserve cheaper scalar multiplication when either operand is in the base field.
        if self.known.get(&a[1]) == Some(&Val::ZERO) && self.known.get(&a[2]) == Some(&Val::ZERO) {
            return b.map(|w| self.mul(a[0], w));
        }
        if self.known.get(&b[1]) == Some(&Val::ZERO) && self.known.get(&b[2]) == Some(&Val::ZERO) {
            return a.map(|w| self.mul(b[0], w));
        }
        if let (Some(av), Some(bv)) = (self.known_cubic(a), self.known_cubic(b)) {
            return self
                .folding
                .fold(FoldOperation::CubicMul, av, bv)
                .unwrap()
                .map(|v| self.constant(v));
        }
        let key = (0, a.min(b), a.max(b));
        if let Some(&out) = self.cubic_expressions.get(&key) {
            return out;
        }
        let out = core::array::from_fn(|_| self.allocate());
        self.push_operation(Op::CubicMul { a, b, out });
        self.cubic_expressions.insert(key, out, &mut self.memory);
        out
    }
    fn known_cubic(&self, a: [Wire; 3]) -> Option<[Val; 3]> {
        Some([
            *self.known.get(&a[0])?,
            *self.known.get(&a[1])?,
            *self.known.get(&a[2])?,
        ])
    }
    pub(crate) fn cubic_inverse(&mut self, a: [Wire; 3]) -> [Wire; 3] {
        if self.memory.failed {
            return [Wire(0); 3];
        }
        if let Some(values) = self.known_cubic(a) {
            if let Some(inverse) =
                self.folding
                    .fold(FoldOperation::CubicInverse, values, [Val::ZERO; 3])
            {
                return inverse.map(|v| self.constant(v));
            }
        }
        let key = (1, a, a);
        if let Some(&out) = self.cubic_expressions.get(&key) {
            return out;
        }
        let out = core::array::from_fn(|_| self.allocate());
        self.push_operation(Op::CubicInverse { a, out });
        self.cubic_expressions.insert(key, out, &mut self.memory);
        out
    }
    pub fn assert_equal(&mut self, a: Wire, b: Wire) {
        if self.memory.failed {
            return;
        }
        if a == b {
            return;
        }
        self.push_operation(Op::Equal { a, b });
    }
    pub fn assert_bool(&mut self, a: Wire) {
        if self.memory.failed {
            return;
        }
        if self
            .known
            .get(&a)
            .is_some_and(|&v| v == Val::ZERO || v == Val::ONE)
            || !self.booleans.insert(a, &mut self.memory)
        {
            return;
        }
        self.push_operation(Op::Boolean { a });
    }
    pub(crate) fn bit_hint(&mut self, source: Wire, bit: usize) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        let out = self.allocate();
        self.push_operation(Op::Bit { source, bit, out });
        out
    }
    pub fn poseidon(&mut self, input: [Wire; 8]) -> [Wire; 8] {
        if self.memory.failed {
            return [Wire(0); 8];
        }
        if let Some(&output) = self.permutations.get(&input) {
            return output;
        }
        let output = core::array::from_fn(|_| self.allocate());
        self.push_operation(Op::Poseidon { input, output });
        self.permutations.insert(input, output, &mut self.memory);
        output
    }
    fn admit_hint_storage(&mut self, entries: usize, bits: usize) -> bool {
        let Some(bytes) = entries
            .checked_add(bits)
            .and_then(|n| n.checked_mul(core::mem::size_of::<Wire>()))
        else {
            return self.memory.reject();
        };
        self.memory.reserve(bytes)
    }

    #[cfg(test)]
    pub(crate) fn select_hint(&mut self, entries: Vec<Wire>, bits: &[Wire]) -> Wire {
        if !self.admit_hint_storage(entries.capacity(), bits.len()) {
            return Wire(0);
        }
        self.retain_hint(entries, bits)
    }

    /// Materialize hint entries only after admitting their exact allocation.
    /// A counted callback cannot exceed the allocation by misreporting an
    /// iterator size hint, and is never invoked after quota rejection.
    pub(super) fn select_hint_with(
        &mut self,
        count: usize,
        bits: &[Wire],
        mut entry: impl FnMut(usize) -> Wire,
    ) -> Wire {
        if !self.admit_hint_storage(count, bits.len()) {
            return Wire(0);
        }
        let mut entries = Vec::new();
        if entries.try_reserve_exact(count).is_err() {
            self.memory.reject();
            return Wire(0);
        }
        for index in 0..count {
            entries.push(entry(index));
        }
        self.retain_hint(entries, bits)
    }

    fn retain_hint(&mut self, entries: Vec<Wire>, bits: &[Wire]) -> Wire {
        let out = self.allocate();
        if self.memory.failed {
            return out;
        }
        self.push_operation(Op::SelectHint {
            entries,
            bits: bits.to_vec(),
            out,
        });
        out
    }

    /// Keep Merkle scratch inside the same construction allowance. The body
    /// borrows a fixed slice and cannot grow or retain this allocation.
    pub(super) fn with_digest_scratch<T>(
        &mut self,
        source: &[[Wire; 4]],
        body: impl FnOnce(&mut Self, &mut [[Wire; 4]]) -> Result<T, ExecutionError>,
    ) -> Result<T, ExecutionError> {
        let Some(bytes) = source.len().checked_mul(core::mem::size_of::<[Wire; 4]>()) else {
            self.memory.reject();
            return Err(ExecutionError::TooLarge);
        };
        if !self.memory.reserve(bytes) {
            return Err(ExecutionError::TooLarge);
        }
        let mut scratch = Vec::new();
        if scratch.try_reserve_exact(source.len()).is_err() {
            self.memory.release(bytes);
            self.memory.reject();
            return Err(ExecutionError::TooLarge);
        }
        scratch.extend_from_slice(source);
        let result = body(self, &mut scratch);
        drop(scratch);
        self.memory.release(bytes);
        if let Some(error) = self.resource_failure() {
            Err(error)
        } else {
            result
        }
    }
    pub(crate) fn folding_failure(&self) -> Option<&super::verifier::CompileError> {
        self.folding.failure()
    }

    pub fn finish(mut self, fixed_height: Option<usize>) -> Result<Program, ExecutionError> {
        if let Some(error) = self.resource_failure() {
            self.memory.report("rejected");
            return Err(error);
        }
        if self.folding.failure().is_some() {
            return Err(ExecutionError::CompilerBackend);
        }
        if self.wires > MAX_WIRES {
            return Err(ExecutionError::TooLarge);
        }
        // Construction interning tables and constant-folding caches are no
        // longer needed. Drop them before cloning operations into AIR rows;
        // another registered program can still be live in the worker cache.
        let (publics, witnesses, wires) = (self.publics, self.witnesses, self.wires);
        let operations = core::mem::take(&mut self.operations);
        let mut memory = self.memory;
        drop(self);

        // Count only layout metadata. Preserve the original flush order,
        // including a partial ALU row before a partial cubic row at the end.
        // Exact capacities avoid old/new vector storage overlapping on growth
        // and prevent every retained 23-lane row from owning 32 slots.
        let (mut alu_left, mut cubic_left, mut hash_rows) = (0usize, 0usize, 0usize);
        for op in &operations {
            match op {
                Op::Poseidon { .. } => hash_rows += 1,
                Op::CubicMul { .. } | Op::CubicInverse { .. } => cubic_left += 1,
                _ => alu_left += 1,
            }
        }
        let public_rows = publics.div_ceil(PUBLICS_PER_ROW);
        let row_count =
            public_rows + hash_rows + alu_left.div_ceil(LANES) + cubic_left.div_ceil(EXT_LANES);
        let height = fixed_height.unwrap_or_else(|| row_count.max(8).next_power_of_two());
        if !height.is_power_of_two() || height < row_count.max(8) || height > (1 << 24) {
            return Err(ExecutionError::InvalidHeight);
        }
        let packing_bytes =
            construction::packing_bytes(&operations, row_count, alu_left + cubic_left, wires)?;
        if !memory.packing(packing_bytes) {
            memory.report("packing_rejected");
            return Err(ExecutionError::TooLarge);
        }
        let mut defined = vec![false; wires];
        defined[..publics].fill(true);
        let mut references = vec![0u32; wires];
        let mut rows = Vec::with_capacity(row_count);
        rows.extend((0..public_rows).map(Row::Public));
        let mut alu = Vec::new();
        let mut cubic = Vec::new();
        for op in &operations {
            if let Op::SelectHint { entries, bits, .. } = op {
                if bits.len() > 24
                    || entries.len() != 1usize << bits.len()
                    || entries
                        .iter()
                        .chain(bits)
                        .any(|w| w.0 >= wires || !defined[w.0])
                {
                    return Err(ExecutionError::InvalidWire);
                }
            }
            if let Op::Bit { source, bit, .. } = &op {
                if source.0 >= wires || !defined[source.0] || *bit >= 64 {
                    return Err(ExecutionError::InvalidWire);
                }
            }
            for w in op.reads() {
                if w.0 >= wires || !defined[w.0] {
                    return Err(ExecutionError::InvalidWire);
                }
                references[w.0] = references[w.0]
                    .checked_add(1)
                    .ok_or(ExecutionError::TooLarge)?;
            }
            for w in op.writes() {
                if w.0 >= wires || defined[w.0] {
                    return Err(ExecutionError::InvalidWire);
                }
                defined[w.0] = true;
            }
            // The SSA bus authenticates a DAG, not mutable machine state. Packing
            // independent row types cannot alter its semantics.
            match op {
                Op::Poseidon { input, output } => rows.push(Row::Poseidon {
                    input: *input,
                    output: *output,
                }),
                Op::CubicMul { .. } | Op::CubicInverse { .. } => {
                    if cubic.is_empty() {
                        cubic = Vec::with_capacity(cubic_left.min(EXT_LANES));
                    }
                    cubic.push(op.clone());
                    cubic_left -= 1;
                    if cubic.len() == EXT_LANES {
                        rows.push(Row::Cubic(core::mem::take(&mut cubic)));
                    }
                }
                op => {
                    if alu.is_empty() {
                        alu = Vec::with_capacity(alu_left.min(LANES));
                    }
                    alu.push(op.clone());
                    alu_left -= 1;
                    if alu.len() == LANES {
                        rows.push(Row::Alu(core::mem::take(&mut alu)));
                    }
                }
            }
        }
        if !alu.is_empty() {
            rows.push(Row::Alu(alu));
        }
        if !cubic.is_empty() {
            rows.push(Row::Cubic(cubic));
        }
        debug_assert_eq!(rows.len(), row_count);
        debug_assert_eq!((alu_left, cubic_left), (0, 0));
        memory.report("packed");
        Ok(Program {
            construction_host_bytes: memory.peak,
            operations,
            rows,
            references,
            publics,
            witnesses,
            height,
        })
    }
}

#[cfg(test)]
mod packing_tests;
