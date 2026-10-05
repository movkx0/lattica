//! Immutable SSA programs. Wire addresses, selectors and reference counts live
//! in the authenticated preprocessing, never in the prover's witness.

use crate::block_v2::profile::Challenge;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;
use std::collections::{BTreeMap, HashMap, HashSet};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    // Witness evaluation retains topological order; authenticated rows may be packed by opcode.
    pub(crate) operations: Vec<Op>,
    pub(crate) rows: Vec<Row>,
    pub(crate) references: Vec<u32>,
    pub(crate) publics: usize,
    pub(crate) witnesses: usize,
    pub(crate) height: usize,
}

impl Program {
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
        let mut out = vec![
            if cfg!(feature = "block-v2-wide-lanes") {
                6
            } else {
                3
            },
            self.publics as u64,
            self.witnesses as u64,
            self.height as u64,
            self.references.len() as u64,
            self.rows.len() as u64,
        ];
        #[cfg(feature = "block-v2-wide-lanes")]
        out.extend([
            LANES as u64,
            EXT_LANES as u64,
            PUBLICS_PER_ROW as u64,
            crate::block_v2::profile::NODE_CODEC_REVISION,
        ]);
        for row in &self.rows {
            let ops = match row {
                Row::Public(bank) => {
                    out.push(3);
                    out.push(*bank as u64);
                    vec![]
                }
                Row::Alu(ops) => {
                    out.push(0);
                    ops.clone()
                }
                Row::Cubic(ops) => {
                    out.push(2);
                    ops.clone()
                }
                Row::Poseidon { input, output } => {
                    out.push(1);
                    vec![Op::Poseidon {
                        input: *input,
                        output: *output,
                    }]
                }
            };
            out.push(ops.len() as u64);
            for op in ops {
                out.push(op.code() as u64);
                match &op {
                    Op::Input { index, .. } => {
                        out.push(0);
                        out.push(*index as u64);
                    }
                    Op::Bit { source, bit, .. } => {
                        out.push(1);
                        out.push(source.0 as u64);
                        out.push(*bit as u64);
                    }
                    Op::SelectHint { entries, bits, .. } => {
                        out.push(2);
                        out.push(entries.len() as u64);
                        out.extend(entries.iter().map(|w| w.0 as u64));
                        out.push(bits.len() as u64);
                        out.extend(bits.iter().map(|w| w.0 as u64));
                    }
                    Op::Constant { value, .. } => out.push(value.as_canonical_u64()),
                    _ => (),
                }
                let reads = op.reads();
                let writes = op.writes();
                out.push(reads.len() as u64);
                out.extend(reads.iter().map(|w| w.0 as u64));
                out.push(writes.len() as u64);
                out.extend(writes.iter().map(|w| w.0 as u64));
            }
        }
        out.extend(self.references.iter().map(|&r| u64::from(r)));
        out
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

pub struct ProgramBuilder {
    publics: usize,
    witnesses: usize,
    wires: usize,
    operations: Vec<Op>,
    constants: BTreeMap<u64, Wire>,
    known: HashMap<Wire, Val>,
    expressions: HashMap<(u8, Wire, Wire), Wire>,
    booleans: HashSet<Wire>,
    cubic_expressions: HashMap<(u8, [Wire; 3], [Wire; 3]), [Wire; 3]>,
    selections: HashMap<(Wire, Wire, Wire), Wire>,
    permutations: HashMap<[Wire; 8], [Wire; 8]>,
}

impl ProgramBuilder {
    pub fn new(publics: usize) -> Result<Self, ExecutionError> {
        if publics > MAX_PUBLIC_VALUES {
            return Err(ExecutionError::TooLarge);
        }
        Ok(Self {
            publics,
            witnesses: 0,
            wires: publics,
            operations: vec![],
            constants: BTreeMap::new(),
            known: HashMap::new(),
            expressions: HashMap::new(),
            booleans: HashSet::new(),
            cubic_expressions: HashMap::new(),
            selections: HashMap::new(),
            permutations: HashMap::new(),
        })
    }
    pub fn public(&self, index: usize) -> Result<Wire, ExecutionError> {
        if index >= self.publics {
            return Err(ExecutionError::InvalidWire);
        }
        Ok(Wire(index))
    }
    fn allocate(&mut self) -> Wire {
        let w = Wire(self.wires);
        self.wires += 1;
        w
    }
    pub fn input(&mut self) -> Wire {
        let out = self.allocate();
        let index = self.witnesses;
        self.witnesses += 1;
        self.operations.push(Op::Input { index, out });
        out
    }
    pub fn constant(&mut self, value: Val) -> Wire {
        let key = value.as_canonical_u64();
        if let Some(w) = self.constants.get(&key) {
            return *w;
        }
        let out = self.allocate();
        self.operations.push(Op::Constant { value, out });
        self.constants.insert(key, out);
        self.known.insert(out, value);
        out
    }
    pub fn add(&mut self, a: Wire, b: Wire) -> Wire {
        if let (Some(&x), Some(&y)) = (self.known.get(&a), self.known.get(&b)) {
            return self.constant(x + y);
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
        self.operations.push(Op::Add { a, b, out });
        self.expressions.insert(key, out);
        out
    }
    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        if let (Some(&x), Some(&y)) = (self.known.get(&a), self.known.get(&b)) {
            return self.constant(x * y);
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
        self.operations.push(Op::Mul { a, b, out });
        self.expressions.insert(key, out);
        out
    }
    pub fn inverse(&mut self, a: Wire) -> Wire {
        if let Some(&x) = self.known.get(&a) {
            if let Some(inv) = x.try_inverse() {
                return self.constant(inv);
            }
        }
        let key = (2, a, a);
        if let Some(&w) = self.expressions.get(&key) {
            return w;
        }
        let out = self.allocate();
        self.operations.push(Op::Inverse { a, out });
        self.expressions.insert(key, out);
        out
    }
    pub fn select(&mut self, bit: Wire, a: Wire, b: Wire) -> Wire {
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
        self.operations.push(Op::Select { bit, a, b, out });
        self.booleans.insert(bit); // Select itself enforces booleanity.
        self.selections.insert(key, out);
        out
    }
    pub(crate) fn cubic_mul(&mut self, a: [Wire; 3], b: [Wire; 3]) -> [Wire; 3] {
        // Preserve cheaper scalar multiplication when either operand is in the base field.
        if self.known.get(&a[1]) == Some(&Val::ZERO) && self.known.get(&a[2]) == Some(&Val::ZERO) {
            return b.map(|w| self.mul(a[0], w));
        }
        if self.known.get(&b[1]) == Some(&Val::ZERO) && self.known.get(&b[2]) == Some(&Val::ZERO) {
            return a.map(|w| self.mul(b[0], w));
        }
        if let (Some(av), Some(bv)) = (self.known_cubic(a), self.known_cubic(b)) {
            return (av * bv)
                .as_basis_coefficients_slice()
                .try_into()
                .map(|v: [Val; 3]| v.map(|v| self.constant(v)))
                .unwrap();
        }
        let key = (0, a.min(b), a.max(b));
        if let Some(&out) = self.cubic_expressions.get(&key) {
            return out;
        }
        let out = core::array::from_fn(|_| self.allocate());
        self.operations.push(Op::CubicMul { a, b, out });
        self.cubic_expressions.insert(key, out);
        out
    }
    fn known_cubic(&self, a: [Wire; 3]) -> Option<Challenge> {
        let values = [
            *self.known.get(&a[0])?,
            *self.known.get(&a[1])?,
            *self.known.get(&a[2])?,
        ];
        Challenge::from_basis_coefficients_slice(&values)
    }
    pub(crate) fn cubic_inverse(&mut self, a: [Wire; 3]) -> [Wire; 3] {
        if let Some(inverse) = self.known_cubic(a).and_then(|v| v.try_inverse()) {
            let values: [Val; 3] = inverse.as_basis_coefficients_slice().try_into().unwrap();
            return values.map(|v| self.constant(v));
        }
        let key = (1, a, a);
        if let Some(&out) = self.cubic_expressions.get(&key) {
            return out;
        }
        let out = core::array::from_fn(|_| self.allocate());
        self.operations.push(Op::CubicInverse { a, out });
        self.cubic_expressions.insert(key, out);
        out
    }
    pub fn assert_equal(&mut self, a: Wire, b: Wire) {
        if a == b {
            return;
        }
        self.operations.push(Op::Equal { a, b });
    }
    pub fn assert_bool(&mut self, a: Wire) {
        if self
            .known
            .get(&a)
            .is_some_and(|&v| v == Val::ZERO || v == Val::ONE)
            || !self.booleans.insert(a)
        {
            return;
        }
        self.operations.push(Op::Boolean { a });
    }
    pub(crate) fn bit_hint(&mut self, source: Wire, bit: usize) -> Wire {
        let out = self.allocate();
        self.operations.push(Op::Bit { source, bit, out });
        out
    }
    pub fn poseidon(&mut self, input: [Wire; 8]) -> [Wire; 8] {
        if let Some(&output) = self.permutations.get(&input) {
            return output;
        }
        let output = core::array::from_fn(|_| self.allocate());
        self.operations.push(Op::Poseidon { input, output });
        self.permutations.insert(input, output);
        output
    }
    pub(crate) fn select_hint(&mut self, entries: Vec<Wire>, bits: &[Wire]) -> Wire {
        let out = self.allocate();
        self.operations.push(Op::SelectHint {
            entries,
            bits: bits.to_vec(),
            out,
        });
        out
    }
    pub fn finish(self, fixed_height: Option<usize>) -> Result<Program, ExecutionError> {
        if self.wires > MAX_WIRES {
            return Err(ExecutionError::TooLarge);
        }
        let mut defined = vec![false; self.wires];
        defined[..self.publics].fill(true);
        let mut references = vec![0u32; self.wires];
        let mut rows: Vec<_> = (0..self.publics.div_ceil(PUBLICS_PER_ROW))
            .map(Row::Public)
            .collect();
        let mut alu = Vec::new();
        let mut cubic = Vec::new();
        for op in &self.operations {
            if let Op::SelectHint { entries, bits, .. } = op {
                if bits.len() > 24
                    || entries.len() != 1usize << bits.len()
                    || entries
                        .iter()
                        .chain(bits)
                        .any(|w| w.0 >= self.wires || !defined[w.0])
                {
                    return Err(ExecutionError::InvalidWire);
                }
            }
            if let Op::Bit { source, bit, .. } = &op {
                if source.0 >= self.wires || !defined[source.0] || *bit >= 64 {
                    return Err(ExecutionError::InvalidWire);
                }
            }
            for w in op.reads() {
                if w.0 >= self.wires || !defined[w.0] {
                    return Err(ExecutionError::InvalidWire);
                }
                references[w.0] = references[w.0]
                    .checked_add(1)
                    .ok_or(ExecutionError::TooLarge)?;
            }
            for w in op.writes() {
                if w.0 >= self.wires || defined[w.0] {
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
                    cubic.push(op.clone());
                    if cubic.len() == EXT_LANES {
                        rows.push(Row::Cubic(core::mem::take(&mut cubic)));
                    }
                }
                op => {
                    alu.push(op.clone());
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
        let height = fixed_height.unwrap_or_else(|| rows.len().max(8).next_power_of_two());
        if !height.is_power_of_two() || height < rows.len().max(8) || height > (1 << 24) {
            return Err(ExecutionError::InvalidHeight);
        }
        Ok(Program {
            operations: self.operations,
            rows,
            references,
            publics: self.publics,
            witnesses: self.witnesses,
            height,
        })
    }
}
