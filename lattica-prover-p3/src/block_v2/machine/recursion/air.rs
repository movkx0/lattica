use super::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField64;
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks as LL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
};
use p3_lookup::{Count, InteractionBuilder, LookupBus};
use p3_poseidon2::GenericPoseidon2LinearLayers;

pub(super) const SCALAR_LANES: usize = super::super::program::LANES;
pub(super) const CUBIC_LANES: usize = super::super::program::EXT_LANES;
// Two compact hashes fit the bounded quotient specializer. Four lanes exceed
// its compiler envelope and fall back to the substantially slower interpreter.
pub(super) const HASH_LANES: usize = 2;
// Keep each doubled-degree hash prefix below 2 GiB so a consumed input and
// its replacement prefix fit together on the qualified device.
pub(super) const HASH_TABLE_MAX_ROWS: usize = 1 << 19;
// Arithmetic quotient evaluation materializes main, lookup and public columns
// together. Bound its rows independently of the smaller transition table.
pub(super) const SCALAR_TABLE_MAX_ROWS: usize = 1 << 18;
// Reduction rows contain an initial cubic accumulator, eight (weight, value)
// tuples, and a final accumulator. Public addresses authenticate every term and
// both chain boundaries; no transition crosses a chain or table boundary.
const REDUCTION_TERMS: usize = typed::TERMS_PER_ROW;
const REDUCTION_FINAL: usize = 3 + 4 * REDUCTION_TERMS;
const REDUCTION_START: usize = REDUCTION_TERMS;
const REDUCTION_END: usize = REDUCTION_START + 1;
const REDUCTION_INPUTS: usize = REDUCTION_END + 1;
const REDUCTION_INITIAL_ADDRESS: usize = REDUCTION_INPUTS + 4 * REDUCTION_TERMS;
const REDUCTION_FINAL_ADDRESS: usize = REDUCTION_INITIAL_ADDRESS + 3;
const REDUCTION_REFERENCES: usize = REDUCTION_FINAL_ADDRESS + 3;
const HASH_WIDTH: usize = 8 + 8 * 8 + 22;
// Eight raw input words and one authenticated direction bit precede the
// permutation trace. Ordinary hashes fix the direction bit to zero. Keeping
// both forms in one table avoids another commitment and quotient matrix set.
const SWAP_HASH_WIDTH: usize = HASH_WIDTH + 9;
const BUS: LookupBus<'static> = LookupBus::new("lattica-recursion-v3-wire");
#[derive(Clone, Debug)]
pub(super) struct TableAir {
    pub template: Arc<RecursionTemplate>,
    pub kind: usize,
    pub first_row: usize,
    pub active_rows: usize,
    pub height: usize,
}

/// A trusted AIR descriptor retains no compiler, witness, or GPU buffers.
#[derive(Clone, Debug)]
pub(super) struct VerifierAir {
    pub kind: usize,
    pub height: usize,
    pub publics: usize,
    pub id: [u8; 32],
    pub hash_input_count_bound: u32,
}
impl TableAir {
    pub fn verifier_air(&self) -> VerifierAir {
        VerifierAir {
            kind: self.kind,
            height: self.height,
            publics: self.template.program.publics,
            id: self.template.id,
            hash_input_count_bound: self.template.typed.stats().hash_input_count_bound.max(1),
        }
    }
}
impl BaseAir<Val> for VerifierAir {
    fn width(&self) -> usize {
        match self.kind {
            0 => 4 * SCALAR_LANES,
            1 => 9 * CUBIC_LANES,
            2 => SWAP_HASH_WIDTH * HASH_LANES,
            4 => REDUCTION_FINAL + 3,
            _ => 1,
        }
    }
    fn num_public_values(&self) -> usize {
        if self.kind == 3 {
            self.publics
        } else {
            0
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self.kind {
            0 => 8 + 6 * SCALAR_LANES,
            1 => 14 * CUBIC_LANES,
            2 => 35 * HASH_LANES,
            4 => REDUCTION_REFERENCES + 3,
            _ => self.publics.max(1) + 8,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.kind == 4 {
            vec![0, 1, 2]
        } else {
            vec![]
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(if self.kind == 2 { 8 } else { 4 })
    }
}
impl BaseAir<Val> for TableAir {
    fn width(&self) -> usize {
        self.verifier_air().width()
    }
    fn num_public_values(&self) -> usize {
        self.verifier_air().num_public_values()
    }
    fn preprocessed_width(&self) -> usize {
        self.verifier_air().preprocessed_width()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.verifier_air().main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.verifier_air().max_constraint_degree()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let width = self.preprocessed_width();
        let mut data = Val::zero_vec(self.height * width);
        let program = &self.template.program;
        if self.kind == 4 {
            for (i, group) in self
                .template
                .typed
                .groups
                .iter()
                .skip(self.first_row)
                .take(self.active_rows)
                .enumerate()
            {
                let p = &mut data[i * width..(i + 1) * width];
                let first = &self.template.typed.rows[group.terms[0] as usize];
                p[REDUCTION_START] = Val::from_bool(first.start);
                p[REDUCTION_END] = Val::from_bool(group.end != PADDING);
                for (slot, &index) in group.terms.iter().enumerate() {
                    if index == PADDING {
                        continue;
                    }
                    let row = &self.template.typed.rows[index as usize];
                    p[slot] = Val::ONE;
                    for j in 0..3 {
                        p[REDUCTION_INPUTS + 4 * slot + j] = Val::from_u32(row.weights[j] + 1);
                    }
                    p[REDUCTION_INPUTS + 4 * slot + 3] = Val::from_u32(row.value + 1);
                }
                for j in 0..3 {
                    if first.start {
                        p[REDUCTION_INITIAL_ADDRESS + j] = Val::from_u32(first.acc[j] + 1);
                    }
                    if group.end != PADDING {
                        let last = &self.template.typed.rows[group.end as usize];
                        p[REDUCTION_FINAL_ADDRESS + j] = Val::from_u32(last.acc[j] + 1);
                        p[REDUCTION_REFERENCES + j] =
                            Val::from_u32(self.template.typed.references[last.acc[j] as usize]);
                    }
                }
            }
        } else if self.kind == 3 {
            for (i, &count) in self.template.typed.references[..program.publics]
                .iter()
                .enumerate()
            {
                data[i] = Val::from_u32(count);
            }
            for row in data.chunks_exact_mut(width) {
                for (i, bytes) in self.template.id.chunks_exact(4).enumerate() {
                    row[program.publics.max(1) + i] =
                        Val::from_u32(u32::from_le_bytes(bytes.try_into().unwrap()));
                }
            }
        } else {
            let lanes = match self.kind {
                0 => SCALAR_LANES,
                1 => CUBIC_LANES,
                2 => HASH_LANES,
                _ => 1,
            };
            for (i, &index) in self.template.rows[self.kind]
                .iter()
                .skip(self.first_row * lanes)
                .take(self.active_rows * lanes)
                .enumerate()
            {
                if index == PADDING {
                    continue;
                }
                let op = program.operation(index).ok()?;
                if self.kind == 0 {
                    data[(i / lanes) * width + op.code()] = Val::ONE;
                }
                let offset = if self.kind == 0 {
                    8 + (i % lanes) * 6
                } else {
                    (i % lanes) * (width / lanes)
                };
                let p = &mut data[(i / lanes) * width + offset..];
                let addr = |w: super::super::Wire| Val::from_usize(w.0 + 1);
                match self.kind {
                    0 => {
                        p[0] = Val::ONE;
                        let reads = op.reads();
                        let writes = op.writes();
                        for (j, at) in [1, 2, 3].into_iter().enumerate() {
                            if let Some(&w) = reads.get(j) {
                                p[at] = addr(w);
                            }
                        }
                        if let Some(&w) = writes.first() {
                            p[4] = addr(w);
                            p[5] = Val::from_u32(self.template.typed.references[w.0]);
                        }
                        if let Op::Constant { value, .. } = op {
                            p[2] = *value;
                        }
                    }
                    1 => {
                        let (a, b, out) = match op {
                            Op::CubicMul { a, b, out } => {
                                p[0] = Val::ONE;
                                (a, Some(b), out)
                            }
                            Op::CubicInverse { a, out } => {
                                p[1] = Val::ONE;
                                (a, None, out)
                            }
                            _ => unreachable!(),
                        };
                        for j in 0..3 {
                            p[2 + j] = addr(a[j]);
                            if let Some(b) = b {
                                p[5 + j] = addr(b[j]);
                            }
                            p[8 + j] = addr(out[j]);
                            p[11 + j] = Val::from_u32(self.template.typed.references[out[j].0]);
                        }
                    }
                    2 => {
                        let Op::Poseidon { input, output } = op else {
                            unreachable!()
                        };
                        let swap = swaps::find(&self.template.typed.swaps, index as usize);
                        let input = swap.map_or(input, |swap| &swap.input);
                        let owners = self.template.typed.hash_input_owners(index);
                        p[0] = Val::ONE;
                        for j in 0..8 {
                            p[1 + j] = Val::from_u32(input[j] + 1);
                            p[9 + j] = Val::from_u32(output[j] + 1);
                            p[17 + j] =
                                Val::from_u32(self.template.typed.references[output[j] as usize]);
                            // The owner supplies all other uses; a sole-use
                            // private value contributes zero. Counts and wire
                            // addresses are fixed by trusted preprocessing.
                            p[27 + j] = if owners & (1 << j) != 0 {
                                Val::ONE
                                    - Val::from_u32(
                                        self.template.typed.references[input[j] as usize],
                                    )
                            } else {
                                Val::ONE
                            };
                        }
                        if let Some(swap) = swap {
                            p[25] = Val::from_u32(swap.bit + 1);
                            p[26] = Val::ONE;
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
        Some(RowMajorMatrix::new(data, width))
    }
}

impl crate::block_v2::machine::verifier::periodic::Source for VerifierAir {
    fn count(&self) -> usize {
        0
    }
    fn len(&self, _: usize) -> Option<usize> {
        None
    }
    fn fill(
        &self,
        _: usize,
        _: &mut [Val],
    ) -> Result<(), crate::block_v2::machine::verifier::CompileError> {
        Err(
            crate::block_v2::machine::verifier::CompileError::Unsupported(
                "recursion periodic columns",
            ),
        )
    }
}

impl crate::block_v2::machine::verifier::periodic::Source for TableAir {
    fn count(&self) -> usize {
        0
    }
    fn len(&self, _: usize) -> Option<usize> {
        None
    }
    fn fill(
        &self,
        _: usize,
        _: &mut [Val],
    ) -> Result<(), crate::block_v2::machine::verifier::CompileError> {
        Err(
            crate::block_v2::machine::verifier::CompileError::Unsupported(
                "recursion periodic columns",
            ),
        )
    }
}

// Evaluate x^7 directly and keep only round checkpoints. The authenticated
// selector raises the constraint degree to eight, within the pinned blowup.
// Two hashes share a row; the global planner budgets their 16 quotient chunks.
fn permutation<E: PrimeCharacteristicRing>(
    input: [E; 8],
    mut checkpoint: impl FnMut(usize, E) -> E,
) -> [E; 8] {
    let mut state = input;
    let mut column = 8;
    LL::external_linear_layer(&mut state);
    for constants in INITIAL {
        for i in 0..8 {
            let x = state[i].clone() + E::from_u64(constants[i].as_canonical_u64());
            state[i] = x.exp_const_u64::<7>();
        }
        LL::external_linear_layer(&mut state);
        for value in &mut state {
            *value = checkpoint(column, value.clone());
            column += 1;
        }
    }
    for constant in INTERNAL {
        let x = state[0].clone() + E::from_u64(constant.as_canonical_u64());
        state[0] = checkpoint(column, x.exp_const_u64::<7>());
        column += 1;
        LL::internal_linear_layer(&mut state);
    }
    for constants in FINAL {
        for i in 0..8 {
            let x = state[i].clone() + E::from_u64(constants[i].as_canonical_u64());
            state[i] = x.exp_const_u64::<7>();
        }
        LL::external_linear_layer(&mut state);
        for value in &mut state {
            *value = checkpoint(column, value.clone());
            column += 1;
        }
    }
    assert_eq!(column, HASH_WIDTH);
    state
}

pub(super) fn trace(air: &TableAir, values: &[Val]) -> RowMajorMatrix<Val> {
    let template = &air.template;
    let kind = air.kind;
    let width = air.width();
    let lanes = match kind {
        0 => SCALAR_LANES,
        1 => CUBIC_LANES,
        2 => HASH_LANES,
        _ => 1,
    };
    let mut data = Val::zero_vec(air.height * width);
    if kind == 4 {
        for (i, group) in template
            .typed
            .groups
            .iter()
            .skip(air.first_row)
            .take(air.active_rows)
            .enumerate()
        {
            let m = &mut data[i * width..(i + 1) * width];
            let first = &template.typed.rows[group.terms[0] as usize];
            for j in 0..3 {
                m[j] = values[first.acc[j] as usize];
                if group.end != PADDING {
                    let last = &template.typed.rows[group.end as usize];
                    m[REDUCTION_FINAL + j] = values[last.acc[j] as usize];
                }
            }
            for (slot, &index) in group.terms.iter().enumerate() {
                if index == PADDING {
                    continue;
                }
                let row = &template.typed.rows[index as usize];
                for j in 0..3 {
                    m[3 + slot * 4 + j] = values[row.weights[j] as usize];
                }
                m[3 + slot * 4 + 3] = values[row.value as usize];
            }
        }
    } else if kind < 3 {
        for (i, &index) in template.rows[kind]
            .iter()
            .skip(air.first_row * lanes)
            .take(air.active_rows * lanes)
            .enumerate()
        {
            if index == PADDING {
                continue;
            }
            let op = template.program.operation(index).unwrap();
            let m = &mut data[(i / lanes) * width + (i % lanes) * (width / lanes)..];
            match kind {
                0 => {
                    let reads = op.reads();
                    for (j, &w) in reads.iter().enumerate() {
                        m[j] = values[w.0];
                    }
                    if let Some(&w) = op.writes().first() {
                        m[3] = values[w.0];
                    }
                }
                1 => {
                    let (a, b, out) = match op {
                        Op::CubicMul { a, b, out } => (a, Some(b), out),
                        Op::CubicInverse { a, out } => (a, None, out),
                        _ => unreachable!(),
                    };
                    for j in 0..3 {
                        m[j] = values[a[j].0];
                        if let Some(b) = b {
                            m[3 + j] = values[b[j].0];
                        }
                        m[6 + j] = values[out[j].0];
                    }
                }
                2 => {
                    let Op::Poseidon { input, .. } = op else {
                        unreachable!()
                    };
                    if let Some(swap) = swaps::find(&template.typed.swaps, index as usize) {
                        for j in 0..8 {
                            m[j] = values[swap.input[j] as usize];
                        }
                        m[8] = values[swap.bit as usize];
                    } else {
                        for j in 0..8 {
                            m[j] = values[input[j] as usize];
                        }
                    }
                    let input = input.map(|w| values[w as usize]);
                    m[9..17].copy_from_slice(&input);
                    let _ = permutation(input, |column, value| {
                        m[9 + column] = value;
                        value
                    });
                }
                _ => unreachable!(),
            }
        }
    }
    RowMajorMatrix::new(data, width)
}

fn cubic<E: PrimeCharacteristicRing>(a: [E; 3], b: [E; 3]) -> [E; 3] {
    let t: [[E; 3]; 3] =
        core::array::from_fn(|i| core::array::from_fn(|j| a[i].clone() * b[j].clone()));
    let c3 = t[1][2].clone() + t[2][1].clone();
    [
        t[0][0].clone() + c3.clone(),
        t[0][1].clone() + t[1][0].clone() + c3 + t[2][2].clone(),
        t[0][2].clone() + t[1][1].clone() + t[2][0].clone() + t[2][2].clone(),
    ]
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for TableAir {
    fn eval(&self, b: &mut AB) {
        self.verifier_air().eval(b);
    }
}
impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for VerifierAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let pre = b.preprocessed().clone();
        let m = main.current_slice();
        let p = pre.current_slice();
        match self.kind {
            0 => {
                for lane in 0..SCALAR_LANES {
                    let selectors: [AB::Expr; 8] = core::array::from_fn(|i| p[i].into());
                    let p = &p[8 + lane * 6..];
                    let m = &m[lane * 4..];
                    let active: AB::Expr = p[0].into();
                    let s: [AB::Expr; 8] =
                        core::array::from_fn(|i| selectors[i].clone() * active.clone());
                    let [a, v, d, c]: [AB::Expr; 4] = core::array::from_fn(|i| m[i].into());
                    b.assert_zero(s[1].clone() * (c.clone() - p[2]));
                    b.assert_zero(s[2].clone() * (c.clone() - a.clone() - v.clone()));
                    b.assert_zero(s[3].clone() * (c.clone() - a.clone() * v.clone()));
                    b.assert_zero(s[4].clone() * (a.clone() - v.clone()));
                    b.assert_zero(s[5].clone() * a.clone() * (a.clone() - AB::Expr::ONE));
                    b.assert_zero(s[6].clone() * (a.clone() * c.clone() - AB::Expr::ONE));
                    b.assert_zero(
                        s[7].clone()
                            * (c.clone() - a.clone() - d.clone() * (v.clone() - a.clone())),
                    );
                    b.assert_zero(s[7].clone() * d.clone() * (d.clone() - AB::Expr::ONE));
                    let ra = s[2..].iter().cloned().sum::<AB::Expr>();
                    let rb = s[2].clone() + s[3].clone() + s[4].clone() + s[7].clone();
                    let write = s[0].clone()
                        + s[1].clone()
                        + s[2].clone()
                        + s[3].clone()
                        + s[6].clone()
                        + s[7].clone();
                    for (value, count, addr) in [(a, ra, 1), (v, rb, 2), (d, s[7].clone(), 3)] {
                        b.assert_zero((AB::Expr::ONE - count.clone()) * value.clone());
                        BUS.lookup_key(b, [p[addr].into(), value], Count::bounded(count, 1));
                    }
                    b.assert_zero((AB::Expr::ONE - write) * c.clone());
                    BUS.table_entry(b, [p[4].into(), c], p[5]);
                }
            }
            1 => {
                for lane in 0..CUBIC_LANES {
                    let p = &p[lane * 14..];
                    let m = &m[lane * 9..];
                    let a: [AB::Expr; 3] = core::array::from_fn(|i| m[i].into());
                    let v: [AB::Expr; 3] = core::array::from_fn(|i| m[3 + i].into());
                    let c: [AB::Expr; 3] = core::array::from_fn(|i| m[6 + i].into());
                    let mul: AB::Expr = p[0].into();
                    let inv: AB::Expr = p[1].into();
                    let active = mul.clone() + inv.clone();
                    let product = cubic(a.clone(), v.clone());
                    let inverse = cubic(a.clone(), c.clone());
                    for i in 0..3 {
                        b.assert_zero(
                            mul.clone() * (product[i].clone() - c[i].clone())
                                + inv.clone()
                                    * (inverse[i].clone()
                                        - if i == 0 {
                                            AB::Expr::ONE
                                        } else {
                                            AB::Expr::ZERO
                                        }),
                        );
                        b.assert_zero((AB::Expr::ONE - active.clone()) * a[i].clone());
                        b.assert_zero((AB::Expr::ONE - mul.clone()) * v[i].clone());
                        b.assert_zero((AB::Expr::ONE - active.clone()) * c[i].clone());
                        BUS.lookup_key(
                            b,
                            [p[2 + i].into(), a[i].clone()],
                            Count::bounded(active.clone(), 1),
                        );
                        BUS.lookup_key(
                            b,
                            [p[5 + i].into(), v[i].clone()],
                            Count::bounded(mul.clone(), 1),
                        );
                        BUS.table_entry(b, [p[8 + i].into(), c[i].clone()], p[11 + i]);
                    }
                }
            }
            2 => {
                let width = SWAP_HASH_WIDTH;
                let pre_width = 35;
                for lane in 0..HASH_LANES {
                    let m = &m[lane * width..(lane + 1) * width];
                    let p = &p[lane * pre_width..(lane + 1) * pre_width];
                    let h: AB::Expr = p[0].into();
                    let bit: AB::Expr = m[8].into();
                    let swap: AB::Expr = p[26].into();
                    b.assert_zero(h.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
                    b.assert_zero((AB::Expr::ONE - swap.clone()) * bit.clone());
                    for i in 0..8 {
                        b.assert_zero(
                            h.clone() * (m[9 + i] - m[i] - bit.clone() * (m[i ^ 4] - m[i])),
                        );
                    }
                    BUS.lookup_key(b, [p[25].into(), bit], Count::bounded(swap, 1));
                    let hash = &m[9..];
                    let output = permutation(
                        core::array::from_fn(|i| hash[i].into()),
                        |column, expected| {
                            let actual: AB::Expr = hash[column].into();
                            b.assert_zero(h.clone() * (actual.clone() - expected));
                            actual
                        },
                    );
                    for &value in m {
                        b.assert_zero((AB::Expr::ONE - h.clone()) * value);
                    }
                    for i in 0..8 {
                        BUS.lookup_key(
                            b,
                            [p[1 + i].into(), m[i].into()],
                            // Signed count: +1 for an ordinary read, or minus
                            // the remaining uses for a relocated private input.
                            // Its exact magnitude is bounded by the immutable
                            // source's reference counts, not by a proof value.
                            Count::bounded(p[27 + i].into(), self.hash_input_count_bound),
                        );
                        BUS.table_entry(b, [p[9 + i].into(), output[i].clone()], p[17 + i]);
                    }
                }
            }
            4 => {
                let next = main.next_slice();
                let step: AB::Expr = p[0].into();
                let start: AB::Expr = p[REDUCTION_START].into();
                let end: AB::Expr = p[REDUCTION_END].into();
                let mut delta: [AB::Expr; 3] = core::array::from_fn(|_| AB::Expr::ZERO);
                for slot in 0..REDUCTION_TERMS {
                    let active: AB::Expr = p[slot].into();
                    for j in 0..4 {
                        let value: AB::Expr = m[3 + slot * 4 + j].into();
                        b.assert_zero((AB::Expr::ONE - active.clone()) * value.clone());
                        BUS.lookup_key(
                            b,
                            [p[REDUCTION_INPUTS + slot * 4 + j].into(), value],
                            Count::bounded(active.clone(), 1),
                        );
                    }
                    for j in 0..3 {
                        delta[j] = delta[j].clone() + m[3 + slot * 4 + j] * m[3 + slot * 4 + 3];
                    }
                }
                for j in 0..3 {
                    b.assert_zero(
                        (step.clone() - end.clone()) * (next[j] - m[j] - delta[j].clone()),
                    );
                    b.assert_zero(end.clone() * (m[REDUCTION_FINAL + j] - m[j] - delta[j].clone()));
                    b.assert_zero((AB::Expr::ONE - step.clone()) * m[j]);
                    b.assert_zero((AB::Expr::ONE - end.clone()) * m[REDUCTION_FINAL + j]);
                    BUS.lookup_key(
                        b,
                        [p[REDUCTION_INITIAL_ADDRESS + j].into(), m[j].into()],
                        Count::bounded(start.clone(), 1),
                    );
                    BUS.table_entry(
                        b,
                        [
                            p[REDUCTION_FINAL_ADDRESS + j].into(),
                            m[REDUCTION_FINAL + j].into(),
                        ],
                        p[REDUCTION_REFERENCES + j],
                    );
                }
            }
            3 => {
                b.assert_zero(m[0]);
                for (i, bytes) in self.id.chunks_exact(4).enumerate() {
                    b.assert_eq(
                        p[self.publics.max(1) + i],
                        Val::from_u32(u32::from_le_bytes(bytes.try_into().unwrap())),
                    );
                }
                for i in 0..self.publics {
                    let value: AB::Expr = b.public_values()[i].into();
                    BUS.table_entry(b, [AB::Expr::from_usize(i + 1), value], p[i]);
                }
            }
            _ => unreachable!(),
        }
    }
}
