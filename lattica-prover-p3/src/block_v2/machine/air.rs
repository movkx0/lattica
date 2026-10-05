use super::program::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks as LL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as INTERNAL,
};
use p3_lookup::{Count, InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::sync::Arc;

const ARITHMETIC_COLUMNS: usize = 4 * LANES;
// Keep the original eight arithmetic ports at their hash-compatible positions.
// Extra arithmetic lanes reuse hash checkpoints, which are inactive on ALU rows.
const HASH_A: usize = 0;
const HASH_B: usize = 8;
const HASH_C: usize = 16;
const HASH_D: usize = 24;
const HASH: usize = 32;
/// Fixed Poseidon trace width, also covering the selected arithmetic layout.
pub const WIDTH: usize = HASH + 7 * 8 + 22 - 16;
const _: () = assert!(LANES >= 8 && ARITHMETIC_COLUMNS <= WIDTH);
const _: () = assert!(3 * EXT_LANES <= LANES && MAX_PUBLIC_VALUES <= 2 * PUBLICS_PER_ROW);

const fn port_column(port: usize, lane: usize) -> usize {
    assert!(port < 4 && lane < LANES);
    if lane < 8 {
        port * 8 + lane
    } else {
        HASH + port * (LANES - 8) + lane - 8
    }
}

pub(super) const fn a_column(lane: usize) -> usize {
    port_column(0, lane)
}
pub(super) const fn b_column(lane: usize) -> usize {
    port_column(1, lane)
}
pub(super) const fn c_column(lane: usize) -> usize {
    port_column(2, lane)
}
pub(super) const fn d_column(lane: usize) -> usize {
    port_column(3, lane)
}

const SEL: usize = 0;
const ADDR_A: usize = OPCODE_BITS * LANES;
const ADDR_B: usize = ADDR_A + LANES;
const ADDR_C: usize = ADDR_B + LANES;
const ADDR_D: usize = ADDR_C + LANES;
const MULT_C: usize = ADDR_D + LANES;
const CONSTANT: usize = ADDR_B; // Constant instructions have no B read.
const IS_HASH: usize = MULT_C + LANES;
const EXT_MUL: usize = IS_HASH + 1;
const EXT_INV: usize = EXT_MUL + EXT_LANES;
const PUBLIC_BANK: usize = EXT_INV + EXT_LANES;
const PREPROCESSED_WIDTH: usize = PUBLIC_BANK + 1;
#[cfg(not(feature = "block-v2-wide-lanes"))]
const BUS: LookupBus<'static> = LookupBus::new("lattica-v2-ssa-wire-v3");
#[cfg(feature = "block-v2-wide-lanes")]
const BUS: LookupBus<'static> = LookupBus::new("lattica-v2-ssa-wire-wide23-v3");

#[derive(Clone, Debug)]
pub struct MachineAir {
    pub(crate) program: Arc<Program>,
}

fn pow7<E: PrimeCharacteristicRing>(x: E) -> E {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x2 * x
}

/// Native and AIR use the same round order and upstream constants/linear maps.
/// Every intermediate round is written to / checked against a trace column.
fn permutation<E: PrimeCharacteristicRing>(
    input: [E; 8],
    mut checkpoint: impl FnMut(usize, E) -> E,
) -> [E; 8] {
    let mut state = input;
    let mut column = 0;
    LL::external_linear_layer(&mut state);
    for constants in INITIAL {
        for i in 0..8 {
            state[i] = pow7(state[i].clone() + E::from_u64(constants[i].as_canonical_u64()));
        }
        LL::external_linear_layer(&mut state);
        for item in &mut state {
            *item = checkpoint(hash_column(column), item.clone());
            column += 1;
        }
    }
    for constant in INTERNAL {
        state[0] = checkpoint(
            hash_column(column),
            pow7(state[0].clone() + E::from_u64(constant.as_canonical_u64())),
        );
        column += 1;
        LL::internal_linear_layer(&mut state);
    }
    for (round, constants) in FINAL.iter().enumerate() {
        for i in 0..8 {
            state[i] = pow7(state[i].clone() + E::from_u64(constants[i].as_canonical_u64()));
        }
        LL::external_linear_layer(&mut state);
        for (i, item) in state.iter_mut().enumerate() {
            *item = checkpoint(
                if round == 3 {
                    HASH_C + i
                } else {
                    hash_column(column)
                },
                item.clone(),
            );
            if round != 3 {
                column += 1;
            }
        }
    }
    state
}

impl MachineAir {
    pub fn new(program: Program) -> Self {
        Self {
            program: Arc::new(program),
        }
    }
    pub fn program(&self) -> &Program {
        &self.program
    }
    pub fn trace(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<RowMajorMatrix<Val>, ExecutionError> {
        let values = self.program.evaluate(public, witness)?;
        let mut trace = Val::zero_vec(self.program.height * WIDTH);
        for (r, row) in self.program.rows.iter().enumerate() {
            let t = &mut trace[r * WIDTH..(r + 1) * WIDTH];
            match row {
                Row::Public(_) => {}
                Row::Alu(ops) => {
                    for (lane, op) in ops.iter().enumerate() {
                        let reads = op.reads();
                        let writes = op.writes();
                        if let Some(w) = reads.first() {
                            t[a_column(lane)] = values[w.0];
                        }
                        if let Some(w) = reads.get(1) {
                            t[b_column(lane)] = values[w.0];
                        }
                        if let Some(w) = reads.get(2) {
                            t[d_column(lane)] = values[w.0];
                        }
                        if let Some(w) = writes.first() {
                            t[c_column(lane)] = values[w.0];
                        }
                    }
                }
                Row::Cubic(ops) => {
                    for (group, op) in ops.iter().enumerate() {
                        let (a, b, out) = match op {
                            Op::CubicMul { a, b, out } => (a, Some(b), out),
                            Op::CubicInverse { a, out } => (a, None, out),
                            _ => unreachable!(),
                        };
                        for i in 0..3 {
                            let lane = group * 3 + i;
                            t[a_column(lane)] = values[a[i].0];
                            if let Some(b) = b {
                                t[b_column(lane)] = values[b[i].0];
                            }
                            t[c_column(lane)] = values[out[i].0];
                        }
                    }
                }
                Row::Poseidon { input, .. } => {
                    let input = input.map(|w| values[w.0]);
                    t[HASH_A..HASH_A + 8].copy_from_slice(&input);
                    let _ = permutation(input, |column, value| {
                        t[column] = value;
                        value
                    });
                }
            }
        }
        Ok(RowMajorMatrix::new(trace, WIDTH))
    }
}

impl BaseAir<Val> for MachineAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        self.program.publics
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let width = self.preprocessed_width();
        let mut data = Val::zero_vec(self.program.height * width);
        // Default to the zero-constant opcode. This constrains every padded
        // scalar port, without one-hot selector columns or a per-lane enable.
        for row in data.chunks_exact_mut(width) {
            for lane in 0..LANES {
                set_opcode(row, lane, 1);
            }
        }
        for (r, row) in self.program.rows.iter().enumerate() {
            let t = &mut data[r * width..(r + 1) * width];
            match row {
                Row::Public(bank) => {
                    t[PUBLIC_BANK] = Val::from_usize(bank + 1);
                    for lane in 0..LANES {
                        set_opcode(t, lane, 0);
                    }
                    for i in 0..PUBLICS_PER_ROW {
                        if let Some(&count) = self
                            .program
                            .references
                            .get(bank * PUBLICS_PER_ROW + i)
                            .filter(|_| bank * PUBLICS_PER_ROW + i < self.program.publics)
                        {
                            t[ADDR_A + i] = Val::from_u32(count);
                        }
                    }
                }
                Row::Alu(ops) => {
                    for (lane, op) in ops.iter().enumerate() {
                        set_opcode(t, lane, op.code());
                        let reads = op.reads();
                        let writes = op.writes();
                        if let Some(w) = reads.first() {
                            t[ADDR_A + lane] = Val::from_usize(w.0 + 1);
                        }
                        if let Some(w) = reads.get(1) {
                            t[ADDR_B + lane] = Val::from_usize(w.0 + 1);
                        }
                        if let Some(w) = reads.get(2) {
                            t[ADDR_D + lane] = Val::from_usize(w.0 + 1);
                        }
                        if let Some(w) = writes.first() {
                            t[ADDR_C + lane] = Val::from_usize(w.0 + 1);
                            t[MULT_C + lane] = Val::from_u32(self.program.references[w.0]);
                        }
                        if let Op::Constant { value, .. } = op {
                            t[CONSTANT + lane] = *value;
                        }
                    }
                }
                Row::Cubic(ops) => {
                    for (group, op) in ops.iter().enumerate() {
                        let (a, b, out) = match op {
                            Op::CubicMul { a, b, out } => {
                                t[EXT_MUL + group] = Val::ONE;
                                (a, Some(b), out)
                            }
                            Op::CubicInverse { a, out } => {
                                t[EXT_INV + group] = Val::ONE;
                                (a, None, out)
                            }
                            _ => unreachable!(),
                        };
                        for i in 0..3 {
                            let lane = group * 3 + i;
                            set_opcode(t, lane, 0); // Cubic constraints own this output.
                            t[ADDR_A + lane] = Val::from_usize(a[i].0 + 1);
                            if let Some(b) = b {
                                t[ADDR_B + lane] = Val::from_usize(b[i].0 + 1);
                            }
                            t[ADDR_C + lane] = Val::from_usize(out[i].0 + 1);
                            t[MULT_C + lane] = Val::from_u32(self.program.references[out[i].0]);
                        }
                    }
                }
                Row::Poseidon { input, output } => {
                    t[IS_HASH] = Val::ONE;
                    // All C ports hold hash checkpoints, including extra lanes.
                    // Only the first eight have authenticated bus multiplicities.
                    for lane in 0..LANES {
                        set_opcode(t, lane, 0);
                    }
                    for i in 0..8 {
                        t[ADDR_A + i] = Val::from_usize(input[i].0 + 1);
                        t[ADDR_C + i] = Val::from_usize(output[i].0 + 1);
                        t[MULT_C + i] = Val::from_u32(self.program.references[output[i].0]);
                    }
                }
            }
        }
        Some(RowMajorMatrix::new(data, width))
    }
    // Do not supply a degree hint: lookup packing must use the complete symbolic AIR.
}

impl<AB> Air<AB> for MachineAir
where
    AB: AirBuilder<F = Val> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let m = main.current_slice();
        let p = pre.current_slice();
        let h: AB::Expr = p[IS_HASH].into();
        let bank: AB::Expr = p[PUBLIC_BANK].into();
        let bank_zero = bank.clone() * (AB::Expr::TWO - bank.clone());
        let bank_one = bank.clone() * (bank.clone() - AB::Expr::ONE) * Val::ONE.halve();
        let public_row = bank_zero.clone() + bank_one.clone();
        for lane in 0..LANES {
            // Preprocessed opcode bits are authenticated constants at trace rows.
            // Evaluating the decoding polynomials raises degree, so lookup packing
            // and quotient geometry are recomputed from the full symbolic AIR.
            let bits: [AB::Expr; OPCODE_BITS] =
                core::array::from_fn(|bit| p[SEL + lane * OPCODE_BITS + bit].into());
            let s: [AB::Expr; OPS] = core::array::from_fn(|op| {
                (0..OPCODE_BITS).fold(AB::Expr::ONE, |v, bit| {
                    v * if (op >> bit) & 1 == 1 {
                        bits[bit].clone()
                    } else {
                        AB::Expr::ONE - bits[bit].clone()
                    }
                })
            });
            let a: AB::Expr = m[a_column(lane)].into();
            let b: AB::Expr = m[b_column(lane)].into();
            let c: AB::Expr = m[c_column(lane)].into();
            let d: AB::Expr = m[d_column(lane)].into();
            let (ext_mul, ext_inv): (AB::Expr, AB::Expr) = if lane / 3 < EXT_LANES {
                (p[EXT_MUL + lane / 3].into(), p[EXT_INV + lane / 3].into())
            } else {
                (AB::Expr::ZERO, AB::Expr::ZERO)
            };
            let ext = ext_mul.clone() + ext_inv;
            builder.assert_zero(s[1].clone() * (c.clone() - p[CONSTANT + lane]));
            builder.assert_zero(s[2].clone() * (c.clone() - a.clone() - b.clone()));
            builder.assert_zero(s[3].clone() * (c.clone() - a.clone() * b.clone()));
            builder.assert_zero(s[4].clone() * (a.clone() - b.clone()));
            builder.assert_zero(s[5].clone() * a.clone() * (a.clone() - AB::Expr::ONE));
            builder.assert_zero(s[6].clone() * (a.clone() * c.clone() - AB::Expr::ONE));
            builder.assert_zero(
                s[7].clone() * (c.clone() - a.clone() - d.clone() * (b.clone() - a.clone())),
            );
            builder.assert_zero(s[7].clone() * d.clone() * (d.clone() - AB::Expr::ONE));
            let hash_read = if lane < 8 { h.clone() } else { AB::Expr::ZERO };
            let read_a = hash_read
                + ext.clone()
                + s[7].clone()
                + s[2].clone()
                + s[3].clone()
                + s[4].clone()
                + s[5].clone()
                + s[6].clone();
            let read_b = ext_mul + s[2].clone() + s[3].clone() + s[4].clone() + s[7].clone();
            let read_d = s[7].clone();
            let write = s[7].clone()
                + s[0].clone()
                + s[1].clone()
                + s[2].clone()
                + s[3].clone()
                + s[6].clone();
            builder.assert_zero(public_row.clone() * c.clone());
            // Canonical inactive ports. Active multiplicities are fixed preprocessing.
            // Extra A ports contain permutation checkpoints on hash rows, not reads.
            let unused_a = if lane < 8 {
                AB::Expr::ONE - read_a.clone()
            } else {
                AB::Expr::ONE - read_a.clone() - h.clone()
            };
            builder.assert_zero(unused_a * a.clone());
            builder.assert_zero((AB::Expr::ONE - read_b.clone() - h.clone()) * b.clone());
            builder.assert_zero((AB::Expr::ONE - write) * c.clone());
            builder.assert_zero((AB::Expr::ONE - read_d.clone() - h.clone()) * d.clone());
            BUS.lookup_key(
                builder,
                [p[ADDR_A + lane].into(), a],
                Count::bounded(read_a, 1),
            );
            BUS.lookup_key(
                builder,
                [p[ADDR_B + lane].into(), b],
                Count::bounded(read_b, 1),
            );
            BUS.lookup_key(
                builder,
                [p[ADDR_D + lane].into(), d],
                Count::bounded(read_d, 1),
            );
            BUS.table_entry(builder, [p[ADDR_C + lane].into(), c], p[MULT_C + lane]);
        }
        for group in 0..EXT_LANES {
            let a: [AB::Expr; 3] = core::array::from_fn(|i| m[a_column(group * 3 + i)].into());
            let b: [AB::Expr; 3] = core::array::from_fn(|i| m[b_column(group * 3 + i)].into());
            let c: [AB::Expr; 3] = core::array::from_fn(|i| m[c_column(group * 3 + i)].into());
            let product = cubic_product(a.clone(), b);
            let inverse_product = cubic_product(a, c.clone());
            let mul: AB::Expr = p[EXT_MUL + group].into();
            let inv: AB::Expr = p[EXT_INV + group].into();
            for i in 0..3 {
                let unit = if i == 0 {
                    AB::Expr::ONE
                } else {
                    AB::Expr::ZERO
                };
                builder.assert_zero(
                    mul.clone() * (product[i].clone() - c[i].clone())
                        + inv.clone() * (inverse_product[i].clone() - unit),
                );
            }
        }
        for i in 0..self.program.publics {
            let value: AB::Expr = builder.public_values()[i].into();
            BUS.table_entry(
                builder,
                [AB::Expr::from_usize(i + 1), value],
                p[ADDR_A + i % PUBLICS_PER_ROW]
                    * if i < PUBLICS_PER_ROW {
                        bank_zero.clone()
                    } else {
                        bank_one.clone()
                    },
            );
        }
        permutation(
            core::array::from_fn(|i| m[HASH_A + i].into()),
            |column, expected: AB::Expr| {
                let actual: AB::Expr = m[column].into();
                builder.assert_zero(h.clone() * (actual.clone() - expected));
                actual
            },
        );
        for &v in &m[ARITHMETIC_COLUMNS..WIDTH] {
            builder.assert_zero((AB::Expr::ONE - h.clone()) * v);
        }
    }
}

/// Multiplication modulo X^3 - X - 1, shared by cubic multiply/inverse constraints.
fn cubic_product<E: PrimeCharacteristicRing>(a: [E; 3], b: [E; 3]) -> [E; 3] {
    let t: [[E; 3]; 3] =
        core::array::from_fn(|i| core::array::from_fn(|j| a[i].clone() * b[j].clone()));
    let c3 = t[1][2].clone() + t[2][1].clone();
    [
        t[0][0].clone() + c3.clone(),
        t[0][1].clone() + t[1][0].clone() + c3 + t[2][2].clone(),
        t[0][2].clone() + t[1][1].clone() + t[2][0].clone() + t[2][2].clone(),
    ]
}

fn set_opcode(row: &mut [Val], lane: usize, code: usize) {
    for bit in 0..OPCODE_BITS {
        row[SEL + lane * OPCODE_BITS + bit] = Val::from_usize((code >> bit) & 1);
    }
}

// Hash rows have no B/D bus reads, so their first two round checkpoints share
// these scalar ports. Every shared column is constrained in each row mode.
fn hash_column(index: usize) -> usize {
    match index {
        0..=7 => HASH_B + index,
        8..=15 => HASH_D + index - 8,
        _ => HASH + index - 16,
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn row_family_column_maps_cover_the_intended_disjoint_ports() {
        let hash: Vec<_> = (HASH_A..HASH_A + 8)
            .chain(HASH_C..HASH_C + 8)
            .chain((0..78).map(hash_column))
            .collect();
        let unique: BTreeSet<_> = hash.iter().copied().collect();
        assert_eq!(hash.len(), WIDTH);
        assert_eq!(unique, (0..WIDTH).collect());
        let arithmetic: Vec<_> = (0..LANES)
            .flat_map(|lane| {
                [
                    a_column(lane),
                    b_column(lane),
                    c_column(lane),
                    d_column(lane),
                ]
            })
            .collect();
        assert_eq!(arithmetic.len(), ARITHMETIC_COLUMNS);
        assert_eq!(
            arithmetic.into_iter().collect::<BTreeSet<_>>(),
            (0..ARITHMETIC_COLUMNS).collect()
        );
        assert_eq!(PREPROCESSED_WIDTH, 8 * LANES + 2 * EXT_LANES + 2);
        assert_eq!(PUBLICS_PER_ROW, 32);
    }

    #[test]
    fn first_eight_ports_keep_the_legacy_hash_compatible_positions() {
        for lane in 0..8 {
            assert_eq!(a_column(lane), HASH_A + lane);
            assert_eq!(b_column(lane), HASH_B + lane);
            assert_eq!(c_column(lane), HASH_C + lane);
            assert_eq!(d_column(lane), HASH_D + lane);
        }
        #[cfg(feature = "block-v2-wide-lanes")]
        for (port, base) in [32, 47, 62, 77].into_iter().enumerate() {
            // A cubic operation straddles lanes 7/8; its coefficients are not
            // necessarily contiguous in the physical trace.
            assert_eq!(port_column(port, 6), port * 8 + 6);
            assert_eq!(port_column(port, 7), port * 8 + 7);
            for lane in 8..LANES {
                assert_eq!(port_column(port, lane), base + lane - 8);
            }
        }
    }

    #[test]
    fn manifest_version_and_public_banks_bind_the_selected_layout() {
        let program = ProgramBuilder::new(33).unwrap().finish(None).unwrap();
        let fields = program.manifest_fields();
        assert_eq!(
            &fields[..6],
            &[
                if cfg!(feature = "block-v2-wide-lanes") {
                    6
                } else {
                    3
                },
                33,
                0,
                8,
                33,
                2,
            ]
        );
        #[cfg(feature = "block-v2-wide-lanes")]
        assert_eq!(&fields[6..10], &[23, 7, 32, 2]);
    }

    #[test]
    fn hash_trace_and_preprocessing_keep_the_fixed_eight_port_map() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let input = core::array::from_fn(|_| b.input());
        let output = b.poseidon(input);
        let program = b.finish(Some(16)).unwrap();
        let row = program
            .rows
            .iter()
            .position(|r| matches!(r, Row::Poseidon { .. }))
            .unwrap();
        let witness = core::array::from_fn::<_, 8, _>(|i| Val::from_usize(i + 1));
        let values = program.evaluate(&[], &witness).unwrap();
        let air = MachineAir::new(program);
        let trace = air.trace(&[], &witness).unwrap();
        let pre = air.preprocessed_trace().unwrap();
        let t = &trace.values[row * WIDTH..(row + 1) * WIDTH];
        let p = &pre.values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];
        assert_eq!(&t[HASH_A..HASH_A + 8], &witness);
        assert_eq!(p[IS_HASH], Val::ONE);
        assert!(p[SEL..ADDR_A].iter().all(|v| *v == Val::ZERO));
        assert!(p[EXT_MUL..PUBLIC_BANK].iter().all(|v| *v == Val::ZERO));
        for lane in 0..LANES {
            assert_eq!(p[ADDR_B + lane], Val::ZERO);
            assert_eq!(p[ADDR_D + lane], Val::ZERO);
        }
        for i in 0..8 {
            assert_eq!(t[HASH_C + i], values[output[i].0]);
            assert_eq!(p[ADDR_A + i], Val::from_usize(input[i].0 + 1));
            assert_eq!(p[ADDR_C + i], Val::from_usize(output[i].0 + 1));
        }
        for i in 8..LANES {
            assert_eq!(p[ADDR_A + i], Val::ZERO);
            assert_eq!(p[ADDR_C + i], Val::ZERO);
            assert_eq!(p[MULT_C + i], Val::ZERO);
        }
    }
}
