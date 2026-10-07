//! Validated postfix constraints for Goldilocks / (X^3-X-1).
//! Instructions are data; the prover never generates executable shader source.
use super::*;
use crate::metal_compute::{resident::SharedWords, ProQue};
use p3_air::symbolic::{BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use std::collections::BTreeMap;

const STACK: usize = 32;
const MAX_INSTRUCTIONS: usize = 1 << 20;
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Input {
    Main(usize, usize),
    Prep(usize, usize),
    Perm(usize, usize),
    Selector(usize),
}
#[derive(Default)]
struct Program {
    code: Vec<u64>,
    inputs: BTreeMap<Input, usize>,
    width: usize,
    depth: usize,
    depths: std::collections::HashMap<(bool, usize), usize>,
    temps: std::collections::HashMap<(bool, usize), usize>,
    temporary_words: usize,
}
impl Program {
    fn base_depth<F: PrimeField64>(&mut self, e: &SymbolicExpression<F>) -> usize {
        let key = (false, e as *const _ as usize);
        if let Some(n) = self.depths.get(&key) {
            return *n;
        }
        let n = match e {
            SymbolicExpr::Leaf(_) => 1,
            SymbolicExpr::Neg { x, .. } => self.base_depth(x),
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let a = self.base_depth(x);
                let b = self.base_depth(y);
                a.max(b) + usize::from(a == b)
            }
        };
        self.depths.insert(key, n);
        n
    }
    fn ext_depth<F: PrimeField64, E: p3_field::ExtensionField<F>>(
        &mut self,
        e: &SymbolicExpressionExt<F, E>,
    ) -> usize {
        let key = (true, e as *const _ as usize);
        if let Some(n) = self.depths.get(&key) {
            return *n;
        }
        let n = match e {
            SymbolicExpr::Leaf(ExtLeaf::Base(e)) => self.base_depth(e),
            SymbolicExpr::Leaf(_) => 1,
            SymbolicExpr::Neg { x, .. } => self.ext_depth(x),
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let a = self.ext_depth(x);
                let b = self.ext_depth(y);
                a.max(b) + usize::from(a == b)
            }
        };
        self.depths.insert(key, n);
        n
    }
    fn instruction(
        &mut self,
        op: u64,
        args: [u64; 3],
        pop: usize,
        push: usize,
    ) -> Result<(), String> {
        if self.depth < pop {
            return Err("quotient instruction stack underflow".into());
        }
        self.depth = self.depth - pop + push;
        if self.depth > STACK || self.code.len() / 4 >= MAX_INSTRUCTIONS {
            return Err(format!(
                "quotient instruction capacity depth={} instructions={}",
                self.depth,
                self.code.len() / 4
            ));
        }
        self.code.extend([op, args[0], args[1], args[2]]);
        Ok(())
    }
    fn constant<F: PrimeField64, E: p3_field::ExtensionField<F>>(
        &mut self,
        e: E,
    ) -> Result<(), String> {
        let c = e.as_basis_coefficients_slice();
        self.instruction(
            0,
            [
                c[0].as_canonical_u64(),
                c[1].as_canonical_u64(),
                c[2].as_canonical_u64(),
            ],
            0,
            1,
        )
    }
    fn input(&mut self, input: Input) -> Result<(), String> {
        let ext = matches!(input, Input::Perm(..));
        let offset = *self.inputs.entry(input).or_insert_with(|| {
            let n = self.width;
            self.width += if ext { 3 } else { 1 };
            n
        });
        self.instruction(if ext { 2 } else { 1 }, [offset as u64, 0, 0], 0, 1)
    }
    fn base<F: PrimeField64>(
        &mut self,
        e: &SymbolicExpression<F>,
        public: &[F],
    ) -> Result<(), String> {
        let key = (false, e as *const _ as usize);
        if let Some(&slot) = self.temps.get(&key) {
            return self.instruction(15, [slot as u64, 1, 0], 0, 1);
        }
        match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(c) => self.instruction(0, [c.as_canonical_u64(), 0, 0], 0, 1),
                BaseLeaf::IsFirstRow => self.input(Input::Selector(0)),
                BaseLeaf::IsLastRow => self.input(Input::Selector(1)),
                BaseLeaf::IsTransition => self.input(Input::Selector(2)),
                BaseLeaf::Variable(v) => match v.entry {
                    BaseEntry::Main { offset } if offset <= 1 => {
                        self.input(Input::Main(v.index, offset))
                    }
                    BaseEntry::Preprocessed { offset } if offset <= 1 => {
                        self.input(Input::Prep(v.index, offset))
                    }
                    BaseEntry::Public => self.instruction(
                        0,
                        [
                            public
                                .get(v.index)
                                .ok_or("public column")?
                                .as_canonical_u64(),
                            0,
                            0,
                        ],
                        0,
                        1,
                    ),
                    _ => Err("unsupported quotient periodic column or row offset".into()),
                },
            },
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let reverse = self.base_depth(y) > self.base_depth(x);
                let (a, b) = if reverse { (y, x) } else { (x, y) };
                self.base(a, public)?;
                self.base(b, public)?;
                self.instruction(
                    match e {
                        SymbolicExpr::Add { .. } => 3,
                        SymbolicExpr::Sub { .. } => {
                            if reverse {
                                13
                            } else {
                                4
                            }
                        }
                        _ => 5,
                    },
                    [0; 3],
                    2,
                    1,
                )
            }
            SymbolicExpr::Neg { x, .. } => {
                self.base(x, public)?;
                self.instruction(6, [0; 3], 1, 1)
            }
        }?;
        if !matches!(e, SymbolicExpr::Leaf(_)) {
            if self.temps.len() >= 65536 {
                return Err("quotient register capacity".into());
            }
            let slot = self.temporary_words;
            self.temporary_words += 1;
            self.temps.insert(key, slot);
            self.instruction(16, [slot as u64, 1, 0], 1, 1)?;
        }
        Ok(())
    }
    fn ext<F: PrimeField64, E: p3_field::ExtensionField<F>>(
        &mut self,
        e: &SymbolicExpressionExt<F, E>,
        public: &[F],
        challenges: &[E],
        terminals: &[E],
    ) -> Result<(), String> {
        let key = (true, e as *const _ as usize);
        if let Some(&slot) = self.temps.get(&key) {
            return self.instruction(15, [slot as u64, 3, 0], 0, 1);
        }
        match e {
            SymbolicExpr::Leaf(ExtLeaf::Base(e)) => self.base(e, public),
            SymbolicExpr::Leaf(ExtLeaf::ExtConstant(e)) => self.constant(*e),
            SymbolicExpr::Leaf(ExtLeaf::ExtVariable(v)) => match v.entry {
                ExtEntry::Permutation { offset } if offset <= 1 => {
                    self.input(Input::Perm(v.index, offset))
                }
                ExtEntry::Challenge => {
                    self.constant(*challenges.get(v.index).ok_or("lookup challenge")?)
                }
                ExtEntry::PermutationValue => {
                    self.constant(*terminals.get(v.index).ok_or("lookup terminal")?)
                }
                _ => Err("unsupported permutation row offset".into()),
            },
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let reverse = self.ext_depth(y) > self.ext_depth(x);
                let (a, b) = if reverse { (y, x) } else { (x, y) };
                self.ext(a, public, challenges, terminals)?;
                self.ext(b, public, challenges, terminals)?;
                self.instruction(
                    match e {
                        SymbolicExpr::Add { .. } => 7,
                        SymbolicExpr::Sub { .. } => {
                            if reverse {
                                14
                            } else {
                                8
                            }
                        }
                        _ => 9,
                    },
                    [0; 3],
                    2,
                    1,
                )
            }
            SymbolicExpr::Neg { x, .. } => {
                self.ext(x, public, challenges, terminals)?;
                self.instruction(10, [0; 3], 1, 1)
            }
        }?;
        if !matches!(e, SymbolicExpr::Leaf(_)) {
            if self.temps.len() >= 65536 {
                return Err("quotient register capacity".into());
            }
            let slot = self.temporary_words;
            self.temporary_words += 3;
            self.temps.insert(key, slot);
            self.instruction(16, [slot as u64, 3, 0], 1, 1)?;
        }
        Ok(())
    }
    fn emit<F: PrimeField64, E: p3_field::ExtensionField<F>>(
        &mut self,
        weight: E,
        base: bool,
    ) -> Result<(), String> {
        if self.depth != 1 {
            return Err("quotient expression is not a single result".into());
        }
        let c = weight.as_basis_coefficients_slice();
        self.instruction(
            if base { 11 } else { 12 },
            [
                c[0].as_canonical_u64(),
                c[1].as_canonical_u64(),
                c[2].as_canonical_u64(),
            ],
            1,
            0,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate<SC, A, Mat>(
    _pcs: &SC::Pcs,
    air: &A,
    public: &[Val<SC>],
    layout: AirLayout,
    trace: Domain<SC>,
    domain: Domain<SC>,
    main: &Mat,
    perm: Option<&Mat>,
    lookups: &[Lookup<Val<SC>>],
    terminals: &[SC::Challenge],
    gadget: &LogUpGadget,
    challenges: &[SC::Challenge],
    prep: Option<&Mat>,
    alpha: SC::Challenge,
) -> Result<Vec<SC::Challenge>, String>
where
    SC: SGC,
    Val<SC>: PrimeField64,
    A: Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>,
    Mat: Matrix<Val<SC>> + Sync,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
{
    if Val::<SC>::ORDER_U64 != 0xffff_ffff_0000_0001
        || SC::Challenge::DIMENSION != 3
        || layout.num_periodic_columns != 0
    {
        return Err("Metal quotient requires cubic Goldilocks without periodic columns".into());
    }
    let x = SC::Challenge::from_basis_coefficients_fn(|i| {
        if i == 1 {
            Val::<SC>::ONE
        } else {
            Val::<SC>::ZERO
        }
    });
    if x * x * x != x + SC::Challenge::ONE {
        return Err("Metal quotient extension polynomial mismatch".into());
    }
    let (base, ext) = get_symbolic_constraints(air, layout, lookups, gadget);
    let cl = p3_batch_stark::symbolic::get_constraint_layout(air, layout, lookups, gadget);
    let (bw, ew) = cl.decompose_alpha(alpha);
    let mut program = Program::default();
    for (i, e) in base.iter().enumerate() {
        program.base(e, public)?;
        program.emit(
            SC::Challenge::from_basis_coefficients_fn(|j| bw[j][i]),
            true,
        )?;
    }
    for (e, w) in ext.iter().zip(ew) {
        program.ext(e, public, challenges, terminals)?;
        program.emit(w, false)?;
    }
    if program.depth != 0 || program.code.is_empty() {
        return Err("empty/incomplete quotient program".into());
    }
    let h = domain.size();
    if h == 0
        || h % trace.size() != 0
        || main.height() != h
        || prep.is_some_and(|m| m.height() != h)
        || perm.is_some_and(|m| m.height() != h)
    {
        return Err("quotient matrix geometry".into());
    }
    for input in program.inputs.keys() {
        let valid = match *input {
            Input::Main(c, _) => c < main.width(),
            Input::Prep(c, _) => prep.is_some_and(|m| c < m.width()),
            Input::Perm(c, _) => perm.is_some_and(|m| 3 * c + 2 < m.width()),
            Input::Selector(c) => c < 3,
        };
        if !valid {
            return Err("quotient instruction input outside matrix".into());
        }
    }
    let selectors = trace.selectors_on_coset(domain);
    let next = h / trace.size();
    let stride = program.width + 1;
    let rows = ((8 << 20) / 8 / stride)
        .min((128 << 20) / (program.temporary_words.max(1) * 8))
        .clamp(1, 4096)
        .min(h);
    let result = super::super::gpu_hash::engine::with_metal(|pq| {
        execute::<SC, Mat>(
            pq,
            &program,
            rows,
            h,
            stride,
            main,
            prep,
            perm,
            next,
            [
                &selectors.is_first_row,
                &selectors.is_last_row,
                &selectors.is_transition,
                &selectors.inv_vanishing,
            ],
        )
    })?;
    println!("metal_quotient rows={h} instructions={} input_columns={} base_constraints={} extension_constraints={} rows_per_tile={rows} temporary_slots={} temporary_words={} scratch_bytes={} gpu=true",program.code.len()/4,program.width,base.len(),ext.len(),program.temps.len(),program.temporary_words,rows*program.temporary_words.max(1)*8);
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn execute<SC: SGC, Mat: Matrix<Val<SC>>>(
    pq: &ProQue,
    p: &Program,
    rows: usize,
    h: usize,
    stride: usize,
    main: &Mat,
    prep: Option<&Mat>,
    perm: Option<&Mat>,
    next: usize,
    sels: [&[Val<SC>]; 4],
) -> Result<Vec<SC::Challenge>, String>
where
    Val<SC>: PrimeField64,
{
    let mut code = SharedWords::new(pq.queue(), p.code.len())?;
    code.with_cpu_mut(|dst| dst.copy_from_slice(&p.code))?;
    let mut input = SharedWords::new(pq.queue(), rows * stride)?;
    let output = SharedWords::new(pq.queue(), rows * 3)?;
    let scratch = SharedWords::new(pq.queue(), rows * p.temporary_words.max(1))?;
    let mut result = Vec::with_capacity(h);
    for start in (0..h).step_by(rows) {
        let n = rows.min(h - start);
        input.with_cpu_mut(|dst| {
            use rayon::prelude::*;
            dst[..n * stride]
                .par_chunks_mut(stride)
                .enumerate()
                .for_each(|(r, dst)| {
                    let r = start + r;
                    for (src, &offset) in &p.inputs {
                        let (mat, c, row, dim) = match *src {
                            Input::Main(c, o) => (Some(main), c, (r + o * next) % h, 1),
                            Input::Prep(c, o) => (prep, c, (r + o * next) % h, 1),
                            Input::Perm(c, o) => (perm, 3 * c, (r + o * next) % h, 3),
                            Input::Selector(c) => {
                                dst[offset] = sels[c][r].as_canonical_u64();
                                continue;
                            }
                        };
                        for j in 0..dim {
                            dst[offset + j] =
                                mat.unwrap().get(row, c + j).unwrap().as_canonical_u64();
                        }
                    }
                    dst[stride - 1] = sels[3][r].as_canonical_u64();
                });
        })?;
        let kernel = pq
            .kernel_builder("quotient_eval")
            .arg(code.buffer())
            .arg(input.buffer())
            .arg(output.buffer())
            .arg((p.code.len() / 4) as u32)
            .arg(stride as u32)
            .arg(scratch.buffer())
            .arg(n as u32)
            .global_work_size(n)
            .build()?;
        unsafe {
            kernel.cmd().enq()?;
        }
        output.with_cpu(|words| {
            for c in words[..n * 3].chunks_exact(3) {
                result.push(SC::Challenge::from_basis_coefficients_fn(|j| {
                    Val::<SC>::from_u64(c[j])
                }));
            }
        })?;
    }
    Ok(result)
}
