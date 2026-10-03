//! Read-only attribution of an already compiled program, never proof validation.
//!
//! Counts describe the current unified trace layout. Unassigned cells are not
//! automatically removable: specialization changes the AIR/lookup construction,
//! registered keys, recursive closure, and its privacy/composition obligations.
//! No witness is read and no trace, preprocessing, LDE, or key is allocated here.

use super::program::{Op, Program, Row, EXT_LANES, LANES, PUBLICS_PER_ROW};
use super::WIDTH;

pub const OPERATION_NAMES: [&str; 13] = [
    "input",
    "bit_hint",
    "select_hint",
    "constant",
    "add",
    "multiply",
    "equal",
    "boolean",
    "inverse",
    "select",
    "cubic_multiply",
    "cubic_inverse",
    "poseidon",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowCounts {
    pub public: u64,
    pub alu: u64,
    pub cubic: u64,
    pub poseidon: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramUsage {
    pub height: u64,
    pub active_rows: u64,
    pub padding_rows: u64,
    pub rows: RowCounts,
    pub operations: [u64; 13],
    pub total_operations: u64,
    pub authenticated_reads: u64,
    pub wires: u64,
    pub public_unused_slots: u64,
    pub alu_used_lanes: u64,
    pub alu_unused_lanes: u64,
    pub cubic_used_lanes: u64,
    pub cubic_unused_lanes: u64,
    /// Natural main trace only; not the LDE or a resident-memory measurement.
    pub main_allocated_cells: u64,
    /// Cells assigned by the native trace writer, including assignments of zero.
    pub main_assigned_cells: u64,
    pub main_unassigned_cells: u64,
    /// Occupancy arithmetic only. Recompiling smaller child proofs changes work.
    pub half_height_target: Option<u64>,
    pub rows_to_remove_for_half_height: Option<u64>,
}

type Result<T> = core::result::Result<T, &'static str>;

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("program usage overflow")
}

fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or("program usage overflow")
}

// (operation kind, assigned main cells, authenticated wire reads).
// Bit/select-hint dependencies deliberately are not SSA-bus reads: the hint is
// unconstrained until separate reconstruction/authentication operations bind it.
fn operation(op: &Op) -> (usize, u64, u64) {
    match op {
        Op::Input { .. } => (0, 1, 0),
        Op::Bit { .. } => (1, 1, 0),
        Op::SelectHint { .. } => (2, 1, 0),
        Op::Constant { .. } => (3, 1, 0),
        Op::Add { .. } => (4, 3, 2),
        Op::Mul { .. } => (5, 3, 2),
        Op::Equal { .. } => (6, 2, 2),
        Op::Boolean { .. } => (7, 1, 1),
        Op::Inverse { .. } => (8, 2, 1),
        Op::Select { .. } => (9, 4, 3),
        Op::CubicMul { .. } => (10, 9, 6),
        Op::CubicInverse { .. } => (11, 6, 3),
        Op::Poseidon { .. } => (12, WIDTH as u64, 8),
    }
}

/// Inspect compiler output without modifying it or making a feasibility claim.
pub fn analyze(program: &Program) -> Result<ProgramUsage> {
    // The current Poseidon writer assigns exactly the entire 94-column row.
    // Changing its layout requires updating this attribution, not silently
    // carrying a source-accounting claim over to a different machine.
    let expected_lanes = if cfg!(feature = "block-v2-wide-lanes") {
        23
    } else {
        8
    };
    if WIDTH != 94 || LANES != expected_lanes || EXT_LANES != LANES / 3 || PUBLICS_PER_ROW != 32 {
        return Err("program usage layout requires review");
    }
    let height = program.height() as u64;
    let active_rows = program.active_rows() as u64;
    if height < 8 || !height.is_power_of_two() || active_rows > height {
        return Err("invalid program geometry for usage accounting");
    }
    let mut operations = [0u64; 13];
    let mut reads = 0u64;
    for op in &program.operations {
        let (kind, _, count) = operation(op);
        operations[kind] = add(operations[kind], 1)?;
        reads = add(reads, count)?;
    }
    let mut rows = RowCounts::default();
    let mut packed = [0u64; 13];
    let mut assigned = 0u64;
    let mut alu_used = 0u64;
    let mut cubic_used = 0u64;
    for row in &program.rows {
        match row {
            Row::Public(_) => rows.public = add(rows.public, 1)?,
            Row::Poseidon { .. } => {
                rows.poseidon = add(rows.poseidon, 1)?;
                packed[12] = add(packed[12], 1)?;
                assigned = add(assigned, WIDTH as u64)?;
            }
            Row::Alu(ops) | Row::Cubic(ops) => {
                let cubic = matches!(row, Row::Cubic(_));
                let capacity = if cubic { EXT_LANES } else { LANES };
                if ops.is_empty() || ops.len() > capacity {
                    return Err("invalid packed row capacity");
                }
                if cubic {
                    rows.cubic = add(rows.cubic, 1)?;
                    cubic_used = add(cubic_used, ops.len() as u64)?;
                } else {
                    rows.alu = add(rows.alu, 1)?;
                    alu_used = add(alu_used, ops.len() as u64)?;
                }
                for op in ops {
                    let (kind, cells, _) = operation(op);
                    if (cubic && !(10..=11).contains(&kind)) || (!cubic && kind >= 10) {
                        return Err("wrong operation family in packed row");
                    }
                    packed[kind] = add(packed[kind], 1)?;
                    assigned = add(assigned, cells)?;
                }
            }
        }
    }
    let expected_public_rows = program.public_values().div_ceil(PUBLICS_PER_ROW) as u64;
    if packed != operations || rows.public != expected_public_rows || reads != program.total_reads()
    {
        return Err("program operation/row/reference accounting differs");
    }
    let main_allocated_cells = mul(height, WIDTH as u64)?;
    let half_height_target = (height > 8).then_some(height / 2);
    Ok(ProgramUsage {
        height,
        active_rows,
        padding_rows: height - active_rows,
        rows: rows.clone(),
        total_operations: operations.iter().try_fold(0, |a, &b| add(a, b))?,
        operations,
        authenticated_reads: reads,
        wires: program.wire_count() as u64,
        public_unused_slots: mul(rows.public, PUBLICS_PER_ROW as u64)?
            - program.public_values() as u64,
        alu_used_lanes: alu_used,
        alu_unused_lanes: mul(rows.alu, LANES as u64)? - alu_used,
        cubic_used_lanes: cubic_used,
        cubic_unused_lanes: mul(rows.cubic, EXT_LANES as u64)? - cubic_used,
        main_allocated_cells,
        main_assigned_cells: assigned,
        main_unassigned_cells: main_allocated_cells
            .checked_sub(assigned)
            .ok_or("assigned cell accounting exceeds allocation")?,
        half_height_target,
        rows_to_remove_for_half_height: half_height_target
            .map(|target| active_rows.saturating_sub(target)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::machine::{
        program::{ProgramBuilder, Val},
        MachineAir,
    };
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn empty_program_has_padding_but_no_assigned_cells() {
        let program = ProgramBuilder::new(0).unwrap().finish(None).unwrap();
        let u = analyze(&program).unwrap();
        assert_eq!((u.height, u.active_rows, u.padding_rows), (8, 0, 8));
        assert_eq!(u.main_allocated_cells, 8 * 94);
        assert_eq!(u.main_assigned_cells, 0);
        assert_eq!(u.main_unassigned_cells, u.main_allocated_cells);
        assert_eq!(u.half_height_target, None);
    }

    #[test]
    fn scalar_packing_and_hints_are_counted_separately() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let source = b.input();
        let bit = b.bit_hint(source, 0);
        b.select_hint(vec![source, source], &[bit]);
        for _ in 0..LANES - 2 {
            b.input();
        }
        let p = b.finish(None).unwrap();
        let u = analyze(&p).unwrap();
        assert_eq!(&u.operations[..3], &[(LANES - 1) as u64, 1, 1]);
        assert_eq!(
            (u.rows.alu, u.alu_used_lanes, u.alu_unused_lanes),
            (2, (LANES + 1) as u64, (LANES - 1) as u64)
        );
        assert_eq!(
            (u.authenticated_reads, u.main_assigned_cells),
            (0, (LANES + 1) as u64)
        );
    }

    #[test]
    fn public_banks_use_no_main_trace_cells() {
        let p = ProgramBuilder::new(33).unwrap().finish(None).unwrap();
        let u = analyze(&p).unwrap();
        assert_eq!((u.rows.public, u.public_unused_slots), (2, 31));
        assert_eq!(u.main_assigned_cells, 0);
    }

    #[test]
    fn cubic_rows_account_for_layout_capacity_and_distinct_inverse_cost() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let a = core::array::from_fn(|_| b.input());
        let c = core::array::from_fn(|_| b.input());
        let product = b.cubic_mul(a, c);
        b.cubic_inverse(a);
        b.cubic_mul(a, product);
        let u = analyze(&b.finish(None).unwrap()).unwrap();
        assert_eq!((u.operations[10], u.operations[11]), (2, 1));
        assert_eq!(
            (u.rows.cubic, u.cubic_used_lanes, u.cubic_unused_lanes),
            (
                3usize.div_ceil(EXT_LANES) as u64,
                3,
                (3usize.div_ceil(EXT_LANES) * EXT_LANES - 3) as u64
            )
        );
        assert_eq!(u.main_assigned_cells, 6 + 9 + 6 + 9);
        assert_eq!(u.authenticated_reads, 6 + 3 + 6);
    }

    #[test]
    fn cached_permutation_is_counted_once_and_inspection_does_not_mutate() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let input = core::array::from_fn(|_| b.input());
        assert_eq!(b.poseidon(input), b.poseidon(input));
        let p = b.finish(Some(16)).unwrap();
        let before = p.clone();
        let u = analyze(&p).unwrap();
        assert_eq!(p, before);
        assert_eq!((u.rows.poseidon, u.operations[12]), (1, 1));
        assert_eq!(u.main_assigned_cells, 8 + 94);
        assert_eq!(u.half_height_target, Some(8));
        assert_eq!(u.rows_to_remove_for_half_height, Some(0));
        // Assignment counts do not depend on whether a witness value is zero.
        p.evaluate(&[], &[Val::ZERO; 8]).unwrap();
        assert_eq!(analyze(&p).unwrap(), u);
    }

    #[test]
    fn all_scalar_opcode_assignment_costs_match_trace_writer() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let a = b.input();
        let c = b.input();
        let bit = b.input();
        let two = b.constant(Val::from_u64(2));
        b.add(a, two);
        b.mul(a, two);
        b.inverse(a);
        b.assert_equal(a, c);
        b.assert_bool(bit);
        b.select(bit, a, c);
        let program = b.finish(None).unwrap();
        let u = analyze(&program).unwrap();
        assert_eq!(&u.operations[3..10], &[1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(u.main_assigned_cells, 3 + 1 + 3 + 3 + 2 + 2 + 1 + 4);
        assert_eq!(u.authenticated_reads, 2 + 2 + 1 + 2 + 1 + 3);
        // This fixture makes every assigned scalar cell nonzero, so compare
        // attribution directly with the existing native trace writer as well.
        let trace = MachineAir::new(program)
            .trace(&[], &[Val::from_u64(3), Val::from_u64(3), Val::ONE])
            .unwrap();
        assert_eq!(
            trace
                .values
                .iter()
                .filter(|&&value| value != Val::ZERO)
                .count() as u64,
            u.main_assigned_cells
        );
    }

    #[test]
    fn bad_packing_or_reference_metadata_is_rejected() {
        let mut b = ProgramBuilder::new(0).unwrap();
        let a = b.input();
        b.assert_bool(a);
        let p = b.finish(None).unwrap();
        let mut bad = p.clone();
        bad.rows.push(Row::Alu(vec![]));
        assert_eq!(analyze(&bad), Err("invalid packed row capacity"));
        let mut bad = p.clone();
        bad.references[a.0] += 1;
        assert_eq!(
            analyze(&bad),
            Err("program operation/row/reference accounting differs")
        );
        let mut bad = p;
        bad.operations.pop();
        assert_eq!(
            analyze(&bad),
            Err("program operation/row/reference accounting differs")
        );
    }

    #[test]
    fn half_height_work_target_uses_active_rows_not_padding() {
        let mut b = ProgramBuilder::new(0).unwrap();
        for _ in 0..LANES * 8 + 1 {
            b.input();
        }
        let u = analyze(&b.finish(Some(16)).unwrap()).unwrap();
        assert_eq!((u.active_rows, u.padding_rows), (9, 7));
        assert_eq!(u.rows_to_remove_for_half_height, Some(1));
    }
}
