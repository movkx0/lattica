use super::super::{
    ExecutionError, Op, Program, ProgramBuilder, Row, Val, Wire, EXT_LANES, LANES,
    MAX_PUBLIC_VALUES, PUBLICS_PER_ROW,
};
use crate::block_v2::{machine::MachineAir, profile::Challenge};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_symmetric::Permutation;

fn compare(
    program: &Program,
    public: &[Val],
    witness: &[Val],
    expected: Result<(), ExecutionError>,
) {
    assert_eq!(program.check_host_constraints(public, witness), expected);
    let air = MachineAir::new(program.clone());
    assert_eq!(air.trace(public, witness).map(drop), expected);
}

fn all_operations(publics: usize) -> (Program, Vec<Val>, Vec<Val>) {
    let mut builder = ProgramBuilder::new(publics).unwrap();
    let values = [3, 5, 1, 7, 11, 13, 17, 19].map(Val::from_u64);
    let input: [Wire; 8] = core::array::from_fn(|_| builder.input());
    let mut witness = values.to_vec();
    let public = (0..publics).map(|i| values[i % 8]).collect::<Vec<_>>();
    for i in 0..publics {
        let wire = builder.public(i).unwrap();
        builder.assert_equal(wire, input[i % 8]);
    }
    let one = builder.constant(Val::ONE);
    let zero = builder.constant(Val::ZERO);
    let sum = builder.add(input[0], input[1]);
    let eight = builder.constant(Val::from_u64(8));
    builder.assert_equal(sum, eight);
    let product = builder.mul(input[0], input[1]);
    let fifteen = builder.constant(Val::from_u64(15));
    builder.assert_equal(product, fifteen);
    builder.assert_bool(input[2]);
    let inverse = builder.inverse(input[0]);
    let identity = builder.mul(input[0], inverse);
    builder.assert_equal(identity, one);
    let selected = builder.select(input[2], input[0], input[1]);
    builder.assert_equal(selected, input[1]);
    let bit = builder.bit_hint(input[3], 2);
    builder.assert_equal(bit, one);
    let hinted = builder.select_hint(vec![input[0], input[1]], &[input[2]]);
    builder.assert_equal(hinted, selected);
    let a = [input[0], input[1], input[2]];
    let b = [input[3], input[4], input[5]];
    let result = builder.cubic_mul(a, b);
    let a_value = Challenge::from_basis_coefficients_slice(&values[..3]).unwrap();
    let b_value = Challenge::from_basis_coefficients_slice(&values[3..6]).unwrap();
    for (&wire, &value) in result
        .iter()
        .zip((a_value * b_value).as_basis_coefficients_slice())
    {
        let expected = builder.constant(value);
        builder.assert_equal(wire, expected);
    }
    let inverse = builder.cubic_inverse(a);
    let identity = builder.cubic_mul(a, inverse);
    for (i, &wire) in identity.iter().enumerate() {
        builder.assert_equal(wire, if i == 0 { one } else { zero });
    }
    let output = builder.poseidon(input);
    let mut expected = values;
    default_goldilocks_poseidon2_8().permute_mut(&mut expected);
    for (&wire, value) in output.iter().zip(expected) {
        let expected = builder.constant(value);
        builder.assert_equal(wire, expected);
    }
    // Distinct unknown inputs prevent interning or constant folding from
    // removing a full cubic row plus a partial row in either machine layout.
    for _ in 0..EXT_LANES + 2 {
        let more = core::array::from_fn(|_| builder.input());
        witness.extend_from_slice(&values[..3]);
        builder.cubic_mul(a, more);
    }
    (builder.finish(None).unwrap(), public, witness)
}

fn operation_kind(op: &Op) -> usize {
    match op {
        Op::Input { .. } => 0,
        Op::Bit { .. } => 1,
        Op::SelectHint { .. } => 2,
        Op::Constant { .. } => 3,
        Op::Add { .. } => 4,
        Op::Mul { .. } => 5,
        Op::Equal { .. } => 6,
        Op::Boolean { .. } => 7,
        Op::Inverse { .. } => 8,
        Op::Select { .. } => 9,
        Op::CubicMul { .. } => 10,
        Op::CubicInverse { .. } => 11,
        Op::Poseidon { .. } => 12,
    }
}

/// Check the finalization invariants that make trace serialization infallible
/// after successful operation evaluation. No malformed private Program is
/// treated as admitted input to the public diagnostic.
fn check_row_invariants(program: &Program) {
    assert!(program.height().is_power_of_two());
    assert!(program.active_rows() <= program.height());
    let mut seen = vec![false; program.operations.len()];
    let mut public_rows = 0;
    let mut record = |index: u32| {
        let index = index as usize;
        assert!(index < seen.len() && !seen[index]);
        seen[index] = true;
    };
    for row in &program.rows {
        match row {
            Row::Public(bank) => {
                assert_eq!(*bank, public_rows);
                public_rows += 1;
            }
            Row::Alu(indices) => {
                assert!(!indices.is_empty() && indices.len() <= LANES);
                for &index in indices {
                    record(index);
                    assert!(!matches!(
                        program.operations[index as usize],
                        Op::CubicMul { .. } | Op::CubicInverse { .. } | Op::Poseidon { .. }
                    ));
                }
            }
            Row::Cubic(indices) => {
                assert!(!indices.is_empty() && indices.len() <= EXT_LANES);
                for &index in indices {
                    record(index);
                    assert!(matches!(
                        program.operations[index as usize],
                        Op::CubicMul { .. } | Op::CubicInverse { .. }
                    ));
                }
            }
            Row::Poseidon(index) => {
                record(*index);
                assert!(matches!(
                    program.operations[*index as usize],
                    Op::Poseidon { .. }
                ));
            }
        }
    }
    assert_eq!(
        public_rows,
        program.public_values().div_ceil(PUBLICS_PER_ROW)
    );
    assert!(seen.into_iter().all(|value| value));
    for op in &program.operations {
        assert!(op
            .reads()
            .into_iter()
            .chain(op.writes())
            .all(|wire| wire.0 < program.wire_count()));
    }
}

#[test]
fn every_operation_and_valid_packing_padding_shape_matches_trace_acceptance() {
    for publics in [
        0,
        1,
        PUBLICS_PER_ROW,
        PUBLICS_PER_ROW + 1,
        MAX_PUBLIC_VALUES,
    ] {
        let (program, public, witness) = all_operations(publics);
        let mut covered = [false; 13];
        for op in &program.operations {
            covered[operation_kind(op)] = true;
        }
        assert!(covered.into_iter().all(|present| present));
        check_row_invariants(&program);
        compare(&program, &public, &witness, Ok(()));
        let height = program.height();
        let padded = program.pad_to(height * 2).unwrap();
        check_row_invariants(&padded);
        compare(&padded, &public, &witness, Ok(()));
    }
}

#[test]
fn empty_and_public_only_programs_match_without_special_acceptance_paths() {
    for publics in [0, 1, MAX_PUBLIC_VALUES] {
        let program = ProgramBuilder::new(publics)
            .unwrap()
            .finish(Some(16))
            .unwrap();
        let public = vec![Val::from_u64(9); publics];
        check_row_invariants(&program);
        compare(&program, &public, &[], Ok(()));
    }
}

#[test]
fn input_count_errors_and_their_priority_match_the_trace_path() {
    let (program, public, witness) = all_operations(4);
    compare(
        &program,
        &public[..3],
        &witness,
        Err(ExecutionError::PublicInputCount),
    );
    compare(
        &program,
        &public,
        &witness[..witness.len() - 1],
        Err(ExecutionError::WitnessCount),
    );
    compare(&program, &[], &[], Err(ExecutionError::PublicInputCount));
    let mut longer = witness.clone();
    longer.push(Val::ZERO);
    compare(
        &program,
        &public,
        &longer,
        Err(ExecutionError::WitnessCount),
    );
    compare(&program, &public, &witness, Ok(()));
}

#[test]
fn every_unsatisfied_operation_rejects_identically_and_failure_does_not_mutate_owner() {
    for case in 0..6 {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let x: [Wire; 3] = core::array::from_fn(|_| builder.input());
        let (valid, invalid) = match case {
            0 => {
                builder.assert_equal(x[0], x[1]);
                ([1, 1, 0], [1, 2, 0])
            }
            1 => {
                builder.assert_bool(x[0]);
                ([1, 0, 0], [2, 0, 0])
            }
            2 => {
                builder.inverse(x[0]);
                ([1, 0, 0], [0, 0, 0])
            }
            3 => {
                builder.select(x[0], x[1], x[2]);
                ([1, 7, 9], [2, 7, 9])
            }
            4 => {
                builder.select_hint(vec![x[1], x[2]], &[x[0]]);
                ([1, 7, 9], [2, 7, 9])
            }
            _ => {
                builder.cubic_inverse(x);
                ([1, 0, 0], [0, 0, 0])
            }
        };
        let program = builder.finish(None).unwrap();
        compare(&program, &[], &valid.map(Val::from_u64), Ok(()));
        compare(
            &program,
            &[],
            &invalid.map(Val::from_u64),
            Err(ExecutionError::Unsatisfied),
        );
        compare(&program, &[], &valid.map(Val::from_u64), Ok(()));
    }
}

#[test]
fn malformed_wire_hint_or_padding_is_refused_before_a_finalized_owner_exists() {
    let mut builder = ProgramBuilder::new(0).unwrap();
    let input = builder.input();
    builder.add(input, Wire(usize::MAX));
    assert_eq!(
        builder.finish(None).unwrap_err(),
        ExecutionError::InvalidWire
    );

    let mut builder = ProgramBuilder::new(0).unwrap();
    let input = builder.input();
    builder.bit_hint(input, 64);
    assert_eq!(
        builder.finish(None).unwrap_err(),
        ExecutionError::InvalidWire
    );

    let mut builder = ProgramBuilder::new(0).unwrap();
    let input = builder.input();
    builder.select_hint(vec![input], &[input]);
    assert_eq!(
        builder.finish(None).unwrap_err(),
        ExecutionError::InvalidWire
    );

    assert_eq!(
        ProgramBuilder::new(0).unwrap().finish(Some(9)).unwrap_err(),
        ExecutionError::InvalidHeight
    );
    assert_eq!(
        ProgramBuilder::new(0)
            .unwrap()
            .finish(None)
            .unwrap()
            .pad_to(7)
            .unwrap_err(),
        ExecutionError::InvalidHeight
    );
}
