use super::*;

fn assert_exact_rows(program: &Program) {
    assert_eq!(program.rows.capacity(), program.rows.len());
    for row in &program.rows {
        if let Row::Alu(ops) | Row::Cubic(ops) = row {
            assert_eq!(ops.capacity(), ops.len());
        }
    }
}

#[test]
fn empty_and_public_only_programs_keep_exact_row_storage() {
    for publics in [
        0,
        1,
        PUBLICS_PER_ROW,
        PUBLICS_PER_ROW + 1,
        MAX_PUBLIC_VALUES,
    ] {
        let program = ProgramBuilder::new(publics).unwrap().finish(None).unwrap();
        assert_eq!(program.active_rows(), publics.div_ceil(PUBLICS_PER_ROW));
        assert_eq!(program.height(), 8);
        assert_eq!(program.wire_count(), publics);
        assert_exact_rows(&program);
        for (index, row) in program.rows.iter().enumerate() {
            assert_eq!(*row, Row::Public(index));
        }
    }
}

#[test]
fn full_and_partial_rows_do_not_retain_geometric_growth_slack() {
    for count in [LANES - 1, LANES, LANES + 1, 2 * LANES, 2 * LANES + 1] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let outputs: Vec<_> = (0..count).map(|_| builder.input()).collect();
        let operations_address = builder.operations.as_ptr();
        let program = builder.finish(None).unwrap();
        assert_eq!(program.operations.as_ptr(), operations_address);
        assert_eq!(program.active_rows(), count.div_ceil(LANES));
        assert_exact_rows(&program);
        let inputs: Vec<_> = (0..count).map(|i| Val::from_usize(i + 1)).collect();
        let values = program.evaluate(&[], &inputs).unwrap();
        for (wire, expected) in outputs.iter().zip(inputs) {
            assert_eq!(values[wire.0], expected);
        }
    }
    for count in [EXT_LANES - 1, EXT_LANES, EXT_LANES + 1, 2 * EXT_LANES + 1] {
        let mut builder = ProgramBuilder::new(6).unwrap();
        let mut left = [Wire(0), Wire(1), Wire(2)];
        for _ in 0..count {
            left = builder.cubic_mul(left, [Wire(3), Wire(4), Wire(5)]);
        }
        let program = builder.finish(None).unwrap();
        assert_eq!(program.active_rows(), 1 + count.div_ceil(EXT_LANES));
        assert_exact_rows(&program);
    }
}

#[test]
fn packing_preserves_interleaved_flush_order_and_trailing_row_order() {
    let mut builder = ProgramBuilder::new(MAX_PUBLIC_VALUES).unwrap();
    builder.input();
    let input = core::array::from_fn(Wire);
    let output = builder.poseidon(input);
    let mut cubic = [Wire(0), Wire(1), Wire(2)];
    for _ in 0..EXT_LANES + 1 {
        cubic = builder.cubic_mul(cubic, [Wire(3), Wire(4), Wire(5)]);
    }
    for _ in 0..LANES {
        builder.input();
    }
    let expected_alu: Vec<_> = builder
        .operations
        .iter()
        .filter(|op| matches!(op, Op::Input { .. }))
        .cloned()
        .collect();
    let expected_cubic: Vec<_> = builder
        .operations
        .iter()
        .filter(|op| matches!(op, Op::CubicMul { .. }))
        .cloned()
        .collect();
    let program = builder.finish(None).unwrap();
    assert_eq!(
        program.rows,
        vec![
            Row::Public(0),
            Row::Public(1),
            Row::Poseidon { input, output },
            Row::Cubic(expected_cubic[..EXT_LANES].to_vec()),
            Row::Alu(expected_alu[..LANES].to_vec()),
            Row::Alu(expected_alu[LANES..].to_vec()),
            Row::Cubic(expected_cubic[EXT_LANES..].to_vec()),
        ]
    );
    assert_eq!(program.height(), 8);
    assert_exact_rows(&program);
}

#[test]
fn packing_preserves_hint_routing_and_nested_allocations() {
    let mut builder = ProgramBuilder::new(0).unwrap();
    let a = builder.input();
    let b = builder.input();
    let bit = builder.input();
    let mut entries = Vec::with_capacity(64);
    entries.extend([a, b]);
    let out = builder.select_hint(entries, &[bit]);
    let program = builder.finish(None).unwrap();
    assert_exact_rows(&program);
    for choice in 0..2 {
        let values = program
            .evaluate(
                &[],
                &[
                    Val::from_u64(17),
                    Val::from_u64(29),
                    Val::from_usize(choice),
                ],
            )
            .unwrap();
        assert_eq!(
            values[out.0],
            Val::from_u64(if choice == 0 { 17 } else { 29 })
        );
    }
    let Op::SelectHint { entries, bits, .. } = program.operations.last().unwrap() else {
        panic!()
    };
    assert_eq!(entries.capacity(), 64);
    assert_eq!(bits.len(), 1);
    let Row::Alu(ops) = program.rows.last().unwrap() else {
        panic!()
    };
    let Op::SelectHint { entries, bits, .. } = ops.last().unwrap() else {
        panic!()
    };
    assert_eq!(entries.capacity(), 2);
    assert_eq!(bits.capacity(), 1);
}

#[test]
fn packing_rejects_invalid_height_sources_and_duplicate_outputs() {
    for height in [0, 3, 4, 1 << 25] {
        assert_eq!(
            ProgramBuilder::new(0)
                .unwrap()
                .finish(Some(height))
                .unwrap_err(),
            ExecutionError::InvalidHeight
        );
    }
    let mut builder = ProgramBuilder::new(0).unwrap();
    for _ in 0..9 * LANES {
        builder.input();
    }
    assert_eq!(
        builder.finish(Some(8)).unwrap_err(),
        ExecutionError::InvalidHeight
    );
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.bit_hint(Wire(100), 0);
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
    let out = builder.input();
    builder.operations.push(Op::Input { index: 0, out });
    assert_eq!(
        builder.finish(None).unwrap_err(),
        ExecutionError::InvalidWire
    );
}
