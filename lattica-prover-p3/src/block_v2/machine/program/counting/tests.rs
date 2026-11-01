use super::*;
use crate::block_v2::machine::verifier::batch::shape::{selection_hint_words, OperationCounts};

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 64 << 20,
        max_wires: 1 << 20,
        max_input_values: 1 << 16,
    }
}
fn emit(b: &mut ProgramBuilder) {
    let x = b.input();
    let y = b.input();
    let p = b.public(0).unwrap();
    let zero = b.constant(Val::ZERO);
    let one = b.constant(Val::ONE);
    let mut z = x;
    for _ in 0..4096 {
        z = b.add(z, y);
    }
    assert_eq!(b.add(x, zero), x);
    assert_eq!(b.mul(x, one), x);
    let product = b.mul(z, y);
    let inverse = b.inverse(product);
    let bit = b.bit_hint(x, 3);
    b.assert_bool(bit);
    b.assert_bool(bit);
    let selected = b.select(bit, x, y);
    let hint = b.select_hint_with(2, &[bit], |i| [x, y][i]);
    b.assert_equal(hint, selected);
    let cube = b.cubic_mul([x, y, p], [z, inverse, one]);
    let inverse_cube = b.cubic_inverse(cube);
    let hash = b.poseidon([x, y, z, product, inverse, inverse_cube[0], zero, one]);
    assert_eq!(
        hash,
        b.poseidon([x, y, z, product, inverse, inverse_cube[0], zero, one])
    );
    b.assert_equal(hash[0], p);
}

#[test]
fn counting_matches_full_compiler_without_retaining_instructions() {
    let mut full = ProgramBuilder::new_with_construction_limits(1, limits()).unwrap();
    let mut counting = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut full);
    emit(&mut counting);
    assert!(counting.operations.is_empty());
    let program = full.finish(None).unwrap();
    let counts = counting.finish_counts().unwrap();
    let expected = OperationCounts::from_program(&program);
    assert_eq!(
        (counts.scalar, counts.cubic, counts.poseidon),
        (expected.scalar, expected.cubic, expected.poseidon)
    );
    assert_eq!(counts.wires, program.wire_count());
    assert_eq!(counts.witnesses, program.witness_values());
    assert_eq!(counts.hint_words, selection_hint_words(&program).unwrap());
    assert_eq!(counts.active_rows, program.active_rows());
    assert_eq!(counts.padded_rows, program.height());
    assert!(counts.requested_bytes_peak < program.construction_host_bytes());
}

#[test]
fn counting_cannot_produce_programs_and_refuses_bad_dependencies_and_limits() {
    assert!(matches!(
        ProgramBuilder::new_counting(0, limits())
            .unwrap()
            .finish(None),
        Err(ExecutionError::ProvingPolicy)
    ));
    for mode in 0..4 {
        let mut b = ProgramBuilder::new_counting(1, limits()).unwrap();
        let p = b.public(0).unwrap();
        match mode {
            0 => {
                b.add(Wire(999), p);
            }
            1 => {
                b.bit_hint(p, 64);
            }
            2 => {
                b.select_hint_with(3, &[p], |_| p);
            }
            _ => {
                b.select_hint_with(2, &[p], |_| Wire(999));
            }
        }
        assert!(b.finish_counts().is_err());
    }
    let mut b = ProgramBuilder::new_counting(
        0,
        ConstructionLimits {
            max_requested_program_bytes: 1,
            ..limits()
        },
    )
    .unwrap();
    b.constant(Val::ONE);
    assert!(b.finish_counts().is_err());
}

#[test]
fn worker_workspace_clears_keys_counts_capacity_and_evicts_for_small_caps() {
    let scope = CountingWorkspace::begin(limits().max_requested_program_bytes).unwrap();
    assert!(CountingWorkspace::begin(1).is_err());
    for publics in [1, 3, 1] {
        let mut b = ProgramBuilder::new_counting(publics, limits()).unwrap();
        assert!(ProgramBuilder::new_counting(1, limits()).is_err());
        emit(&mut b);
        let counted = b.finish_counts().unwrap();
        let mut reference =
            ProgramBuilder::new_with_construction_limits(publics, limits()).unwrap();
        emit(&mut reference);
        let reference = reference.finish(None).unwrap();
        assert_eq!(counted.wires, reference.wire_count());
        assert_eq!(counted.witnesses, reference.witness_values());
        assert_eq!(
            counted.hint_words,
            selection_hint_words(&reference).unwrap()
        );
        assert_eq!(counted.active_rows, reference.active_rows());
        assert_eq!(counted.padded_rows, reference.height());
        assert_eq!((counted.scalar, counted.cubic, counted.poseidon), {
            let c = OperationCounts::from_program(&reference);
            (c.scalar, c.cubic, c.poseidon)
        });
        assert!(counted.requested_bytes_peak <= limits().max_requested_program_bytes);
    }
    assert_eq!(scope.reuses(), 2);
    let b = ProgramBuilder::new_counting(
        1,
        ConstructionLimits {
            max_requested_program_bytes: 1,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(b.memory.live, 0); // cached backing was evicted before new allocations
    assert!(b.finish_counts().is_ok());
    drop(scope);
    assert!(CountingWorkspace::begin(limits().max_requested_program_bytes).is_ok());
}

#[test]
fn abandoned_counting_builder_cannot_overallocate_or_reenter_scope() {
    let scope = CountingWorkspace::begin(limits().max_requested_program_bytes).unwrap();
    let b = ProgramBuilder::new_counting(1, limits()).unwrap();
    drop(b);
    assert!(ProgramBuilder::new_counting(1, limits()).is_err());
    drop(scope);
    let _next = CountingWorkspace::begin(limits().max_requested_program_bytes).unwrap();
    assert!(ProgramBuilder::new_counting(1, limits())
        .unwrap()
        .finish_counts()
        .is_ok());
}
