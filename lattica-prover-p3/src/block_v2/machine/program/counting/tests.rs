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

#[test]
fn dynamic_workspace_requires_grants_reports_backing_and_trims_before_reuse() {
    let scope = CountingWorkspace::begin_dynamic().unwrap();
    assert!(ProgramBuilder::new_counting(1, limits()).is_err());
    assert_eq!(scope.retained_bytes().unwrap(), 0);
    scope
        .activate(limits().max_requested_program_bytes)
        .unwrap();
    assert!(scope
        .activate(limits().max_requested_program_bytes)
        .is_err());
    let mut builder = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut builder);
    assert!(scope.deactivate().is_err());
    assert!(scope.trim_idle(0).is_err());
    let mut expected = builder.finish_counts().unwrap();
    let retained = scope.deactivate().unwrap();
    assert!(retained > 0 && retained <= expected.requested_bytes_peak);
    assert_eq!(scope.retained_bytes().unwrap(), retained);
    assert!(ProgramBuilder::new_counting(1, limits()).is_err());
    let smaller = scope.trim_idle(retained / 2).unwrap();
    assert!(smaller <= retained / 2);
    assert_eq!(scope.retained_bytes().unwrap(), smaller);
    scope
        .activate(limits().max_requested_program_bytes)
        .unwrap();
    let mut builder = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut builder);
    let mut actual = builder.finish_counts().unwrap();
    expected.requested_bytes_peak = 0;
    actual.requested_bytes_peak = 0;
    assert_eq!(actual, expected);
    scope.deactivate().unwrap();
    assert_eq!(scope.trim_idle(0).unwrap(), 0);
    assert_eq!(scope.retained_bytes().unwrap(), 0);
}

#[test]
fn dynamic_workspace_never_reclaims_an_abandoned_builder_grant() {
    let scope = CountingWorkspace::begin_dynamic().unwrap();
    scope
        .activate(limits().max_requested_program_bytes)
        .unwrap();
    let mut builder = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut builder);
    drop(builder);
    assert!(scope.deactivate().is_err());
    assert!(scope.trim_idle(0).is_err());
    assert!(scope
        .activate(limits().max_requested_program_bytes)
        .is_err());
    drop(scope);
    let fixed = CountingWorkspace::begin(limits().max_requested_program_bytes).unwrap();
    assert!(fixed.activate(1).is_err());
    assert!(fixed.deactivate().is_err());
    assert!(fixed.trim_idle(0).is_err());
}

impl Counter {
    fn reference_observe(&mut self, op: &Op, allocated: usize) -> Result<(), ExecutionError> {
        let valid = |wire: Wire| wire.0 < self.defined;
        match op {
            Op::Bit { source, bit, .. } if !valid(*source) || *bit >= 64 => {
                return Err(ExecutionError::InvalidWire)
            }
            Op::SelectHint { entries, bits, .. } => {
                if bits.len() > 24
                    || entries.len() != 1usize << bits.len()
                    || entries.iter().chain(bits).any(|&w| !valid(w))
                {
                    return Err(ExecutionError::InvalidWire);
                }
                self.counts.hint_words = self
                    .counts
                    .hint_words
                    .checked_add(entries.len())
                    .and_then(|n| n.checked_add(bits.len()))
                    .ok_or(ExecutionError::TooLarge)?;
            }
            _ => {}
        }
        let reads = op.reads();
        if reads.iter().any(|&w| !valid(w)) {
            return Err(ExecutionError::InvalidWire);
        }
        // A bound on all reads also bounds every individual u32 reference
        // count. The supported row domain is much smaller than this ceiling.
        self.reads = self
            .reads
            .checked_add(reads.len() as u64)
            .filter(|&n| n <= u32::MAX as u64)
            .ok_or(ExecutionError::TooLarge)?;
        for wire in op.writes() {
            if wire.0 != self.defined || wire.0 >= allocated {
                return Err(ExecutionError::InvalidWire);
            }
            self.defined += 1;
        }
        if self.defined != allocated {
            return Err(ExecutionError::InvalidWire);
        }
        let count = match op {
            Op::Poseidon { .. } => &mut self.counts.poseidon,
            Op::CubicMul { .. } | Op::CubicInverse { .. } => &mut self.counts.cubic,
            _ => &mut self.counts.scalar,
        };
        *count = count.checked_add(1).ok_or(ExecutionError::TooLarge)?;
        Ok(())
    }
}

#[test]
fn specialized_counter_preserves_validation_and_overflow_order() {
    let w = Wire;
    let ops = [
        Op::Input {
            index: 0,
            out: w(8),
        },
        Op::Constant {
            value: Val::ONE,
            out: w(8),
        },
        Op::Bit {
            source: w(7),
            bit: 63,
            out: w(8),
        },
        Op::Bit {
            source: w(8),
            bit: 64,
            out: w(8),
        },
        Op::SelectHint {
            entries: vec![w(0), w(7)],
            bits: vec![w(1)],
            out: w(8),
        },
        Op::Add {
            a: w(7),
            b: w(0),
            out: w(8),
        },
        Op::Mul {
            a: w(8),
            b: w(0),
            out: w(9),
        },
        Op::Equal { a: w(7), b: w(0) },
        Op::Boolean { a: w(8) },
        Op::Inverse { a: w(0), out: w(8) },
        Op::Select {
            bit: w(0),
            a: w(1),
            b: w(7),
            out: w(8),
        },
        Op::CubicMul {
            a: [w(0); 3],
            b: [w(7); 3],
            out: [w(8), w(9), w(10)],
        },
        Op::CubicInverse {
            a: [w(0); 3],
            out: [w(8), w(10), w(9)],
        },
        Op::Poseidon {
            input: [0; 8],
            output: core::array::from_fn(|i| 8 + i as u32),
        },
    ];
    for op in ops {
        for allocated in 7..18 {
            for reads in [0, u32::MAX as u64 - 2] {
                let mut old = Counter::new(8);
                let mut new = Counter::new(8);
                old.reads = reads;
                new.reads = reads;
                assert_eq!(
                    new.observe(&op, allocated),
                    old.reference_observe(&op, allocated)
                );
                assert_eq!(
                    (new.defined, new.reads, new.counts),
                    (old.defined, old.reads, old.counts)
                );
            }
        }
    }
}
#[test]
fn cleared_backing_moves_between_threads_under_new_admission() {
    let backing = std::thread::spawn(|| {
        let workspace = CountingWorkspace::begin_dynamic().unwrap();
        workspace
            .activate(limits().max_requested_program_bytes)
            .unwrap();
        let mut b = ProgramBuilder::new_counting(1, limits()).unwrap();
        emit(&mut b);
        b.finish_counts().unwrap();
        assert!(workspace.take_backing().is_err());
        let bytes = workspace.deactivate().unwrap();
        let backing = workspace.take_backing().unwrap().unwrap();
        assert_eq!(backing.retained_bytes().unwrap(), bytes);
        assert_eq!(workspace.retained_bytes().unwrap(), 0);
        backing
    })
    .join()
    .unwrap();
    let workspace = CountingWorkspace::begin_dynamic().unwrap();
    workspace.restore_backing(backing).unwrap();
    assert!(ProgramBuilder::new_counting(1, limits()).is_err());
    workspace
        .activate(limits().max_requested_program_bytes)
        .unwrap();
    let mut b = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut b);
    let got = b.finish_counts().unwrap();
    workspace.deactivate().unwrap();
    assert_eq!(workspace.reuses(), 1);
    drop(workspace);
    let mut b = ProgramBuilder::new_counting(1, limits()).unwrap();
    emit(&mut b);
    let expected = b.finish_counts().unwrap();
    assert_eq!(
        (got.scalar, got.cubic, got.poseidon, got.wires),
        (
            expected.scalar,
            expected.cubic,
            expected.poseidon,
            expected.wires
        )
    );
}
