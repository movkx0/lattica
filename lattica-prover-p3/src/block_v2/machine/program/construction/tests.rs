use super::super::{ProgramBuilder, Val};
use super::*;
use p3_field::PrimeCharacteristicRing;

fn budget(limit: usize) -> Budget {
    let mut budget = Budget::new(Constants::cpu(), 0).unwrap();
    budget.limit = Some(limit);
    budget
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Collision(u64);
impl Hash for Collision {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        0u64.hash(state);
    }
}

#[test]
fn interning_preserves_colliding_keys_and_replacements_across_growth() {
    let mut table = Map::new();
    let mut memory = budget(1 << 20);
    for i in 0..1024 {
        assert_eq!(table.insert(Collision(i), i + 7, &mut memory), None);
    }
    for i in 0..1024 {
        assert_eq!(table.get(&Collision(i)), Some(&(i + 7)));
    }
    let before = (memory.live, memory.peak, table.slots.len());
    for i in 0..1024 {
        assert_eq!(table.insert(Collision(i), i * 3, &mut memory), Some(i + 7));
        assert_eq!(table.get(&Collision(i)), Some(&(i * 3)));
    }
    assert_eq!(before, (memory.live, memory.peak, table.slots.len()));
    assert_eq!(table.get(&Collision(2048)), None);
    assert_eq!(table.entries, 1024);
    assert!(!memory.failed);
}

#[test]
fn table_growth_admits_old_and_new_slots_before_allocating() {
    let slot = size_of::<Option<(u64, u64)>>();
    for limit in [24 * slot - 1, 24 * slot] {
        let mut memory = budget(limit);
        let mut table = Map::<u64, u64>::new();
        for i in 0..7 {
            table.insert(i, i + 1, &mut memory);
        }
        assert_eq!(memory.live, 8 * slot);
        table.insert(7, 8, &mut memory);
        if limit == 24 * slot {
            assert_eq!(table.slots.len(), 16);
            assert_eq!(memory.live, 16 * slot);
            assert_eq!(memory.peak, limit);
            assert!(!memory.failed);
        } else {
            assert_eq!(table.slots.len(), 8);
            assert_eq!(memory.live, 8 * slot);
            assert_eq!(memory.peak, 8 * slot);
            assert!(memory.failed);
            assert_eq!(table.get(&7), None);
            table.insert(0, 999, &mut memory);
            assert_eq!(table.get(&0), Some(&1));
        }
        for i in 0..7 {
            assert_eq!(table.get(&i), Some(&(i + 1)));
        }
    }
}

#[test]
fn separate_tables_share_one_growth_allowance() {
    let slot = size_of::<Option<(u64, u64)>>();
    let mut memory = budget(32 * slot - 1);
    let mut first = Map::<u64, u64>::new();
    let mut second = Map::<u64, u64>::new();
    for i in 0..7 {
        first.insert(i, i, &mut memory);
        second.insert(i, i, &mut memory);
    }
    assert_eq!(memory.live, 16 * slot);
    first.insert(7, 7, &mut memory);
    assert!(memory.failed);
    assert_eq!(first.slots.len(), 8);
    assert_eq!(second.slots.len(), 8);
    assert_eq!(memory.live, 16 * slot);
    assert_eq!(memory.peak, 16 * slot);
}

#[test]
fn operation_growth_counts_both_arrays_and_does_not_append_on_rejection() {
    let op = size_of::<Op>();
    for limit in [12 * op - 1, 12 * op] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        builder.memory = budget(limit);
        for _ in 0..4 {
            builder.input();
        }
        builder.input();
        if limit == 12 * op {
            assert_eq!(builder.operations.len(), 5);
            assert_eq!(builder.memory.live, 8 * op);
            assert_eq!(builder.memory.peak, 12 * op);
            assert_eq!(builder.resource_failure(), None);
        } else {
            assert_eq!(builder.operations.len(), 4);
            assert_eq!(builder.operations.capacity(), 4);
            assert_eq!(builder.memory.live, 4 * op);
            assert_eq!(builder.memory.peak, 4 * op);
            assert_eq!(builder.finish(None).unwrap_err(), ExecutionError::TooLarge);
        }
    }
}

#[test]
fn rejection_stops_builder_operations_and_proof_input_growth() {
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.memory = budget(1);
    builder.constant(Val::ONE);
    assert_eq!(builder.resource_failure(), Some(ExecutionError::TooLarge));
    let before = (
        builder.wires,
        builder.witnesses,
        builder.memory.live,
        builder.memory.peak,
    );
    let zero = Wire(0);
    builder.input();
    builder.constant(Val::ONE);
    builder.add(zero, zero);
    builder.mul(zero, zero);
    builder.inverse(zero);
    builder.select(zero, zero, zero);
    builder.cubic_mul([zero; 3], [zero; 3]);
    builder.cubic_inverse([zero; 3]);
    builder.assert_equal(zero, Wire(1));
    builder.assert_bool(zero);
    builder.bit_hint(zero, 0);
    builder.poseidon([zero; 8]);
    builder.select_hint(vec![zero; 2], &[zero]);
    let mut inputs = super::super::super::verifier::ProofInputs::default();
    inputs.base(&mut builder, Val::ONE);
    assert!(inputs.values.is_empty());
    assert!(builder.operations.is_empty());
    assert_eq!(
        before,
        (
            builder.wires,
            builder.witnesses,
            builder.memory.live,
            builder.memory.peak
        )
    );
    assert_eq!(builder.public(0), Err(ExecutionError::TooLarge));
    assert_eq!(builder.finish(None).unwrap_err(), ExecutionError::TooLarge);
}

#[test]
fn packing_and_hint_storage_share_the_same_enforced_allowance() {
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.input();
    let needed = packing_bytes(&builder.operations, 1, 1, 1).unwrap();
    builder.memory.limit = Some(needed - 1);
    assert_eq!(builder.finish(None).unwrap_err(), ExecutionError::TooLarge);
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.input();
    builder.memory.limit = Some(needed);
    let program = builder.finish(None).unwrap();
    assert_eq!(program.evaluate(&[], &[Val::ONE]).unwrap(), vec![Val::ONE]);

    let mut builder = ProgramBuilder::new(0).unwrap();
    let before = builder.memory.live;
    builder.memory.limit = Some(16);
    builder.select_hint(Vec::with_capacity(64), &[Wire(0)]);
    assert_eq!(builder.memory.live, before);
    assert!(builder.memory.failed);
    assert!(builder.operations.is_empty());
}

#[test]
fn wire_input_and_arithmetic_overflow_limits_fail_closed() {
    for wire_limited in [true, false] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        if wire_limited {
            builder.memory.wire_limit = 1;
        } else {
            builder.memory.input_limit = 1;
        }
        let mut inputs = super::super::super::verifier::ProofInputs::default();
        inputs.base(&mut builder, Val::ONE);
        inputs.base(&mut builder, Val::ONE);
        assert_eq!(inputs.values.len(), 1);
        assert_eq!(builder.witnesses, 1);
        assert_eq!(builder.finish(None).unwrap_err(), ExecutionError::TooLarge);
    }
    let mut memory = budget(usize::MAX);
    assert!(memory.reserve(usize::MAX));
    assert!(!memory.reserve(1));
    assert_eq!(memory.live, usize::MAX);
    assert_eq!(memory.peak, usize::MAX);
    assert!(memory.failed);
}

#[test]
fn hint_factory_is_not_evaluated_until_its_storage_is_admitted() {
    let calls = std::cell::Cell::new(0);
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.memory = budget(1);
    builder.select_hint_with(64, &[Wire(0); 6], |_| {
        calls.set(calls.get() + 1);
        Wire(0)
    });
    assert_eq!(calls.get(), 0);
    assert_eq!(builder.memory.live, 0);
    assert_eq!(builder.finish(None).unwrap_err(), ExecutionError::TooLarge);

    let mut builder = ProgramBuilder::new(0).unwrap();
    let first = builder.input();
    let second = builder.input();
    let bit = builder.bit_hint(second, 0);
    builder.select_hint_with(2, &[bit], |index| {
        calls.set(calls.get() + 1);
        [second, first][index]
    });
    assert_eq!(calls.get(), 2);
    let program = builder.finish(None).unwrap();
    let values = program.evaluate(&[], &[Val::TWO, Val::ONE]).unwrap();
    assert_eq!(values.last(), Some(&Val::TWO));
}

#[test]
fn merkle_scratch_shares_operation_growth_allowance_and_releases_on_failure() {
    let source = [[Wire(0); 4]; 8];
    let scratch = core::mem::size_of_val(&source);
    let op = size_of::<Op>();
    for limit in [12 * op + scratch - 1, 12 * op + scratch] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        builder.input();
        builder.memory.limit = Some(limit);
        let result = builder.with_digest_scratch(&source, |b, entries| {
            assert_eq!(entries, &source);
            for _ in 0..4 {
                b.input();
            }
            Ok(())
        });
        if limit == 12 * op + scratch {
            assert_eq!(result, Ok(()));
            assert_eq!(builder.memory.peak, limit);
            assert_eq!(builder.memory.live, 8 * op);
        } else {
            assert_eq!(result, Err(ExecutionError::TooLarge));
            assert_eq!(builder.operations.len(), 4);
            assert_eq!(builder.memory.live, 4 * op);
            assert!(builder.memory.failed);
        }
    }
}

#[test]
fn merkle_scratch_rejects_before_body_and_drops_storage_on_ordinary_error() {
    let source = [[Wire(0); 4]; 8];
    let mut builder = ProgramBuilder::new(0).unwrap();
    builder.memory = budget(core::mem::size_of_val(&source) - 1);
    assert_eq!(
        builder.with_digest_scratch(&source, |_, _| -> Result<(), ExecutionError> {
            panic!("body must not run without admitted storage")
        }),
        Err(ExecutionError::TooLarge)
    );
    assert_eq!(builder.memory.live, 0);
    let mut builder = ProgramBuilder::new(0).unwrap();
    let result: Result<(), _> =
        builder.with_digest_scratch(&source, |_, _| Err(ExecutionError::InvalidWire));
    assert_eq!(result, Err(ExecutionError::InvalidWire));
    assert_eq!(builder.memory.live, 0);
    assert!(!builder.memory.failed);
}

#[test]
fn construction_requirement_survives_clone_and_padding_without_changing_identity() {
    let build = |limit| {
        let mut builder = ProgramBuilder::new(0).unwrap();
        builder.memory.limit = limit;
        builder.with_digest_scratch(&[[Wire(0); 4]; 128], |_, _| Ok(()))?;
        builder.finish(None)
    };
    let program = build(None).unwrap();
    let required = program.construction_host_bytes();
    assert_eq!(required, 128 * size_of::<[Wire; 4]>());
    assert_eq!(build(Some(required)).unwrap(), program);
    assert_eq!(build(Some(required - 1)), Err(ExecutionError::TooLarge));
    let reference = ProgramBuilder::new(0).unwrap().finish(None).unwrap();
    assert!(reference.construction_host_bytes() < required);
    assert_eq!(program, reference);
    assert_eq!(program.manifest_fields(), reference.manifest_fields());
    let padded = program.clone().pad_to(256).unwrap();
    assert_eq!(padded.construction_host_bytes(), required);
    assert_eq!(padded, reference.pad_to(256).unwrap());
}
