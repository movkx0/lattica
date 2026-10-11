use super::super::{
    expression::{Base, Extension},
    Builder, Constants, Val,
};
use super::*;
use p3_air::{
    symbolic::{AirLayout, SymbolicExpr},
    AirBuilder, PermutationAirBuilder, WindowAccess,
};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};

fn state() -> State {
    STATE.with(|s| s.borrow().unwrap())
}
fn base_node_bytes() -> usize {
    size_of::<super::super::BaseExpr>() + 4 * size_of::<usize>()
}

#[test]
fn exact_vectors_strings_and_shared_headers_are_admitted_before_allocation() {
    let wrapper = size_of::<Vec<u64>>() + 4 * size_of::<usize>();
    scoped(16 + 3 + wrapper, false, || {
        let values = vector(2, |i| i as u64)?;
        assert_eq!(values.capacity(), 2);
        assert_eq!(string("bus")?, "bus");
        assert_eq!(&**shared(values)?, &[0, 1]);
        assert_eq!(state().bytes, 16 + 3 + wrapper);
        assert_eq!(state().allocations, 3);
        Ok(())
    })
    .unwrap();
    let mut calls = 0;
    assert!(scoped(15, false, || vector(2, |_| {
        calls += 1;
        0u64
    }))
    .is_err());
    assert_eq!(calls, 0);
    assert!(scoped(2, false, || string("bus")).is_err());
    assert!(scoped(wrapper - 1, false, || shared(Vec::<u64>::new())).is_err());
    assert!(scoped(HOST_BYTES, false, || vector(MAX_NODES + 1, |_| {
        calls += 1;
        0u64
    }))
    .is_err());
    assert_eq!(calls, 0);
}

#[test]
fn vector_growth_counts_old_and_new_arrays_and_failure_is_sticky() {
    assert!(scoped(12 * size_of::<u64>(), false, || {
        let mut values = Vec::new();
        for i in 0..8 {
            push(&mut values, i as u64)?;
        }
        assert_eq!(values, (0..8).collect::<Vec<_>>());
        assert_eq!(values.capacity(), 8);
        assert_eq!(state().bytes, (4 + 8) * size_of::<u64>());
        assert_eq!(state().allocations, 2);
        let pointer = values.as_ptr();
        assert!(push(&mut values, 8).is_err());
        assert_eq!(values.as_ptr(), pointer);
        assert_eq!(values.len(), 8);
        drop(values);
        assert!(vector::<u64>(0, |_| unreachable!()).is_err());
        assert!(string("").is_err());
        assert_eq!(state().bytes, 12 * size_of::<u64>());
        Ok(()) // The scope must still reject an ignored allocation error.
    })
    .is_err());
}

#[test]
fn discarded_expression_nodes_keep_their_cumulative_admission() {
    let bytes = base_node_bytes();
    assert!(scoped(4 * bytes, false, || {
        let first = Base::ONE + Base::ONE;
        let alias = first.clone();
        assert_eq!(state().arc_nodes, 2);
        drop((first, alias));
        drop(Base::ONE * Base::TWO);
        assert_eq!(state().arc_nodes, 4);
        let rejected = -Base::ONE;
        assert!(matches!(rejected.0, SymbolicExpr::Leaf(_)));
        assert_eq!(state().arc_nodes, 4);
        assert_eq!(state().bytes, 4 * bytes);
        drop(Base::ONE - Base::ONE);
        assert_eq!(state().arc_nodes, 4);
        Ok(())
    })
    .is_err());
}

#[test]
fn depth_rejects_before_allocating_children_and_counts_lifted_base_leaves() {
    for lift in [false, true] {
        assert!(scoped(HOST_BYTES, false, || {
            let mut e = Base::ONE;
            for _ in 0..MAX_DEPTH {
                e = -e;
            }
            assert_eq!(e.1, MAX_DEPTH);
            assert_eq!(state().arc_nodes, MAX_DEPTH);
            let bytes = state().bytes;
            if lift {
                let rejected = Extension::from(e);
                assert_eq!(rejected.1, 1);
            } else {
                let rejected = e + Base::ONE;
                assert_eq!(rejected.1, 0);
            }
            assert_eq!(state().arc_nodes, MAX_DEPTH);
            assert_eq!(state().bytes, bytes);
            assert_eq!(state().depth, MAX_DEPTH + 1);
            Ok(())
        })
        .is_err());
    }
    assert!(scoped(HOST_BYTES, false, || {
        assert_eq!(Extension::from(Val::ONE).1, 1);
        assert_eq!(Extension::from(super::super::Challenge::ONE).1, 0);
        let mut e = Extension::ONE;
        for _ in 1..MAX_DEPTH {
            e = -e;
        }
        assert_eq!(e.1, MAX_DEPTH);
        assert_eq!(state().arc_nodes, MAX_DEPTH - 1);
        drop(-e);
        assert_eq!(state().arc_nodes, MAX_DEPTH - 1);
        Ok(())
    })
    .is_err());
}

#[test]
fn shared_windows_preserve_both_rows_without_clone_allocations() {
    scoped(HOST_BYTES, false, || {
        let builder = Builder::new(AirLayout {
            main_width: 3,
            preprocessed_width: 2,
            permutation_width: 4,
            num_public_values: 1,
            num_periodic_columns: 1,
            num_permutation_challenges: 2,
            num_permutation_values: 1,
        })?;
        let before = state();
        let a = builder.main();
        let b = builder.main();
        assert_eq!(a.current_slice().len(), 3);
        assert_eq!(a.next_slice().len(), 3);
        assert_eq!(a.current_slice().as_ptr(), b.current_slice().as_ptr());
        assert_eq!(a.next_slice().as_ptr(), b.next_slice().as_ptr());
        assert_eq!(
            a.next_slice().as_ptr(),
            a.current_slice().as_ptr().wrapping_add(3)
        );
        let p = builder.permutation();
        assert_eq!(p.next_slice().len(), 4);
        assert_eq!(
            p.current_slice().as_ptr(),
            builder.permutation().current_slice().as_ptr()
        );
        assert_eq!(builder.preprocessed().next_slice().len(), 2);
        assert_eq!(state().bytes, before.bytes);
        assert_eq!(state().allocations, before.allocations);
        drop(builder);
        assert_eq!(a.current_slice().len(), 3);
        let empty = Builder::new(AirLayout::default())?;
        assert!(empty.main().current_slice().is_empty());
        assert!(empty.main().next_slice().is_empty());
        Ok(())
    })
    .unwrap();
}

#[test]
fn layout_overflow_and_oversized_bus_stop_recording() {
    assert!(scoped(HOST_BYTES, false, || Builder::new(AirLayout {
        main_width: usize::MAX,
        ..AirLayout::default()
    }))
    .is_err());
    let bus = "x".repeat(MAX_NODES + 1);
    let mut calls = 0;
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    builder.push_interaction(
        &bus,
        std::iter::from_fn(|| {
            calls += 1;
            Some(Base::ONE)
        }),
        Count::bounded(Base::ONE, 1),
    );
    assert_eq!(calls, 0);
    assert!(builder.check().is_err());
    assert!(super::super::finish(&builder, Constants::cpu()).is_err());
    assert!(builder.global.is_empty());
    // The persistent builder failure also works outside a recording scope.
    builder.assert_zero(Base::ONE);
    assert!(builder.base.is_empty());
}

#[test]
fn local_interactions_admit_output_independently_of_input_capacity() {
    scoped(HOST_BYTES, false, || {
        let mut builder = Builder::new(AirLayout::default())?;
        let before = state().bytes;
        let mut fields = Vec::with_capacity(1024);
        fields.push(Base::ONE);
        builder.push_local_interaction([(fields, Base::TWO)]);
        builder.check()?;
        let output = &builder.local[0].tuples[0].0;
        assert_eq!(output.len(), 1);
        assert_eq!(output.capacity(), 1);
        assert_eq!(
            state().bytes - before,
            size_of::<super::super::BaseExpr>()
                + 4 * size_of::<(Vec<super::super::BaseExpr>, super::super::BaseExpr)>()
                + 4 * size_of::<p3_lookup::SymbolicLocalInteraction<Val>>()
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn scopes_restore_on_success_error_unwind_and_reject_nesting() {
    scoped(8, false, || vector(1, |_| 7u64)).unwrap();
    assert!(STATE.with(|s| s.borrow().is_none()));
    assert!(scoped::<()>(8, false, || Err(error())).is_err());
    assert!(STATE.with(|s| s.borrow().is_none()));
    let result = std::panic::catch_unwind(|| {
        let _ = scoped::<()>(8, false, || {
            let _ = vector(1, |_| 7u64)?;
            panic!("injected AIR unwind")
        });
    });
    assert!(result.is_err());
    assert!(STATE.with(|s| s.borrow().is_none()));
    assert!(scoped(8, false, || {
        let _ = vector(1, |_| 7u64)?;
        assert!(scoped(1024, false, || Ok(())).is_err());
        assert_eq!(state().limit, 8);
        assert_eq!(state().bytes, 8);
        Ok(())
    })
    .is_err());
    assert!(STATE.with(|s| s.borrow().is_none()));
    scoped(8, false, || vector(1, |_| 7u64)).unwrap();
}

#[test]
fn recording_scopes_are_thread_local() {
    scoped(8, false, || {
        let child = std::thread::spawn(|| scoped(0, false, || vector(1, |_| 0u64)));
        assert!(child.join().unwrap().is_err());
        assert_eq!(state().bytes, 0);
        assert!(!state().failed);
        let _ = vector(1, |_| 1u64)?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn builder_rejects_partial_root_growth_before_normalization() {
    let initialization = 3 * (size_of::<Vec<u64>>() + 4 * size_of::<usize>());
    assert!(scoped(initialization + 4 * size_of::<usize>(), false, || {
        let mut builder = Builder::new(AirLayout::default())?;
        builder.assert_zero(Base::ONE);
        assert_eq!(builder.order.base_indices.len(), 1);
        assert!(builder.base.is_empty());
        assert!(super::super::finish(&builder, Constants::cpu()).is_err());
        let bytes = state().bytes;
        builder.assert_zero(Base::ONE);
        assert_eq!(state().bytes, bytes);
        Ok(())
    })
    .is_err());
}
