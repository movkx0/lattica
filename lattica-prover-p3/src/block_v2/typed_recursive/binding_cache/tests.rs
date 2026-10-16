use super::*;
use crate::proving::{Backend, Capabilities, CoverageScope, Profile, Request, Stage};

fn binding() -> Binding {
    let run = Run::new(
        "binding_receipt_test",
        Request::compatible(),
        Capabilities::cpu(Profile::BlockV2Cubic, true, false)
            .scoped(CoverageScope::RegistryCompilation, &[Stage::Preprocessing]),
    )
    .unwrap();
    run.measure(Stage::Preprocessing, Backend::Cpu, || ())
        .unwrap();
    Binding {
        key: Key {
            height: 2048,
            keys: 12,
            mode: programs::MERGE,
            profile: [7; 32],
        },
        layout: Layout::Recursive(Shape::new(2048).unwrap()),
        values: 99,
        compilation: CachedScope::registry_compilation(&run.finish(true).unwrap()).unwrap(),
    }
}

#[test]
fn cached_layout_requires_exact_registry_height_mode_and_input_count() {
    let binding = binding();
    let key = binding.key;
    binding.check_identity(key, binding.values).unwrap();
    for changed in [
        Key {
            profile: [8; 32],
            ..key
        },
        Key {
            height: 4096,
            ..key
        },
        Key { keys: 6, ..key },
        Key {
            mode: typed_pairs::FINALIZE,
            ..key
        },
    ] {
        assert!(binding.check_identity(changed, binding.values).is_err());
    }
    assert!(binding.check_identity(key, binding.values + 1).is_err());
    assert!(
        binding.compilation.retained_host_bytes().unwrap() <= storage::COMPILATION_RECEIPT_BYTES
    );
    assert!(Operation::Merge.mode::<4>().is_err());
    assert!(Operation::Finalize.mode::<5>().is_err());
    assert_eq!(
        Operation::Finalize.mode::<6>().unwrap(),
        typed_finalizer::FINALIZE
    );
    assert_eq!(
        Operation::Finalize.mode::<12>().unwrap(),
        typed_pairs::FINALIZE
    );
}

#[test]
fn fresh_input_budget_subtracts_publics_and_respects_each_independent_limit() {
    let count = 419094u64;
    let bytes = count * 8;
    let assignment = count + PUBLIC_VALUES as u64;
    assert_eq!(
        input_limit(bytes, Some(assignment)).unwrap(),
        bytes as usize
    );
    assert_eq!(
        input_limit(bytes - 1, Some(assignment)).unwrap(),
        bytes as usize - 1
    );
    assert_eq!(
        input_limit(bytes + 8, Some(assignment - 1)).unwrap(),
        bytes as usize - 8
    );
    assert_eq!(input_limit(0, None).unwrap(), 0);
    assert!(input_limit(bytes, Some(PUBLIC_VALUES as u64 - 1)).is_err());
    assert!(input_limit(bytes, Some(u64::MAX)).is_err());
    assert_eq!(
        input_limit(u64::MAX, None).unwrap(),
        recursive_inputs::MAX_INPUT_BYTES
    );
}

#[test]
fn layout_and_receipt_are_owned_and_dropped_together_on_eviction_and_clear() {
    use std::{cell::Cell, rc::Rc};
    struct Owned(Binding, Rc<Cell<usize>>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.1.set(self.1.get() + 1);
        }
    }
    let dropped = Rc::new(Cell::new(0));
    let mut cache = storage::Cache::<Owned, 2>::new();
    cache.push(Owned(binding(), dropped.clone())).unwrap();
    cache.push(Owned(binding(), dropped.clone())).unwrap();
    assert!(cache[0].0.compilation.retained_host_bytes().unwrap() > 0);
    drop(cache.remove(0));
    assert_eq!(dropped.get(), 1);
    cache.clear();
    assert_eq!(dropped.get(), 2);
    assert_eq!(cache.len(), 0);
}
