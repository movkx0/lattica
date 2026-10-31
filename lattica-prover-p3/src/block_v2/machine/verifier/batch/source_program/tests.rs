use super::*;
use crate::block_v2::profile;
use p3_field::PrimeCharacteristicRing;

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: 1 << 26,
        max_input_values: 1 << 20,
    }
}
fn shape() -> RegisteredChildShape {
    RegisteredChildShape {
        public_values: 4,
        height: 8,
        preprocessing_cap_roots: 1 << profile::CAP_HEIGHT,
    }
}

#[test]
fn trusted_source_shape_cap_and_complete_storage_are_checked_before_compilation() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let storage = Storage::new(shape(), limits()).unwrap();
    let cap = [[Val::ZERO; 4]; ROOTS];
    assert!(
        reconstruct_single_child(shape(), &cap, limits(), storage.required_bytes() - 1).is_err()
    );
    assert!(reconstruct_single_child(
        shape(),
        &cap[..ROOTS - 1],
        limits(),
        storage.required_bytes()
    )
    .is_err());
    for bad in [
        RegisteredChildShape {
            public_values: 5,
            ..shape()
        },
        RegisteredChildShape {
            height: 0,
            ..shape()
        },
        RegisteredChildShape {
            height: 9,
            ..shape()
        },
        RegisteredChildShape {
            preprocessing_cap_roots: ROOTS - 1,
            ..shape()
        },
    ] {
        assert!(Storage::new(bad, limits()).is_err());
    }
    // The independent reconstruction adds complete helper owners to the
    // original symbolic/template/input/program envelope, not an observed peak.
    assert!(storage.required_bytes() > storage.planning.total_requested_bytes);
}
