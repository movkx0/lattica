use super::*;

fn claim(category: Category, host: u64, device: u64) -> Requirements {
    Requirements::single(category, Bytes { host, device })
}

#[test]
fn incompatible_categories_cannot_carry_compiler_maxima_into_proofs() {
    for old in Category::ALL {
        for new in Category::ALL {
            assert_eq!(same_category_support(claim(old, 1, 0), claim(new, u64::MAX, 0)), old == new);
        }
    }
    let mut compiler = claim(Category::SymbolicCompiler, 2 << 30, 0);
    compiler.add(Category::RegisteredMetadata, Bytes { host: 4096, device: 0 }).unwrap();
    let mut proof = claim(Category::RecursiveProof, 262144, 0);
    proof.add(Category::RegisteredMetadata, Bytes { host: 4096, device: 0 }).unwrap();
    assert!(!same_category_support(compiler, proof));
    assert!(!same_category_support(proof, compiler));
}

#[test]
fn host_and_device_support_are_independent_at_zero_boundaries() {
    for old in [Bytes::ZERO, Bytes { host: 1, device: 0 },
        Bytes { host: 0, device: 1 }, Bytes { host: 1, device: 1 }]
    {
        for new in [Bytes::ZERO, Bytes { host: u64::MAX, device: 0 },
            Bytes { host: 0, device: u64::MAX }, Bytes { host: 7, device: 11 }]
        {
            let expected = (old.host == 0) == (new.host == 0)
                && (old.device == 0) == (new.device == 0);
            for category in Category::ALL {
                assert_eq!(same_category_support(Requirements::single(category, old),
                    Requirements::single(category, new)), expected);
            }
        }
    }
}

#[test]
fn first_compatible_preserves_live_inputs_and_excludes_failure_slot() {
    let native = claim(Category::NativeProof, 1, 0);
    let compiler = claim(Category::SymbolicCompiler, 2 << 30, 0);
    let proof = claim(Category::RecursiveProof, 1, 0);
    let slots = [SlotSpec { requirements: proof }, SlotSpec { requirements: compiler },
        SlotSpec { requirements: proof }, SlotSpec { requirements: native },
        SlotSpec { requirements: claim(Category::RecursiveProof, 2, 0) },
        SlotSpec { requirements: claim(Category::RecursiveProof, 3, 0) }];
    // Even a caller-supplied free flag at zero never makes failure reusable.
    let mut live = [false, false, true, false, false, false];
    assert_eq!(first_compatible(&slots, &live, proof), Some(4));
    live[4] = true;
    assert_eq!(first_compatible(&slots, &live, proof), Some(5));
    live[5] = true;
    assert_eq!(first_compatible(&slots, &live, proof), None);
    assert_eq!(first_compatible(&slots, &live, compiler), Some(1));
    assert_eq!(first_compatible(&slots, &live, native), Some(3));
    assert_eq!(first_compatible(&[], &[], proof), None);
    assert_eq!(first_compatible(&slots[..1], &live[..1], proof), None);
}

#[test]
fn every_category_dimension_must_match_not_just_the_largest_one() {
    let mut old = claim(Category::SymbolicCompiler, 2 << 30, 0);
    let base = old;
    for category in Category::ALL {
        if category == Category::SymbolicCompiler { continue; }
        old.add(category, Bytes { host: 1, device: 0 }).unwrap();
        assert!(!same_category_support(base, old));
        assert!(!same_category_support(old, base));
        let mut same = old;
        same.add(category, Bytes { host: 9, device: 0 }).unwrap();
        assert!(same_category_support(old, same));
        old = base;
    }
}

fn compiler(metadata: u64) -> Requirements {
    let mut output = claim(Category::SymbolicCompiler, 2 << 30, 0);
    output.add(Category::CompilerInputs, Bytes { host: 8 << 20, device: 0 }).unwrap();
    output.add(Category::RegisteredMetadata, Bytes { host: metadata, device: 0 }).unwrap();
    output
}

#[test]
fn serial_compiler_shapes_reuse_one_idle_original_without_erasing_metadata() {
    let plain = compiler(0);
    let with_owner = compiler(4096);
    assert!(!same_category_support(plain, with_owner));
    assert!(compatible(plain, with_owner));
    assert!(compatible(with_owner, plain));
    let mut slots = [SlotSpec { requirements: claim(Category::Report, 1, 0) },
        SlotSpec { requirements: plain }];
    assert_eq!(first_compatible(&slots, &[false, false], with_owner), Some(1));
    slots[1].requirements = super::super::maximum(slots[1].requirements, with_owner);
    assert_eq!(first_compatible(&slots, &[false, false], plain), Some(1));
    slots[1].requirements = super::super::maximum(slots[1].requirements, plain);
    assert_eq!(slots[1].requirements, with_owner);
    assert_eq!(slots[1].requirements.get(Category::RegisteredMetadata).host, 4096);
    assert!(slots[1].requirements.total().unwrap().host
        < plain.total().unwrap().host + with_owner.total().unwrap().host);
}

#[test]
fn compiler_union_never_absorbs_other_categories_or_device_claims() {
    let plain = compiler(0);
    for category in Category::ALL {
        let mut device = compiler(4096);
        device.add(category, Bytes { host: 0, device: 1 }).unwrap();
        assert!(!compatible(plain, device));
        assert!(!compatible(device, plain));
        if matches!(category, Category::SymbolicCompiler | Category::CompilerInputs | Category::RegisteredMetadata) {
            continue;
        }
        let mut extra = compiler(4096);
        extra.add(category, Bytes { host: 1, device: 0 }).unwrap();
        assert!(!compatible(plain, extra));
        assert!(!compatible(extra, plain));
    }
    for missing in [claim(Category::SymbolicCompiler, 1, 0),
        claim(Category::CompilerInputs, 1, 0), claim(Category::RegisteredMetadata, 1, 0)] {
        assert!(!compatible(plain, missing));
        assert!(!compatible(missing, plain));
    }
}

#[test]
fn compiler_union_cannot_reuse_a_live_input_or_the_failure_slot() {
    let slots = [SlotSpec { requirements: compiler(4096) },
        SlotSpec { requirements: compiler(0) }, SlotSpec { requirements: compiler(4096) }];
    assert_eq!(first_compatible(&slots, &[false, true, false], compiler(0)), Some(2));
    assert_eq!(first_compatible(&slots, &[false, true, true], compiler(0)), None);
    assert_eq!(first_compatible(&slots[..1], &[false], compiler(0)), None);
}

#[test]
fn selection_minimizes_growth_and_keeps_stable_ties() {
    let req = |n| claim(Category::SymbolicCompiler, n, 0);
    let slots = [SlotSpec { requirements: req(100) },
        SlotSpec { requirements: req(2) }, SlotSpec { requirements: req(8) },
        SlotSpec { requirements: req(8) }];
    assert_eq!(first_compatible(&slots, &[false; 4], req(10)), Some(2));
    assert_eq!(first_compatible(&slots, &[false, false, true, false], req(10)), Some(3));
    assert_eq!(first_compatible(&slots, &[false; 4], req(1)), Some(1));
}
