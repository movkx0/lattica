use super::*;
use crate::block_v2::typed_recursive::{CheckedRegistryRef, Registry as TypedRegistry};
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

fn caps<const N: usize>() -> programs::Caps<N> {
    core::array::from_fn(|key| {
        (0..1 << profile::CAP_HEIGHT)
            .map(|root| {
                core::array::from_fn(|lane| Val::from_u64((1 + 256 * key + 4 * root + lane) as u64))
            })
            .collect()
    })
}

#[test]
fn public_registry_pins_use_bounded_setup_for_every_admitted_height() {
    // The measurement includes every allocation on this one worker thread.
    // Compare against the bounded builder from this same feature configuration.
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            for log_height in 3..=21 {
                let registry = Registry {
                    height: 1 << log_height,
                    caps: caps(),
                };
                let expected = registry.id().unwrap();
                let (bounded, setup) = measure(|| registry.bounded_id());
                assert_eq!(bounded.unwrap(), expected);
                let (pin, construction) = measure(|| {
                    RegistryPin::new(&registry, expected, WrapperConstruction::SingleWallet)
                });
                let pin = pin.unwrap();
                let (checked, checking) = measure(|| pin.check(&registry));
                checked.unwrap();
                assert!(!setup.overflow && !construction.overflow && !checking.overflow);
                assert_eq!(
                    (construction.bytes, construction.calls),
                    (setup.bytes, setup.calls)
                );
                assert_eq!((checking.bytes, checking.calls), (setup.bytes, setup.calls));
                assert_eq!(pin.profile(), expected);

                let registry = TypedRegistry::<12> {
                    height: 1 << log_height,
                    caps: caps(),
                };
                let expected = registry.id().unwrap();
                let (bounded, setup) = measure(|| CheckedRegistryRef::new(&registry));
                assert_eq!(bounded.unwrap().profile(), expected);
                let (pin, construction) = measure(|| RegistryPin::new_typed(&registry, expected));
                let pin = pin.unwrap();
                let (checked, checking) = measure(|| pin.check_typed(&registry));
                checked.unwrap();
                assert!(!setup.overflow && !construction.overflow && !checking.overflow);
                assert_eq!(
                    (construction.bytes, construction.calls),
                    (setup.bytes, setup.calls)
                );
                assert_eq!((checking.bytes, checking.calls), (setup.bytes, setup.calls));
                assert_eq!(
                    pin,
                    TypedRegistryContext::new(&registry, expected)
                        .unwrap()
                        .pin()
                );
            }
        });
    eprintln!("public_registry_pin_setup heights=19 families=2 construction_and_check_requests_match_bounded_builder=true reference_identities_match=true");
}

#[test]
fn public_registry_pins_reject_spare_capacity_before_symbolic_work() {
    let mut legacy = Registry {
        height: 1024,
        caps: caps(),
    };
    let legacy_pin = RegistryPin::new(
        &legacy,
        legacy.id().unwrap(),
        WrapperConstruction::SingleWallet,
    )
    .unwrap();
    let mut typed = TypedRegistry::<12> {
        height: 1024,
        caps: caps(),
    };
    let typed_pin = RegistryPin::new_typed(&typed, typed.id().unwrap()).unwrap();
    for (cap, limit) in [
        (&mut legacy.caps[0], Registry::STORAGE_LIMIT_BYTES),
        (&mut typed.caps[0], TypedRegistry::<12>::STORAGE_LIMIT_BYTES),
    ] {
        let mut oversized = Vec::with_capacity(limit / core::mem::size_of::<[Val; 4]>());
        oversized.extend_from_slice(cap);
        *cap = oversized;
    }
    // Extra capacity changes no registry value or reference profile.
    assert_eq!(legacy.id().unwrap(), legacy_pin.profile());
    assert_eq!(
        programs::profile_id(typed.height, &typed.caps).unwrap(),
        typed_pin.profile()
    );
    for requested in [
        measure(|| {
            RegistryPin::new(&legacy, legacy_pin.profile(), legacy_pin.construction()).is_err()
        }),
        measure(|| legacy_pin.check(&legacy).is_err()),
        measure(|| RegistryPin::new_typed(&typed, typed_pin.profile()).is_err()),
        measure(|| typed_pin.check_typed(&typed).is_err()),
    ] {
        assert!(requested.0);
        assert!(
            !requested.1.overflow && requested.1.bytes <= 1024 + core::mem::size_of::<String>()
        );
    }
    eprintln!("public_registry_pin_capacity early_rejections=4 symbolic_allocations=0 storage_ceiling_bytes=65536");
}

#[test]
fn bounded_public_registry_pins_keep_shape_family_and_substitution_checks() {
    let registry = Registry {
        height: 1024,
        caps: caps(),
    };
    let pin = RegistryPin::new(
        &registry,
        registry.id().unwrap(),
        WrapperConstruction::GroupedPair,
    )
    .unwrap();
    let typed = TypedRegistry::<12> {
        height: 1024,
        caps: caps(),
    };
    let typed_pin = RegistryPin::new_typed(&typed, typed.id().unwrap()).unwrap();
    assert!(pin.check_typed(&typed).is_err());
    assert!(typed_pin.check(&registry).is_err());
    let mut wrong_family = typed_pin;
    wrong_family.construction = WrapperConstruction::SingleWallet;
    assert!(wrong_family.check_typed(&typed).is_err());

    let mut changed = registry.clone();
    changed.caps[0][0][0] += Val::ONE;
    assert!(pin.check(&changed).is_err());
    let mut changed = typed.clone();
    changed.caps[0][0][0] += Val::ONE;
    assert!(typed_pin.check_typed(&changed).is_err());
    let mut wrong = pin.profile();
    wrong[0] ^= 1;
    assert!(RegistryPin::new(&registry, wrong, pin.construction()).is_err());
    let mut wrong = typed_pin.profile();
    wrong[0] ^= 1;
    assert!(RegistryPin::new_typed(&typed, wrong).is_err());

    for height in [0, 7, 9, 1 << 22] {
        let mut legacy = registry.clone();
        legacy.height = height;
        let mut typed = typed.clone();
        typed.height = height;
        for requested in [
            measure(|| RegistryPin::new(&legacy, pin.profile(), pin.construction()).is_err()),
            measure(|| pin.check(&legacy).is_err()),
            measure(|| RegistryPin::new_typed(&typed, typed_pin.profile()).is_err()),
            measure(|| typed_pin.check_typed(&typed).is_err()),
        ] {
            assert!(requested.0);
            assert!(
                !requested.1.overflow && requested.1.bytes <= 1024 + core::mem::size_of::<String>()
            );
        }
    }
    let mut legacy = registry.clone();
    legacy.caps[0].pop();
    let mut typed = typed.clone();
    typed.caps[0].pop();
    assert!(pin.check(&legacy).is_err());
    assert!(typed_pin.check_typed(&typed).is_err());
    eprintln!("public_registry_pin_substitution family_checks=3 changed_caps=2 wrong_pins=2 invalid_heights=16 malformed_caps=2");
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh CPU proof through public node acceptance in a bounded service"]
fn fresh_public_node_acceptance_preserves_numerical_verification() {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
    let height = 1024;
    let budget = 512 << 20;
    let mut registry = Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let compiled = programs::empty(height, &registry.caps).unwrap();
    let registered = RegisteredProgram::new_with_memory_budget(
        MachineAir::new(compiled.program.pad_to(height).unwrap()),
        budget - recursive::storage::SESSION_HOST_BYTES,
    )
    .unwrap();
    registry.caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    let expected = registry.id().unwrap();
    let pin = RegistryPin::new(&registry, expected, WrapperConstruction::SingleWallet).unwrap();
    let mut session =
        recursive::ProverSession::new_with_memory_budget(registry.clone(), expected, budget)
            .unwrap();
    let proof = session.empty(recursive::DEMO_CHAIN, 0).unwrap();
    drop(session);
    registry.verify(expected, &proof, &proof.public).unwrap();
    let bytes = codec::encode_node(&proof).unwrap();
    let job = Job::empty(pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
    VerifiedNode::verify(&job, &registry, &bytes).unwrap();
    let wrong_job = Job::empty(pin, [7; 32], 0, 0).unwrap();
    assert!(VerifiedNode::verify(&wrong_job, &registry, &bytes).is_err());
    let mut changed_registry = registry.clone();
    changed_registry.caps[0][0][0] += Val::ONE;
    assert!(VerifiedNode::verify(&job, &changed_registry, &bytes).is_err());
    let mut changed = codec::decode_node(&bytes).unwrap();
    changed.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    assert!(VerifiedNode::verify(&job, &registry, &codec::encode_node(&changed).unwrap()).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(VerifiedNode::verify(&job, &registry, &trailing).is_err());
    eprintln!("public_registry_pin_fresh cpu_proofs=1 height=1024 reference_and_public_verification_pass=true context_registry_opening_and_framing_mutations_reject=true");
}
