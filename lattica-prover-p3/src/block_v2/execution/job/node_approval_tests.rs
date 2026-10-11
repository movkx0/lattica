use super::*;
use crate::spill_alloc::allocation_requests::{measure, measure_all};
use p3_field::PrimeCharacteristicRing;

fn registry(height: usize) -> Registry {
    Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    }
}

#[test]
fn borrowed_legacy_approval_is_bound_and_pin_checks_reuse_it_without_setup() {
    let mut registry = registry(64);
    let pin = RegistryPin::new(
        &registry,
        registry.id().unwrap(),
        WrapperConstruction::SingleWallet,
    )
    .unwrap();
    let approved = pin.approve(&registry).unwrap();
    assert!(core::ptr::eq(approved.as_registry(), &registry));
    assert_eq!(approved.profile(), pin.profile());
    assert!(!core::mem::needs_drop::<recursive::CheckedRegistryRef<'_>>());
    let (valid, requests) = measure(|| pin.check_approved(&approved));
    valid.unwrap();
    assert!(!requests.overflow && requests.bytes == 0 && requests.calls == 0);
    let job = Job::empty(pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
    let (invalid, requests) = measure(|| VerifiedNode::verify_approved(&job, &approved, &[0]));
    assert!(invalid.is_err());
    assert!(!requests.overflow && requests.bytes <= 1048);
    for typed in [false, true] {
        let mut wrong_pin = pin;
        wrong_pin.profile[0] ^= 1;
        wrong_pin.typed = typed;
        let wrong_job = Job::empty(wrong_pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
        let (invalid, requests) =
            measure(|| VerifiedNode::verify_approved(&wrong_job, &approved, &[0]));
        assert!(invalid.is_err());
        assert!(!requests.overflow && requests.bytes <= 1048);
        let (invalid, requests) = measure(|| {
            VerifiedWallet::verify_approved(
                wrong_pin,
                &approved,
                recursive::DEMO_CHAIN,
                &[WALLET_MAGIC.as_slice(), &[0]].concat(),
            )
        });
        assert!(invalid.is_err());
        assert!(!requests.overflow && requests.bytes <= 1048);
    }
    registry.caps[0][0][0] += Val::ONE;
    assert!(pin.approve(&registry).is_err());
    eprintln!("public_proof_approval borrowed_registry=true pin_reuse_allocations=0 stale_registry_rejected=true wrong_node_and_wallet_pins_rejected=true");
}

#[test]
fn public_acceptance_rejects_wrong_families_before_identity_or_decode() {
    let legacy = registry(64);
    let typed = crate::block_v2::typed_recursive::Registry::<12> {
        height: 64,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let legacy_pin = RegistryPin::new(
        &legacy,
        legacy.id().unwrap(),
        WrapperConstruction::SingleWallet,
    )
    .unwrap();
    let typed_pin = RegistryPin::new_typed(&typed, typed.id().unwrap()).unwrap();
    let legacy_job = Job::empty(legacy_pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
    let typed_job = Job::empty(typed_pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
    for (invalid, requests) in [
        measure(|| VerifiedNode::verify(&typed_job, &legacy, &[0])),
        measure(|| VerifiedNode::verify_typed(&legacy_job, &typed, &[0])),
    ] {
        assert!(invalid.is_err());
        assert!(!requests.overflow && requests.bytes <= 1048);
    }
    let mut wrong = typed_pin;
    wrong.construction = WrapperConstruction::SingleWallet;
    let job = Job::empty(wrong, recursive::DEMO_CHAIN, 0, 0).unwrap();
    let (invalid, requests) = measure(|| VerifiedNode::verify_typed(&job, &typed, &[0]));
    assert!(invalid.is_err());
    assert!(!requests.overflow && requests.bytes <= 1048);
    eprintln!("public_proof_approval_family early_rejections=3 decoder_and_symbolic_work_not_started=true");
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh legacy node with one bounded approval and numerical mutation checks"]
fn fresh_legacy_node_acceptance_uses_one_approval() {
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
        let mut registry = registry(1024);
        let budget = 512 << 20;
        let compiled = programs::empty(registry.height, &registry.caps).unwrap();
        let registered = RegisteredProgram::new_with_memory_budget(
            MachineAir::new(compiled.program.pad_to(registry.height).unwrap()),
            budget - recursive::storage::SESSION_HOST_BYTES,
        ).unwrap();
        registry.caps[1] = registered.preprocessing_cap().roots().to_vec();
        drop(registered);
        let pin = RegistryPin::new(&registry, registry.id().unwrap(), WrapperConstruction::SingleWallet).unwrap();
        let mut session = recursive::ProverSession::new_with_memory_budget(registry.clone(), pin.profile(), budget).unwrap();
        let mut node = session.empty(recursive::DEMO_CHAIN, 0).unwrap();
        drop(session);
        let job = Job::empty(pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
        let expected = job.expected_public();
        let approved = pin.approve(&registry).unwrap();
        registry.verify(pin.profile(), &node, &expected).unwrap();
        approved.verify(&node, &expected).unwrap();
        let bytes = codec::encode_node(&node).unwrap();
        let expected_ticket = VerifiedNode::verify(&job, &registry, &bytes).unwrap();
        assert_eq!(expected_ticket, VerifiedNode::verify_approved(&job, &approved, &bytes).unwrap());
        let (_, identity) = measure_all(|| pin.approve(&registry).unwrap());
        let (direct, direct_requests) = measure_all(|| VerifiedNode::verify(&job, &registry, &bytes));
        let (reused, reused_requests) = measure_all(|| VerifiedNode::verify_approved(&job, &approved, &bytes));
        assert_eq!(direct.unwrap(), reused.unwrap());
        assert!(!identity.overflow && !direct_requests.overflow && !reused_requests.overflow);
        assert_eq!(direct_requests.bytes - reused_requests.bytes, identity.bytes);
        assert_eq!(direct_requests.calls - reused_requests.calls, identity.calls);
        let mut wrong = expected;
        wrong[programs::ROOT] += Val::ONE;
        assert!(registry.verify(pin.profile(), &node, &wrong).is_err());
        assert!(approved.verify(&node, &wrong).is_err());
        node.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
        assert!(registry.verify(pin.profile(), &node, &expected).is_err());
        assert!(approved.verify(&node, &expected).is_err());
        assert!(VerifiedNode::verify(&job, &registry, &codec::encode_node(&node).unwrap()).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(VerifiedNode::verify(&job, &registry, &trailing).is_err());
        eprintln!("public_node_approval_fresh cpu_proofs=1 identity_builds=1 reference_and_public_verification=true mutations_rejected=true identity_bytes={} identity_calls={} direct_bytes={} direct_calls={} reused_bytes={} reused_calls={}", identity.bytes, identity.calls, direct_requests.bytes, direct_requests.calls, reused_requests.bytes, reused_requests.calls);
    });
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh legacy wallet through bounded public acceptance and retained approval"]
fn fresh_legacy_wallet_acceptance_uses_one_approval() {
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        let mut wallet = recursive::demo_wallet(0).unwrap();
        recursive::verify_wallet(&wallet).unwrap();
        let registry = registry(1024);
        let pin = RegistryPin::new(&registry, registry.id().unwrap(), WrapperConstruction::SingleWallet).unwrap();
        let approved = pin.approve(&registry).unwrap();
        let encode = |wallet: &WalletProof| {
            let mut bytes = WALLET_MAGIC.to_vec();
            bytes.extend(postcard::to_allocvec(wallet).unwrap());
            bytes
        };
        let bytes = encode(&wallet);
        let reference = recursive::wallet_summary(&registry, &wallet).unwrap();
        let ticket = VerifiedWallet::verify(pin, &registry, wallet.chain, &bytes).unwrap();
        assert_eq!(ticket.summary(), reference);
        assert_eq!(approved.wallet_summary(&wallet).unwrap(), reference);
        let (_, identity) = measure_all(|| pin.approve(&registry).unwrap());
        let (direct, direct_requests) = measure_all(|| VerifiedWallet::verify(pin, &registry, wallet.chain, &bytes));
        let (reused, reused_requests) = measure_all(|| VerifiedWallet::verify_approved(pin, &approved, wallet.chain, &bytes));
        let direct = direct.unwrap();
        let reused = reused.unwrap();
        assert_eq!(direct.artifact(), reused.artifact());
        assert_eq!(direct.summary(), reused.summary());
        assert_eq!(direct.pin, reused.pin);
        assert!(!identity.overflow && !direct_requests.overflow && !reused_requests.overflow);
        assert_eq!(direct_requests.bytes - reused_requests.bytes, identity.bytes);
        assert_eq!(direct_requests.calls - reused_requests.calls, identity.calls);
        assert!(VerifiedWallet::verify(pin, &registry, [7; 32], &bytes).is_err());
        let mut changed_registry = registry.clone();
        changed_registry.caps[0][0][0] += Val::ONE;
        assert!(VerifiedWallet::verify(pin, &changed_registry, wallet.chain, &bytes).is_err());
        wallet.proof.opened_values.quotient_chunks[0][0] += profile::Challenge::ONE;
        assert!(recursive::verify_wallet(&wallet).is_err());
        assert!(VerifiedWallet::verify(pin, &registry, wallet.chain, &encode(&wallet)).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(VerifiedWallet::verify(pin, &registry, wallet.chain, &trailing).is_err());
        eprintln!("public_wallet_approval_fresh cpu_proofs=1 identity_builds=1 reference_and_public_verification=true mutations_rejected=true identity_bytes={} identity_calls={} direct_bytes={} direct_calls={} reused_bytes={} reused_calls={}", identity.bytes, identity.calls, direct_requests.bytes, direct_requests.calls, reused_requests.bytes, reused_requests.calls);
    });
}
