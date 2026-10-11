use super::*;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

#[test]
fn recovery_verification_reuses_one_job_allowance_and_rejects_short_ram() {
    #[cfg(all(not(debug_assertions), target_arch = "x86_64", target_os = "linux"))]
    {
        let (plan, requested) = measure(recovery::Plan::new);
        let plan = plan.unwrap();
        assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
        let floor = crate::block_v2::execution::worker_budget::COORDINATOR_JOB_BYTES;
        assert_eq!(plan.peak_bytes as u64, floor);
        assert_eq!(
            TypedRegistryContext::recovery_storage_bytes().unwrap(),
            plan.peak_bytes
        );
        TypedRegistryContext::admit_recovery_storage(floor).unwrap();
        for limit in [0, plan.control_bytes as u64, floor - 1] {
            assert!(TypedRegistryContext::admit_recovery_storage(limit).is_err());
        }
        assert!(plan.wallet_bytes < plan.node_bytes);
        assert!(plan.registry_bytes < plan.node_bytes);
        eprintln!("recovery_verification_storage registry_bytes={} wallet_bytes={} node_bytes={} control_bytes={} peak_bytes={} allowance_bytes={floor} allocations=0 short_rejections=3", plan.registry_bytes, plan.wallet_bytes, plan.node_bytes, plan.control_bytes, plan.peak_bytes);
    }
    #[cfg(not(all(not(debug_assertions), target_arch = "x86_64", target_os = "linux")))]
    {
        assert!(TypedRegistryContext::recovery_storage_bytes().is_err());
        assert!(TypedRegistryContext::admit_recovery_storage(u64::MAX).is_err());
    }
}

#[test]
fn recovery_pin_rejects_family_and_construction_before_registry_compilation() {
    let registry = registry();
    let profile = registry.id().unwrap();
    let pin = RegistryPin::new_typed(&registry, profile).unwrap();
    for change in 0..2 {
        let mut pin = pin;
        if change == 0 {
            pin.typed = false;
        } else {
            pin.construction = WrapperConstruction::SingleWallet;
        }
        let (result, requested) = measure(|| TypedRegistryContext::for_pin(&registry, pin));
        assert!(result.is_err());
        assert!(!requested.overflow && requested.bytes <= 1048);
    }
    assert_eq!(
        TypedRegistryContext::for_pin(&registry, pin).unwrap().pin(),
        pin
    );
    eprintln!("recovery_registry_pin early_rejections=2 complete_pin=true");
}

#[test]
fn sequential_registry_and_wallet_phases_share_one_payload_reservation() {
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    {
        let setup = crate::block_v2::machine::programs::registry_setup::Plan::new().unwrap();
        let intake = TypedRegistryContext::wallet_intake_storage_bytes().unwrap();
        let (result, requested) = crate::spill_alloc::allocation_requests::measure(
            TypedRegistryContext::preparation_storage_bytes,
        );
        let bytes = result.unwrap();
        assert_eq!(bytes, setup.peak_bytes.max(intake));
        assert!(bytes < setup.peak_bytes + intake);
        assert!(!requested.overflow);
        assert_eq!(requested.bytes, 0);
        assert_eq!(requested.calls, 0);
        eprintln!("bounded_registry_wallet setup_bytes={} wallet_intake_bytes={intake} sequential_bytes={bytes}", setup.peak_bytes);
    }
    #[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
    assert!(TypedRegistryContext::preparation_storage_bytes().is_err());
}

fn registry() -> TypedRegistry<12> {
    TypedRegistry {
        height: 64,
        caps: core::array::from_fn(|_| vec![[Val::ONE; 4]; 1 << profile::CAP_HEIGHT]),
    }
}

#[test]
fn borrowed_registry_admission_counts_spare_capacity_before_symbolic_setup() {
    let mut registry = registry();
    let profile = registry.id().unwrap();
    let fixed = core::mem::size_of::<TypedRegistry<12>>()
        + registry.caps[1..]
            .iter()
            .map(|cap| cap.capacity() * core::mem::size_of::<[Val; 4]>())
            .sum::<usize>();
    let roots =
        (TypedRegistry::<12>::STORAGE_LIMIT_BYTES - fixed) / core::mem::size_of::<[Val; 4]>();
    let mut boundary = Vec::with_capacity(roots);
    boundary.extend_from_slice(&registry.caps[0]);
    registry.caps[0] = boundary;
    assert_eq!(
        TypedRegistryContext::new(&registry, profile)
            .unwrap()
            .pin()
            .profile(),
        profile
    );
    let mut oversized = Vec::with_capacity(roots + 1);
    oversized.extend_from_slice(&registry.caps[0]);
    registry.caps[0] = oversized;
    let (result, requested) = crate::spill_alloc::allocation_requests::measure(|| {
        TypedRegistryContext::new(&registry, profile)
    });
    assert!(result.is_err());
    assert!(!requested.overflow && requested.bytes <= 1048);
    assert!(RegistryPin::new_typed(&registry, profile).is_err());
    eprintln!("borrowed_registry_backing boundary_roots={roots} next_root_rejected=true requested_bytes={} before_symbolic_setup=true", requested.bytes);
}

#[test]
fn checked_node_rejects_every_pin_substitution_before_decoding() {
    use crate::block_v2::{execution::job::Job, typed_recursive::CheckedRegistry};
    let registry = registry();
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let checked = CheckedRegistry::new(registry).unwrap();
    let original = Job::empty(pin, [47; 32], 0, 0).unwrap();
    for changed in 0..3 {
        let mut job = original.clone();
        match changed {
            0 => job.pin.typed = false,
            1 => {
                job.pin.construction = crate::block_v2::recursive::WrapperConstruction::SingleWallet
            }
            _ => job.pin.profile[0] ^= 1,
        }
        let error = crate::block_v2::execution::job::VerifiedNode::verify_typed_checked(
            &job,
            &checked,
            &[1],
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "typed execution registry substitution");
    }
    eprintln!("checked_node_pin substitutions_rejected=3 before_decode=true");
}

#[test]
fn context_binds_the_exact_borrowed_registry_and_rejects_substitution() {
    let mut registry = registry();
    let profile = registry.id().unwrap();
    let context = TypedRegistryContext::new(&registry, profile).unwrap();
    assert!(core::ptr::eq(context.approved.as_registry(), &registry));
    assert_eq!(
        context.pin(),
        RegistryPin::new_typed(&registry, profile).unwrap()
    );
    assert_eq!(context.pin().profile(), profile);
    assert!(context.pin().is_typed());
    let mut other_profile = profile;
    other_profile[0] ^= 1;
    assert!(TypedRegistryContext::new(&registry, other_profile).is_err());
    // The immutable borrow above must end before the registry can change.
    registry.caps[0][0][0] += Val::ONE;
    assert!(TypedRegistryContext::new(&registry, profile).is_err());
    registry.caps[0][0][0] -= Val::ONE;
    registry.height = 63;
    assert!(TypedRegistryContext::new(&registry, profile).is_err());
    registry.height = 64;
    registry.caps[0].pop();
    assert!(TypedRegistryContext::new(&registry, profile).is_err());
    eprintln!("wallet_registry_context_binding cases=4 substitutions_rejected=true borrowed=true");
}

#[test]
fn context_reuses_identity_without_allocating_and_keeps_framing_checks() {
    let registry = registry();
    let context = TypedRegistryContext::new(&registry, registry.id().unwrap()).unwrap();
    let (_, requests) = measure(|| {
        for _ in 0..64 {
            assert_eq!(context.pin, context.pin());
        }
    });
    assert_eq!(requests.bytes, 0);
    assert_eq!(requests.calls, 0);
    for bytes in [&[][..], &b"LBV2TW01"[..], &b"LBV2WL02x"[..]] {
        assert!(context
            .verify_wallet([0; 32], Policy::JoinSplit, bytes)
            .is_err());
    }
    eprintln!("wallet_registry_context_reuse pins=64 allocations=0 framing_rejections=3");
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
pub(crate) fn fresh_check(wallet: &WalletProof, policy: Policy) {
    let registry = registry();
    let context = TypedRegistryContext::new(&registry, registry.id().unwrap()).unwrap();
    let mut artifact = TYPED_WALLET_MAGIC.to_vec();
    artifact.extend(postcard::to_allocvec(wallet).unwrap());
    let direct =
        VerifiedWallet::verify_typed(context.pin(), &registry, wallet.chain, policy, &artifact)
            .unwrap();
    for _ in 0..2 {
        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        let reused = {
            let plan = recursive::verification::intake::Plan::new(
                wallet.proof.degree_bits,
                matches!(policy, Policy::Htlc { .. }),
            )
            .unwrap();
            let (result, requests) = crate::spill_alloc::allocation_requests::measure_all(|| {
                context.verify_wallet(wallet.chain, policy, &artifact)
            });
            assert!(!requests.overflow && requests.bytes <= plan.cumulative_requested_bytes);
            eprintln!("wallet_intake_fresh mode={} requested_bytes={} calls={} cumulative_bound={} peak_payload_bound={}", policy.mode(), requests.bytes, requests.calls, plan.cumulative_requested_bytes, plan.peak_bytes);
            result.unwrap()
        };
        #[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
        let reused = context
            .verify_wallet(wallet.chain, policy, &artifact)
            .unwrap();
        assert_eq!(reused.pin, direct.pin);
        assert_eq!(reused.mode, direct.mode);
        assert_eq!(reused.summary(), direct.summary());
        assert_eq!(reused.artifact(), direct.artifact());
    }
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    {
        let (summary, requests) = measure(|| {
            VerifiedWallet::typed_ticket(context.pin(), wallet.chain, policy, wallet, &artifact)
        });
        assert_eq!(summary.unwrap().artifact(), direct.artifact());
        let bound = recursive::verification::intake::summary_requested_bytes();
        assert!(!requests.overflow && requests.bytes <= bound);
        eprintln!(
            "wallet_intake_summary mode={} requested_bytes={} calls={} source_bound={bound}",
            policy.mode(),
            requests.bytes,
            requests.calls
        );
    }
    // Stop after decoding, before Rayon/numerical work. The request difference
    // is the independently measured registry check, without worker scheduling.
    let mut wrong_chain = wallet.chain;
    wrong_chain[0] ^= 1;
    let (checked, identity) = measure(|| context.pin().check_typed(&registry));
    checked.unwrap();
    let (direct, reference) = measure(|| {
        VerifiedWallet::verify_typed(context.pin(), &registry, wrong_chain, policy, &artifact)
    });
    let (reused, observed) = measure(|| context.verify_wallet(wrong_chain, policy, &artifact));
    assert!(direct.is_err() && reused.is_err());
    assert_eq!(
        direct.unwrap_err().to_string(),
        reused.unwrap_err().to_string()
    );
    assert!(!identity.overflow && !reference.overflow && !observed.overflow);
    assert!(identity.calls > 0 && identity.bytes > 0);
    assert_eq!(reference.bytes - observed.bytes, identity.bytes);
    assert_eq!(reference.calls - observed.calls, identity.calls);
    // A canonical altered statement still reaches unchanged numerical checks.
    let mut altered: WalletProof =
        postcard::from_bytes(&artifact[TYPED_WALLET_MAGIC.len()..]).unwrap();
    altered.public[0] += Val::ONE;
    let mut bad = TYPED_WALLET_MAGIC.to_vec();
    bad.extend(postcard::to_allocvec(&altered).unwrap());
    assert!(context.verify_wallet(wallet.chain, policy, &bad).is_err());
    eprintln!("wallet_registry_context_fresh mode={} verified=3 chain_rejections=2 altered_public_rejected=true identity_bytes={} identity_calls={} direct_rejected_bytes={} reused_rejected_bytes={} direct_rejected_calls={} reused_rejected_calls={}",
        policy.mode(), identity.bytes, identity.calls, reference.bytes, observed.bytes, reference.calls, observed.calls);
}
