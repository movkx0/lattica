use super::*;
use crate::block_v2::{
    execution::job::TYPED_WALLET_MAGIC, profile, typed_recursive::CheckedRegistry,
};
use crate::config::Val;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

fn registry() -> TypedRegistry<12> {
    TypedRegistry {
        height: 8,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    }
}

fn resources() -> Resources {
    Resources {
        ram_bytes: storage::STARTUP_HOST_BYTES,
        vram_bytes: 0,
        scratch_bytes: 500,
        threads: 2,
    }
}

#[test]
fn undersized_worker_rejects_before_registry_allocation() {
    let registry = registry();
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    for ram_bytes in [0, storage::HOST_BYTES, storage::STARTUP_HOST_BYTES - 1] {
        let registry = registry.clone();
        let (result, requested) = measure(|| {
            TypedWorker::new(
                registry,
                pin,
                Resources {
                    ram_bytes,
                    ..resources()
                },
            )
        });
        assert!(result.is_err());
        assert!(!requested.overflow && requested.bytes <= 1048);
    }
    let mut worker = TypedWorker::new(registry, pin, resources()).unwrap();
    let session_memory = storage::session_memory_bytes(resources().ram_bytes).unwrap();
    assert_eq!(
        session_memory,
        resources().ram_bytes - storage::HOST_BYTES - storage::INPUT_HOST_BYTES
    );
    let active =
        crate::block_v2::typed_recursive::storage::active_memory_bytes(session_memory, 0).unwrap();
    let session = worker.session.as_mut().unwrap();
    assert!(session.configure_cache(2, active).is_err());
    session.configure_cache(2, active - 1).unwrap();
    eprintln!("worker_registry_startup minimum_bytes={} early_rejections=3 session_bytes={session_memory} active_bytes={active} registry_setup_not_subtracted=true decoded_input_bytes={}", storage::STARTUP_HOST_BYTES, storage::INPUT_HOST_BYTES);
}

#[test]
fn checked_configuration_moves_into_session_without_recompiling_or_cloning_caps() {
    let raw = registry();
    let pin = RegistryPin::new_typed(&raw, raw.id().unwrap()).unwrap();
    let checked = CheckedRegistry::new(raw).unwrap();
    let address = checked.as_registry().caps[0].as_ptr();
    let (result, requested) = measure(|| TypedWorker::from_checked(checked, pin, resources()));
    let worker = result.unwrap();
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    let session = worker.session.as_ref().unwrap();
    assert_eq!(session.registry().caps[0].as_ptr(), address);
    let (_, requested) = measure(|| {
        for _ in 0..1024 {
            let approved = session.registry_approval().unwrap();
            pin.check_typed_approved(&approved).unwrap();
        }
    });
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    eprintln!("worker_registry_transfer cap_backing_moved=true transfer_allocations=0 approvals=1024 approval_allocations=0");
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh wallet proof and complete worker input verification"]
fn fresh_wallet_inputs_keep_numerical_and_policy_verification() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(fresh_wallet_inputs_serial);
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_wallet_inputs_serial() {
    use crate::spill_alloc::allocation_requests::measure_all;
    let mut wallet = crate::block_v2::recursive::demo_wallet(0).unwrap();
    let encode = |wallet: &WalletProof| {
        let mut bytes = TYPED_WALLET_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(wallet).unwrap());
        bytes
    };
    let bytes = encode(&wallet);
    let raw = registry();
    let pin = RegistryPin::new_typed(&raw, raw.id().unwrap()).unwrap();
    let ticket =
        VerifiedWallet::verify_typed(pin, &raw, wallet.chain, Policy::JoinSplit, &bytes).unwrap();
    let job = Job::typed_pair(0, ticket, None).unwrap();
    let worker = TypedWorker::new(raw.clone(), pin, resources()).unwrap();
    let mut request = Request {
        key: [7; 32],
        resources: resources(),
        pin,
        job: job.id(),
        operation: job.operation(),
        start: job.start(),
        expected: job.expected(),
        children: Vec::new(),
        manifest: job.wallet_inputs().to_vec(),
        inputs: vec![bytes.as_slice(); 2],
    };
    let prepared = worker
        .prepare(&request, &mut |_| Ok(Policy::JoinSplit))
        .unwrap();
    prepared
        .with(|inputs| {
            let TypedInputs::Pair(proofs, policies, count) = inputs else {
                panic!("expected pair")
            };
            assert_eq!(*count, 1);
            assert_eq!(policies.len(), 2);
            assert!(policies
                .iter()
                .all(|policy| matches!(policy, Policy::JoinSplit)));
            assert_eq!(proofs[0].public, wallet.public);
            assert_eq!(proofs[1].public, wallet.public);
            Ok(())
        })
        .unwrap();
    assert!(worker
        .prepare(&request, &mut |_| Ok(Policy::Issuance {
            authorized_mint: 7
        }))
        .is_err());
    let approval = worker
        .session
        .as_ref()
        .unwrap()
        .registry_approval()
        .unwrap();
    let (_, identity) =
        measure_all(|| crate::block_v2::typed_recursive::CheckedRegistryRef::new(&raw).unwrap());
    let mut wrong_chain = wallet.chain;
    wrong_chain[0] ^= 1;
    let limit = || codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
    let (_, direct) = measure_all(|| {
        VerifiedWallet::verify_typed_owned(
            pin,
            &raw,
            wrong_chain,
            Policy::JoinSplit,
            &bytes,
            &limit(),
        )
    });
    let (_, reused) = measure_all(|| {
        VerifiedWallet::verify_typed_owned_approved(
            pin,
            &approval,
            wrong_chain,
            Policy::JoinSplit,
            &bytes,
            &limit(),
        )
    });
    assert!(!identity.overflow && !direct.overflow && !reused.overflow);
    assert_eq!(direct.bytes - reused.bytes, identity.bytes);
    assert_eq!(direct.calls - reused.calls, identity.calls);
    wallet.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    let changed = encode(&wallet);
    request.inputs = vec![changed.as_slice(); 2];
    request.manifest = vec![ArtifactRef::from_bytes(ArtifactKind::Wallet, &changed).unwrap(); 2];
    request.validate().unwrap();
    assert!(worker
        .prepare(&request, &mut |_| Ok(Policy::JoinSplit))
        .is_err());
    eprintln!("worker_registry_fresh cpu_wallet_proofs=1 verified_slots=2 padded_count=1 policy_rejected=true altered_opening_rejected=true identity_bytes={} direct_rejected_bytes={} reused_rejected_bytes={}", identity.bytes, direct.bytes, reused.bytes);
}
