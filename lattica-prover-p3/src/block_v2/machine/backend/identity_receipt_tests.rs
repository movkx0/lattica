use super::identity_receipt::fingerprint_stream;
use super::*;

const DOMAIN: u64 = 0x4c42563210;
const HOST_BUDGET: u64 = 2 << 30;

fn small_air(addend: u64) -> MachineAir {
    let mut b = super::super::ProgramBuilder::new(1).unwrap();
    let public = b.public(0).unwrap();
    let input = b.input();
    let constant = b.constant(Val::from_u64(addend));
    let sum = b.add(input, constant);
    b.assert_equal(public, sum);
    MachineAir::new(b.finish(Some(64)).unwrap())
}

fn fingerprint_fields(fields: &[u64]) -> identity_receipt::StreamFingerprint {
    fingerprint_stream(DOMAIN, |sink| fields.iter().try_for_each(|&v| sink(v))).unwrap()
}

#[test]
fn exact_emitted_identity_fingerprint_binds_program_profile_analysis_and_cap() {
    let air = small_air(3);
    let analysis = super::super::analysis::analyze(&air).unwrap();
    let degree = air.program().height().ilog2() as usize + 1;
    let roots =
        vec![[Val::from_u64(7); 4]; 1 << (degree + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT)];
    let common = common_from_cap(&air, p3_symmetric::MerkleCap::new(roots.clone())).unwrap();
    let original = program_identity_fields(&air, &common, &analysis);
    let receipt =
        RegisteredIdentityReceipt::from_gpu_result([1, 2, 3, 4], fingerprint_fields(&original));
    assert!(receipt
        .matching_id(&fingerprint_fields(&original))
        .is_some());
    // Representative profile/program/constraint/tail changes; keep this test
    // bounded instead of rehashing the whole stream once per emitted field.
    for index in [
        0,
        4,
        5,
        11,
        original.len() / 2,
        original.len() - 5,
        original.len() - 1,
    ] {
        let mut changed = original.clone();
        changed[index] = if changed[index] == crate::block_v2::commitment::MODULUS - 1 {
            0
        } else {
            changed[index] + 1
        };
        assert!(
            receipt.matching_id(&fingerprint_fields(&changed)).is_none(),
            "field {index}"
        );
    }
    let mut changed_roots = roots;
    changed_roots[0][0] += Val::ONE;
    let changed_common =
        common_from_cap(&air, p3_symmetric::MerkleCap::new(changed_roots)).unwrap();
    assert!(receipt
        .matching_id(&fingerprint_fields(&program_identity_fields(
            &air,
            &changed_common,
            &analysis
        )))
        .is_none());
    let changed_air = small_air(5);
    let changed_analysis = super::super::analysis::analyze(&changed_air).unwrap();
    assert!(receipt
        .matching_id(&fingerprint_fields(&program_identity_fields(
            &changed_air,
            &common,
            &changed_analysis
        )))
        .is_none());
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda")))]
#[test]
fn cpu_registration_never_mints_or_echoes_a_gpu_identity_receipt() {
    let request = crate::proving::Request {
        policy: crate::proving::Policy::CpuRequired,
        emit_report: false,
    };
    let first = RegisteredProgram::new_with_request(small_air(3), HOST_BUDGET, request).unwrap();
    assert!(first.identity_receipt().is_none());
    let fields =
        program_identity_fields(first.air(), &first.prepared.data.common, first.analysis());
    let hint = RegisteredIdentityReceipt::from_gpu_result(first.id(), fingerprint_fields(&fields));
    drop(first);
    let second = RegisteredProgram::new_with_request_and_identity_hint(
        small_air(3),
        HOST_BUDGET,
        request,
        Some(&hint),
    )
    .unwrap();
    assert!(second.identity_receipt().is_none());
    assert!(!second.identity_hint_hit());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires exclusive bounded OpenCL, complete strict GPU switches and original proof profile"]
fn gpu_identity_reuse_preserves_id_preprocessing_proofs_and_rejects_changed_hints() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    assert!(quotient_pcs::gpu_witness_enabled());
    let request = crate::proving::Request {
        policy: crate::proving::Policy::GpuRequired,
        emit_report: true,
    };
    let first = RegisteredProgram::new_with_request_and_identity_hint(
        small_air(3),
        HOST_BUDGET,
        request,
        None,
    )
    .unwrap();
    assert!(!first.identity_hint_hit());
    let receipt = first
        .identity_receipt()
        .expect("GPU identity receipt")
        .clone();
    let expected_id = first.id();
    assert_eq!(
        expected_id,
        program_identity(first.air(), &first.prepared.data.common, first.analysis())
    );
    let cap = first.preprocessing_cap().clone();
    let public = [Val::from_u64(12)];
    let witness = [Val::from_u64(9)];
    let proof1 = first
        .prove_with_request(&public, &witness, request)
        .unwrap();
    first.verifier().verify(&proof1, &public).unwrap();
    let mut changed_cap_fields =
        program_identity_fields(first.air(), &first.prepared.data.common, first.analysis());
    let last = changed_cap_fields.last_mut().unwrap();
    *last = if *last == crate::block_v2::commitment::MODULUS - 1 {
        0
    } else {
        *last + 1
    };
    // Private negative fixture: a ticket for the same program but different cap
    // must miss. This synthetic constructor is inaccessible to public callers.
    let changed_cap_hint = RegisteredIdentityReceipt::from_gpu_result(
        expected_id,
        fingerprint_fields(&changed_cap_fields),
    );
    drop(first);

    let before = identity_receipt::full_gpu_hashes();
    let second = RegisteredProgram::new_with_request_and_identity_hint(
        small_air(3),
        HOST_BUDGET,
        request,
        Some(&receipt),
    )
    .unwrap();
    let after = identity_receipt::full_gpu_hashes();
    assert!(second.identity_hint_hit());
    assert_eq!(second.id(), expected_id);
    assert_eq!(second.preprocessing_cap(), &cap);
    assert_eq!(
        after, before,
        "identity hit must not run protocol hash again"
    );
    // Success includes complete GPU preprocessing; proving reuses that complete
    // scope, still creates a fresh proof, and passes independent CPU verification.
    let proof2 = second
        .prove_with_request(&public, &witness, request)
        .unwrap();
    let verifier = second.verifier();
    verifier.verify(&proof2, &public).unwrap();
    assert_ne!(
        serde_json::to_vec(&proof1).unwrap(),
        serde_json::to_vec(&proof2).unwrap()
    );
    assert!(verifier.verify(&proof2, &[Val::from_u64(13)]).is_err());
    drop(second);

    let before = identity_receipt::full_gpu_hashes();
    let cap_miss = RegisteredProgram::new_with_request_and_identity_hint(
        small_air(3),
        HOST_BUDGET,
        request,
        Some(&changed_cap_hint),
    )
    .unwrap();
    let after = identity_receipt::full_gpu_hashes();
    assert!(!cap_miss.identity_hint_hit());
    assert_eq!(cap_miss.id(), expected_id);
    assert_eq!(after, before + 1);
    drop(cap_miss);

    let before = identity_receipt::full_gpu_hashes();
    let changed = RegisteredProgram::new_with_request_and_identity_hint(
        small_air(5),
        HOST_BUDGET,
        request,
        Some(&receipt),
    )
    .unwrap();
    let after = identity_receipt::full_gpu_hashes();
    assert!(!changed.identity_hint_hit());
    assert_ne!(changed.id(), expected_id);
    assert_eq!(
        changed.id(),
        program_identity(
            changed.air(),
            &changed.prepared.data.common,
            changed.analysis()
        )
    );
    assert_eq!(after, before + 1);
}
