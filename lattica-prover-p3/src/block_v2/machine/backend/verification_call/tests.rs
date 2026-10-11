use super::super::{profile, verification_envelope, BatchProof, Config, RegisteredVerifier};
use super::*;
use crate::block_v2::machine::verifier::template;
#[cfg(feature = "stream")]
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;
#[cfg(not(feature = "stream"))]
use requests::measure;
#[cfg(not(feature = "stream"))]
use std::alloc::GlobalAlloc;

// The production non-stream build uses System directly. Wrap it only in this
// test executable so the same allocation-free observer covers both DFT layouts.
#[cfg(not(feature = "stream"))]
#[path = "../../../../spill_alloc/allocation_requests.rs"]
mod requests;
#[cfg(not(feature = "stream"))]
struct ObservedSystem;
#[cfg(not(feature = "stream"))]
#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;
#[cfg(not(feature = "stream"))]
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        requests::observe(layout.size());
        // SAFETY: The caller's allocator contract is forwarded unchanged.
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        requests::observe(layout.size());
        // SAFETY: The caller's allocator contract is forwarded unchanged.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: Only System allocates this executable's observed buffers.
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        requests::observe(size);
        // SAFETY: The original pointer/layout and requested size are forwarded.
        unsafe { std::alloc::System.realloc(pointer, layout, size) }
    }
}

fn fixture(publics: usize, height: usize) -> (RegisteredVerifier, BatchProof<Config>) {
    let log_lde = height.ilog2() as usize + 1 + profile::LOG_BLOWUP;
    let cap = MerkleCap::new(vec![[Val::ZERO; 4]; 1 << log_lde.min(profile::CAP_HEIGHT)]);
    let verifier = RegisteredVerifier::from_trusted_cap(publics, height, cap).unwrap();
    let proof = template::batch(&verifier.air).unwrap();
    (verifier, proof)
}

fn checked_plan(verifier: &RegisteredVerifier, proof: &BatchProof<Config>) -> Plan {
    verification_envelope::check(
        &verifier.air,
        &verifier.common,
        verifier.quotient_chunks,
        proof,
    )
    .unwrap();
    let (plan, requests) = measure(|| {
        Plan::new(
            &verifier.air,
            &verifier.common,
            verifier.quotient_chunks,
            proof,
        )
    });
    assert_eq!(requests.calls, 0);
    let plan = plan.unwrap();
    plan.admit().unwrap();
    plan
}

#[test]
fn templates_admit_both_caller_capacity_and_temporary_requests_without_allocating() {
    let mut maximum_proof = 0;
    let mut maximum_temporary = 0;
    for publics in [0, 1, 23, 32, 33, 64] {
        for height in [8, 64, 1 << 19, 1 << 24] {
            let (verifier, proof) = fixture(publics, height);
            let plan = checked_plan(&verifier, &proof);
            assert_eq!(
                plan.public_copy_bytes,
                publics * core::mem::size_of::<Val>()
            );
            assert_eq!(plan.diagnostic_bytes, DIAGNOSTIC_BYTES);
            assert_eq!(
                plan.temporary_requested_bytes,
                plan.numerical_bytes
                    + plan.configuration_bytes
                    + plan.public_copy_bytes
                    + plan.diagnostic_bytes
            );
            maximum_proof = maximum_proof.max(plan.proof_backing_bytes);
            maximum_temporary = maximum_temporary.max(plan.temporary_requested_bytes);
        }
    }
    eprintln!("native_verifier_call_templates cases=24 max_proof_bytes={maximum_proof} max_temporary_bytes={maximum_temporary} proof_limit={} temporary_limit={} wide={}",
        storage::PROOF_LIMIT_BYTES, storage::TEMPORARY_LIMIT_BYTES, cfg!(feature = "block-v2-wide-lanes"));
}

fn grow<T>(vector: &mut Vec<T>) -> usize {
    let before = vector.capacity();
    vector.reserve_exact(before + 7 - vector.len());
    (vector.capacity() - before) * core::mem::size_of::<T>()
}
fn grow_cap(cap: &mut p3_batch_stark::Commitment<Config>) -> usize {
    let before = cap.root_capacity();
    let mut roots = Vec::with_capacity(before + 7);
    roots.extend_from_slice(cap.roots());
    *cap = MerkleCap::new(roots);
    (cap.root_capacity() - before) * core::mem::size_of::<[Val; 4]>()
}

#[test]
fn spare_capacity_at_every_owned_proof_level_is_counted_once() {
    let (verifier, mut proof) = fixture(1, 64);
    let mut previous = checked_plan(&verifier, &proof).proof_backing_bytes;
    let mut mutations = 0;
    macro_rules! check {
        ($change:expr) => {{
            let added = $change;
            assert!(added > 0);
            let current = storage::proof_bytes(&proof).unwrap();
            assert_eq!(current - previous, added);
            previous = current;
            mutations += 1;
        }};
    }
    check!(grow_cap(&mut proof.commitments.main));
    check!(grow_cap(&mut proof.commitments.quotient_chunks));
    check!(grow_cap(proof.commitments.permutation.as_mut().unwrap()));
    check!(grow_cap(proof.commitments.random.as_mut().unwrap()));
    check!(grow(&mut proof.degree_bits));
    check!(grow(&mut proof.lookup_terminals));
    check!(grow(&mut proof.opened_values.instances));
    check!(grow(
        &mut proof.opened_values.instances[0]
            .base_opened_values
            .trace_local
    ));
    check!(grow(
        proof.opened_values.instances[0]
            .base_opened_values
            .preprocessed_local
            .as_mut()
            .unwrap()
    ));
    check!(grow(
        proof.opened_values.instances[0]
            .base_opened_values
            .random
            .as_mut()
            .unwrap()
    ));
    check!(grow(
        &mut proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks
    ));
    check!(grow(
        &mut proof.opened_values.instances[0]
            .base_opened_values
            .quotient_chunks[0]
    ));
    check!(grow(
        &mut proof.opened_values.instances[0].permutation_local
    ));
    check!(grow(&mut proof.opened_values.instances[0].permutation_next));
    check!(grow(&mut proof.opening_proof.0));
    check!(grow(&mut proof.opening_proof.0[0]));
    check!(grow(&mut proof.opening_proof.0[0][0]));
    check!(grow(&mut proof.opening_proof.0[0][0][0]));
    check!(grow(&mut proof.opening_proof.1.commit_phase_commits));
    check!(grow_cap(&mut proof.opening_proof.1.commit_phase_commits[0]));
    check!(grow(&mut proof.opening_proof.1.commit_pow_witnesses));
    check!(grow(&mut proof.opening_proof.1.final_poly));
    check!(grow(&mut proof.opening_proof.1.query_proofs));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .1
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .1
    ));
    assert_eq!(
        checked_plan(&verifier, &proof).proof_backing_bytes,
        previous
    );
    assert_eq!(mutations, 34);
    // Empty optional buffers still own spare capacity. They are unsupported
    // by the registered shape, but the capacity walker must include them.
    let values = &mut proof.opened_values.instances[0].base_opened_values;
    values.trace_next = Some(Vec::with_capacity(7));
    values.preprocessed_next = Some(Vec::with_capacity(9));
    assert_eq!(
        storage::proof_bytes(&proof).unwrap() - previous,
        16 * core::mem::size_of::<profile::Challenge>()
    );
    assert!(verification_envelope::check(
        &verifier.air,
        &verifier.common,
        verifier.quotient_chunks,
        &proof
    )
    .is_err());
    eprintln!(
        "native_verifier_call_capacity mutations=34 optional_empty_buffers=2 allocation_free=true"
    );
}

#[test]
fn fresh_configuration_and_public_copy_requests_fit_independent_source_bounds() {
    let bound = profile::verification::requested_bytes();
    for attempt in 0..3 {
        let (config, observed) = measure(profile::verification::make_config);
        assert!(config.is_ok());
        assert!(!observed.overflow && observed.bytes > 0 && observed.bytes <= bound);
        eprintln!("native_verifier_config attempt={attempt} requested_bytes={} calls={} source_bound={bound} gpu={} stream={}", observed.bytes, observed.calls, cfg!(any(feature = "gpu", feature = "gpu-metal")), cfg!(feature = "stream"));
        drop(config);
    }
    for count in [0, 1, 23, 32, 33, 64] {
        let input = vec![Val::ZERO; count];
        let (copy, observed) = measure(|| copy_public(&input));
        assert_eq!(copy.unwrap(), input);
        assert_eq!(observed.bytes, count * core::mem::size_of::<Val>());
        assert_eq!(observed.calls, usize::from(count != 0));
    }
}

#[test]
fn diagnostics_preserve_short_messages_and_bound_long_utf8_and_failed_formatting() {
    struct Raw<'a>(&'a str);
    impl fmt::Debug for Raw<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    for text in [
        "".to_owned(),
        "valid UTF-8 🦀".to_owned(),
        "é".repeat(DIAGNOSTIC_BYTES / 2),
        "x".repeat(DIAGNOSTIC_BYTES + 1),
    ] {
        let (message, requests) = measure(|| error(&Raw(&text)));
        assert!(!requests.overflow);
        assert_eq!(requests.bytes, message.len());
        assert_eq!(requests.calls, usize::from(!message.is_empty()));
        assert!(message.len() <= DIAGNOSTIC_BYTES);
        if text.len() <= DIAGNOSTIC_BYTES {
            assert_eq!(message, text);
        } else {
            assert!(message.contains("diagnostic exceeds limit"));
        }
    }
    struct Broken;
    impl fmt::Debug for Broken {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    assert!(error(&Broken).contains("diagnostic exceeds limit"));
    eprintln!(
        "native_verifier_call_diagnostics limit=1024 utf8=true exact_boundary=true overflow=true"
    );
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn complete_entry_point_requests_fit_on_valid_and_late_rejected_proofs() {
    use super::super::RegisteredProgram;
    use crate::block_v2::machine::{MachineAir, ProgramBuilder};
    for publics in [1, 33] {
        let mut builder = ProgramBuilder::new(publics).unwrap();
        let public = builder.public(0).unwrap();
        let private = builder.input();
        builder.assert_equal(public, private);
        let program =
            RegisteredProgram::new(MachineAir::new(builder.finish(Some(64)).unwrap())).unwrap();
        let public = vec![Val::ZERO; publics];
        let mut proof = program.prove(&public, &[Val::ZERO]).unwrap();
        let plan = Plan::new(
            &program.air,
            &program.data.common,
            program.analysis.quotient_chunks,
            &proof,
        )
        .unwrap();
        plan.admit().unwrap();
        for valid in [true, false, true] {
            let (result, observed) = measure(|| program.verify(&proof, &public));
            assert_eq!(result.is_ok(), valid);
            assert!(!observed.overflow && observed.bytes <= plan.temporary_requested_bytes);
            eprintln!("native_verifier_call_observed publics={publics} valid={valid} requested_bytes={} source_bound={} proof_bytes={} wide={}", observed.bytes, plan.temporary_requested_bytes, plan.proof_backing_bytes, cfg!(feature = "block-v2-wide-lanes"));
            let last = proof.opening_proof.1.query_proofs.last_mut().unwrap();
            let value = &mut last
                .commit_phase_openings
                .last_mut()
                .unwrap()
                .sibling_values[0];
            if valid {
                *value += profile::Challenge::ONE;
            } else {
                *value -= profile::Challenge::ONE;
            }
        }
    }
}
