use super::*;
use crate::block_v2::native_gpu::private_spend::{PrivateSpendWitness, PublicSpendInputs};
use crate::spill_alloc::allocation_requests::measure;

fn request(extra_capacity: usize) -> PrivateSpendRequest {
    let mut ring = Vec::with_capacity(input_layout::RING_POLYS + extra_capacity);
    ring.resize(input_layout::RING_POLYS, [0u64; 256]);
    let public = PublicSpendInputs { setup_seed: [1; 32], context: [2; 32], ring,
        recipients: vec![[0u64; 256]; input_layout::RECIPIENT_POLYS] };
    let witness = PrivateSpendWitness::new(vec![[0i64; 256]; 16],
        vec![[0i64; 256]; 18], [[1; 32], [2; 32]], 0, [1, 1], [1, 1]).unwrap();
    PrivateSpendRequest::new(public, witness).unwrap()
}
fn plan() -> NativeSpendOperationPlan {
    NativeSpendOperationPlan::new(SpendLimits::bounded(24 << 30)).unwrap()
}

#[test]
fn native_spend_source_plan_is_allocation_free_and_not_the_api_ceiling() {
    let (plan, requests) = measure(plan);
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    assert_eq!(plan.input_backing_bytes(), 454_656);
    assert_eq!(plan.packed_backing_bytes(), 455_976);
    assert_eq!(plan.managed_bytes(), 3_151_744);
    let operation = plan.requirements().get(Category::PhaseScratch);
    assert_eq!(operation.device, plan.managed_bytes() as u64);
    assert!(operation.host < (24 << 30));
    assert!(operation.host > plan.packed_backing_bytes() as u64);
    assert!(plan.shared_static_requirements().get(Category::RegisteredMetadata).host
        > pins::BUNDLE.len() as u64);
    assert_eq!(plan.requirements().get(Category::NativeProof), Bytes::ZERO);
    assert_eq!(plan.output_requirements().get(Category::PhaseScratch), Bytes::ZERO);
    println!("NATIVE_SPEND_SOURCE_CENSUS host={} device={} static={} output={} input={} packed={}",
        operation.host, operation.device,
        plan.shared_static_requirements().total().unwrap().host,
        plan.output_requirements().total().unwrap().host,
        plan.input_backing_bytes(), plan.packed_backing_bytes());
}

#[test]
fn native_spend_request_census_rejects_spare_capacity_without_repacking() {
    let plan = plan();
    let (input, owned) = measure(|| request(0));
    assert_eq!(owned.bytes, plan.input_backing_bytes());
    let (accepted, checked) = measure(|| plan.check_request(&input));
    assert_eq!(accepted, Ok(()));
    assert_eq!(checked.calls, 0);
    let oversized = request(1);
    assert_eq!(plan.check_request(&oversized), Err(NativeSpendSourceError::Request));
    assert_eq!(plan.check_request(&input), Ok(()));
}

#[test]
fn native_spend_source_evidence_requires_exact_geometry_and_masks() {
    let plan = plan();
    let original = || SpendEvidence { prelude_steps: PRELUDE_MASK,
        accepted_attempt_steps: ACCEPTED_MASK, managed_bytes: plan.managed_bytes(),
        kernel_source_sha256: SOURCE_SHA256 };
    assert_eq!(plan.check_evidence(&original()), Ok(()));
    let mut evidence = original(); evidence.prelude_steps ^= 1;
    assert_eq!(plan.check_evidence(&evidence), Err(NativeSpendSourceError::Evidence));
    let mut evidence = original(); evidence.accepted_attempt_steps ^= 1 << 25;
    assert_eq!(plan.check_evidence(&evidence), Err(NativeSpendSourceError::Evidence));
    let mut evidence = original(); evidence.managed_bytes -= 8;
    assert_eq!(plan.check_evidence(&evidence), Err(NativeSpendSourceError::Evidence));
    let mut evidence = original(); evidence.kernel_source_sha256 = "different kernel";
    assert_eq!(plan.check_evidence(&evidence), Err(NativeSpendSourceError::Evidence));
}

#[test]
fn native_spend_source_output_census_binds_private_key_capacity() {
    let plan = plan();
    let output = |extra: usize| {
        let mut polynomials = Vec::with_capacity(18 + extra);
        polynomials.resize(18, [0i64; 256]);
        PrivateSpendOutput { statement: vec![0; STATEMENT_BYTES], proof: vec![0; PROOF_BYTES],
            output_keys: PrivateOutputKeys::new(polynomials).unwrap() }
    };
    let (exact, requested) = measure(|| output(0));
    assert_eq!(requested.bytes, InputSource::output_backing_bytes());
    assert_eq!(requested.bytes, 293_312);
    assert_eq!(plan.check_output(&exact), Ok(()));
    assert_eq!(plan.check_output(&output(1)), Err(NativeSpendSourceError::Output));
}

#[test]
fn native_spend_program_and_kernel_builder_requests_fit_source_census() {
    // These are real ocl 0.19.7 host constructors. No Context, Program build,
    // queue, device query or GPU work occurs in these allocation canaries.
    let (_, program) = measure(|| {
        let mut builder = ocl::Program::builder();
        builder.src(pins::BUNDLE).cmplr_opt("-cl-std=CL1.2");
        let strings = builder.get_src_strings().unwrap();
        let options = builder.get_compiler_options().unwrap();
        std::hint::black_box((&builder, &strings, &options));
    });
    assert!(!program.overflow);
    assert!(program.bytes <= ocl_storage::program_bytes().unwrap());
    let (_, kernel) = measure(|| {
        let mut builder = ocl::Kernel::builder();
        builder.name("pq_spend_parallel_polynomials").global_work_size(1usize);
        for _ in 0..9 { builder.arg(0u64); }
        std::hint::black_box(&builder);
        // Independent maximum live Mem-argument map shape and its clone.
        let values: std::collections::BTreeMap<u32, usize> = (0..4).map(|i| (i, 0)).collect();
        std::hint::black_box((&values, values.clone()));
    });
    assert!(!kernel.overflow);
    assert!(kernel.bytes <= ocl_storage::kernel_bytes().unwrap());
}

#[test]
fn native_spend_source_plan_rejects_changed_resource_profile() {
    let defaults = SpendLimits::bounded(24 << 30);
    for limits in [SpendLimits::bounded(0), SpendLimits::bounded(32 << 30),
        SpendLimits { max_attempts: 1023, ..defaults },
        SpendLimits { random_call_limit: 1 << 25, ..defaults },
        SpendLimits { proposal_limit: 1 << 29, ..defaults }]
    {
        assert!(matches!(NativeSpendOperationPlan::new(limits),
            Err(NativeSpendSourceError::Configuration)));
    }
    assert_eq!(add(usize::MAX, 1), Err(NativeSpendSourceError::Overflow));
    assert_eq!(mul(usize::MAX, 2), Err(NativeSpendSourceError::Overflow));
}
