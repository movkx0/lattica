use super::*;
use crate::block_v2::{gpu_hash, quotient_pcs, machine::{ProgramBuilder, backend::RegisteredProgram}};
use p3_field::PrimeCharacteristicRing;

fn program(addend: u64) -> Arc<Program> {
    let mut b = ProgramBuilder::new(1).unwrap();
    let public = b.public(0).unwrap(); let input = b.input();
    let constant = b.constant(Val::from_u64(addend)); let sum = b.add(input, constant);
    b.assert_equal(public, sum);
    Arc::new(b.finish(Some(64)).unwrap())
}

fn initialize() {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
}

#[test]
fn identity_batch_plan_rejects_duplicates_and_insufficient_memory_without_gpu() {
    let context = IdentityBatchContext::new(); let p = program(3);
    assert!(context.plan(IdentityBatchLimits::default(), vec![(0, Arc::clone(&p))], 2 << 30, 8 << 30).is_err());
    assert!(context.plan(IdentityBatchLimits::batched(2).unwrap(),
        vec![(0, Arc::clone(&p)), (0, Arc::clone(&p))], 2 << 30, 8 << 30).is_err());
    for (host, device) in [(0, 8 << 30), (2 << 30, 0), (33 << 30, 8 << 30), (2 << 30, 9 << 30)] {
        assert!(context.plan(IdentityBatchLimits::batched(2).unwrap(), vec![(0, Arc::clone(&p))], host, device).is_err());
    }
    let plan = context.plan(IdentityBatchLimits::batched(2).unwrap(), vec![(0, Arc::clone(&p))], 2 << 30, 8 << 30).unwrap();
    let size = plan.footprint();
    assert!(size.host_bytes > size.retained_host_bytes);
    assert!(context.plan(IdentityBatchLimits::batched(2).unwrap(), vec![(0, Arc::clone(&p))], size.host_bytes - 1, size.managed_bytes).is_err());
    assert!(context.plan(IdentityBatchLimits::batched(2).unwrap(), vec![(0, p)], size.host_bytes, size.managed_bytes).is_ok());
}

#[test]
fn identity_source_footprint_refuses_overflow_and_bounds_prefix_storage() {
    assert!(IdentityBatchFootprint::for_program_bounds(0, 0).is_err());
    assert!(IdentityBatchFootprint::for_program_bounds(MAX_IDENTITY_STREAMS + 1, 0).is_err());
    assert!(IdentityBatchFootprint::for_program_bounds(2, u64::MAX).is_err());
    for count in 1..=MAX_IDENTITY_STREAMS {
        let source = count as u64 * (2 << 30);
        let bound = IdentityBatchFootprint::for_program_bounds(count, source).unwrap();
        assert_eq!(bound.retained_host_bytes, source + count as u64 * IDENTITY_PREFIX_HOST_BYTES);
        assert!(bound.host_bytes > bound.retained_host_bytes);
        assert!(bound.max_allocation_bytes <= bound.managed_bytes);
    }
}

#[test]
fn borrowed_prefix_plan_charges_only_additional_storage_and_retains_no_credit() {
    let context = IdentityBatchContext::new();
    let programs = [program(3), program(5)];
    let limits = IdentityBatchLimits::batched(2).unwrap();
    let source = programs.iter().map(|p| p.source_host_bytes().unwrap() as u64).sum::<u64>();
    let owned = context.plan(limits, programs.iter().enumerate()
        .map(|(job, p)| (job as u64, Arc::clone(p))).collect(), 2 << 30, 8 << 30).unwrap().footprint();
    let borrowed = context.plan_borrowed(limits, programs.iter().enumerate()
        .map(|(job, p)| (job as u64, p)).collect(), 2 << 30, 8 << 30).unwrap().footprint();
    assert_eq!(borrowed.program_storage, IdentityProgramStorage::Borrowed);
    assert_eq!(borrowed.borrowed_program_host_bytes, source);
    assert_eq!(owned.borrowed_program_host_bytes, 0);
    assert_eq!(owned.host_bytes, borrowed.host_bytes + source);
    assert_eq!(owned.retained_host_bytes, borrowed.retained_host_bytes + source);
    assert_eq!(owned.managed_bytes, borrowed.managed_bytes);
    assert!(context.plan_borrowed(limits, vec![(0, &programs[0]), (0, &programs[1])],
        2 << 30, 8 << 30).is_err());
    assert!(context.plan_borrowed(limits, vec![(0, &programs[0]), (1, &programs[1])],
        borrowed.host_bytes - 1, borrowed.managed_bytes).is_err());
    assert!(context.plan_borrowed(limits, vec![(0, &programs[0]), (1, &programs[1])],
        borrowed.host_bytes, borrowed.managed_bytes).is_ok());
    assert!(context.plan(limits, programs.iter().enumerate()
        .map(|(job, p)| (job as u64, Arc::clone(p))).collect(),
        borrowed.host_bytes, borrowed.managed_bytes).is_err());
    assert!(IdentityBatchFootprint::for_borrowed_program_bounds(24, u64::MAX).is_err());
}

#[test]
#[ignore = "requires strict OpenCL worker; run serially with the existing resource guard"]
fn gpu_identity_prefix_registration_preserves_caps_ids_and_fresh_proofs() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let context = IdentityBatchContext::new();
    let programs: Vec<_> = (0..MAX_IDENTITY_STREAMS).map(|i| program(3 + 2 * i as u64)).collect();
    let request = Request { policy: Policy::GpuRequired, emit_report: false };
    let plan = context.plan_borrowed(IdentityBatchLimits::batched(MAX_IDENTITY_STREAMS).unwrap(),
        programs.iter().enumerate().map(|(i, p)| (i as u64, p)).collect(), 2 << 30, 8 << 30).unwrap();
    let pending = plan.execute(request).unwrap();
    assert!(pending.pending.pending.iter().all(|p| !p.prefix.origin_retired()));
    gpu_hash::shutdown().unwrap();
    let (mut tokens, report) = pending.complete_after_retirement().unwrap();
    assert_eq!(report.streams, MAX_IDENTITY_STREAMS);
    assert_eq!(report.footprint.program_storage, IdentityProgramStorage::Borrowed);
    assert!(report.device_ns > 0 && report.preprocessing.stage_coverage_complete);
    println!("IDENTITY_BATCH_REPORT {}", serde_json::to_string(&report).unwrap());
    let wrong_context = IdentityBatchContext::new();
    let air = MachineAir::from_shared_program(Arc::clone(&programs[0]));
    assert!(tokens[0].check_owner(&wrong_context, 0, &air).is_err());
    assert!(tokens[0].check_owner(&context, 1, &air).is_err());
    assert!(tokens[0].check_owner(&context, 0, &MachineAir::new((*programs[0]).clone())).is_err());
    initialize();
    // The baseline identity and cap remain independent of the prefix path.
    let baseline = RegisteredProgram::new_with_request(
        MachineAir::from_shared_program(Arc::clone(&programs[0])), 2 << 30, request).unwrap();
    let expected_id = baseline.id(); let expected_cap = baseline.preprocessing_cap().clone();
    drop(baseline);
    let prefix = tokens.remove(0);
    let (registered, report) = RegisteredProgram::new_with_identity_prefix_and_report(
        air, 2 << 30, request, &context, 0, prefix).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(registered.id(), expected_id);
    assert_eq!(registered.preprocessing_cap(), &expected_cap);
    assert!(!registered.identity_hint_hit());
    let mut proofs = Vec::new();
    for witness in [9, 19] {
        let public = [Val::from_u64(witness + 3)];
        let proof = registered.prove_with_request(&public, &[Val::from_u64(witness)], request).unwrap();
        registered.verifier().verify(&proof, &public).unwrap();
        assert!(registered.verifier().verify(&proof, &[Val::from_u64(witness + 4)]).is_err());
        proofs.push(serde_json::to_vec(&proof).unwrap());
    }
    assert_ne!(proofs[0], proofs[1]);
    drop(registered);
    // Exact metadata, rather than a caller-provided digest, binds the prefix.
    let mut changed = tokens.remove(0);
    changed.fingerprint[0] ^= 1;
    assert!(RegisteredProgram::new_with_identity_prefix_and_report(
        MachineAir::from_shared_program(Arc::clone(&programs[1])), 2 << 30, request, &context, 1, changed).is_err());
    let mut changed = tokens.remove(0);
    changed.cap_fields += 4;
    assert!(RegisteredProgram::new_with_identity_prefix_and_report(
        MachineAir::from_shared_program(Arc::clone(&programs[2])), 2 << 30, request, &context, 2, changed).is_err());
    drop(tokens);
    println!("PUBLIC_HASH_EXECUTION {}", serde_json::to_string(&gpu_hash::public_hash_execution().unwrap().unwrap()).unwrap());
}
