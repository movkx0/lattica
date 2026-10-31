use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    mul_recording::{self, MulRecorder}, mul_preparation::{Q, QHAT},
};

fn recorded_replay(air: &SourceAir) -> MulSymbolicReplay {
    let source = MulPreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + mul_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = MulRecorder::begin(source, &mut original, &ledger).unwrap();
    air.eval(recorder.builder_mut());
    let prepared = recorder.finish().unwrap();
    let replay = prepared.symbolic_replay_census();
    assert!(replay.required_host_bytes() > 0);
    drop(prepared);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    replay
}

#[test]
fn mul_owned_verifier_preserves_small_batch_default_and_original_budget() {
    for (modulus, count) in [(Q, 1), (QHAT, 1)] {
        let air = SourceAir::new(MulDescriptor::new(modulus, count).unwrap());
        assert_eq!(air.max_constraint_degree(), None);
        let replay = recorded_replay(&air);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&air,
            p3_air::symbolic::AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), QUOTIENT);
        let plan = Plan::for_recorded(&air, replay).unwrap();
        assert_eq!(plan.bounds().symbolic_replay_bytes, replay.required_host_bytes());
        assert!(plan.bounds().cumulative_requested_bytes + plan.bounds().entry_frame_bytes <= COMPONENT_BYTES);
    }
}

#[test]
fn mul_owned_verifier_refuses_changed_modulus_or_count_even_at_equal_padded_height() {
    let a = SourceAir::new(MulDescriptor::new(Q, 5).unwrap());
    let b = SourceAir::new(MulDescriptor::new(QHAT, 5).unwrap());
    let c = SourceAir::new(MulDescriptor::new(Q, 6).unwrap());
    assert_eq!(a.height(), c.height());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&b).unwrap());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&c).unwrap());
    let replay = recorded_replay(&a);
    assert!(Plan::for_recorded(&b, replay).is_err());
    assert!(Plan::for_recorded(&c, replay).is_err());
}

#[test]
fn full_height_mul_periodic_storage_cannot_bypass_source_verifier_ceiling() {
    let config = CpuVerificationConfigPlan::new().unwrap();
    let small = SourceAir::new(MulDescriptor::new(Q, 1).unwrap());
    assert_eq!(Bounds::new(Shape::new(&small).unwrap(), config.requested_bytes(), COMPONENT_CEILING_BYTES), Err(BUDGET));
    // Original standalone descriptors still support128. The reviewed owned
    // profile refuses counts above32 before recording or proof execution.
    for count in [33, 64, 128] {
        let air = SourceAir::new(MulDescriptor::new(Q, count).unwrap());
        assert_eq!(Bounds::new(Shape::new(&air).unwrap(), config.requested_bytes(), 0), Err(GEOMETRY));
    }
}

/// Historical64 MiB ceiling applied to current-layout heap+entry census only.
/// Immutable original64 MiB logs remain authoritative for historical bytes.
/// This diagnostic grants no candidate admission, native proof or GPU dispatch.
/// A zero replay term is a rigorous lower bound because the exact symbolic
/// census is nonnegative. Do not construct large periodic tables merely to
/// reconfirm a refusal already implied by the maintained source inventory.
#[test]
fn mul_owned_verifier_exact_count_admission_diagnostic() {
    let config = CpuVerificationConfigPlan::new().unwrap();
    let mut admitted_counts = [[false; 129]; 2];
    for (modulus_index, modulus) in [Q, QHAT].into_iter().enumerate() {
        for count in 1..=128 {
            let air = SourceAir::new(MulDescriptor::new(modulus, count).unwrap());
            let shape = Shape::new(&air).unwrap();
            let lower = Bounds::source_census(shape, config.requested_bytes(), 0).unwrap();
            let lower_total = add(lower.cumulative_requested_bytes, lower.entry_frame_bytes).unwrap();
            let (requested, replay_bytes, replay_measured, admitted) = if lower_total > COMPONENT_BYTES {
                assert_eq!(require(lower_total <= COMPONENT_BYTES, BUDGET), Err(BUDGET));
                (lower_total, 0, false, false)
            } else {
                let replay = recorded_replay(&air);
                let census = Bounds::source_census(shape, config.requested_bytes(), replay.required_host_bytes()).unwrap();
                let total = add(census.cumulative_requested_bytes, census.entry_frame_bytes).unwrap();
                // Current compiled frame layout may differ from historical
                // evidence; this historical-ceiling comparison is not a Plan.
                let admitted = total <= COMPONENT_BYTES;
                (total, replay.required_host_bytes(), true, admitted)
            };
            if admitted {
                admitted_counts[modulus_index][count] = true;
            }
            eprintln!("mul_verifier_admission modulus={modulus} count={count} height={} width={} periodic={} requested_or_lower_bound_bytes={requested} symbolic_replay_bytes={replay_bytes} symbolic_replay_measured={replay_measured} admitted={admitted} wrapper_cap_bytes={COMPONENT_BYTES} proof_execution=false gpu_execution=false",
                shape.height, shape.width, shape.periodic);
        }
    }
    // First native preparation from each accepted canonical N3/N4 leaf.
    // Evidence: canonical-inventory.json in the frozen diagnostic capsule.
    // This reports consequences; it does not split, alter, or retry a batch.
    let canonical = [
        (Q, 32), (Q, 32), (Q, 32), (Q, 32), (Q, 32), (Q, 32), (Q, 32),
        (QHAT, 32), (QHAT, 32), (QHAT, 32), (QHAT, 32), (QHAT, 32), (QHAT, 2),
        (Q, 32), (Q, 32), (Q, 16), (Q, 8),
    ];
    let mut refused_per_transaction = 0;
    for (modulus, count) in canonical {
        let modulus_index = usize::from(modulus == QHAT);
        if !admitted_counts[modulus_index][count] {
            refused_per_transaction += 1;
        }
    }
    for (modulus_index, modulus) in [Q, QHAT].into_iter().enumerate() {
        let admitted_total = admitted_counts[modulus_index].iter().filter(|admitted| **admitted).count();
        eprintln!("mul_verifier_admission_summary modulus={modulus} enumerated_counts=128 admitted_counts={admitted_total} refused_counts={} wrapper_cap_bytes={COMPONENT_BYTES} canonical_inventory_verified=true proof_execution=false gpu_execution=false", 128 - admitted_total);
    }
    eprintln!("mul_verifier_canonical_admission_summary canonical_batches_per_transaction=17 canonical_transactions=7 refused_per_transaction={refused_per_transaction} refused_canonical_batches={} wrapper_cap_bytes={COMPONENT_BYTES} proof_execution=false gpu_execution=false", refused_per_transaction * 7);
}

#[test]
fn mul_owned_verifier_plan32_real_replay_diagnostic() {
    for modulus in [Q, QHAT] {
        let air = SourceAir::new(MulDescriptor::new(modulus, 32).unwrap());
        let replay = recorded_replay(&air);
        let plan = Plan::for_recorded(&air, replay).unwrap();
        let bounds = plan.bounds();
        let required = bounds.cumulative_requested_bytes + bounds.entry_frame_bytes
            + bounds.retaining_caller_frame_bytes;
        assert_eq!(bounds.symbolic_replay_bytes, replay.required_host_bytes());
        assert_eq!(bounds.component_reservation_bytes, required);
        assert!(required > COMPONENT_BYTES && required <= COMPONENT_CEILING_BYTES);
        assert!(required < COMPONENT_CEILING_BYTES); // no flat ceiling claim
        assert_eq!(plan.component_requirement(), Requirements::single(Category::IndependentVerifier,
            Bytes { host: required as u64, device: 0 }));
        // The encompassing192 MiB symbolic preparation claim and its separate
        // pinned64 MiB recorder sublimit are unchanged by verifier sizing.
        assert_eq!(MulPreparationPlan::new(air.kind()).unwrap().host().symbolic_compiler_bytes, 192 << 20);
        eprintln!("mul_verifier_source768 modulus={modulus} count=32 height={} symbolic_replay_bytes={} requested_heap_bytes={} entry_frame_bytes={} retaining_caller_frame_bytes={} exact_reservation_bytes={required} ceiling_bytes={COMPONENT_CEILING_BYTES} admitted=true symbolic_recording_ceiling_bytes={} proof_execution=false gpu_execution=false",
            air.height(), bounds.symbolic_replay_bytes, bounds.cumulative_requested_bytes,
            bounds.entry_frame_bytes, bounds.retaining_caller_frame_bytes, 64 << 20);
    }
}

#[test]
fn mul_owned_verifier_exact_plan_reservation_scales_and_does_not_round_to_ceiling() {
    let mut previous = 0;
    for count in [1, 4, 8, 16] {
        let air = SourceAir::new(MulDescriptor::new(Q, count).unwrap());
        let plan = Plan::for_recorded(&air, recorded_replay(&air)).unwrap();
        let required = plan.bounds().component_reservation_bytes;
        assert!(required > previous && required < COMPONENT_CEILING_BYTES);
        assert_eq!(plan.component_requirement().get(Category::IndependentVerifier).host, required as u64);
        previous = required;
    }
}

/// Real unchanged symbolic recordings for every canonical native batch size.
/// Multiplicities reproduce the frozen per-transaction inventory; MUL Q2 is an
/// extra requested boundary case with zero canonical multiplicity. Recording
/// and exact reservation owners are retired between profiles, never accumulated.
#[test]
fn mul_owned_verifier_canonical_source_admission_diagnostic() {
    let mut canonical_batches = 0;
    for (modulus, count, multiplicity) in [(Q, 2, 0), (Q, 8, 1), (Q, 16, 1), (Q, 32, 9), (QHAT, 2, 1), (QHAT, 32, 5)] {
        let air = SourceAir::new(MulDescriptor::new(modulus, count).unwrap());
        let replay = recorded_replay(&air); // asserts actual recorder cleanup
        let plan = Plan::for_recorded(&air, replay).unwrap();
        let bounds = plan.bounds();
        let required = add(add(bounds.cumulative_requested_bytes, bounds.entry_frame_bytes).unwrap(),
            bounds.retaining_caller_frame_bytes).unwrap();
        assert_eq!(bounds.symbolic_replay_bytes, replay.required_host_bytes());
        assert_eq!(bounds.component_reservation_bytes, required);
        assert!(required > 0 && required < COMPONENT_CEILING_BYTES);
        assert_eq!(COMPONENT_CEILING_BYTES, 768 << 20);
        let requirements = plan.component_requirement();
        assert_eq!(requirements, Requirements::single(Category::IndependentVerifier,
            Bytes { host: required as u64, device: 0 }));
        let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let original = ledger.admit_phase(requirements).unwrap();
        assert!(original.belongs_to(&ledger));
        assert_eq!(original.requirements(), requirements);
        assert_eq!(ledger.snapshot().current, Bytes { host: required as u64, device: 0 });
        assert_eq!(ledger.snapshot().peak, ledger.snapshot().current);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(MulPreparationPlan::new(air.kind()).unwrap().host().symbolic_compiler_bytes, 192 << 20);
        canonical_batches += multiplicity;
        eprintln!("mul_verifier_canonical_source768 modulus={modulus} count={count} canonical_multiplicity={multiplicity} height={} symbolic_replay_bytes={} exact_reservation_bytes={required} ceiling_bytes={COMPONENT_CEILING_BYTES} admitted=true recording_ledger_zero=true reservation_ledger_zero=true proof_execution=false gpu_execution=false",
            air.height(), bounds.symbolic_replay_bytes);
    }
    assert_eq!(canonical_batches, 17);
    eprintln!("mul_verifier_canonical_source768_summary profiles=6 canonical_batches_per_transaction={canonical_batches} canonical_transactions=7 covered_canonical_batches={} proof_execution=false gpu_execution=false complete_workflow_qualification=false", canonical_batches * 7);
}
