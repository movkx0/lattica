//! CPU reference parity, with no native proof or device execution.
use crate::permutation_air::{PermutationAir, PermutationKind, HEIGHT};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};
use lattica_prover_p3::block_v2::native_gpu::{
    permutation_preparation::{PermutationDescriptor, PermutationOperation, PermutationGeometry, PermutationPreparationPlan},
    permutation_recording::{self, PermutationRecorder},
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks as Val;
fn cases() -> [(PermutationOperation, PermutationKind); 2] {
    [(PermutationOperation::AutomorphismQ, PermutationKind::AutomorphismQ),
     (PermutationOperation::InverseChallenge, PermutationKind::InverseChallenge)]
}
#[test]
fn owned_permutation_descriptor_and_schedule_match_unchanged_reference() {
    for (operation, kind) in cases() {
        let air = PermutationAir::new(kind);
        let descriptor = PermutationDescriptor::new(operation);
        let g = PermutationGeometry::for_kind(descriptor);
        assert_eq!((HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns()), descriptor.geometry_tuple());
        let sources = descriptor.sources();
        let factors = descriptor.factors();
        for index in 0..256 {
            assert_eq!(sources[index], air.source_index(index) as u64);
            assert_eq!(factors[index], air.factor(index).as_canonical_u64());
        }
        for (column, values) in air.periodic_columns().iter().enumerate() {
            assert_eq!(values.len(), g.period());
            for (row, value) in values.iter().enumerate() { assert_eq!(g.periodic_value(column, row).unwrap(), *value); }
        }
    }
}
#[test]
fn owned_permutation_preserves_default_quotient_inference() {
    for (_, kind) in cases() {
        let air = PermutationAir::new(kind);
        assert_eq!(air.max_constraint_degree(), None);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&air, AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), 16);
    }
}
#[test]
fn owned_permutation_recording_replay_keeps_original_backing() {
    for (operation, kind) in cases() {
        let air = PermutationAir::new(kind);
        let source = PermutationPreparationPlan::new(PermutationDescriptor::new(operation)).unwrap();
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let symbolic = source.host().prepared_partition_bytes().unwrap();
        let other = source.host().required_host_bytes() - symbolic + permutation_recording::additional_host_bytes();
        let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
        requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
        let mut original = ledger.admit_phase(requirements).unwrap();
        let mut recorder = PermutationRecorder::begin(source, &mut original, &ledger).unwrap();
        air.eval(recorder.builder_mut());
        let prepared = recorder.finish().unwrap();
        assert_eq!(prepared.census(), source);
        assert_eq!(prepared.symbolic_replay_census().geometry(), source.geometry());
        assert!(prepared.symbolic_replay_census().required_host_bytes() > 0);
        assert!(prepared.constraints() > 0);
        assert!(prepared.reservation().belongs_to(&ledger));
        drop(prepared); drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
