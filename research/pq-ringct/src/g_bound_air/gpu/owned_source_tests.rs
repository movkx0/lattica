//! CPU reference parity, with no native proof or device execution.
use crate::g_bound_air::{GBoundAir, HEIGHT};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};
use lattica_prover_p3::block_v2::native_gpu::{
    g_bound_preparation::{GBoundDescriptor, GBoundGeometry, GBoundPreparationPlan},
    g_bound_recording::{self, GBoundRecorder},
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks as Val;

#[test]
fn owned_g_bound_descriptor_and_schedule_match_unchanged_reference() {
    for bound in [6_825_771, 1_137_628] {
        let air = GBoundAir::new(bound).unwrap();
        let descriptor = GBoundDescriptor::new(bound).unwrap();
        let g = GBoundGeometry::for_kind(descriptor);
        assert_eq!((HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns()),
            descriptor.geometry_tuple());
        assert_eq!(descriptor.f_bound(), air.f_bound());
        assert_eq!(descriptor.g_bound(), air.g_bound());
        assert_eq!(descriptor.maximum_integer_difference(), air.maximum_integer_difference());
        let psi = Val::two_adic_generator(9);
        assert_eq!(descriptor.psi_128(), psi.exp_u64(128).as_canonical_u64());
        assert_eq!(descriptor.inverse_psi_128(), psi.inverse().exp_u64(128).as_canonical_u64());
        let schedule = descriptor.schedule();
        for (column, values) in air.periodic_columns().iter().enumerate() {
            assert_eq!(values.len(), g.period());
            for (row, value) in values.iter().enumerate() {
                assert_eq!(g.periodic_value(column, row).unwrap(), *value);
                assert_eq!(schedule[column * 128 + row], value.as_canonical_u64());
            }
        }
    }
}

#[test]
fn owned_g_bound_preserves_default_quotient_inference() {
    for bound in [6_825_771, 1_137_628] {
        let air = GBoundAir::new(bound).unwrap();
        assert_eq!(air.max_constraint_degree(), None);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(
            &air, AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), 16);
    }
}

#[test]
fn owned_g_bound_recording_replay_keeps_original_backing() {
    for bound in [6_825_771, 1_137_628] {
        let air = GBoundAir::new(bound).unwrap();
        let source = GBoundPreparationPlan::new(GBoundDescriptor::new(bound).unwrap()).unwrap();
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let symbolic = source.host().prepared_partition_bytes().unwrap();
        let other = source.host().required_host_bytes() - symbolic + g_bound_recording::additional_host_bytes();
        let mut requirements = Requirements::single(Category::SymbolicCompiler,
            Bytes { host: symbolic as u64, device: 0 });
        requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
        let mut original = ledger.admit_phase(requirements).unwrap();
        let mut recorder = GBoundRecorder::begin(source, &mut original, &ledger).unwrap();
        air.eval(recorder.builder_mut());
        let prepared = recorder.finish().unwrap();
        assert_eq!(prepared.census(), source);
        assert_eq!(prepared.symbolic_replay_census().geometry(), source.geometry());
        assert!(prepared.symbolic_replay_census().required_host_bytes() > 0);
        assert!(prepared.constraints() > 0);
        assert!(prepared.reservation().belongs_to(&ledger));
        drop(prepared);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
