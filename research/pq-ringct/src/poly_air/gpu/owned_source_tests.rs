//! Reference-source parity only; the coordinator serializes all validation.
use crate::poly_air::MulAir;
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};
use lattica_prover_p3::block_v2::native_gpu::{
    mul_preparation::{MulDescriptor, MulGeometry, MulPreparationPlan, Q, QHAT},
    mul_recording::{self, MulRecorder},
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_goldilocks::Goldilocks as Val;

#[test]
fn owned_product_terms_and_periodic_values_match_the_unchanged_reference() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 8] {
            let air = MulAir::new(modulus, count).unwrap();
            let descriptor = MulDescriptor::new(modulus, count).unwrap();
            let geometry = MulGeometry::for_kind(descriptor);
            assert_eq!((air.height, air.width(), air.num_public_values(), air.num_periodic_columns()),
                descriptor.geometry_tuple());
            for index in 0..1024 {
                let (factor, negative) = air.term(index / 16, index % 16 / 4, index % 4);
                assert_eq!(descriptor.term(index).unwrap(), [factor, negative as u64]);
            }
            for (column, values) in air.periodic_columns().iter().enumerate() {
                assert_eq!(values.len(), geometry.period());
                for (row, value) in values.iter().enumerate() {
                    assert_eq!(geometry.periodic_value(column, row).unwrap(), *value,
                        "modulus={modulus} count={count} column={column} row={row}");
                }
            }
        }
    }
}

#[test]
fn owned_product_preserves_default_quotient_inference() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 16, 128] {
            let air = MulAir::new(modulus, count).unwrap();
            assert_eq!(air.max_constraint_degree(), None);
            let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(
                &air, AirLayout::from_air::<Val>(&air), 1);
            assert_eq!(1 << (log_chunks + 1), 16);
        }
    }
}

#[test]
fn owned_product_recording_retains_its_original_through_replay() {
    for (modulus, count) in [(Q, 1), (QHAT, 3), (Q, 8)] {
        let air = MulAir::new(modulus, count).unwrap();
        let source = MulPreparationPlan::new(MulDescriptor::new(modulus, count).unwrap()).unwrap();
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let symbolic = source.host().prepared_partition_bytes().unwrap();
        let other = source.host().required_host_bytes() - symbolic + mul_recording::additional_host_bytes();
        let mut requirements = Requirements::single(Category::SymbolicCompiler,
            Bytes { host: symbolic as u64, device: 0 });
        requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
        let mut original = ledger.admit_phase(requirements).unwrap();
        let mut recorder = MulRecorder::begin(source, &mut original, &ledger).unwrap();
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
