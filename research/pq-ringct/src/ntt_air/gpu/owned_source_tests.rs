//! CPU source parity for the closed core NTT path; no proof or GPU dispatch.
use crate::ntt_air::NttAir;
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};
use lattica_prover_p3::block_v2::native_gpu::{
    ntt_preparation::{NttDescriptor, NttGeometry, NttPreparationPlan, Q, QHAT},
    ntt_recording::{self, NttRecorder},
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_goldilocks::Goldilocks as Val;

#[test]
fn owned_ntt_schedule_and_periodic_values_match_unchanged_reference() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 8] {
            let air = NttAir::new(modulus, count).unwrap();
            let descriptor = NttDescriptor::new(modulus, count).unwrap();
            let geometry = NttGeometry::for_kind(descriptor);
            assert_eq!((air.height, air.width(), air.num_public_values(), air.num_periodic_columns()),
                descriptor.geometry_tuple());
            let steps = air.steps();
            for (index, expected) in steps.iter().enumerate() {
                assert_eq!(descriptor.step(index).unwrap(),
                    [expected.a as u64, expected.b as u64, expected.factor_u, expected.factor_v]);
            }
            let expected_permutation = if modulus == Q { crate::rust_verify::constants::PERM_NTT }
                else { core::array::from_fn(|i| i as u64) };
            assert_eq!(descriptor.permutation(), expected_permutation);
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
fn owned_ntt_metadata_preserves_default_quotient_including_maximum_counts() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 64, 128] {
            let air = NttAir::new(modulus, count).unwrap();
            assert_eq!(air.max_constraint_degree(), None);
            let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(
                &air, AirLayout::from_air::<Val>(&air), 1);
            // This compares the unchanged AIR's real inference; the core
            // continuation supplies no degree hint to manufacture this value.
            assert_eq!(1 << (log_chunks + 1), 16);
        }
    }
}

#[test]
fn owned_ntt_source_recording_replay_remains_under_same_original() {
    for (modulus, count) in [(Q, 1), (QHAT, 3), (Q, 8)] {
        let air = NttAir::new(modulus, count).unwrap();
        let source = NttPreparationPlan::new(NttDescriptor::new(modulus, count).unwrap()).unwrap();
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
        let symbolic = source.host().prepared_partition_bytes().unwrap();
        let other = source.host().required_host_bytes() - symbolic + ntt_recording::additional_host_bytes();
        let mut requirements = Requirements::single(Category::SymbolicCompiler,
            Bytes { host: symbolic as u64, device: 0 });
        requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
        let mut original = ledger.admit_phase(requirements).unwrap();
        let mut recorder = NttRecorder::begin(source, &mut original, &ledger).unwrap();
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
