//! CPU-only parity checks of the exact existing AIR/source schedule.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{linear_map_preparation::{LinearMapDescriptor as OwnedDescriptor,
    LinearMapGeometry, LinearMapPreparationPlan}, linear_map_recording::LinearMapRecorder};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};
#[test]
fn owned_linear_map_source_matches_original_all_columns_and_rows() {
    for n in [1, 3, 16] {
        for kind in [PolynomialKind::Canonical { modulus: Q }, PolynomialKind::Canonical { modulus: QHAT },
            PolynomialKind::Signed { bound: 17 }] {
            let mut coefficients = vec![[1;D];n]; coefficients[0][252] = -2;
            let mut constant = [0;D]; constant[255] = 3;
            let source = LinearMapDescriptor::new(vec![kind;n],kind,coefficients,constant).unwrap();
            let kinds: Vec<_> = source.inputs.iter().chain(core::iter::once(&source.output)).map(|kind| match kind {
                PolynomialKind::Canonical { modulus } => [*modulus,0], PolynomialKind::Signed { bound } => [0,u64::from(*bound)] }).collect();
            let owned = OwnedDescriptor::new(&kinds, &source.coefficients, &source.constant).unwrap();
            let geometry = LinearMapGeometry::for_kind(owned);
            let air = LinearMapAir::new(source);
            assert_eq!(geometry.kind().bits(),air.bits());
            assert_eq!(geometry.kind().quotient_bound(),air.descriptor.quotient_bound);
            assert_eq!((geometry.rows(),geometry.width(),geometry.public_values(),geometry.periodic_columns()),
                (air.height(),air.width(),air.public_values(),air.periodic_count()));
            let original = air.periodic_columns();
            for index in 0..air.periodic_count() {
                let len = geometry.column_len(index).unwrap();
                assert_eq!(Some(len),air.column_len(index)); assert_eq!(len,original[index].len());
                for row in 0..air.height() { assert_eq!(geometry.periodic_value(index,row).unwrap(),air.gpu_periodic_value(index,row)); }
            }
        }
    }
}
#[test]
fn owned_linear_map_recording_keeps_default_degree_and_original_claim() {
    let kind = PolynomialKind::Signed { bound: 3 };
    let air = LinearMapAir::new(LinearMapDescriptor::new(vec![kind;2],kind,vec![[1;D];2],[0;D]).unwrap());
    assert_eq!(air.max_constraint_degree(),None);
    let kind = OwnedDescriptor::new(&[[0,3];3],&[[1;D];2],&[0;D]).unwrap();
    let plan = LinearMapPreparationPlan::new(kind).unwrap();
    let symbolic = plan.host().prepared_partition_bytes().unwrap();
    let other = plan.host().required_host_bytes() - symbolic
        + lattica_prover_p3::block_v2::native_gpu::linear_map_recording::additional_host_bytes();
    let ledger = Ledger::new(WorkerAllowance {host:32<<30,device:0});
    let mut requirements = Requirements::single(Category::SymbolicCompiler,Bytes{host:symbolic as u64,device:0});
    requirements.add(Category::PhaseScratch,Bytes{host:other as u64,device:0}).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let before = ledger.snapshot();
    let mut recorder = LinearMapRecorder::begin(plan,&mut original,&ledger).unwrap();
    air.eval(recorder.builder_mut());
    let recorded = recorder.finish().unwrap();
    assert!(recorded.constraints()>0); assert_eq!(recorded.census(),plan);
    drop(recorded); assert_eq!(ledger.snapshot().current,before.current);
    drop(original); assert_eq!(ledger.snapshot().current,Bytes::ZERO);
}

#[test]
fn owned_linear_map_preserves_original_quotient_inference() {
    use p3_air::symbolic::AirLayout;
    for kind in [PolynomialKind::Canonical{modulus:Q},PolynomialKind::Canonical{modulus:QHAT},PolynomialKind::Signed{bound:3}] {
        let air=LinearMapAir::new(LinearMapDescriptor::new(vec![kind;2],kind,vec![[1;D];2],[0;D]).unwrap());
        assert_eq!(air.max_constraint_degree(),None);
        let log=p3_uni_stark::get_log_num_quotient_chunks::<Val,_>(&air,AirLayout::from_air::<Val>(&air),1);
        assert_eq!(1<<(log+1),16);
    }
}
