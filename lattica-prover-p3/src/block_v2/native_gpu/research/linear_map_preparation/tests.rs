use super::*;
use crate::block_v2::native_gpu::arithmetic::ArithmeticSpec;
#[test]
fn bounded_linear_map_descriptor_matches_unchanged_six_buffer_spec() {
    for n in [1, 2, 3, 7, 16] {
        for kind in [[Q, 0], [QHAT, 0], [0, 17]] {
            let kinds = vec![kind; n + 1];
            let coefficients = vec![[1; D]; n];
            let descriptor = LinearMapDescriptor::new(&kinds, &coefficients, &[0; D]).unwrap();
            let plan = LinearMapPreparationPlan::new(descriptor).unwrap();
            let g = plan.geometry();
            let spec = ArithmeticSpec::linear_map(descriptor.kinds(), descriptor.coefficients(),
                descriptor.constant(), descriptor.bits(), descriptor.quotient_bound()).unwrap();
            assert_eq!((g.rows(), g.width(), g.raw_words()), (spec.rows(), spec.width(), spec.raw_input_words()));
            assert_eq!(g.public_values(), 4 * (n + 1));
            assert_eq!(g.periodic_columns(), 5 * n + 6 + if kind[0] == 0 { 2 } else { 0 });
            let d = plan.device();
            assert_eq!(d.trace_bytes, g.rows() * g.width() * 8);
            assert_eq!(d.public_bytes, g.public_values() * 8);
            assert_eq!(d.raw_bytes, 256 * n * 8);
            assert_eq!(d.geometry_bytes, (32 + 2 * (n + 1) + 256 * n + 256) * 8);
            assert_eq!(d.endpoint_bytes, g.public_values() * 8);
            assert_eq!(d.status_bytes, 8);
            assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
        }
    }
}
#[test]
fn canonical_normalization_and_exact_identity_are_constructor_bound() {
    let a = LinearMapDescriptor::new(&[[Q,0];2], &[[Q as i64 + 1;D]], &[Q as i64 - 1;D]).unwrap();
    let b = LinearMapDescriptor::new(&[[Q,0];2], &[[1;D]], &[-1;D]).unwrap();
    let c = LinearMapDescriptor::new(&[[Q,0];2], &[[1;D]], &[0;D]).unwrap();
    assert_eq!(a,b); assert_eq!(a.identity(),b.identity()); assert_ne!(b,c); assert_ne!(b.identity(),c.identity());
    assert_eq!(a.bits(),28); assert_eq!(a.coefficients()[0],[1;D]);
}
#[test]
fn invalid_kinds_and_noninjective_integer_embeddings_are_refused() {
    assert!(LinearMapDescriptor::new(&[], &[], &[0;D]).is_err());
    assert!(LinearMapDescriptor::new(&[[Q,0];18], &[[1;D];17], &[0;D]).is_err());
    for kinds in [[[Q,0],[QHAT,0]], [[Q,1],[Q,1]], [[0,0],[0,1]], [[0,1],[0,i32::MAX as u64+1]]] {
        assert!(LinearMapDescriptor::new(&kinds,&[[1;D]],&[0;D]).is_err());
    }
    assert!(LinearMapDescriptor::new(&[[0,3];2], &[[i64::MAX;D]], &[0;D]).is_err());
    assert!(LinearMapDescriptor::new(&[[QHAT,0];2], &[[QHAT as i64 / 2;D]], &[0;D]).is_ok());
    assert!(LinearMapDescriptor::new(&[[QHAT,0];3], &[[QHAT as i64 / 2;D];2], &[0;D]).is_err());
}
#[test]
fn periodic_columns_use_exact_minimal_powers_of_two() {
    let mut coefficients = [[1;D];2]; coefficients[0][252] = 2;
    let d = LinearMapDescriptor::new(&[[0,1],[0,2],[0,3]], &coefficients, &[0;D]).unwrap();
    assert_eq!(d.bounds(), &[0,1,2,3]);
    let g = LinearMapGeometry::for_kind(d);
    assert_eq!(g.rows(),256); assert_eq!(g.column_len(0),Ok(4));
    assert_eq!(g.column_len(4),Ok(256)); assert_eq!(g.column_len(5),Ok(1));
    assert_eq!(g.column_len(12),Ok(1));
    for column in 0..g.periodic_columns() {
        let period = g.column_len(column).unwrap();
        assert!(period.is_power_of_two());
        for row in 0..g.rows() { assert_eq!(g.periodic_value(column,row),g.periodic_value(column,row%period)); }
        if period > 1 { assert!((0..period/2).any(|row| g.periodic_value(column,row) != g.periodic_value(column,row+period/2))); }
    }
    assert!(g.column_len(g.periodic_columns()).is_err()); assert!(g.periodic_value(0,g.rows()).is_err());
}
