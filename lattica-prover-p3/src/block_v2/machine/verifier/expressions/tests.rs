use super::*;

#[test]
fn borrowed_and_repeated_values_match_materialized_indexing() {
    let pattern = [[Wire(1), Wire(2), Wire(3)], [Wire(3), Wire(1), Wire(2)]];
    for width in 0..=pattern.len() {
        for copies in [0, 1, 2, 9] {
            let materialized = pattern[..width].repeat(copies);
            let repeated = Values::repeat(&pattern[..width], copies).unwrap();
            let borrowed = Values::Slice(&materialized);
            for index in (0..=materialized.len()).chain([usize::MAX]) {
                assert_eq!(repeated.get(index), materialized.get(index));
                assert_eq!(borrowed.get(index), materialized.get(index));
            }
        }
    }
    assert!(Values::repeat(&pattern, usize::MAX).is_err());
    // Empty patterns remain empty without indexing or modulo panics.
    assert!(Values::repeat(&[], usize::MAX).unwrap().get(0).is_none());
}

#[test]
fn periodic_output_geometry_and_quotient_bounds_reject_before_emission() {
    let mut b = ProgramBuilder::new(0).unwrap();
    let zeta = [Wire(0); 3];
    assert!(periodic_values_into(
        &mut b,
        &[vec![Val::ONE]],
        zeta,
        3,
        Constants::cpu(),
        &mut []
    )
    .is_err());
    assert!(
        periodic_values_into(&mut b, &[], zeta, usize::MAX, Constants::cpu(), &mut []).is_err()
    );
    let chunks = vec![vec![zeta; 3]; super::super::pcs::MAX_MATRICES * 2];
    assert!(quotient_with_constants(&mut b, &chunks, zeta, 3, Constants::cpu()).is_err());
    assert_eq!(
        b.finish(None).unwrap(),
        ProgramBuilder::new(0).unwrap().finish(None).unwrap()
    );
}
