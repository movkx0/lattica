use super::*;
use crate::block_v2::profile::Challenge;
use crate::spill_alloc::allocation_requests::measure;
use p3_air::symbolic::{
    get_max_constraint_degree_extension, get_symbolic_constraints, AirLayout, SymbolicAirBuilder,
};

fn check<A>(name: &str, hinted: DegreeAir<A>)
where
    A: Air<SymbolicAirBuilder<Val>> + Air<SymbolicAirBuilder<Val, Challenge>>,
{
    let original = &hinted.0;
    assert_eq!(original.max_constraint_degree(), None);
    let layout = AirLayout::from_air::<Val>(original);
    let degree = get_max_constraint_degree_extension::<Val, Val, A>(original, layout);
    let extension_degree =
        get_max_constraint_degree_extension::<Val, Challenge, A>(original, layout);
    let constraints = get_symbolic_constraints::<Val, A>(original, layout).len();
    assert_eq!(degree, CONSTRAINT_DEGREE);
    assert_eq!(extension_degree, CONSTRAINT_DEGREE);
    assert_eq!(hinted.max_constraint_degree(), Some(degree));
    assert_eq!(hinted.width(), original.width());
    assert_eq!(hinted.num_public_values(), original.num_public_values());
    assert_eq!(
        hinted.num_periodic_columns(),
        original.num_periodic_columns()
    );
    assert_eq!(hinted.preprocessed_width(), original.preprocessed_width());
    assert_eq!(hinted.num_constraints(), original.num_constraints());
    assert_eq!(
        hinted.main_next_row_columns(),
        original.main_next_row_columns()
    );
    assert_eq!(
        hinted.preprocessed_next_row_columns(),
        original.preprocessed_next_row_columns()
    );
    assert!(hinted.preprocessed_trace().is_none());
    assert!(original.preprocessed_trace().is_none());
    assert_eq!(hinted.periodic_columns(), original.periodic_columns());

    for is_zk in [0, 1] {
        let (reference_log, reference) = measure(|| {
            p3_uni_stark::get_log_num_quotient_chunks::<Val, A>(original, layout, is_zk)
        });
        let (hinted_log, requests) = measure(|| {
            p3_uni_stark::get_log_num_quotient_chunks::<Val, DegreeAir<A>>(&hinted, layout, is_zk)
        });
        assert!(!reference.overflow && !requests.overflow);
        assert_eq!(reference_log, 3);
        assert_eq!(hinted_log, reference_log);
        assert!(reference.calls > 0);
        if !cfg!(debug_assertions) {
            assert_eq!(requests.calls, 0);
            assert_eq!(requests.bytes, 0);
        }
        println!(
            "wallet_verifier_degree air={name} zk={is_zk} constraints={constraints} degree={degree} extension_degree={extension_degree} log_chunks={hinted_log} reference_bytes={} reference_allocations={} hinted_bytes={} hinted_allocations={} debug_assertions={}",
            reference.bytes, reference.calls, requests.bytes, requests.calls, cfg!(debug_assertions)
        );
    }
}

#[test]
fn verifier_hint_matches_original_symbolic_degree_without_release_allocations() {
    check("join_split", join_split());
    check("htlc", htlc());
    check("issuance", issuance());
}
