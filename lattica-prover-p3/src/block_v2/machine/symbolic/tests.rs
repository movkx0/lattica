use super::*;
use crate::block_v2::machine::{fingerprint, programs};
use p3_air::{PermutationAirBuilder, WindowAccess};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder, InteractionSymbolicBuilder, Lookups};

struct Synthetic;
impl BaseAir<Val> for Synthetic {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
}
impl<AB: PermutationAirBuilder<F = Val, EF = Challenge> + InteractionBuilder> Air<AB>
    for Synthetic
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let x: AB::Expr = m.current_slice()[0].into();
        let y: AB::Expr = m.current_slice()[1].into();
        let shared = (x.clone() + y.clone()).square();
        let zero = AB::Expr::from(Val::NEG_ONE) + AB::Expr::ONE;
        let one = AB::Expr::from_u64(11) - AB::Expr::from_u64(10);
        b.assert_zero(shared.clone() * one.clone() + zero.clone());
        b.assert_zero(zero.clone() - shared.clone());
        b.assert_zero(-(-shared.clone()));
        b.assert_zero(shared.clone() * zero.clone());
        let v = Challenge::from_basis_coefficients_slice(&[Val::ONE, Val::TWO, Val::ONE]).unwrap();
        let e = AB::ExprEF::from(v);
        b.assert_zero_ext(e.clone() * AB::ExprEF::ZERO);
        b.assert_zero(shared.clone() + x);
        b.assert_zero_ext(e.clone() + AB::ExprEF::from(Challenge::ZERO));
        b.assert_zero_ext(AB::ExprEF::from(zero.clone()) - e.clone());
        b.assert_zero_ext(AB::ExprEF::from(Challenge::ONE) * e);
        let periodic: AB::Expr = b.periodic_values()[0].into();
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_zero(periodic - public);
        b.push_interaction(
            "second",
            [shared.clone(), y.clone()],
            Count::bounded(one.clone(), u32::MAX),
        );
        b.push_interaction("first", [y.clone()], Count::bounded(zero.clone(), 2));
        b.push_interaction("second", [shared, y.clone()], Count::bounded(one, 4));
        b.push_local_interaction([(vec![y], -zero.clone())]);
    }
}

fn same(selected: &Constraints, reference: &Constraints) {
    assert_eq!(selected.order.base_indices, reference.order.base_indices);
    assert_eq!(selected.order.ext_indices, reference.order.ext_indices);
    assert_eq!(selected.max_degree(), reference.max_degree());
    let actual = fingerprint::encode(&selected.base, &selected.extension, &selected.order);
    let expected = fingerprint::encode(&reference.base, &reference.extension, &reference.order);
    assert!(
        actual == expected,
        "canonical DAG differs: lengths {} and {}, first mismatch {:?}",
        actual.len(),
        expected.len(),
        actual.iter().zip(&expected).position(|(a, b)| a != b)
    );
}
fn native<A: BaseAir<Val> + Air<InteractionSymbolicBuilder<Val, Challenge>>>(
    air: &A,
    lookups: &[Lookup<Val>],
) -> Constraints {
    let layout = AirLayout::from_air::<Val>(air);
    let (base, extension) = p3_batch_stark::symbolic::get_symbolic_constraints(
        air,
        layout,
        lookups,
        &LogUpGadget::new(),
    );
    let order =
        p3_batch_stark::symbolic::get_constraint_layout(air, layout, lookups, &LogUpGadget::new());
    Constraints {
        base,
        extension,
        order,
    }
}
pub(super) fn lookup_encoding(lookups: &[Lookup<Val>]) -> Vec<(Kind, u32, usize, Vec<Vec<u64>>)> {
    lookups
        .iter()
        .map(|l| {
            let mut fields = Vec::new();
            for e in &l.elements {
                let order = ConstraintLayout {
                    base_indices: (0..e.len()).collect(),
                    ext_indices: vec![],
                };
                fields.push(fingerprint::encode(e, &[], &order));
            }
            let order = ConstraintLayout {
                base_indices: (0..l.multiplicities.len()).collect(),
                ext_indices: vec![],
            };
            fields.push(fingerprint::encode(&l.multiplicities, &[], &order));
            (l.kind.clone(), l.count_weight, l.column, fields)
        })
        .collect()
}

#[test]
fn symbolic_cpu_normalization_preserves_pinned_simplification_and_lookup_packing() {
    let selected = lookups(&Synthetic, Constants::cpu()).unwrap();
    let reference = Lookups::from_air::<Challenge, _>(&Synthetic);
    assert_eq!(lookup_encoding(&selected), lookup_encoding(&reference));
    same(
        &batch(&Synthetic, &selected, Constants::cpu()).unwrap(),
        &native(&Synthetic, &reference),
    );
    for degree in [1, 2, 3, 4, 8, 16, 32] {
        let selected = pack(selected.clone(), degree);
        let reference = reference.clone().pack_same_bus(&LogUpGadget::new(), degree);
        assert_eq!(lookup_encoding(&selected), lookup_encoding(&reference));
        same(
            &batch(&Synthetic, &selected, Constants::cpu()).unwrap(),
            &native(&Synthetic, &reference),
        );
    }
}

#[test]
fn symbolic_machine_graph_preserves_native_dag_identity_and_degrees() {
    let air = programs::shape(64).unwrap();
    let selected = lookups(&air, Constants::cpu()).unwrap();
    let reference = Lookups::from_air::<Challenge, _>(&air);
    assert_eq!(lookup_encoding(&selected), lookup_encoding(&reference));
    let raw = batch(&air, &selected, Constants::cpu()).unwrap();
    same(&raw, &native(&air, &reference));
    let chunks = log_chunks(raw.max_degree());
    let reference_chunks =
        p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
            &air,
            AirLayout::from_air::<Val>(&air),
            &reference,
            1,
            &LogUpGadget::new(),
        );
    assert_eq!(chunks, reference_chunks);
    let selected = pack(selected, 1 << chunks);
    let reference = reference.pack_same_bus(&LogUpGadget::new(), 1 << chunks);
    assert_eq!(lookup_encoding(&selected), lookup_encoding(&reference));
    same(
        &batch(&air, &selected, Constants::cpu()).unwrap(),
        &native(&air, &reference),
    );
}

pub(crate) fn conformance(constants: Constants<'_>) {
    for height in [8, 64, 2048] {
        let air = programs::shape(height).unwrap();
        let selected = prepare_machine(&air, constants).unwrap();
        let reference = prepare_machine(&air, Constants::cpu()).unwrap();
        assert_eq!(selected.log_chunks, reference.log_chunks);
        assert_eq!(
            lookup_encoding(&selected.lookups),
            lookup_encoding(&reference.lookups)
        );
        same(&selected.constraints, &reference.constraints);
        let analysis = super::super::analysis::analyze_prepared(&air, &selected).unwrap();
        let reference = super::super::analysis::analyze(&air).unwrap();
        assert_eq!(analysis.quotient_chunks, reference.quotient_chunks);
        assert_eq!(
            analysis.max_constraint_degree,
            reference.max_constraint_degree
        );
        assert_eq!(analysis.constraints, reference.constraints);
        assert_eq!(
            analysis.permutation_width_base,
            reference.permutation_width_base
        );
        assert_eq!(
            analysis.query_multiplicity_bound,
            reference.query_multiplicity_bound
        );
        assert_eq!(analysis.retained_lde_bytes, reference.retained_lde_bytes);
        assert_eq!(analysis.fri_ali_bits, reference.fri_ali_bits);
        let template =
            super::super::verifier::template::batch_with_constants(&air, constants).unwrap();
        let reference = super::super::verifier::template::batch(&air).unwrap();
        assert_eq!(
            serde_json::to_vec(&template).unwrap(),
            serde_json::to_vec(&reference).unwrap(),
            "registration template differs at height {height}"
        );
    }
    let synthetic = lookups(&Synthetic, constants).unwrap();
    let reference = Lookups::from_air::<Challenge, _>(&Synthetic);
    for degree in [1, 4, 16, 32] {
        let selected = pack(synthetic.clone(), degree);
        let reference = reference.clone().pack_same_bus(&LogUpGadget::new(), degree);
        assert_eq!(lookup_encoding(&selected), lookup_encoding(&reference));
        same(
            &batch(&Synthetic, &selected, constants).unwrap(),
            &native(&Synthetic, &reference),
        );
    }
    fn wallet<A>(air: &A, constants: Constants<'_>)
    where
        A: BaseAir<Val> + Air<Builder> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>>,
    {
        let (selected, chunks) = prepare_uni(air, constants).unwrap();
        let (reference, reference_chunks) = native_uni(air);
        assert_eq!(chunks, reference_chunks);
        let order = || ConstraintLayout {
            base_indices: (0..selected.len()).collect(),
            ext_indices: vec![],
        };
        let actual = fingerprint::encode(&selected, &[], &order());
        let expected = fingerprint::encode(&reference, &[], &order());
        assert!(
            actual == expected,
            "wallet symbolic DAG mismatch: lengths {} and {}, first difference {:?}",
            actual.len(),
            expected.len(),
            actual.iter().zip(&expected).position(|(a, b)| a != b)
        );
    }
    wallet(&crate::joinsplit_air::JoinSplitAir, constants);
    wallet(&crate::htlc_air::HtlcAir, constants);
}

pub(crate) fn reject_geometry(constants: Constants<'_>) {
    lookup::tests::reject_allowance(!matches!(constants, Constants::Cpu(None)));
    normalize::tests::reject_allowance(constants);
    use expression::Base;
    use p3_air::AirBuilder;
    // Even discarded over-deep intermediates invalidate the entire recording,
    // before normalization can fold the later constant constraint.
    struct Discarded;
    impl BaseAir<Val> for Discarded {
        fn width(&self) -> usize {
            0
        }
    }
    impl Air<Builder> for Discarded {
        fn eval(&self, builder: &mut Builder) {
            let mut discarded = Base::ONE;
            for _ in 0..=recording::MAX_DEPTH {
                discarded = -discarded;
            }
            drop(discarded);
            builder.assert_zero(Base::ONE + Base::ONE);
        }
    }
    assert!(matches!(
        uni(&Discarded, constants),
        Err(CompileError::Shape("symbolic recording allowance"))
    ));
    assert!(matches!(
        batch(&Discarded, &[], constants),
        Err(CompileError::Shape("symbolic recording allowance"))
    ));
    assert!(matches!(
        lookups(&Discarded, constants),
        Err(CompileError::Shape("symbolic recording allowance"))
    ));
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    let mut e = Base::ONE;
    for _ in 0..514 {
        e = e + Base::ONE;
    }
    builder.assert_zero(e);
    assert!(matches!(
        finish(&builder, constants),
        Err(CompileError::Shape(_))
    ));
    // The shallow root is visited first. Its shared descendants must still be
    // checked when the other root reaches them through a longer path.
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    let mut shared = Base::ONE;
    for _ in 0..300 {
        shared = shared + Base::ONE;
    }
    let mut deep = shared.clone();
    for _ in 0..220 {
        deep = deep + Base::ONE;
    }
    builder.assert_zero(deep);
    builder.assert_zero(shared);
    assert!(matches!(
        finish(&builder, constants),
        Err(CompileError::Shape(_))
    ));
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    builder.base = vec![Base::ONE.0; MAX_NODES + 1];
    assert!(matches!(
        finish(&builder, constants),
        Err(CompileError::Shape(_))
    ));
    // Small shared DAGs can have exponentially growing polynomial degrees.
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    let mut e = builder.is_first_row();
    for _ in 0..usize::BITS {
        e = e.square();
    }
    builder.assert_zero(e);
    assert!(matches!(
        finish(&builder, constants),
        Err(CompileError::Shape("symbolic degree overflow"))
    ));
}

#[test]
fn symbolic_geometry_rejects_before_arithmetic_and_degree_metadata_cannot_overflow() {
    use crate::proving::{Capabilities, Profile, Request, Run};
    let run = Run::new(
        "symbolic_admission",
        Request::compatible(),
        Capabilities::cpu(Profile::BlockV2Cubic, true, true),
    )
    .unwrap();
    reject_geometry(Constants::cpu_reported(&run));
    assert!(run.finish(false).unwrap().observations.is_empty());
    assert_eq!(log_chunks(0), 0);
    assert_eq!(log_chunks(1), 0);
    assert_eq!(log_chunks(usize::MAX), usize::BITS as usize);
}
