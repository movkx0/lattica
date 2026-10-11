use super::super::{tests::lookup_encoding, Challenge};
use super::*;
use p3_air::{
    symbolic::{BaseEntry, BaseLeaf, SymbolicVariable},
    Air, BaseAir,
};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{
    Count, InteractionBuilder, InteractionSymbolicBuilder, LogUpGadget, LookupProtocol,
};
use std::sync::Arc;

// Frozen public replay path used before the bounded implementation. The
// upstream packer remains unchanged in the local dependency.
struct Replay(Vec<Lookup<Val>>);
impl BaseAir<Val> for Replay {
    fn width(&self) -> usize {
        0
    }
}
impl Air<InteractionSymbolicBuilder<Val, Challenge>> for Replay {
    fn eval(&self, builder: &mut InteractionSymbolicBuilder<Val, Challenge>) {
        for lookup in &self.0 {
            match &lookup.kind {
                Kind::Local => builder.push_local_interaction(
                    lookup
                        .elements
                        .iter()
                        .cloned()
                        .zip(lookup.multiplicities.iter().cloned()),
                ),
                Kind::Global(bus) => builder.push_interaction(
                    bus,
                    lookup.elements[0].iter().cloned(),
                    Count::bounded(lookup.multiplicities[0].clone(), lookup.count_weight),
                ),
            }
        }
    }
}
fn global(bus: &str, fields: Vec<BaseExpr>, count: BaseExpr, weight: u32) -> Lookup<Val> {
    Lookup {
        kind: Kind::Global(bus.into()),
        elements: vec![fields],
        multiplicities: vec![count],
        count_weight: weight,
        column: 99,
    }
}
fn local() -> Lookup<Val> {
    Lookup {
        kind: Kind::Local,
        elements: vec![vec![variable()]],
        multiplicities: vec![BaseExpr::ONE],
        count_weight: 0,
        column: 99,
    }
}
fn variable() -> BaseExpr {
    SymbolicExpr::Leaf(BaseLeaf::Variable(SymbolicVariable::new(
        BaseEntry::Main { offset: 0 },
        0,
    )))
}
fn inputs() -> Vec<Lookup<Val>> {
    let shared = variable().square();
    vec![
        global("second", vec![shared.clone()], BaseExpr::ONE, u32::MAX),
        local(),
        global("first", vec![variable(), shared.clone()], variable(), 3),
        global("second", vec![shared], BaseExpr::ONE, 9),
        global("first", vec![], BaseExpr::ONE, 1),
        Lookup {
            elements: vec![],
            multiplicities: vec![],
            ..local()
        },
    ]
}
pub(crate) fn reject_allowance(report: bool) {
    let storage = Storage::lookup_limited(0, report);
    assert!(matches!(
        with_storage(inputs(), 4, &storage),
        Err(CompileError::Shape("symbolic lookup packing allowance"))
    ));
    assert!(storage.capacity::<u64>(0).is_err());
}

#[test]
fn owned_constructor_preserves_arrays_and_shared_arcs_without_replay() {
    let mut values = vec![global("bus", vec![variable().square()], BaseExpr::ONE, 1)];
    values[0].column = 0;
    let outer = values.as_ptr();
    let fields = values[0].elements[0].as_ptr();
    let SymbolicExpr::Mul { x, .. } = &values[0].elements[0][0] else {
        unreachable!()
    };
    let child = Arc::as_ptr(x);
    let references = Arc::strong_count(x);
    let owned = Lookups::try_from_ordered(values).unwrap();
    assert_eq!(owned.as_ptr(), outer);
    assert_eq!(owned[0].elements[0].as_ptr(), fields);
    let SymbolicExpr::Mul { x, .. } = &owned[0].elements[0][0] else {
        unreachable!()
    };
    assert_eq!(Arc::as_ptr(x), child);
    assert_eq!(Arc::strong_count(x), references);
}

#[test]
fn owned_constructor_rejects_inconsistent_metadata() {
    let mut one = local();
    one.column = 0;
    let mut bad = one.clone();
    bad.column = 1;
    assert!(Lookups::try_from_ordered(vec![bad]).is_err());
    let mut bad = one.clone();
    bad.multiplicities.clear();
    assert!(Lookups::try_from_ordered(vec![bad]).is_err());
    let mut bad = one.clone();
    bad.count_weight = 1;
    assert!(Lookups::try_from_ordered(vec![bad]).is_err());
    let mut g = global("bus", vec![], BaseExpr::ONE, 0);
    g.column = 0;
    one.column = 1;
    assert!(Lookups::try_from_ordered(vec![g.clone(), one]).is_err());
    g.elements.clear();
    g.multiplicities.clear();
    assert!(Lookups::try_from_ordered(vec![g]).is_err());
    assert!(Lookups::<Val>::try_from_ordered(vec![]).unwrap().is_empty());
}

#[test]
fn packing_matches_frozen_replay_order_weights_and_dag_sharing() {
    for max_degree in 0..=32 {
        let original = inputs();
        let reference = Lookups::from_air::<Challenge, _>(&Replay(original.clone()))
            .pack_same_bus(&LogUpGadget::new(), max_degree);
        let packed = pack(original, max_degree, false).unwrap();
        assert_eq!(
            lookup_encoding(&packed),
            lookup_encoding(&reference),
            "budget {max_degree}"
        );
        assert!(matches!(packed[0].kind, Kind::Local) && matches!(packed[1].kind, Kind::Local));
        assert_eq!(packed[2].kind, Kind::Global("second".into()));
        assert_eq!(packed[2].count_weight, u32::MAX);
    }
}

#[test]
fn allocation_free_degree_matches_the_unchanged_library() {
    for n in 0..=8 {
        for field_degree in 0..=8 {
            for count_degree in 0..=8 {
                let lookup = Lookup {
                    kind: Kind::Local,
                    elements: (0..n)
                        .map(|i| {
                            if i % 3 == 0 {
                                vec![]
                            } else {
                                vec![variable().exp_u64(field_degree)]
                            }
                        })
                        .collect(),
                    multiplicities: (0..n).map(|_| variable().exp_u64(count_degree)).collect(),
                    count_weight: 0,
                    column: 0,
                };
                assert_eq!(
                    degree(&lookup).unwrap(),
                    LogUpGadget::new().constraint_degree(&lookup)
                );
            }
        }
    }
}

#[test]
fn malformed_shapes_and_degree_overflow_are_fallible() {
    let mut bad = local();
    bad.multiplicities.clear();
    assert!(degree(&bad).is_err());
    assert!(pack(vec![bad], 4, false).is_err());
    let mut bad = global("bus", vec![], BaseExpr::ONE, 0);
    bad.elements.push(vec![]);
    bad.multiplicities.push(BaseExpr::ONE);
    assert!(pack(vec![bad], 4, false).is_err());
    let huge = SymbolicExpr::Neg {
        x: Arc::new(variable()),
        degree_multiple: usize::MAX,
    };
    assert!(matches!(
        degree(&global("bus", vec![huge], BaseExpr::ONE, 0)),
        Err(CompileError::Shape("symbolic lookup degree overflow"))
    ));
}

#[test]
fn packing_accepts_exact_quota_and_rejects_one_byte_less() {
    let storage = Storage::lookup(false);
    let (packed, retained_bytes) = with_storage(inputs(), 3, &storage).unwrap();
    assert!(retained_bytes <= RETAINED_BYTES);
    let required = storage.admitted_bytes();
    assert!(required > retained_bytes);
    let exact = Storage::lookup_limited(required, false);
    let (again, _) = with_storage(inputs(), 3, &exact).unwrap();
    assert_eq!(lookup_encoding(&again), lookup_encoding(&packed));
    assert_eq!(exact.admitted_bytes(), required);
    let short = Storage::lookup_limited(required - 1, false);
    assert!(with_storage(inputs(), 3, &short).is_err());
    assert!(short.capacity::<u64>(0).is_err());
    reject_allowance(false);
}

#[test]
fn retained_census_counts_spare_capacity_and_shared_arcs_once() {
    let child = Arc::new(BaseExpr::ONE);
    let expression = SymbolicExpr::Add {
        x: child.clone(),
        y: child.clone(),
        degree_multiple: 0,
    };
    let mut fields = Vec::with_capacity(8);
    fields.extend([expression.clone(), expression]);
    let mut elements = Vec::with_capacity(4);
    elements.push(fields);
    let mut values = Vec::with_capacity(3);
    values.push(Lookup {
        kind: Kind::Global("bus".into()),
        elements,
        multiplicities: vec![BaseExpr::ONE],
        count_weight: 0,
        column: 0,
    });
    let expected = values.capacity() * size_of::<Lookup<Val>>()
        + 3
        + 4 * size_of::<Vec<BaseExpr>>()
        + 9 * size_of::<BaseExpr>()
        + size_of::<BaseExpr>()
        + 4 * size_of::<usize>();
    let count = Arc::strong_count(&child);
    assert_eq!(
        retained(&values, &Storage::lookup(false), expected).unwrap(),
        expected
    );
    assert_eq!(Arc::strong_count(&child), count);
    assert!(matches!(
        retained(&values, &Storage::lookup(false), expected - 1),
        Err(CompileError::Shape("symbolic lookup retained allowance"))
    ));
}

#[test]
#[cfg(feature = "stream")]
fn packed_cache_output_obeys_retained_limit_after_packing_storage_drops() {
    let (packed, bytes) = pack_limited(
        inputs(),
        4,
        super::super::normalize::HOST_BYTES,
        RETAINED_BYTES,
    )
    .unwrap();
    assert!(bytes > 0 && bytes <= RETAINED_BYTES);
    assert_eq!(
        super::super::LOOKUP_RETAINED_HOST_BYTES,
        RETAINED_BYTES as u64
    );
    let pointer = packed.as_ptr();
    let (layout, allocation) =
        crate::spill_alloc::allocation_requests::measure(|| super::super::LookupLayout {
            lookups: packed,
            log_chunks: 2,
        });
    assert_eq!(allocation.calls, 0);
    assert_eq!(layout.lookups.as_ptr(), pointer);
    let (exact, exact_bytes) =
        pack_limited(inputs(), 4, super::super::normalize::HOST_BYTES, bytes).unwrap();
    assert_eq!(exact_bytes, bytes);
    assert_eq!(layout.lookups.len(), exact.len());
    assert!(matches!(
        pack_limited(inputs(), 4, super::super::normalize::HOST_BYTES, bytes - 1),
        Err(CompileError::Shape("symbolic lookup retained allowance"))
    ));
    eprintln!("cached_lookup_output retained_bytes={bytes} workspace_dropped=true exact_boundary=true ownership_move_allocation_free=true");
}

#[test]
fn oversized_input_geometry_rejects_before_packing_allocations() {
    let storage = Storage::lookup_limited(0, false);
    let fields = vec![BaseExpr::ONE; MAX_NODES];
    assert!(matches!(
        with_storage(vec![global("bus", fields, BaseExpr::ONE, 0)], 4, &storage),
        Err(CompileError::Shape("symbolic lookup roots"))
    ));
    assert_eq!(storage.admitted_bytes(), 0);
    let empty = Lookup {
        kind: Kind::Local,
        elements: vec![],
        multiplicities: vec![],
        count_weight: 0,
        column: 0,
    };
    assert!(matches!(
        with_storage(vec![empty; MAX_NODES + 1], 4, &storage),
        Err(CompileError::Shape("symbolic lookup count"))
    ));
    assert_eq!(storage.admitted_bytes(), 0);
}
