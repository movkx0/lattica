use super::*;
use crate::block_v2::machine::{compiler_constants::Constants, symbolic, ProgramBuilder};
use p3_air::symbolic::{ConstraintLayout, SymbolicExpr, SymbolicExpression};
use p3_lookup::{Kind, Lookup, Lookups};
use p3_symmetric::MerkleCap;
use std::sync::Arc;

type Expr = SymbolicExpression<Val>;

fn air(height: usize) -> MachineAir {
    MachineAir::new(
        ProgramBuilder::new(1)
            .unwrap()
            .finish(Some(height))
            .unwrap(),
    )
}
fn cap(air: &MachineAir) -> p3_batch_stark::Commitment<Config> {
    let degree = air.program().height().ilog2() as usize + 1;
    MerkleCap::new(vec![
        [Val::ZERO; 4];
        1 << (degree + profile::LOG_BLOWUP)
            .min(profile::CAP_HEIGHT)
    ])
}
fn layout(child: &Arc<Expr>) -> symbolic::LookupLayout {
    let mut fields = Vec::with_capacity(20);
    fields.push(SymbolicExpr::Neg {
        x: child.clone(),
        degree_multiple: 0,
    });
    let mut elements = Vec::with_capacity(8);
    elements.push(fields);
    let mut counts = Vec::with_capacity(7);
    counts.push(Expr::ONE);
    let mut name = String::with_capacity(32);
    name.push_str("test");
    let mut lookups = Vec::with_capacity(16);
    lookups.push(Lookup {
        kind: Kind::Global(name),
        elements,
        multiplicities: counts,
        count_weight: 1,
        column: 0,
    });
    symbolic::LookupLayout {
        lookups: Lookups::try_from_ordered(lookups).unwrap(),
        log_chunks: 0,
    }
}

#[test]
fn owned_layout_preserves_nested_buffers_and_arc_ownership() {
    let child = Arc::new(Expr::ONE);
    let layout = layout(&child);
    let constraint = SymbolicExpr::Neg {
        x: child.clone(),
        degree_multiple: 0,
    };
    let prepared = symbolic::Prepared {
        lookups: layout.lookups,
        log_chunks: layout.log_chunks,
        constraints: symbolic::Constraints {
            base: vec![constraint],
            extension: vec![],
            order: ConstraintLayout {
                base_indices: vec![0],
                ext_indices: vec![],
            },
        },
    };
    let outer = prepared.lookups.as_ptr();
    let elements = prepared.lookups[0].elements.as_ptr();
    let fields = prepared.lookups[0].elements[0].as_ptr();
    let counts = prepared.lookups[0].multiplicities.as_ptr();
    let Kind::Global(name) = &prepared.lookups[0].kind else {
        unreachable!()
    };
    let bus = name.as_ptr();
    let constraint_roots = prepared.constraints.base.as_ptr();
    let refs = Arc::strong_count(&child);
    let (layout, constraints) = prepared.into_parts();
    assert_eq!(constraints.base.as_ptr(), constraint_roots);
    let air = air(8);
    let common = common_from_prepared(&air, cap(&air), layout).unwrap();
    assert_eq!(common.lookups.capacity(), 1);
    let pre = common.preprocessed.as_ref().unwrap();
    assert_eq!(pre.instances.capacity(), 1);
    assert_eq!(pre.matrix_to_instance.capacity(), 1);
    assert_eq!(common.lookups[0].as_ptr(), outer);
    let lookup = &common.lookups[0][0];
    assert_eq!(lookup.elements.as_ptr(), elements);
    assert_eq!(lookup.elements[0].as_ptr(), fields);
    assert_eq!(lookup.multiplicities.as_ptr(), counts);
    assert_eq!(lookup.elements.capacity(), 8);
    assert_eq!(lookup.elements[0].capacity(), 20);
    assert_eq!(lookup.multiplicities.capacity(), 7);
    let Kind::Global(name) = &lookup.kind else {
        unreachable!()
    };
    assert_eq!(name.as_ptr(), bus);
    assert_eq!(name.capacity(), 32);
    assert_eq!(Arc::strong_count(&child), refs);
    drop(constraints);
    assert_eq!(Arc::strong_count(&child), refs - 1);
    drop(common);
    assert_eq!(Arc::strong_count(&child), 1);
}

#[test]
fn owned_batch_metadata_matches_the_trusted_cap_reference() {
    let airs = [air(8), air(32)];
    let cap = cap(&airs[1]);
    let reference: Vec<_> = airs
        .iter()
        .map(|air| common_from_cap(air, cap.clone()).unwrap())
        .collect();
    let mut layouts = Vec::new();
    let mut pointers = Vec::new();
    for air in &airs {
        let prepared = symbolic::prepare_machine(air, Constants::cpu()).unwrap();
        pointers.push(prepared.lookups.as_ptr());
        layouts.push(prepared.into_parts().0);
    }
    let common = common_batch_from_prepared(&[&airs[0], &airs[1]], cap.clone(), layouts).unwrap();
    let pre = common.preprocessed.as_ref().unwrap();
    assert_eq!(pre.instances.capacity(), 2);
    assert_eq!(pre.matrix_to_instance.capacity(), 2);
    assert_eq!(common.lookups.capacity(), 2);
    assert_eq!(pre.commitment.roots(), cap.roots());
    assert_eq!(pre.matrix_to_instance, vec![0, 1]);
    for i in 0..2 {
        let actual = pre.instances[i].as_ref().unwrap();
        let expected = reference[i].preprocessed.as_ref().unwrap().instances[0]
            .as_ref()
            .unwrap();
        assert_eq!(actual.matrix_index, i);
        assert_eq!(actual.width, expected.width);
        assert_eq!(actual.degree_bits, expected.degree_bits);
        assert_eq!(common.lookups[i].as_ptr(), pointers[i]);
        assert_eq!(
            format!("{:?}", common.lookups[i]),
            format!("{:?}", reference[i].lookups[0])
        );
    }
}

#[test]
fn rejected_metadata_releases_owned_lookup_graphs() {
    let air = air(8);
    let child = Arc::new(Expr::ONE);
    assert!(common_batch_from_prepared(&[], cap(&air), vec![layout(&child)]).is_err());
    assert_eq!(Arc::strong_count(&child), 1);
    assert!(common_batch_from_prepared(&[&air, &air], cap(&air), vec![layout(&child)]).is_err());
    assert_eq!(Arc::strong_count(&child), 1);
    let mut excessive_degree = layout(&child);
    excessive_degree.log_chunks = profile::LOG_BLOWUP + 1;
    assert!(common_from_prepared(&air, cap(&air), excessive_degree).is_err());
    assert_eq!(Arc::strong_count(&child), 1);
    assert!(
        common_from_prepared(&air, MerkleCap::new(vec![[Val::ZERO; 4]]), layout(&child)).is_err()
    );
    assert_eq!(Arc::strong_count(&child), 1);
    let airs = vec![&air; 257];
    let layouts = (0..airs.len()).map(|_| layout(&child)).collect();
    assert!(common_batch_from_prepared(&airs, cap(&air), layouts).is_err());
    assert_eq!(Arc::strong_count(&child), 1);
}

#[test]
fn descriptor_capacity_is_exact_through_the_batch_limit() {
    for count in [0, 1, 256] {
        assert_eq!(metadata_vector::<usize>(count).unwrap().capacity(), count);
    }
    assert_eq!(metadata_vector::<usize>(257), Err(ExecutionError::TooLarge));
    assert_eq!(
        metadata_vector::<usize>(usize::MAX),
        Err(ExecutionError::TooLarge)
    );
    let air = air(8);
    let child = Arc::new(Expr::ONE);
    let airs = vec![&air; 256];
    let layouts = (0..256).map(|_| layout(&child)).collect();
    let common = common_batch_from_prepared(&airs, cap(&air), layouts).unwrap();
    let pre = common.preprocessed.as_ref().unwrap();
    assert_eq!(pre.instances.capacity(), 256);
    assert_eq!(pre.matrix_to_instance.capacity(), 256);
    assert_eq!(common.lookups.capacity(), 256);
    assert_eq!(pre.matrix_to_instance, (0..256).collect::<Vec<_>>());
    for (index, meta) in pre.instances.iter().enumerate() {
        assert_eq!(meta.as_ref().unwrap().matrix_index, index);
    }
    assert_eq!(Arc::strong_count(&child), 257);
    drop(common);
    assert_eq!(Arc::strong_count(&child), 1);
}
