use super::*;

fn shaped_inputs() -> (Statement, Proof) {
    (
        Statement {
            seed: [0; 32],
            ring: (0..10)
                .map(|_| {
                    core::array::from_fn(|_| Account {
                        pk: vec![[0; D]; 4],
                        cn: vec![[0; D]; 5],
                    })
                })
                .collect(),
            recipients: vec![vec![[0; D]; 4]; 2],
            coins: vec![vec![[0; D]; 5]; 2],
            serials: [[0; 32], [1; 32]],
        },
        Proof {
            c: [0; D],
            v: vec![[0; D]; 4],
            v1: [0; D],
            v2: [0; D],
            b: vec![[0; D]; 5],
            alpha: [0; 32],
            x: [0; D],
            z_out: vec![vec![[0; D]; 9]; 2],
            z0: vec![[0; D]; 9],
            z1: vec![[0; D]; 11],
            z2: vec![[0; D]; 11],
            f1: vec![[0; D]; 11],
            zb: vec![[0; D]; 10],
            z: vec![[0; D]; 8],
        },
    )
}

#[test]
fn every_variable_native_dimension_is_checked_before_import() {
    type Mutation = fn(&mut Statement, &mut Proof);
    let mutations: [Mutation; 16] = [
        |s, _| {
            s.ring.pop();
        },
        |s, _| {
            s.ring[9][1].pk.pop();
        },
        |s, _| {
            s.ring[0][0].cn.push([0; D]);
        },
        |s, _| {
            s.recipients.pop();
        },
        |s, _| {
            s.recipients[1].pop();
        },
        |s, _| {
            s.coins.push(vec![[0; D]; 5]);
        },
        |s, _| {
            s.coins[0].pop();
        },
        |_, p| {
            p.v.pop();
        },
        |_, p| {
            p.b.push([0; D]);
        },
        |_, p| {
            p.z_out.pop();
        },
        |_, p| {
            p.z_out[1].pop();
        },
        |_, p| {
            p.z0.pop();
        },
        |_, p| {
            p.z1.pop();
        },
        |_, p| {
            p.z2.pop();
        },
        |_, p| {
            p.f1.pop();
        },
        |_, p| {
            p.zb.pop();
        },
    ];
    for mutation in mutations {
        let (mut statement, mut proof) = shaped_inputs();
        assert!(FixedProfile::inspect(&statement, &proof).is_ok());
        mutation(&mut statement, &mut proof);
        assert!(FixedProfile::inspect(&statement, &proof).is_err());
    }
    let (statement, mut proof) = shaped_inputs();
    proof.z.pop();
    assert!(FixedProfile::inspect(&statement, &proof).is_err());
}

#[test]
fn shape_check_neither_verifies_values_nor_binds_an_existing_graph() {
    let (mut statement, mut proof) = shaped_inputs();
    statement.ring[0][0].pk[0][0] = Q;
    statement.serials[1] = statement.serials[0];
    proof.z[0][0] = i64::MIN;
    let profile = FixedProfile::inspect(&statement, &proof).unwrap();
    let graph = CommittedBackend::new([0; 32]).into_unproved_graph();
    assert!(inspect_graph(&profile, &graph).is_err());
}

#[test]
fn source_ceiling_arithmetic_remains_bounded_and_has_no_dispatch_authority() {
    let c = Ceilings::fixed();
    assert_eq!(
        (c.polynomials, c.bytes, c.expressions, c.operations),
        (4351, 20, 1_165_932, 4089)
    );
    assert_eq!(
        (c.canonical_lookups, c.signed_lookups, c.byte_lookups),
        (2596, 178, 12)
    );
    assert_eq!(
        (c.constant_calls, c.alpha_parts, c.x_parts, c.norm_inputs),
        (47_363, 228, 17, 57)
    );
    let retained = add(
        c.main_vector_bytes(2).unwrap(),
        c.nested_vector_bytes(2).unwrap(),
    )
    .unwrap();
    let growth = add(
        c.main_vector_bytes(3).unwrap(),
        c.nested_vector_bytes(3).unwrap(),
    )
    .unwrap();
    assert!(retained > 0 && retained < growth);
    assert!(growth < 1 << 30);
    assert!(mul(usize::MAX, 2).is_err());
    assert!(add(usize::MAX, 1).is_err());
}

#[test]
fn census_charges_spare_capacity_and_keeps_all_authority_flags_false() {
    let (statement, proof) = shaped_inputs();
    let profile = FixedProfile::inspect(&statement, &proof).unwrap();
    let mut backend = CommittedBackend::new([0; 32]);
    let poly = backend.canonical_node([0; D], Q, Source::Fixed);
    let bytes = backend.byte_node([0; 32], Source::Fixed);
    let mut alpha = Vec::with_capacity(300);
    alpha.extend(core::iter::repeat_n(TranscriptPart::Polynomial(poly), 225));
    alpha.extend(core::iter::repeat_n(TranscriptPart::Bytes(bytes), 3));
    let mut x = Vec::with_capacity(20);
    x.extend(core::iter::repeat_n(TranscriptPart::Polynomial(poly), 16));
    x.push(TranscriptPart::Bytes(bytes));
    let mut norm = Vec::with_capacity(80);
    norm.extend(core::iter::repeat_n(poly, 57));
    backend.graph.operations.extend([
        Operation::HashAlpha {
            parts: alpha,
            output: bytes,
        },
        Operation::HashX {
            parts: x,
            output: poly,
        },
        Operation::Norm {
            inputs: norm,
            maximum: 0,
        },
    ]);
    let graph = backend.into_unproved_graph();
    let report = inspect_graph(&profile, &graph).unwrap();
    // Synthetic inventory exercises byte accounting only; qualify_fixture
    // additionally demands the genuine whole-polynomial call census.
    assert_eq!(report.nested_transcript_capacity, 320);
    assert_eq!(report.nested_id_capacity, 80);
    assert_eq!(report.lengths[3], 3);
    assert_eq!(report.capacities[3], graph.operations.capacity());
    assert!(report.observed_inline_and_backing_bytes < report.retained_graph_vector_ceiling_bytes);
    assert!(
        report.retained_graph_vector_ceiling_bytes
            < report.graph_vector_growth_coexistence_ceiling_bytes
    );
    assert!(!report.complete_constructor_bound);
    assert!(!report.owns_source_graph_allocation);
    assert!(!report.workflow_dispatch_authority);
    assert!(qualify_fixture(&statement, &proof, &graph).is_err());
}
