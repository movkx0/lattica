//! Positive trace baselines for the real header/context equations. These
//! probes do not contain recursive proof verifiers and establish no complete
//! branch or transaction proof mutation qualification.
use super::*;

#[test]
fn header_probe_binds_every_profile_context_statement_manifest_and_typed_field() {
    for descriptor in [
        Descriptor::AlphaUniform,
        Descriptor::AlphaSparse,
        Descriptor::HashX(vec![PartKind::Bytes32, PartKind::PolynomialQ]),
    ] {
        let node = header_only_probe(descriptor);
        node.evaluate().unwrap();
        let machine = MachineAir::from_shared_program(node.program);
        for index in 0..INPUT {
            let mut changed = node.public.clone();
            changed[index] += Val::ONE;
            assert!(
                machine.trace(&changed, &node.witness).is_err(),
                "header field {index}"
            );
        }
        // Roots are interfaces: the header alone intentionally does not prove
        // their semantics. Complete producers and atomic graph joins do that.
        for index in INPUT..PUBLIC_VALUES {
            let mut changed = node.public.clone();
            changed[index] += Val::ONE;
            machine.trace(&changed, &node.witness).unwrap();
        }
    }
}

#[test]
fn consumer_context_probe_rejects_every_parent_and_child_field_substitution() {
    let (spec, context, roots) = fixture(Descriptor::AlphaUniform);
    let child = header(&spec, &context, roots).unwrap();
    let public = child[..OPERATION].to_vec();
    let mut b = ProgramBuilder::new(OPERATION).unwrap();
    let outer: Vec<_> = (0..OPERATION).map(|i| b.public(i).unwrap()).collect();
    let expected = context_wires(&outer);
    let manifest = outer[NODE_MANIFEST..OPERATION].try_into().unwrap();
    let mut inputs = ProofInputs::default();
    let child_wires = inputs.bases(&mut b, &child).unwrap();
    bind_context(&mut b, &child_wires, &expected, &manifest);
    let machine = MachineAir::new(b.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for index in 0..OPERATION {
        let mut changed = public.clone();
        changed[index] += Val::ONE;
        assert!(
            machine.trace(&changed, &inputs.values).is_err(),
            "parent field {index}"
        );
        let mut changed = inputs.values.clone();
        changed[index] += Val::ONE;
        assert!(
            machine.trace(&public, &changed).is_err(),
            "child field {index}"
        );
    }
}

#[test]
fn typed_descriptor_commits_role_request_index_and_exact_transcript_order() {
    let (uniform, _, _) = fixture(Descriptor::AlphaUniform);
    let (sparse, _, _) = fixture(Descriptor::AlphaSparse);
    assert_eq!(uniform.request_index().unwrap(), 1248);
    assert_eq!(sparse.request_index().unwrap(), 1249);
    let u = uniform.descriptor.aes().unwrap();
    let s = sparse.descriptor.aes().unwrap();
    assert_eq!((u.domain, u.start_counter, u.output_len), (0x4368, 0, 2572));
    assert_eq!(
        (s.domain, s.start_counter, s.output_len),
        (0x4368, 161, 127)
    );
    assert_ne!(
        uniform.descriptor_root().unwrap(),
        sparse.descriptor_root().unwrap()
    );
    let mut next = uniform.clone();
    next.operation += 1;
    assert_ne!(
        uniform.descriptor_root().unwrap(),
        next.descriptor_root().unwrap()
    );
    next.operation = u32::MAX;
    assert!(next.request_index().is_err());
    assert!(next.descriptor_root().is_err());

    let layouts = [
        vec![
            PartKind::Bytes32,
            PartKind::PolynomialQ,
            PartKind::PolynomialQhat,
        ],
        vec![
            PartKind::PolynomialQ,
            PartKind::Bytes32,
            PartKind::PolynomialQhat,
        ],
        vec![
            PartKind::Bytes32,
            PartKind::PolynomialQhat,
            PartKind::PolynomialQ,
        ],
    ];
    let specs: Vec<_> = layouts
        .into_iter()
        .map(|parts| fixture(Descriptor::HashX(parts)).0)
        .collect();
    let byte_lens: Vec<_> = specs
        .iter()
        .map(|spec| match &spec.descriptor {
            Descriptor::HashX(parts) => TranscriptAir::new(parts.clone()).unwrap().byte_len(),
            _ => unreachable!(),
        })
        .collect();
    assert!(byte_lens.iter().all(|len| *len == byte_lens[0]));
    for (index, spec) in specs.iter().enumerate() {
        assert_eq!(spec.request_index().unwrap(), 1248);
        assert!(spec.descriptor.aes().is_err());
        for other in &specs[index + 1..] {
            assert_ne!(
                spec.descriptor_root().unwrap(),
                other.descriptor_root().unwrap()
            );
        }
    }
}

#[test]
fn header_probe_zero_budget_rejects_before_registration() {
    let node = header_only_probe(Descriptor::AlphaUniform);
    node.evaluate().unwrap();
    assert!(node.geometry().unwrap().retained_lde_bytes > 0);
    let error = match node.prepare(0) {
        Err(error) => error,
        Ok(_) => panic!("zero budget admitted registration"),
    };
    assert!(error.0.contains("before registration"), "{error}");
}
