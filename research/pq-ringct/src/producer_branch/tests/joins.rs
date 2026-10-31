//! Isolated ordered-bundle equations, with valid baseline traces. No proof
//! templates or acceptance claims are used to test these joins.
use super::*;

fn roots(count: usize) -> Vec<[Val; 4]> {
    (0..count)
        .map(|i| core::array::from_fn(|j| Val::from_usize(11 + i * 4 + j)))
        .collect()
}

fn root_wires(b: &mut ProgramBuilder, count: usize) -> Vec<[Wire; 4]> {
    (0..count)
        .map(|i| core::array::from_fn(|j| b.public(4 + i * 4 + j).unwrap()))
        .collect()
}

fn bind_bundle(b: &mut ProgramBuilder, bundle: [Wire; 4]) {
    for (index, wire) in bundle.into_iter().enumerate() {
        let expected = b.public(index).unwrap();
        b.assert_equal(wire, expected);
    }
}

fn check_root_mutations(machine: &MachineAir, public: &[Val], count: usize) {
    machine.trace(public, &[]).unwrap();
    for index in 0..public.len() {
        let mut changed = public.to_vec();
        changed[index] += Val::ONE;
        assert!(
            machine.trace(&changed, &[]).is_err(),
            "bundle field {index}"
        );
    }
    for index in 1..count {
        let mut changed = public.to_vec();
        for word in 0..4 {
            changed.swap(4 + word, 4 + index * 4 + word);
        }
        assert!(machine.trace(&changed, &[]).is_err(), "root order {index}");
        let mut changed = public.to_vec();
        changed[4 + index * 4..8 + index * 4].copy_from_slice(&public[4..8]);
        assert!(
            machine.trace(&changed, &[]).is_err(),
            "duplicated root {index}"
        );
    }
}

#[test]
fn alpha_uniform_bundle_probe_binds_output_count_roots_and_order() {
    let kind = uniform_air::Kind::ExpandAlpha2;
    let roots = roots(2);
    let mut public = UniformAir::new(kind).bundle(&roots).unwrap().to_vec();
    public.extend(roots.iter().flatten().copied());
    let mut b = ProgramBuilder::new(public.len()).unwrap();
    let wires = root_wires(&mut b, roots.len());
    assert!(uniform_air::join::bundle_wires(&mut b, kind, &wires[..1]).is_err());
    let bundle = uniform_air::join::bundle_wires(&mut b, kind, &wires).unwrap();
    bind_bundle(&mut b, bundle);
    check_root_mutations(
        &MachineAir::new(b.finish(None).unwrap()),
        &public,
        roots.len(),
    );
}

#[test]
fn hash_x_transcript_bundle_probe_binds_root_order_and_part_types() {
    let parts = vec![
        PartKind::Bytes32,
        PartKind::PolynomialQ,
        PartKind::PolynomialQhat,
    ];
    let air = TranscriptAir::new(parts.clone()).unwrap();
    let roots = roots(parts.len());
    let mut public = air.bundle(&roots).unwrap().to_vec();
    public.extend(roots.iter().flatten().copied());
    let mut b = ProgramBuilder::new(public.len()).unwrap();
    let wires = root_wires(&mut b, roots.len());
    assert!(crate::transcript_air::join::bundle_wires(&mut b, &air, &wires[..2]).is_err());
    let bundle = crate::transcript_air::join::bundle_wires(&mut b, &air, &wires).unwrap();
    bind_bundle(&mut b, bundle);
    let machine = MachineAir::new(b.finish(None).unwrap());
    check_root_mutations(&machine, &public, roots.len());
    for changed_parts in [
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
    ] {
        let other = TranscriptAir::new(changed_parts).unwrap();
        assert_eq!(other.byte_len(), air.byte_len());
        let mut changed = public.clone();
        changed[..4].copy_from_slice(&other.bundle(&roots).unwrap());
        assert!(machine.trace(&changed, &[]).is_err());
    }
}
