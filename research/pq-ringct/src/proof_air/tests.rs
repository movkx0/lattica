use super::*;
use crate::rust_verify::constraints_ntt::{commit_signed_values, commit_values};
use p3_air::check_all_constraints;

fn fixture() -> ProofValues {
    let polynomials = (0..POLYNOMIALS)
        .map(|index| {
            let kind = class(index);
            let mut values = core::array::from_fn(|i| {
                if kind < 2 {
                    ((i * 37 + index) as u64 % MAXIMA[kind]) as i64
                } else if kind == 2 {
                    (i % 3) as i64 - 1
                } else {
                    (i % 31) as i64 - 15
                }
            });
            values[0] = MAXIMA[kind] as i64 - i64::from(OFFSETS[kind]);
            values[1] = -i64::from(OFFSETS[kind]);
            values
        })
        .collect();
    ProofValues {
        polynomials,
        alpha: core::array::from_fn(|i| (19 * i + 3) as u8),
    }
}
fn accepts(w: &ProofWitness) -> bool {
    check_all_constraints(&ProofAir, &w.trace, &w.public_values, Some(2))
        .failures
        .is_empty()
}
#[test]
fn structured_proof_ranges_norms_and_all_root_domains_match() {
    let input = fixture();
    let bundle = input.bundle().unwrap();
    for (index, poly) in input.polynomials.iter().enumerate() {
        let expected = if index < 12 {
            commit_values(
                POLYNOMIAL_DOMAIN,
                if index < 7 { Q } else { QHAT },
                &poly.map(|x| x as u64),
            )
        } else {
            commit_signed_values(poly)
        };
        assert_eq!(bundle.roots[index], expected, "polynomial={index}");
    }
    let witness = ProofAir.generate(&input).unwrap();
    assert_eq!(witness.public_values, bundle.commitment());
    assert!(accepts(&witness));
}

#[test]
#[cfg(feature = "native-matrict")]
fn native_private_proof_import_preserves_exact_bounds_norms_and_bundle() {
    let context = [97; 32];
    let fixture = crate::native::generate_fixture_with_setup_seed(
        context,
        [43; 32],
        4,
        crate::native::FixtureAmounts {
            input: [19, 31],
            output: [23, 27],
        },
    )
    .unwrap();
    assert!(crate::rust_verify::verify(&context, &fixture.statement, &fixture.proof).unwrap());
    let decoded = Proof::decode(&fixture.proof).unwrap();
    let input = ProofValues::from_proof(&decoded).unwrap();
    assert_eq!(input.polynomials.len(), POLYNOMIALS);
    assert_eq!(input.polynomials[0], decoded.c.map(|x| x as i64));
    assert_eq!(input.polynomials[7], decoded.b[0].map(|x| x as i64));
    assert_eq!(input.polynomials[12], decoded.x);
    assert_eq!(input.polynomials[62], decoded.f1[0]);
    assert_eq!(input.polynomials[90], decoded.z[7]);
    assert_eq!(input.alpha, decoded.alpha);
    let witness = ProofAir.generate(&input).unwrap();
    assert_eq!(witness.public_values, input.bundle().unwrap().commitment());
    assert!(accepts(&witness));
}
#[test]
fn private_proof_rejects_regenerated_noncanonical_coefficients_and_excess_norms() {
    let input = fixture();
    for index in [0, 7, 12, 13, 62, 83] {
        let mut bad = input.clone();
        let kind = class(index);
        bad.polynomials[index][0] = MAXIMA[kind] as i64 - i64::from(OFFSETS[kind]) + 1;
        assert!(
            !accepts(&ProofAir.generate(&bad).unwrap()),
            "range polynomial={index}"
        );
        assert!(bad.bundle().is_err());
        bad.polynomials[index][0] = u32::MAX as i64 - i64::from(OFFSETS[kind]);
        assert!(
            !accepts(&ProofAir.generate(&bad).unwrap()),
            "offset alias polynomial={index}"
        );
    }
    for (first, end, _) in NORMS {
        let mut bad = input.clone();
        for index in first..end {
            bad.polynomials[index].fill(i64::from(OFFSETS[class(index)]));
        }
        let witness = ProofAir.generate(&bad).unwrap();
        assert_eq!(witness.public_values, bad.bundle().unwrap().commitment());
        assert!(!accepts(&witness), "norm group={first}..{end}");
    }
}
#[test]
fn private_proof_rejects_trace_bundle_and_alpha_mutations() {
    let input = fixture();
    let mut witness = ProofAir.generate(&input).unwrap();
    for (row, column) in [
        (0, BITS),
        (0, PREFIX),
        (63, POLY_ACC),
        (64, BUNDLE_ACC),
        (13 * 64, NORM_ACC),
        (22 * 64 - 1, NORM_BITS),
        (22 * 64 - 1, NORM_PREFIX),
        (63, POLY_POSEIDON),
        (63, BUNDLE_POSEIDON),
        (POLY_ROWS, WORD),
        (0, POLYNOMIAL_COUNTER),
        (HEIGHT - 1, POLYNOMIAL_COUNTER),
        (6 * 64, EVENT_EQUAL),
        (7 * 64, EVENT_EQUAL),
        (6 * 64, EVENT_INVERSE),
        (7 * 64, CLASS),
        (13 * 64, NORM_ACTIVE),
        (13 * 64 + 1, NORM_RESET),
        (91 * 64, EVENT_EQUAL + 11),
    ] {
        witness.trace.values[row * WIDTH + column] += Val::ONE;
        assert!(!accepts(&witness), "row={row} col={column}");
        witness.trace.values[row * WIDTH + column] -= Val::ONE;
    }
    witness.public_values[0] += Val::ONE;
    assert!(!accepts(&witness));
    let expected = input.bundle().unwrap();
    let mut swapped = expected.clone();
    swapped.roots.swap(0, POLYNOMIALS - 1);
    assert_ne!(expected.commitment(), swapped.commitment());
    for index in 0..8 {
        let mut bad = expected.clone();
        bad.alpha[index] ^= 1;
        assert_ne!(expected.commitment(), bad.commitment());
    }
}
#[test]
#[ignore = "actual private-proof STARK and recursive verifier: run under a memory guard"]
fn structured_proof_actual_stark_and_typed_recursive_join() {
    use lattica_prover_p3::block_v2::{
        machine::{program::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    let input = fixture();
    let bundle = input.bundle().unwrap();
    let witness = ProofAir.generate(&input).unwrap();
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(&config, &ProofAir, witness.trace, &witness.public_values);
    p3_uni_stark::verify(&config, &ProofAir, &proof, &witness.public_values).unwrap();
    let mut bad = witness.public_values;
    bad[0] += Val::ONE;
    assert!(p3_uni_stark::verify(&config, &ProofAir, &proof, &bad).is_err());
    let artifact = join::ProofArtifact {
        public_values: witness.public_values,
        proof,
    };
    let mut builder = ProgramBuilder::new(4).unwrap();
    let mut inputs = ProofInputs::default();
    let roots: [[_; 4]; POLYNOMIALS] = inputs
        .bases(
            &mut builder,
            &bundle.roots.into_iter().flatten().collect::<Vec<_>>(),
        )
        .unwrap()
        .chunks_exact(4)
        .map(|c| c.try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let alpha: [_; 8] = inputs
        .bases(&mut builder, &bundle.alpha.map(Val::from_u32))
        .unwrap()
        .try_into()
        .unwrap();
    let digest = join::verify_bundle(&mut builder, &mut inputs, &roots, &alpha, &artifact).unwrap();
    for (i, d) in digest.into_iter().enumerate() {
        let public = builder.public(i).unwrap();
        builder.assert_equal(d, public);
    }
    let program = builder.finish(None).unwrap();
    eprintln!(
        "private proof AIR width={WIDTH} height={HEIGHT}; recursive rows={} height={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    let machine = MachineAir::new(program);
    machine
        .trace(&witness.public_values, &inputs.values)
        .unwrap();
    assert!(machine.trace(&bad, &inputs.values).is_err());
    for index in [
        0,
        4 * (POLYNOMIALS - 1),
        4 * POLYNOMIALS,
        4 * POLYNOMIALS + 7,
    ] {
        inputs.values[index] += Val::ONE;
        assert!(machine
            .trace(&witness.public_values, &inputs.values)
            .is_err());
        inputs.values[index] -= Val::ONE;
    }
    for i in 0..4 {
        inputs.values.swap(i, 4 * (POLYNOMIALS - 1) + i);
    }
    assert!(machine
        .trace(&witness.public_values, &inputs.values)
        .is_err());
}
