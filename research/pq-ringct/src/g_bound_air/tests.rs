use super::*;
use crate::rust_verify::{arithmetic, constraints_ntt::commit_signed_values};
use p3_air::check_all_constraints;
fn accepts(air: &GBoundAir, witness: &GBoundWitness) -> bool {
    let report = check_all_constraints(air, &witness.trace, &witness.public_values, Some(2));
    if !report.failures.is_empty() {
        eprintln!("{report:?}");
    }
    report.failures.is_empty()
}
#[test]
fn goldilocks_convolution_matches_signed_integer_reference_and_roots() {
    for limit in [6_825_771, 1_137_628] {
        let air = GBoundAir::new(limit).unwrap();
        for pattern in 0..3 {
            let f = core::array::from_fn(|i| match pattern {
                0 => (i % 5) as i64 - 2,
                1 => i64::from(i == 255),
                _ => 0,
            });
            let x = core::array::from_fn(|i| (i % 3) as i64 - 1);
            let witness = air.generate(&f, &x).unwrap();
            let other = core::array::from_fn(|i| x[i] - f[i]);
            assert_eq!(witness.output, arithmetic::signed_mul(&f, &other));
            assert_eq!(&witness.public_values[..4], &commit_signed_values(&f));
            assert_eq!(&witness.public_values[4..], &commit_signed_values(&x));
            assert!(accepts(&air, &witness));
        }
    }
}
#[test]
fn g_bound_rejects_trace_mutations_and_wrong_descriptor() {
    let air = GBoundAir::new(6_825_771).unwrap();
    let f = core::array::from_fn(|i| (i % 7) as i64 - 3);
    let x = core::array::from_fn(|i| (i % 3) as i64 - 1);
    let mut witness = air.generate(&f, &x).unwrap();
    for (row, column) in [
        (0, RANGES + 1),
        (0, ADDRESS_PREFIX),
        (64, ACC),
        (128, PHASE + 1),
        (3 * 128, READS),
        (4 * 128, LEFT + 255),
        (11 * 128, LEFT),
        (13 * 128, RIGHT + 111),
        (21 * 128, LEFT),
        (23 * 128, RANGES),
        (24 * 128, LEFT + 33),
        (HEIGHT - 1, PHASE + 31),
    ] {
        witness.trace.values[row * WIDTH + column] += Val::ONE;
        assert!(!accepts(&air, &witness), "row={row} column={column}");
        witness.trace.values[row * WIDTH + column] -= Val::ONE;
    }
    witness.public_values[4] += Val::ONE;
    assert!(!accepts(&air, &witness));
    assert!(GBoundAir::new(6_825_772).is_err());
}
#[test]
fn g_bound_rejects_regenerated_input_ranges_and_excess_convolution() {
    let air = GBoundAir::new(1_137_628).unwrap();
    let mut f = [0; D];
    let mut x = [0; D];
    f[0] = 566;
    match air.generate(&f, &x) {
        Ok(w) => assert!(!accepts(&air, &w)),
        Err(_) => {}
    }
    f[0] = 0;
    x[0] = 2;
    match air.generate(&f, &x) {
        Ok(w) => assert!(!accepts(&air, &w)),
        Err(_) => {}
    }
    f.fill(565);
    x.fill(0);
    assert!(arithmetic::signed_mul(&f, &f.map(|v| -v))
        .iter()
        .any(|v| v.unsigned_abs() > u64::from(air.g_bound())));
    match air.generate(&f, &x) {
        Ok(w) => assert!(!accepts(&air, &w)),
        Err(_) => {}
    }
}

#[test]
fn g_bound_positive_excess_has_encodable_witness_but_constraints_reject() {
    let air = GBoundAir::new(1_137_628).unwrap();
    let mut f = [0; D];
    f[128..132].fill(565);
    let x = [0; D];
    let witness = air.generate(&f, &x).unwrap();
    assert!(witness.output.iter().any(|&v| v > i64::from(air.g_bound())));
    assert!(!accepts(&air, &witness));
}

#[test]
#[cfg(feature = "native-matrict")]
fn g_bound_all_twelve_native_fixture_obligations_match() {
    let context = [73; 32];
    let fixture = crate::native::generate_fixture_with_setup_seed(
        context,
        [91; 32],
        4,
        crate::native::FixtureAmounts {
            input: [19, 31],
            output: [23, 27],
        },
    )
    .unwrap();
    assert!(crate::rust_verify::verify(&context, &fixture.statement, &fixture.proof).unwrap());
    let proof = crate::rust_verify::Proof::decode(&fixture.proof).unwrap();
    let mut f0 = proof.x;
    for f in proof.f1.iter().take(9) {
        for i in 0..D {
            f0[i] -= f[i];
        }
    }
    for (index, f) in core::iter::once(&f0).chain(proof.f1.iter()).enumerate() {
        let air = GBoundAir::new(if index == 0 { 6_825_771 } else { 1_137_628 }).unwrap();
        let witness = air.generate(f, &proof.x).unwrap();
        assert_eq!(
            witness.output,
            arithmetic::signed_mul(f, &core::array::from_fn(|i| proof.x[i] - f[i]))
        );
        assert_eq!(&witness.public_values[..4], &commit_signed_values(f));
        assert_eq!(&witness.public_values[4..], &commit_signed_values(&proof.x));
        assert!(accepts(&air, &witness), "obligation={index}");
    }
}

#[test]
#[ignore = "actual GBound child STARK and recursive verifier; reserve an 8GiB memory window"]
fn g_bound_actual_stark_and_typed_recursive_geometry() {
    use join::RegisteredGBoundAir;
    use lattica_prover_p3::block_v2::{
        machine::{analysis, verifier::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    for bound in [6_825_771, 1_137_628] {
        let registered = RegisteredGBoundAir::new(bound).unwrap();
        let f = core::array::from_fn(|i| (i % 7) as i64 - 3);
        let x = core::array::from_fn(|i| (i % 3) as i64 - 1);
        let mut artifact = registered.prove(&f, &x).unwrap();
        artifact.public_values[0] += Val::ONE;
        assert!(registered.verify(&artifact).is_err());
        artifact.public_values[0] -= Val::ONE;
        artifact.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
        assert!(registered.verify(&artifact).is_err());
        artifact.proof.opened_values.trace_local[0] -= profile::Challenge::ONE;
        artifact.proof.degree_bits += 1;
        assert!(registered.verify(&artifact).is_err());
        artifact.proof.degree_bits -= 1;
        assert!(RegisteredGBoundAir::new(if bound == 6_825_771 {
            1_137_628
        } else {
            6_825_771
        })
        .unwrap()
        .verify(&artifact)
        .is_err());
        let mut builder = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
        let f_root = core::array::from_fn(|i| builder.public(i).unwrap());
        let x_root = core::array::from_fn(|i| builder.public(4 + i).unwrap());
        let mut inputs = ProofInputs::default();
        registered
            .compile_join(&mut builder, &mut inputs, &f_root, &x_root, &artifact)
            .unwrap();
        let machine = MachineAir::new(builder.finish(None).unwrap());
        let geometry = analysis::analyze(&machine).unwrap();
        eprintln!("GBound bound={bound} child width={WIDTH} height={HEIGHT} periodic_columns={PERIODIC} period={SCHEDULE_PERIOD}; recursive rows={} height={} wires={} retained_lde_bytes={}", machine.program().active_rows(), machine.program().height(), machine.program().wire_count(), geometry.retained_lde_bytes);
        machine
            .trace(&artifact.public_values, &inputs.values)
            .unwrap();
        let mut bad = artifact.public_values;
        bad[0] += Val::ONE;
        assert!(machine.trace(&bad, &inputs.values).is_err());
        bad = artifact.public_values;
        for i in 0..4 {
            bad.swap(i, 4 + i);
        }
        assert!(machine.trace(&bad, &inputs.values).is_err());
        inputs.values[4] += Val::ONE;
        assert!(machine
            .trace(&artifact.public_values, &inputs.values)
            .is_err());
    }
}
