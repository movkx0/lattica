//! Independent arithmetic/adversarial audit of the research-only fused map.
//! Expected products use the untouched generic/native implementation, never
//! the candidate coefficient routine. These are host constraint diagnostics,
//! not proof verification or cryptographic adoption approval.

use super::super::{
    compile_with_representation_diagnostics, CompilerCapacityProfile, CompilerRepresentation,
};
use super::{coefficient, dot, matrix_poly};
use crate::{ring, ring_native as native, Context, Error, Profile};
use lattica_pq_ringct_research::rust_verify::{
    constraints::{ConstraintContext, ResidueValue},
    constraints_crypto::CryptoObligations,
    generic::{self, Backend},
    D, Q, QHAT,
};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

const FIELD: u128 = 18_446_744_069_414_584_321;
const INVERSE_R: u64 = 54_987_456;
const INVERSE_R_SQUARED: u64 = 106_966_669;
const PHASE: &str = "independent_fused_linear_audit";

fn builder(publics: usize) -> ProgramBuilder {
    let limits = CompilerCapacityProfile::default().limits();
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: limits.program_byte_limit as usize,
            max_wires: limits.wire_limit,
            // This fixture can expose more publics than the compiler's four.
            max_input_values: limits.input_limit.min(limits.wire_limit - publics),
        },
    )
    .unwrap()
}

fn power_mod(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

struct DotFixture {
    program: Program,
    witness: Vec<Val>,
    value: u64,
    quotient_index: usize,
    remainder_index: usize,
}

fn dot_fixture(terms: &[(u64, u64)], addends: &[u64]) -> DotFixture {
    let mut builder = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let value;
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let inputs: Vec<_> = terms
            .iter()
            .map(|&(factor, value)| (factor, c.residue(value, Q)))
            .collect();
        let addends: Vec<_> = addends.iter().map(|&value| c.residue(value, Q)).collect();
        let output = dot(&mut c, &inputs, &addends, PHASE).unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(output.constrained.wire(), public);
        value = output.value;
    }
    assert!(!builder.construction_counters().resource_failed);
    let quotient_index = witness.len() - 2;
    let remainder_index = witness.len() - 1;
    DotFixture {
        program: builder.finish(None).unwrap(),
        witness,
        value,
        quotient_index,
        remainder_index,
    }
}

#[test]
fn integer_bounds_and_both_montgomery_factors_are_independently_pinned() {
    assert_eq!(Q, 167_770_241);
    assert_eq!(u128::from(Val::ORDER_U64), FIELD);
    let q = u128::from(Q);
    let maximum_lhs = 20 * (q - 1) * (q - 1) + 2 * (q - 1);
    let loose_quotient = 20 * (q - 1) + 2;
    let maximum_rhs = loose_quotient * q + (q - 1);
    assert_eq!(maximum_lhs, 562_937_068_928_692_480);
    assert_eq!(maximum_lhs / q, 3_355_404_782);
    assert_eq!(maximum_lhs % q, 18);
    assert_eq!(loose_quotient, 3_355_404_802);
    assert_eq!(maximum_rhs, 562_937_072_451_867_522);
    assert!(maximum_lhs < FIELD && maximum_rhs < FIELD);
    assert_eq!(super::SUM_BOUND, maximum_lhs);
    assert_eq!(u128::from(super::QUOTIENT_BOUND), loose_quotient);
    assert_eq!(super::RHS_BOUND, maximum_rhs);
    assert_eq!(((1_u128 << 32) * u128::from(INVERSE_R)) % q, 1);
    assert_eq!((u128::from(INVERSE_R).pow(2) % q) as u64, INVERSE_R_SQUARED);
    assert_eq!(native::Native.mont(1, 1, Q), INVERSE_R);
    assert_eq!(native::Native.mont(INVERSE_R, 1, Q), INVERSE_R_SQUARED);
    // The fixed-Q proof cannot silently be reused for the other modulus.
    let qhat = u128::from(QHAT);
    assert!(20 * (qhat - 1) * (qhat - 1) + 2 * (qhat - 1) > FIELD);
}

#[test]
fn every_quartic_coefficient_matches_untouched_native_basis_products() {
    for pattern in 0..3 {
        let public: native::Poly = std::array::from_fn(|index| match pattern {
            0 => 0,
            1 => Q - 1,
            _ => ((index as u64 + 1) * 1_000_003 + 97) % Q,
        });
        // All 64 blocks and all four private coordinates cover every public
        // quartic sign/twiddle, both wrap directions and all output positions.
        for block in 0..D / 4 {
            for input in 0..4 {
                let mut basis = [0; D];
                basis[block * 4 + input] = 1;
                let expected = generic::mul_residues(&mut native::Native, &public, &basis, Q);
                for output in 0..4 {
                    assert_eq!(
                        coefficient(&public, block, output, input).unwrap(),
                        expected[block * 4 + output],
                        "pattern={pattern}, block={block}, output={output}, input={input}"
                    );
                }
            }
        }
    }
}

#[test]
fn scalar_extremes_match_integer_reference_and_bind_expected_public_output() {
    let cases = [
        (Vec::new(), Vec::new()),
        (vec![(0, Q - 1)], vec![0]),
        (vec![(1, Q - 1)], vec![Q - 1, Q - 1]),
        (vec![(Q - 1, 1)], vec![0]),
        (vec![(Q - 1, Q - 1)], vec![Q - 1]),
        (vec![(Q - 1, Q - 1); 20], vec![Q - 1; 2]),
        (
            (0..20)
                .map(|i| ((i * 73 + 19) % Q, (i * 101 + 7) % Q))
                .collect(),
            vec![13, Q - 1],
        ),
    ];
    for (terms, addends) in cases {
        let integer_sum: u128 = terms
            .iter()
            .map(|&(a, b)| u128::from(a) * u128::from(b))
            .chain(addends.iter().map(|&a| u128::from(a)))
            .sum();
        let fixture = dot_fixture(&terms, &addends);
        assert_eq!(fixture.value, (integer_sum % u128::from(Q)) as u64);
        assert_eq!(
            fixture.witness[fixture.quotient_index].as_canonical_u64(),
            (integer_sum / u128::from(Q)) as u64
        );
        let expected = Val::from_u64(fixture.value);
        let air = MachineAir::new(fixture.program);
        air.trace(&[expected], &fixture.witness).unwrap();
        assert!(air.trace(&[expected + Val::ONE], &fixture.witness).is_err());
    }
}

#[test]
fn wrong_hints_noncanonical_result_and_field_alias_are_rejected() {
    let fixture = dot_fixture(&[(3, 5), (Q - 2, Q - 1)], &[Q - 1]);
    let air = MachineAir::new(fixture.program);
    let expected = Val::from_u64(fixture.value);
    let quotient = fixture.witness[fixture.quotient_index].as_canonical_u64();
    assert!(quotient > 0 && fixture.value > 0 && fixture.value + 1 < Q);
    air.trace(&[expected], &fixture.witness).unwrap();

    let mut wrong_quotient = fixture.witness.clone();
    wrong_quotient[fixture.quotient_index] += Val::ONE;
    assert!(air.trace(&[expected], &wrong_quotient).is_err());

    let mut wrong_remainder = fixture.witness.clone();
    wrong_remainder[fixture.remainder_index] += Val::ONE;
    // Change the expected public value too: only the arithmetic equation can
    // reject this canonical but incorrect quotient/remainder pair.
    assert!(air.trace(&[expected + Val::ONE], &wrong_remainder).is_err());

    let mut noncanonical = fixture.witness.clone();
    noncanonical[fixture.quotient_index] -= Val::ONE;
    noncanonical[fixture.remainder_index] += Val::from_u64(Q);
    // The integer equation and public output still agree. Strict remainder
    // canonicality must reject the alternate quotient/remainder encoding.
    assert!(air
        .trace(&[expected + Val::from_u64(Q)], &noncanonical)
        .is_err());

    let inverse_q = power_mod(u128::from(Q), FIELD - 2, FIELD);
    assert_eq!(inverse_q * u128::from(Q) % FIELD, 1);
    let alias_quotient = (u128::from(quotient) + inverse_q) % FIELD;
    assert!(alias_quotient > u128::from(super::QUOTIENT_BOUND));
    let mut field_alias = fixture.witness.clone();
    field_alias[fixture.quotient_index] = Val::from_u64(alias_quotient as u64);
    field_alias[fixture.remainder_index] -= Val::ONE;
    assert_eq!(
        field_alias[fixture.quotient_index] * Val::from_u64(Q)
            + field_alias[fixture.remainder_index],
        fixture.witness[fixture.quotient_index] * Val::from_u64(Q)
            + fixture.witness[fixture.remainder_index]
    );
    // This is an actual Goldilocks alias, not just an incorrect field equation.
    assert!(air.trace(&[expected - Val::ONE], &field_alias).is_err());
}

#[test]
fn canonical_private_inputs_and_host_value_hints_remain_constrained() {
    let fixture = dot_fixture(&[(3, 0)], &[]);
    let air = MachineAir::new(fixture.program);
    let mut alternate = fixture.witness.clone();
    alternate[0] = Val::from_u64(Q);
    alternate[fixture.quotient_index] = Val::from_u64(3);
    // 3*Q = 3*Q + 0; rejecting this requires the private input's own
    // canonical constraint, independently of quotient/remainder validity.
    assert!(air.trace(&[Val::ZERO], &alternate).is_err());

    let zero = dot_fixture(&[(0, 0)], &[]);
    let zero_air = MachineAir::new(zero.program);
    let mut negative = zero.witness;
    negative[0] = -Val::ONE;
    assert!(zero_air.trace(&[Val::ZERO], &negative).is_err());

    for corrupt_addend in [false, true] {
        let mut builder = builder(1);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let claimed;
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let mut private = c.residue(5, Q);
            private.value = 6; // corrupt host hint metadata, not its sealed wire
            let output = if corrupt_addend {
                dot(&mut c, &[], &[private], PHASE).unwrap()
            } else {
                dot(&mut c, &[(3, private)], &[], PHASE).unwrap()
            };
            claimed = Val::from_u64(output.value);
            let public = c.builder.public(0).unwrap();
            c.builder.assert_equal(output.constrained.wire(), public);
        }
        assert!(!builder.construction_counters().resource_failed);
        let air = MachineAir::new(builder.finish(None).unwrap());
        assert!(air.trace(&[claimed], &witness).is_err());
    }
}

#[test]
fn invalid_geometry_coefficients_and_moduli_refuse_before_dot_hints() {
    let mut builder = builder(0);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut builder,
        witness: &mut witness,
        crypto: &mut crypto,
    };
    let valid = c.residue(0, Q);
    let foreign = c.residue(0, QHAT);
    let bad_host = ResidueValue { value: Q, ..valid };
    let invalid = [
        (vec![(1, valid); 21], Vec::new()),
        (Vec::new(), vec![valid; 3]),
        (vec![(Q, valid)], Vec::new()),
        (vec![(1, bad_host)], Vec::new()),
        (vec![(1, foreign)], Vec::new()),
        (Vec::new(), vec![foreign]),
    ];
    for (terms, addends) in invalid {
        let before = (c.witness.len(), c.builder.construction_counters().wires);
        assert!(dot(&mut c, &terms, &addends, PHASE).is_err());
        assert_eq!(
            before,
            (c.witness.len(), c.builder.construction_counters().wires)
        );
    }
    let mut public = [0; D];
    public[0] = Q;
    assert_eq!(coefficient(&public, 0, 0, 0), Err(Error::NonCanonical));
    assert!(coefficient(&[0; D], D / 4, 0, 0).is_err());
    assert!(coefficient(&[0; D], 0, 4, 0).is_err());
    assert!(coefficient(&[0; D], 0, 0, 4).is_err());
}

fn native_matrix(
    public: &[native::Poly],
    private: &[native::Poly],
    base: &native::Poly,
    extra: Option<&native::Poly>,
) -> native::Poly {
    let mut expected = *base;
    for (coefficient, value) in public.iter().zip(private) {
        native::multiply_add(&mut native::Native, &mut expected, coefficient, value);
    }
    if let Some(extra) = extra {
        expected = generic::plus_residues(&mut native::Native, &expected, extra, Q);
    }
    expected
}

#[test]
fn complete_polynomial_maps_match_reference_and_bind_public_coefficients() {
    const PUBLIC_OUTPUTS: usize = 64;
    const PUBLIC_START: usize = D - PUBLIC_OUTPUTS;
    for (columns, pattern, extra_present) in [(0, 0, false), (1, 1, true), (5, 2, true)] {
        let public: Vec<native::Poly> = (0..columns)
            .map(|column| {
                std::array::from_fn(|index| match pattern {
                    0 => 0,
                    1 => Q - 1,
                    _ => ((column as u64 + 1) * 97 + (index as u64 + 1) * 73) % Q,
                })
            })
            .collect();
        let private: Vec<native::Poly> = (0..columns)
            .map(|column| {
                std::array::from_fn(|index| {
                    if pattern == 1 {
                        Q - 1
                    } else {
                        ((column as u64 + 1) * 19 + index as u64 * 101 + 1) % Q
                    }
                })
            })
            .collect();
        let base: native::Poly =
            std::array::from_fn(|index| if index % 2 == 0 { 0 } else { Q - 1 });
        let extra: native::Poly = std::array::from_fn(|index| (index as u64 * 31 + 3) % Q);
        let expected = native_matrix(&public, &private, &base, extra_present.then_some(&extra));
        let mut builder = builder(PUBLIC_OUTPUTS);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let base = base.map(|value| c.residue(value, Q));
            let extra = extra_present.then(|| extra.map(|value| c.residue(value, Q)));
            let private: Vec<_> = private
                .iter()
                .map(|poly| poly.map(|value| c.residue(value, Q)))
                .collect();
            let columns: Vec<_> = public.iter().zip(&private).collect();
            let output = matrix_poly(&mut c, &base, &columns, extra.as_ref(), PHASE).unwrap();
            for (index, result) in output.into_iter().enumerate() {
                assert_eq!(result.value, expected[index]);
                // Keep all 256 equalities within the existing 64-public limit.
                // The final 64 outputs remain mutable public expectations.
                let expected_wire = if index < PUBLIC_START {
                    c.builder.constant(Val::from_u64(expected[index]))
                } else {
                    c.builder.public(index - PUBLIC_START).unwrap()
                };
                c.builder
                    .assert_equal(result.constrained.wire(), expected_wire);
            }
        }
        assert!(!builder.construction_counters().resource_failed);
        let air = MachineAir::new(builder.finish(None).unwrap());
        let expected = expected.map(Val::from_u64);
        air.trace(&expected[PUBLIC_START..], &witness).unwrap();
        let mut wrong_output = expected;
        wrong_output[D - 1] += Val::ONE;
        assert!(air.trace(&wrong_output[PUBLIC_START..], &witness).is_err());
        if columns > 0 {
            let mut different_public = public.clone();
            // A different coefficient in the final quartic block must change
            // a public expectation, not only one of the fixed equalities.
            different_public[0][D - 3] = (different_public[0][D - 3] + 1) % Q;
            let different = native_matrix(
                &different_public,
                &private,
                &base,
                extra_present.then_some(&extra),
            );
            let different = different.map(Val::from_u64);
            assert_ne!(different[PUBLIC_START..], expected[PUBLIC_START..]);
            assert!(air.trace(&different[PUBLIC_START..], &witness).is_err());
        }
    }
}

#[test]
fn candidate_selection_preserves_expected_context_and_profile_admission() {
    let context = Context([83; 32]);
    let (mut statement, witness) = ring::fixture(context).unwrap();
    let capacity = CompilerCapacityProfile::default();
    let representation = CompilerRepresentation::FusedPublicLinearV1;
    for wrong_profile in [false, true] {
        let expected = if wrong_profile {
            statement.profile = Profile::PrivateNoteDirectV1;
            context
        } else {
            Context([84; 32])
        };
        let failure = compile_with_representation_diagnostics(
            &statement,
            &witness,
            expected,
            capacity,
            representation,
            capacity.limits().required_host_bytes as usize,
        )
        .err()
        .expect("wrong profile/context must reject before arithmetic");
        assert_eq!(
            failure.error,
            if wrong_profile {
                Error::Profile
            } else {
                Error::Context
            }
        );
        assert_eq!(failure.representation, representation.name());
        assert_eq!(failure.wires, None);
        assert_eq!(failure.input_values, None);
        assert!(!failure.cryptographic_proof_started);
    }
}
