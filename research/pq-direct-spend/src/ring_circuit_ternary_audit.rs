//! Independent audit of the fixed-Q signed ternary transform. The integer
//! oracle uses frozen butterfly constants and an independently pinned output
//! permutation, never candidate quotient hints or native Montgomery reduction.

use super::super::{
    compile_with_representation_diagnostics, ntt::PublicTransform, CompilerCapacityProfile,
    CompilerRepresentation,
};
use super::{dot, ntt, ntt_many};
use crate::{ring, ring_native as native, Context, Error, Profile};
use lattica_pq_ringct_research::rust_verify::{
    constraints::ConstraintContext, constraints_crypto::CryptoObligations, D, OMEGA_Q, Q,
};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

const FIELD: u128 = 18_446_744_069_414_584_321;
const INVERSE_R: u64 = 54_987_456;
const PHASE: &str = "independent_ternary_ntt_audit";
const PERMUTATION: [usize; 64] = [
    0, 32, 8, 44, 5, 39, 13, 40, 2, 35, 10, 47, 7, 37, 15, 43, 1, 33, 9, 45, 4, 38, 12, 41, 3, 34,
    11, 46, 6, 36, 14, 42, 63, 31, 55, 19, 58, 24, 50, 23, 61, 28, 53, 16, 56, 26, 48, 20, 62, 30,
    54, 18, 59, 25, 51, 22, 60, 29, 52, 17, 57, 27, 49, 21,
];

fn builder(publics: usize) -> ProgramBuilder {
    let limits = CompilerCapacityProfile::default().limits();
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: limits.program_byte_limit as usize,
            max_wires: limits.wire_limit,
            max_input_values: limits.input_limit.min(limits.wire_limit - publics),
        },
    )
    .unwrap()
}

fn multiply(a: u64, b: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(Q)) as u64
}

fn integer_ntt(input: &native::Signed) -> native::Poly {
    let input = input.map(|value| value.rem_euclid(Q as i64) as u64);
    let mut values = input;
    let conversion = multiply(138_438_709, INVERSE_R);
    let initial = multiply(OMEGA_Q[1], INVERSE_R);
    for index in 0..128 {
        let low = multiply(input[index], conversion);
        let high = multiply(input[index + 128], initial);
        values[index] = (low + high) % Q;
        values[index + 128] = (low + Q - high) % Q;
    }
    for (groups, stride) in [(2, 64), (4, 32), (8, 16), (16, 8), (32, 4)] {
        for group in 0..groups {
            let factor = multiply(OMEGA_Q[groups + group], INVERSE_R);
            let start = 2 * group * stride;
            for index in start..start + stride {
                let low = values[index];
                let high = multiply(values[index + stride], factor);
                values[index] = (low + high) % Q;
                values[index + stride] = (low + Q - high) % Q;
            }
        }
    }
    std::array::from_fn(|index| values[PERMUTATION[index / 4] * 4 + index % 4])
}

fn power_mod(mut value: u128, mut exponent: u128) -> u128 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % FIELD;
        }
        value = value * value % FIELD;
        exponent >>= 1;
    }
    result
}

fn row_bias(coefficients: &[u64; 64]) -> i128 {
    let sum = coefficients
        .iter()
        .map(|&value| i128::from(value))
        .sum::<i128>();
    ((sum + i128::from(Q) - 1) / i128::from(Q)) * i128::from(Q)
}

fn signed_sum(coefficients: &[u64; 64], input: &[i64; 64]) -> i128 {
    coefficients
        .iter()
        .zip(input)
        .map(|(&coefficient, &value)| i128::from(coefficient) * i128::from(value))
        .sum()
}

struct DotFixture {
    program: Program,
    witness: Vec<Val>,
    quotient: usize,
    remainder: usize,
    output: Val,
}

fn dot_fixture(coefficients: &[u64; 64], input: &[i64; 64]) -> DotFixture {
    let mut builder = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let expected = signed_sum(coefficients, input).rem_euclid(i128::from(Q)) as u64;
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let signed = input.map(|value| c.signed(value, 1));
        let result = dot(&mut c, coefficients, &signed, PHASE).unwrap();
        assert_eq!(result.value, expected);
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(result.constrained.wire(), public);
    }
    assert!(!builder.construction_counters().resource_failed);
    let quotient = witness.len() - 2;
    let remainder = witness.len() - 1;
    let biased = row_bias(coefficients) + signed_sum(coefficients, input);
    assert_eq!(
        witness[quotient].as_canonical_u64(),
        (biased / i128::from(Q)) as u64
    );
    assert_eq!(witness[remainder].as_canonical_u64(), expected);
    DotFixture {
        program: builder.finish(None).unwrap(),
        witness,
        quotient,
        remainder,
        output: Val::from_u64(expected),
    }
}

#[test]
fn signed_integer_bounds_bias_and_seven_bit_quotient_are_independently_pinned() {
    assert_eq!((D, super::WIDTH, Q), (256, 64, 167_770_241));
    assert_eq!(u128::from(Val::ORDER_U64), FIELD);
    let q = u128::from(Q);
    let coefficient_sum = 64 * (q - 1);
    let bias = 64 * q;
    let maximum = bias + coefficient_sum;
    assert_eq!(coefficient_sum, 10_737_295_360);
    assert_eq!(bias, 10_737_295_424);
    assert_eq!(maximum, 21_474_590_784);
    assert_eq!(maximum / q, 127);
    assert_eq!(maximum % q, q - 64);
    assert_eq!(127 * q + (q - 1), 21_474_590_847);
    assert!(maximum < 1_u128 << 35);
    assert!(127 * q + (q - 1) < FIELD);
    assert_eq!(super::QUOTIENT_BOUND, 127);
    assert_eq!(super::SUM_BOUND, maximum);
    assert_eq!(super::RHS_BOUND, 127 * q + (q - 1));
    assert_eq!(((1_u128 << 32) * u128::from(INVERSE_R)) % q, 1);
    assert_eq!((1_u128 << 64) % q, 138_438_709);
    let mut permutation = PERMUTATION;
    permutation.sort_unstable();
    assert_eq!(permutation, std::array::from_fn(|index| index));
    for coefficients in [[0; 64], [Q - 1; 64], std::array::from_fn(|i| i as u64)] {
        let c = coefficients
            .iter()
            .map(|&value| i128::from(value))
            .sum::<i128>();
        let b = row_bias(&coefficients);
        assert_eq!(b % i128::from(Q), 0);
        assert!(b >= c && b - c < i128::from(Q));
        // Every partial sum stays in this interval, including all-negative
        // inputs. Field-encoded negative terms do not invalidate the bound.
        assert!(b - c >= 0 && b + c <= maximum as i128);
    }
}

#[test]
fn integer_oracle_checks_every_signed_basis_lane_and_output_permutation() {
    let transform = PublicTransform::derive();
    for coordinate in 0..D {
        for sign in [-1, 1] {
            let mut input = [0; D];
            input[coordinate] = sign;
            let expected = integer_ntt(&input);
            let native = native::ntt(&mut native::Native, &input);
            assert_eq!(expected, native, "coordinate={coordinate}, sign={sign}");
            for index in 0..D {
                let coefficient = transform.coefficient_row(index / 4).unwrap()[coordinate / 4];
                assert!(coefficient < Q);
                let actual = if index % 4 == coordinate % 4 {
                    (i128::from(coefficient) * i128::from(sign)).rem_euclid(i128::from(Q)) as u64
                } else {
                    0
                };
                assert_eq!(
                    actual, expected[index],
                    "input={coordinate}, output={index}"
                );
            }
        }
    }
    assert!(transform.coefficient_row(64).is_err());
}

#[test]
fn biased_dot_extremes_match_integer_arithmetic_and_reject_both_alias_families() {
    for (coefficients, input) in [
        ([0; 64], [-1; 64]),
        ([Q - 1; 64], [-1; 64]),
        ([Q - 1; 64], [0; 64]),
        ([Q - 1; 64], [1; 64]),
        (
            std::array::from_fn(|i| 17 * i as u64),
            std::array::from_fn(|i| (i % 3) as i64 - 1),
        ),
    ] {
        let fixture = dot_fixture(&coefficients, &input);
        MachineAir::new(fixture.program)
            .trace(&[fixture.output], &fixture.witness)
            .unwrap();
    }
    let fixture = dot_fixture(&[Q - 1; 64], &[1; 64]);
    let air = MachineAir::new(fixture.program);
    assert_eq!(fixture.witness[fixture.quotient].as_canonical_u64(), 127);
    assert_eq!(fixture.output.as_canonical_u64(), Q - 64);

    let mut noncanonical = fixture.witness.clone();
    noncanonical[fixture.quotient] -= Val::ONE;
    noncanonical[fixture.remainder] += Val::from_u64(Q);
    // Preserve the integer equation and match the changed public remainder.
    // Strict canonicality must still reject this second representation.
    assert!(air
        .trace(&[fixture.output + Val::from_u64(Q)], &noncanonical)
        .is_err());

    let inverse_q = power_mod(u128::from(Q), FIELD - 2);
    assert_eq!(inverse_q * u128::from(Q) % FIELD, 1);
    let alias_quotient = (127 + inverse_q) % FIELD;
    assert!(alias_quotient > 127);
    let mut alias = fixture.witness.clone();
    alias[fixture.quotient] = Val::from_u64(alias_quotient as u64);
    alias[fixture.remainder] -= Val::ONE;
    assert_eq!(
        alias[fixture.quotient] * Val::from_u64(Q) + alias[fixture.remainder],
        fixture.witness[fixture.quotient] * Val::from_u64(Q) + fixture.witness[fixture.remainder]
    );
    // This is a genuine Goldilocks alias with a still-canonical remainder.
    assert!(air.trace(&[fixture.output - Val::ONE], &alias).is_err());
}

#[test]
fn zero_coefficients_cannot_remove_private_ternary_domain_constraints() {
    let fixture = dot_fixture(&[0; 64], &[0; 64]);
    let air = MachineAir::new(fixture.program);
    air.trace(&[Val::ZERO], &fixture.witness).unwrap();
    for invalid in [Val::from_u64(2), -Val::from_u64(2), Val::from_u64(Q - 1)] {
        let mut wrong = fixture.witness.clone();
        wrong[0] = invalid;
        // Dot equation and quotient/remainder remain unchanged. Only the
        // pre-existing signed wire constraint rejects this invalid domain.
        assert!(air.trace(&[Val::ZERO], &wrong).is_err());
    }
}

#[test]
fn malformed_host_domain_or_public_coefficient_refuses_before_dot_hints() {
    let mut builder = builder(0);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut builder,
        witness: &mut witness,
        crypto: &mut crypto,
    };
    let valid = c.signed(0, 1);
    let foreign = c.signed(0, 2);
    for variant in 0..3 {
        let mut input = [valid; 64];
        let mut coefficients = [0; 64];
        match variant {
            0 => input[63].value = 2,
            1 => input[63] = foreign,
            _ => coefficients[63] = Q,
        }
        let before = (c.witness.len(), c.builder.construction_counters().wires);
        assert!(dot(&mut c, &coefficients, &input, PHASE).is_err());
        assert_eq!(
            before,
            (c.witness.len(), c.builder.construction_counters().wires)
        );
    }
    let transform = PublicTransform::derive();
    let mut invalid = [valid; D];
    invalid[D - 1] = foreign;
    let before = (c.witness.len(), c.builder.construction_counters().wires);
    assert!(ntt(&mut c, &invalid, &transform, PHASE).is_err());
    // A bad final polynomial must be found before a valid first polynomial
    // causes the batch to allocate any transform hints or wires.
    assert!(ntt_many(&mut c, &[[valid; D], invalid], &transform, PHASE).is_err());
    assert_eq!(
        ntt_many::<0>(&mut c, &[], &transform, PHASE).err(),
        Some(Error::Geometry)
    );
    assert_eq!(
        ntt_many(&mut c, &[[valid; D]; 10], &transform, PHASE).err(),
        Some(Error::Geometry)
    );
    assert_eq!(
        before,
        (c.witness.len(), c.builder.construction_counters().wires)
    );
}

#[test]
fn valid_but_false_host_metadata_cannot_override_the_signed_private_wire() {
    let mut builder = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut coefficients = [0; 64];
    coefficients[0] = 3;
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let mut input = std::array::from_fn(|_| c.signed(-1, 1));
        input[0].value = 1;
        let result = dot(&mut c, &coefficients, &input, PHASE).unwrap();
        assert_eq!(result.value, 3);
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(result.constrained.wire(), public);
    }
    let air = MachineAir::new(builder.finish(None).unwrap());
    assert!(air.trace(&[Val::from_u64(3)], &witness).is_err());
}

fn transform_fixture(input: &native::Signed, bind_all: bool) -> (Program, Vec<Val>, [Val; 64]) {
    let expected = integer_ntt(input);
    assert_eq!(expected, native::ntt(&mut native::Native, input));
    let transform = PublicTransform::derive();
    let mut builder = builder(64);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let signed = input.map(|value| c.signed(value, 1));
        let output = ntt(&mut c, &signed, &transform, PHASE).unwrap();
        for index in 0..D {
            let expected_wire = if index >= D - 64 {
                Some(c.builder.public(index - (D - 64)).unwrap())
            } else if bind_all {
                Some(c.builder.constant(Val::from_u64(expected[index])))
            } else {
                None
            };
            if let Some(expected_wire) = expected_wire {
                c.builder
                    .assert_equal(output[index].constrained.wire(), expected_wire);
            }
        }
    }
    assert!(crypto.ntt.is_empty());
    assert!(!builder.construction_counters().resource_failed);
    let public = std::array::from_fn(|index| Val::from_u64(expected[D - 64 + index]));
    (builder.finish(None).unwrap(), witness, public)
}

#[test]
fn complete_transform_binds_every_oracle_output_and_rejects_mutated_outputs() {
    for input in [
        [-1; D],
        [1; D],
        std::array::from_fn(|index| ((index * 5 + index / 4) % 3) as i64 - 1),
    ] {
        let (program, witness, public) = transform_fixture(&input, true);
        let air = MachineAir::new(program);
        air.trace(&public, &witness).unwrap();
        for index in [0, 1, 62, 63] {
            let mut wrong = public;
            wrong[index] += Val::ONE;
            assert!(air.trace(&wrong, &witness).is_err());
        }
    }
}

#[test]
fn compiled_shape_is_independent_of_private_signs_and_zeros() {
    let first = std::array::from_fn(|index| (index % 3) as i64 - 1);
    let (program, witness, public) = transform_fixture(&first, false);
    let air = MachineAir::new(program.clone());
    air.trace(&public, &witness).unwrap();
    for input in [[0; D], first.map(|value| -value), [1; D]] {
        let (other_program, other_witness, other_public) = transform_fixture(&input, false);
        assert!(
            program == other_program,
            "private values changed program shape"
        );
        assert_eq!(witness.len(), other_witness.len());
        air.trace(&other_public, &other_witness).unwrap();
    }
}

#[test]
fn ternary_representation_rejects_wrong_profile_before_arithmetic() {
    let context = Context([94; 32]);
    let (mut statement, witness) = ring::fixture(context).unwrap();
    statement.profile = Profile::PrivateNoteDirectV1;
    let capacity = CompilerCapacityProfile::default();
    let representation = CompilerRepresentation::FusedTernaryNttV1;
    let failure = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        capacity,
        representation,
        capacity.limits().required_host_bytes as usize,
    )
    .err()
    .expect("wrong profile must refuse before compiling arithmetic");
    assert_eq!(failure.error, Error::Profile);
    assert_eq!(failure.representation, representation.name());
    assert_eq!(failure.wires, None);
    assert!(!failure.cryptographic_proof_started);
}
