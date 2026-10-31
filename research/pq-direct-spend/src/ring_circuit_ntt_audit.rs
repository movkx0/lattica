//! Independent fixed-Q NTT audit. The oracle uses integer modular butterflies
//! and a pinned output permutation, never the candidate's public matrix or
//! native Montgomery reducer. These are host diagnostics, not proof acceptance.

use super::super::{
    compile_with_representation_diagnostics, CompilerCapacityProfile, CompilerRepresentation,
};
use super::{dot, PublicTransform};
use crate::{ring, ring_native as native, Context, Error, Profile};
use lattica_pq_ringct_research::rust_verify::{
    constraints::{ConstraintContext, ResidueValue},
    constraints_crypto::CryptoObligations,
    generic, D, OMEGA_Q, Q, QHAT,
};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

const FIELD: u128 = 18_446_744_069_414_584_321;
const INVERSE_R: u64 = 54_987_456;
const PHASE: &str = "independent_fused_ntt_audit";
// Pinned MatRiCT+ Q-transform output convention, independently of the derived
// public matrix. Every entry denotes a quartic block; lanes are unchanged.
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

fn integer_ntt(input: &native::Poly) -> native::Poly {
    assert!(input.iter().all(|&value| value < Q));
    let mut values = *input;
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

fn signed_oracle(input: &native::Signed) -> native::Poly {
    integer_ntt(&input.map(|value| value.rem_euclid(Q as i64) as u64))
}

fn power_mod(mut value: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % modulus;
        }
        value = value * value % modulus;
        exponent >>= 1;
    }
    result
}

struct DotFixture {
    program: Program,
    witness: Vec<Val>,
    quotient: usize,
    remainder: usize,
    output: Val,
}

fn dot_fixture(coefficients: &[u64; 64], values: &[u64; 64]) -> DotFixture {
    let mut builder = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let output;
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let inputs = values.map(|value| c.residue(value, Q));
        let result = dot(&mut c, coefficients, &inputs, PHASE).unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(result.constrained.wire(), public);
        output = Val::from_u64(result.value);
    }
    assert!(!builder.construction_counters().resource_failed);
    DotFixture {
        program: builder.finish(None).unwrap(),
        quotient: witness.len() - 2,
        remainder: witness.len() - 1,
        witness,
        output,
    }
}

#[test]
fn fixed_q_integer_bound_and_initial_conversion_are_independently_pinned() {
    assert_eq!((D, super::LANES, super::WIDTH), (256, 4, 64));
    assert_eq!(Q, 167_770_241);
    assert_eq!(u128::from(Val::ORDER_U64), FIELD);
    let q = u128::from(Q);
    let lhs = 64 * (q - 1).pow(2);
    let quotient = 64 * (q - 1);
    let rhs = quotient * q + (q - 1);
    assert_eq!(lhs, 1_801_398_619_498_086_400);
    assert_eq!(lhs / q, 10_737_295_296);
    assert_eq!(lhs % q, 64);
    assert_eq!(quotient, 10_737_295_360);
    assert_eq!(rhs, 1_801_398_630_403_152_000);
    assert!(lhs < FIELD && rhs < FIELD);
    assert_eq!(super::SUM_BOUND, lhs);
    assert_eq!(u128::from(super::QUOTIENT_BOUND), quotient);
    assert_eq!(super::RHS_BOUND, rhs);
    assert_eq!(((1_u128 << 32) * u128::from(INVERSE_R)) % q, 1);
    assert_eq!((1_u128 << 64) % q, 138_438_709);
    assert_eq!(multiply(138_438_709, INVERSE_R), 100_711_271);
    assert!(64 * (u128::from(QHAT) - 1).pow(2) > FIELD);
    let mut permutation = PERMUTATION;
    permutation.sort_unstable();
    assert_eq!(permutation, std::array::from_fn(|index| index));
}

#[test]
fn integer_butterfly_oracle_checks_every_basis_coordinate_lane_and_permutation() {
    let transform = PublicTransform::derive();
    for coordinate in 0..D {
        for value in [1, Q - 1] {
            let mut input = [0; D];
            input[coordinate] = value;
            let expected = integer_ntt(&input);
            let native = generic::ntt_residues(&mut native::Native, &input, Q);
            assert_eq!(expected, native, "coordinate={coordinate}, value={value}");
            for index in 0..D {
                let coefficient = transform.coefficients[index / 4][coordinate / 4];
                assert!(coefficient < Q);
                let actual = if index % 4 == coordinate % 4 {
                    multiply(coefficient, value)
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
}

#[test]
fn dense_dot_rejects_integer_reencodings_and_actual_goldilocks_alias() {
    let fixture = dot_fixture(&[Q - 1; 64], &[Q - 1; 64]);
    let air = MachineAir::new(fixture.program);
    air.trace(&[fixture.output], &fixture.witness).unwrap();
    let quotient = fixture.witness[fixture.quotient].as_canonical_u64();
    assert_eq!(quotient, 10_737_295_296);
    assert_eq!(fixture.output.as_canonical_u64(), 64);

    let mut noncanonical = fixture.witness.clone();
    noncanonical[fixture.quotient] -= Val::ONE;
    noncanonical[fixture.remainder] += Val::from_u64(Q);
    // The integer equation still holds. Only strict canonicality rules out
    // this alternate encoding, even when the expected public output agrees.
    assert!(air
        .trace(&[fixture.output + Val::from_u64(Q)], &noncanonical)
        .is_err());

    let inverse_q = power_mod(u128::from(Q), FIELD - 2, FIELD);
    assert_eq!(inverse_q * u128::from(Q) % FIELD, 1);
    let alias_quotient = (u128::from(quotient) + inverse_q) % FIELD;
    assert!(alias_quotient > u128::from(super::QUOTIENT_BOUND));
    let mut alias = fixture.witness.clone();
    alias[fixture.quotient] = Val::from_u64(alias_quotient as u64);
    alias[fixture.remainder] -= Val::ONE;
    assert_eq!(
        alias[fixture.quotient] * Val::from_u64(Q) + alias[fixture.remainder],
        fixture.witness[fixture.quotient] * Val::from_u64(Q) + fixture.witness[fixture.remainder]
    );
    assert!(air.trace(&[fixture.output - Val::ONE], &alias).is_err());

    let mut wrong = fixture.witness.clone();
    wrong[fixture.remainder] += Val::ONE;
    assert!(air.trace(&[fixture.output + Val::ONE], &wrong).is_err());
}

#[test]
fn canonical_private_wire_constraints_cannot_be_replaced_by_host_hints() {
    let mut coefficients = [0; 64];
    coefficients[0] = 3;
    let fixture = dot_fixture(&coefficients, &[0; 64]);
    let air = MachineAir::new(fixture.program);
    let mut noncanonical = fixture.witness;
    noncanonical[0] = Val::from_u64(Q);
    noncanonical[fixture.quotient] = Val::from_u64(3);
    // 3*Q = 3*Q+0; the input's own canonical constraint must reject it.
    assert!(air.trace(&[Val::ZERO], &noncanonical).is_err());

    let fixture = dot_fixture(&[0; 64], &[0; 64]);
    let air = MachineAir::new(fixture.program);
    let mut negative = fixture.witness;
    negative[0] = -Val::ONE;
    assert!(air.trace(&[Val::ZERO], &negative).is_err());

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
        let mut input = std::array::from_fn(|_| c.residue(5, Q));
        input[0].value = 6;
        let output = dot(&mut c, &coefficients, &input, PHASE).unwrap();
        claimed = Val::from_u64(output.value);
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(output.constrained.wire(), public);
    }
    let air = MachineAir::new(builder.finish(None).unwrap());
    assert!(air.trace(&[claimed], &witness).is_err());
}

#[test]
fn wrong_modulus_coefficients_host_values_and_batch_arity_refuse_before_hints() {
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
    for variant in 0..3 {
        let mut input = [valid; 64];
        let mut coefficients = [0; 64];
        match variant {
            0 => input[63] = foreign,
            1 => input[63] = ResidueValue { value: Q, ..valid },
            _ => coefficients[63] = Q,
        }
        let before = (c.witness.len(), c.builder.construction_counters().wires);
        assert_eq!(
            dot(&mut c, &coefficients, &input, PHASE).err(),
            Some(Error::NonCanonical)
        );
        assert_eq!(
            before,
            (c.witness.len(), c.builder.construction_counters().wires)
        );
    }
    let transform = PublicTransform::derive();
    let signed = [c.signed(0, 1); D];
    let before = (c.witness.len(), c.builder.construction_counters().wires);
    assert_eq!(
        transform.ntt_many::<0>(&mut c, &[], PHASE).err(),
        Some(Error::Geometry)
    );
    assert_eq!(
        transform.ntt_many(&mut c, &[signed; 10], PHASE).err(),
        Some(Error::Geometry)
    );
    assert_eq!(
        before,
        (c.witness.len(), c.builder.construction_counters().wires)
    );
}

fn transform_fixture(
    transform: &PublicTransform,
    input: &native::Signed,
    claimed_input: &native::Signed,
    corrupt_host: bool,
) -> (MachineAir, Vec<Val>, [Val; 64]) {
    let expected = signed_oracle(claimed_input);
    assert_eq!(expected, native::ntt(&mut native::Native, claimed_input));
    let mut builder = builder(64);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let mut signed = input.map(|value| c.signed(value, 1));
        if corrupt_host {
            signed[0].value = claimed_input[0];
        }
        let output = transform.ntt(&mut c, &signed, PHASE).unwrap();
        for index in 0..D {
            let expected_wire = if index < D - 64 {
                c.builder.constant(Val::from_u64(expected[index]))
            } else {
                c.builder.public(index - (D - 64)).unwrap()
            };
            c.builder
                .assert_equal(output[index].constrained.wire(), expected_wire);
        }
    }
    assert!(crypto.ntt.is_empty());
    assert!(!builder.construction_counters().resource_failed);
    let public = std::array::from_fn(|index| Val::from_u64(expected[D - 64 + index]));
    (
        MachineAir::new(builder.finish(None).unwrap()),
        witness,
        public,
    )
}

#[test]
fn full_transform_binds_all_outputs_to_independent_oracle_and_rejects_host_corruption() {
    let transform = PublicTransform::derive();
    let input = std::array::from_fn(|index| (index % 3) as i64 - 1);
    let (air, witness, public) = transform_fixture(&transform, &input, &input, false);
    air.trace(&public, &witness).unwrap();
    let mut wrong = public;
    wrong[0] += Val::ONE;
    assert!(air.trace(&wrong, &witness).is_err());

    let mut claimed = input;
    claimed[0] = 1;
    let (air, witness, public) = transform_fixture(&transform, &input, &claimed, true);
    assert!(air.trace(&public, &witness).is_err());
}

#[test]
fn changed_public_table_cannot_satisfy_expected_native_transform() {
    let mut transform = PublicTransform::derive();
    transform.coefficients[63][0] = (transform.coefficients[63][0] + 1) % Q;
    let mut input = [0; D];
    input[0] = 1;
    let (air, witness, public) = transform_fixture(&transform, &input, &input, false);
    assert!(air.trace(&public, &witness).is_err());
}

#[test]
fn ntt_representation_rejects_wrong_profile_before_arithmetic() {
    let context = Context([92; 32]);
    let (mut statement, witness) = ring::fixture(context).unwrap();
    statement.profile = Profile::PrivateNoteDirectV1;
    let capacity = CompilerCapacityProfile::default();
    let representation = CompilerRepresentation::FusedPublicNttV1;
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
