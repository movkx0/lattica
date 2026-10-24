use super::*;
use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir, Program, ProgramBuilder};

#[test]
fn reused_bits_preserve_canonical_unsigned_and_signed_encodings() {
    for q in [2, 167_770_241, 3_489_661_057, u32::MAX] {
        let mut b = ProgramBuilder::new(0).unwrap();
        let bits: Vec<_> = (0..32).map(|_| b.input()).collect();
        canonical_from_bits(&mut b, &bits, Modulus::new(q).unwrap()).unwrap();
        let p = b.finish(None).unwrap();
        let encode = |value: u32| {
            (0..32)
                .map(|i| Val::from_u32((value >> i) & 1))
                .collect::<Vec<_>>()
        };
        for v in [0, q / 2, q - 1] {
            p.evaluate(&[], &encode(v)).unwrap();
        }
        assert!(p.evaluate(&[], &encode(q)).is_err());
        let mut non_boolean = encode(0);
        non_boolean[0] = Val::TWO;
        assert!(p.evaluate(&[], &non_boolean).is_err());
    }
    for bound in [0, 1, 565, 38346, 6212586, i32::MAX as u32] {
        let mut b = ProgramBuilder::new(1).unwrap();
        let expected = b.public(0).unwrap();
        let bits: Vec<_> = (0..32).map(|_| b.input()).collect();
        let result = signed_from_offset_bits(&mut b, &bits, bound).unwrap();
        b.assert_equal(result.wire(), expected);
        let p = b.finish(None).unwrap();
        let encode = |value: u32| {
            (0..32)
                .map(|i| Val::from_u32((value >> i) & 1))
                .collect::<Vec<_>>()
        };
        for (v, expected) in [
            (0, -Val::from_u32(bound)),
            (bound, Val::ZERO),
            (2 * bound, Val::from_u32(bound)),
        ] {
            p.evaluate(&[expected], &encode(v)).unwrap();
        }
        assert!(p
            .evaluate(&[Val::from_u32(bound + 1)], &encode(2 * bound + 1))
            .is_err());
    }
}

fn product_program(modulus: u32) -> Program {
    let mut b = ProgramBuilder::new(1).unwrap();
    let m = Modulus::new(modulus).unwrap();
    let a = b.input();
    let c = b.input();
    let q = b.input();
    let r = b.public(0).unwrap();
    let a = canonical(&mut b, a, m);
    let c = canonical(&mut b, c, m);
    mul(&mut b, a, c, q, r).unwrap();
    b.finish(None).unwrap()
}

#[test]
fn modular_products_bind_quotient_remainder_and_operand_ranges() {
    for modulus in [167_770_241_u32, 3_489_661_057, u32::MAX] {
        let p = product_program(modulus);
        let m = u64::from(modulus);
        for (a, c) in [(0, 0), (1, m - 1), (m - 1, m - 1), (m / 2, m / 3)] {
            let product = u128::from(a) * u128::from(c);
            let q = (product / u128::from(m)) as u64;
            let r = (product % u128::from(m)) as u64;
            let witness = [a, c, q].map(Val::from_u64);
            p.evaluate(&[Val::from_u64(r)], &witness).unwrap();
            let mut bad = witness;
            bad[2] += Val::ONE;
            assert!(p.evaluate(&[Val::from_u64(r)], &bad).is_err());
            assert!(p.evaluate(&[Val::from_u64(r + 1)], &witness).is_err());
        }
        // This equation is mathematically true modulo m but is not canonical.
        assert!(p
            .evaluate(&[Val::ZERO], &[Val::from_u64(m), Val::ZERO, Val::ZERO])
            .is_err());
        // m^2 is already below Goldilocks p even at the maximum accepted modulus.
        assert!(u128::from(m).pow(2) < FIELD_MODULUS);
    }
}

#[test]
fn addition_and_subtraction_bind_boolean_carries() {
    let m = Modulus::new(167_770_241).unwrap();
    for subtract in [false, true] {
        let mut b = ProgramBuilder::new(1).unwrap();
        let a = b.input();
        let c = b.input();
        let carry = b.input();
        let r = b.public(0).unwrap();
        let a = canonical(&mut b, a, m);
        let c = canonical(&mut b, c, m);
        if subtract {
            sub(&mut b, a, c, carry, r).unwrap();
        } else {
            add(&mut b, a, c, carry, r).unwrap();
        }
        let p = b.finish(None).unwrap();
        let modulus = u64::from(m.value());
        for (a, c) in [
            (0, 0),
            (0, modulus - 1),
            (modulus - 1, 0),
            (modulus - 1, modulus - 1),
        ] {
            let integer = if subtract { a + modulus - c } else { a + c };
            let carry = integer / modulus;
            let remainder = integer % modulus;
            p.evaluate(
                &[Val::from_u64(remainder)],
                &[a, c, carry].map(Val::from_u64),
            )
            .unwrap();
            assert!(p
                .evaluate(
                    &[Val::from_u64(remainder)],
                    &[a, c, 1 - carry].map(Val::from_u64)
                )
                .is_err());
            assert!(p
                .evaluate(&[Val::from_u64(remainder)], &[a, c, 2].map(Val::from_u64))
                .is_err());
        }
    }
}

fn signed_val(x: i64) -> Val {
    if x < 0 {
        -Val::from_u64(x.unsigned_abs())
    } else {
        Val::from_u64(x as u64)
    }
}

#[test]
fn signed_conversion_and_norms_reject_aliases_and_overflow() {
    let mut b = ProgramBuilder::new(2).unwrap();
    let x = b.input();
    let negative = b.input();
    let x = signed(&mut b, x, 6_212_586).unwrap();
    let residue =
        signed_to_residue(&mut b, x, Modulus::new(167_770_241).unwrap(), negative).unwrap();
    let expected = b.public(0).unwrap();
    b.assert_equal(expected, residue.wire());
    let norm = assert_squared_norm(&mut b, &[x], 6_212_586_u64.pow(2)).unwrap();
    let expected_norm = b.public(1).unwrap();
    b.assert_equal(expected_norm, norm);
    let p = b.finish(None).unwrap();
    for x in [-6_212_586_i64, -1, 0, 1, 6_212_586] {
        let residue = x.rem_euclid(167_770_241) as u64;
        let norm = x.unsigned_abs().pow(2);
        let public = [residue, norm].map(Val::from_u64);
        let witness = [signed_val(x), Val::from_bool(x < 0)];
        p.evaluate(&public, &witness).unwrap();
        assert!(p
            .evaluate(&public, &[signed_val(x), Val::from_bool(x >= 0)])
            .is_err());
    }
    for x in [-6_212_587_i64, 6_212_587] {
        assert!(p
            .evaluate(&[Val::ZERO; 2], &[signed_val(x), Val::from_bool(x < 0)])
            .is_err());
    }
    let mut b = ProgramBuilder::new(0).unwrap();
    let input = b.input();
    let wide = signed(&mut b, input, i32::MAX as u32).unwrap();
    assert_eq!(
        assert_squared_norm(&mut b, &[wide; 5], 1),
        Err(Error::NormCanWrap)
    );
}

#[test]
fn upper_bound_is_an_integer_comparison() {
    for bound in [0, 1, 2, 167_770_240, 3_161_803_581_581_766, MAX_BOUND] {
        let mut b = ProgramBuilder::new(1).unwrap();
        let value = b.public(0).unwrap();
        assert_at_most(&mut b, value, bound).unwrap();
        let p = b.finish(None).unwrap();
        p.evaluate(&[Val::from_u64(bound)], &[]).unwrap();
        p.evaluate(&[Val::ZERO], &[]).unwrap();
        assert!(p.evaluate(&[Val::from_u64(bound + 1)], &[]).is_err());
        assert!(p.evaluate(&[Val::NEG_ONE], &[]).is_err());
    }
}

#[test]
fn real_stark_proof_binds_modular_product() {
    let modulus = 3_489_661_057_u64;
    let program = product_program(modulus as u32);
    let registered =
        RegisteredProgram::new_with_memory_budget(MachineAir::new(program), 1_u64 << 30).unwrap();
    let a = modulus - 1;
    let product = u128::from(a).pow(2);
    let witness = [a, a, (product / u128::from(modulus)) as u64].map(Val::from_u64);
    let public = [Val::ONE];
    let proof = registered.prove(&public, &witness).unwrap();
    registered.verify(&proof, &public).unwrap();
    assert!(registered.verify(&proof, &[Val::from_u64(2)]).is_err());
}
