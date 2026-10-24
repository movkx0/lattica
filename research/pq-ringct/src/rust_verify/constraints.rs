//! Constrained arithmetic backend. Host values generate hints only; every hint
//! is bound by the public verifier relation before it can affect acceptance.
use super::{generic::*, VerifyError, D, Q, QHAT};
use lattica_prover_p3::block_v2::machine::{
    pq_bytes::Byte,
    pq_modular as modular,
    program::{ScopedProgramBuilder, Val, Wire},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

#[derive(Clone, Copy, Debug)]
pub struct ResidueValue {
    pub value: u64,
    pub constrained: modular::Residue,
}
#[derive(Clone, Copy, Debug)]
pub struct SignedValue {
    pub value: i64,
    pub constrained: modular::Signed,
}
#[derive(Clone, Copy, Debug)]
pub struct ByteValue {
    pub value: u8,
    pub constrained: Byte,
}
pub struct ConstraintContext<'a, 'p> {
    pub builder: &'a mut ScopedProgramBuilder<'p>,
    pub witness: &'a mut Vec<Val>,
    pub crypto: &'a mut super::constraints_crypto::CryptoObligations,
}
impl ConstraintContext<'_, '_> {
    pub fn input(&mut self, value: u64) -> Wire {
        let wire = self.builder.input();
        self.witness.push(Val::from_u64(value));
        wire
    }
    pub fn input_signed(&mut self, value: i64) -> Wire {
        let wire = self.builder.input();
        self.witness.push(if value < 0 {
            -Val::from_u64(value.unsigned_abs())
        } else {
            Val::from_u64(value as u64)
        });
        wire
    }
    pub fn residue(&mut self, value: u64, q: u64) -> ResidueValue {
        let wire = self.input(value);
        let constrained = modular::canonical(self.builder, wire, modulus(q));
        ResidueValue { value, constrained }
    }
    pub fn signed(&mut self, value: i64, bound: u32) -> SignedValue {
        let wire = self.input_signed(value);
        let constrained = modular::signed(self.builder, wire, bound).expect("static signed bound");
        SignedValue { value, constrained }
    }
    pub fn constant_residue(&mut self, value: u64, q: u64) -> ResidueValue {
        assert!(value < q);
        let wire = self.builder.constant(Val::from_u64(value));
        let constrained = modular::canonical(self.builder, wire, modulus(q));
        ResidueValue { value, constrained }
    }
    pub fn byte(&mut self, value: u8) -> ByteValue {
        let wire = self.input(u64::from(value));
        let constrained = Byte::from_wire(self.builder, wire);
        ByteValue { value, constrained }
    }
    pub fn constant_byte(&mut self, value: u8) -> ByteValue {
        ByteValue {
            value,
            constrained: Byte::constant(self.builder, value),
        }
    }
    pub fn constant_signed(&mut self, value: i64, bound: u32) -> SignedValue {
        let field = if value < 0 {
            -Val::from_u64(value.unsigned_abs())
        } else {
            Val::from_u64(value as u64)
        };
        let wire = self.builder.constant(field);
        let constrained = modular::signed(self.builder, wire, bound).expect("static signed bound");
        SignedValue { value, constrained }
    }
    fn multiply(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        let product = u128::from(a.value) * u128::from(b.value);
        let quotient = self.input((product / u128::from(q)) as u64);
        let value = (product % u128::from(q)) as u64;
        let remainder = self.input(value);
        let constrained = modular::mul(
            self.builder,
            a.constrained,
            b.constrained,
            quotient,
            remainder,
        )
        .expect("same fixed modulus");
        ResidueValue { value, constrained }
    }
}
fn modulus(q: u64) -> modular::Modulus {
    assert!(q == Q || q == QHAT);
    modular::Modulus::new(q as u32).expect("fixed nonzero modulus")
}
fn inverse_r(q: u64) -> u64 {
    // extended Euclid, only public profile constants
    let (mut old_r, mut r) = (q as i128, ((1_u64 << 32) % q) as i128);
    let (mut old_s, mut s) = (0_i128, 1_i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }
    assert_eq!(old_r, 1);
    old_s.rem_euclid(q as i128) as u64
}

impl Backend for ConstraintContext<'_, '_> {
    type Residue = ResidueValue;
    type Signed = SignedValue;
    type Byte = ByteValue;
    fn ntt_poly(&mut self, input: &Polynomial<SignedValue>, q: u64) -> Polynomial<ResidueValue> {
        super::constraints_ntt::request_ntt(self, input, q)
    }
    fn mul_poly(
        &mut self,
        a: &Polynomial<ResidueValue>,
        b: &Polynomial<ResidueValue>,
        q: u64,
    ) -> Polynomial<ResidueValue> {
        super::constraints_poly::request_mul(self, a, b, q)
    }
    fn constant(&mut self, value: u64, q: u64) -> ResidueValue {
        self.constant_residue(value, q)
    }
    fn add(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        let sum = a.value + b.value;
        let value = sum % q;
        let carry = self.input(sum / q);
        let remainder = self.input(value);
        let constrained =
            modular::add(self.builder, a.constrained, b.constrained, carry, remainder)
                .expect("same fixed modulus");
        ResidueValue { value, constrained }
    }
    fn sub(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        let shifted = a.value + q - b.value;
        let value = shifted % q;
        let carry = self.input(shifted / q);
        let remainder = self.input(value);
        let constrained =
            modular::sub(self.builder, a.constrained, b.constrained, carry, remainder)
                .expect("same fixed modulus");
        ResidueValue { value, constrained }
    }
    fn mont(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        if let Some(constant) = self.builder.known_constant(b.constrained.wire()) {
            let adjusted = ((u128::from(constant.as_canonical_u64()) * u128::from(inverse_r(q)))
                % u128::from(q)) as u64;
            let factor = self.constant_residue(adjusted, q);
            return self.multiply(a, factor, q);
        }
        if let Some(constant) = self.builder.known_constant(a.constrained.wire()) {
            let adjusted = ((u128::from(constant.as_canonical_u64()) * u128::from(inverse_r(q)))
                % u128::from(q)) as u64;
            let factor = self.constant_residue(adjusted, q);
            return self.multiply(b, factor, q);
        }
        let product = self.multiply(a, b, q);
        let r_inverse = self.constant_residue(inverse_r(q), q);
        self.multiply(product, r_inverse, q)
    }
    fn to_residue(&mut self, a: SignedValue, q: u64) -> ResidueValue {
        let negative = self.input(u64::from(a.value < 0));
        let constrained =
            modular::signed_to_residue(self.builder, a.constrained, modulus(q), negative)
                .expect("signed profile bound smaller than modulus");
        ResidueValue {
            value: a.value.rem_euclid(q as i64) as u64,
            constrained,
        }
    }
    fn signed_neg(&mut self, a: SignedValue) -> SignedValue {
        let zero = self.builder.constant(Val::ZERO);
        let wire = self.builder.sub(zero, a.constrained.wire());
        let constrained = modular::signed(self.builder, wire, a.constrained.bound())
            .expect("static signed bound");
        SignedValue {
            value: -a.value,
            constrained,
        }
    }
    fn signed_sub(&mut self, a: SignedValue, b: SignedValue) -> SignedValue {
        let bound = a
            .constrained
            .bound()
            .checked_add(b.constrained.bound())
            .expect("static signed bound sum");
        let wire = self.builder.sub(a.constrained.wire(), b.constrained.wire());
        let constrained = modular::signed(self.builder, wire, bound).expect("static signed bound");
        SignedValue {
            value: a.value - b.value,
            constrained,
        }
    }
    fn norm(&mut self, a: &[Polynomial<SignedValue>], maximum: u64) -> Result<(), VerifyError> {
        let values: Vec<_> = a.iter().flatten().map(|x| x.constrained).collect();
        modular::assert_squared_norm(self.builder, &values, maximum)
            .expect("static norm bound cannot wrap");
        Ok(())
    }
    fn g_bound(
        &mut self,
        f: &Polynomial<SignedValue>,
        x: &Polynomial<SignedValue>,
        bound: u32,
    ) -> Result<(), VerifyError> {
        let fb = u128::from(
            f.iter()
                .map(|v| v.constrained.bound())
                .max()
                .expect("fixed polynomial"),
        );
        let xb = u128::from(
            x.iter()
                .map(|v| v.constrained.bound())
                .max()
                .expect("fixed polynomial"),
        );
        // Each actual negacyclic coefficient and its claimed bounded encoding
        // differ by less than p. Thus field equality is integer equality.
        assert!((D as u128) * fb * (fb + xb) + u128::from(bound) < 0xffff_ffff_0000_0001);
        let other: Vec<_> = (0..D)
            .map(|i| {
                self.builder
                    .sub(x[i].constrained.wire(), f[i].constrained.wire())
            })
            .collect();
        let zero = self.builder.constant(Val::ZERO);
        let mut out = [zero; D];
        for i in 0..D {
            for j in 0..D {
                let product = self.builder.mul(f[i].constrained.wire(), other[j]);
                let index = (i + j) % D;
                out[index] = if i + j < D {
                    self.builder.add(out[index], product)
                } else {
                    self.builder.sub(out[index], product)
                };
            }
        }
        for wire in out {
            modular::signed(self.builder, wire, bound).expect("static g bound");
        }
        Ok(())
    }
    fn equal_bytes(&mut self, a: &[ByteValue; 32], b: &[ByteValue; 32]) -> Result<(), VerifyError> {
        for i in 0..32 {
            let lhs = a[i].constrained.to_wire(self.builder);
            let rhs = b[i].constrained.to_wire(self.builder);
            self.builder.assert_equal(lhs, rhs);
        }
        Ok(())
    }
    fn equal_signed(
        &mut self,
        a: &Polynomial<SignedValue>,
        b: &Polynomial<SignedValue>,
    ) -> Result<(), VerifyError> {
        for i in 0..D {
            self.builder
                .assert_equal(a[i].constrained.wire(), b[i].constrained.wire());
        }
        Ok(())
    }
    fn parameters(
        &mut self,
        seed: &[ByteValue; 32],
        context: &[ByteValue; 32],
    ) -> Result<GParameters<ResidueValue, ByteValue>, VerifyError> {
        super::constraints_crypto::parameters(self, seed, context)
    }
    fn sample_g(
        &mut self,
        seed: &[ByteValue; 32],
    ) -> Result<Vec<Polynomial<ResidueValue>>, VerifyError> {
        super::constraints_crypto::sample_g(self, seed)
    }
    fn expand_alpha(
        &mut self,
        seed: &[ByteValue; 32],
    ) -> Result<(Vec<Polynomial<ResidueValue>>, Polynomial<SignedValue>), VerifyError> {
        super::constraints_crypto::expand_alpha(self, seed)
    }
    fn hash_alpha(
        &mut self,
        pp: &[ByteValue; 32],
        statement: &GStatement<ResidueValue, ByteValue>,
        w_out: &[Vec<Polynomial<ResidueValue>>],
        w0: &[Polynomial<ResidueValue>],
        v: &[Polynomial<ResidueValue>],
        v2: &Polynomial<ResidueValue>,
        c: &Polynomial<ResidueValue>,
        w: &Polynomial<ResidueValue>,
        w1: &[Polynomial<ResidueValue>],
        w2: &[Polynomial<ResidueValue>],
    ) -> [ByteValue; 32] {
        super::constraints_crypto::hash_alpha(self, pp, statement, w_out, w0, v, v2, c, w, w1, w2)
    }
    fn hash_x(
        &mut self,
        alpha: &[ByteValue; 32],
        v0: &Polynomial<ResidueValue>,
        v1: &Polynomial<ResidueValue>,
        a: &[Polynomial<ResidueValue>],
        b: &[Polynomial<ResidueValue>],
        e: &[Polynomial<ResidueValue>],
    ) -> Result<Polynomial<SignedValue>, VerifyError> {
        super::constraints_crypto::hash_x(self, alpha, v0, v1, a, b, e)
    }
}
