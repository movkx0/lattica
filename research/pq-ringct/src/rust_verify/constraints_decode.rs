//! Canonical packet decoding into the actual verifier wires. Native decoding
//! supplies early errors only: accepted encodings are independently constrained.
//! This is an algebra component, not a complete MatRiCT proof. Its caller must
//! bind `statement_words` to the public digest and discharge all crypto requests.

use super::{
    constraints::{ByteValue, ConstraintContext, ResidueValue, SignedValue},
    generic::{GAccount, GProof, GStatement, Polynomial},
    Proof, Statement, VerifyError, Q, QHAT,
};
use lattica_prover_p3::block_v2::machine::{
    pq_modular as modular,
    program::{Val, Wire},
};
use p3_field::PrimeCharacteristicRing;

#[cfg(test)]
mod tests;

pub struct DecodedPacket {
    pub statement: GStatement<ResidueValue, ByteValue>,
    pub proof: GProof<ResidueValue, SignedValue, ByteValue>,
    pub context: [ByteValue; 32],
    /// Derived from the same bytes that feed the public verifier relation.
    pub statement_words: Vec<Wire>,
}

fn word(c: &mut ConstraintContext<'_, '_>, bytes: &[ByteValue]) -> Wire {
    assert!(bytes.len() <= 4);
    let mut result = c.builder.constant(Val::ZERO);
    for (i, byte) in bytes.iter().enumerate() {
        let value = byte.constrained.to_wire(c.builder);
        let weight = c.builder.constant(Val::from_u64(1 << (8 * i)));
        let term = c.builder.mul(value, weight);
        result = c.builder.add(result, term);
    }
    result
}

struct Reader<'a> {
    bytes: &'a [ByteValue],
    position: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [ByteValue; N] {
        let result = self.bytes[self.position..self.position + N]
            .try_into()
            .unwrap();
        self.position += N;
        result
    }
    fn polys(
        &mut self,
        c: &mut ConstraintContext<'_, '_>,
        n: usize,
    ) -> Vec<Polynomial<ResidueValue>> {
        (0..n)
            .map(|_| {
                core::array::from_fn(|_| {
                    let bytes = self.take::<4>();
                    let value = u64::from(u32::from_le_bytes(bytes.map(|b| b.value)));
                    let bits: Vec<_> = bytes.iter().flat_map(|b| b.constrained.bits()).collect();
                    ResidueValue {
                        value,
                        constrained: modular::canonical_from_bits(
                            c.builder,
                            &bits,
                            modular::Modulus::new(Q as u32).unwrap(),
                        )
                        .unwrap(),
                    }
                })
            })
            .collect()
    }
    fn account(&mut self, c: &mut ConstraintContext<'_, '_>) -> GAccount<ResidueValue> {
        GAccount {
            pk: self.polys(c, 4),
            cn: self.polys(c, 5),
        }
    }
}

struct Bits<'a> {
    bytes: &'a [ByteValue],
    position: usize,
}
impl Bits<'_> {
    fn get(&mut self, c: &mut ConstraintContext<'_, '_>, width: usize) -> (u64, Wire) {
        assert!(width <= 32);
        let mut value = 0;
        let mut wire = c.builder.constant(Val::ZERO);
        for i in 0..width {
            let position = self.position + i;
            let byte = self.bytes[position / 8];
            value |= u64::from((byte.value >> (position % 8)) & 1) << i;
            let bit = byte.constrained.bits()[position % 8];
            let weight = c.builder.constant(Val::from_u64(1 << i));
            let term = c.builder.mul(bit, weight);
            wire = c.builder.add(wire, term);
        }
        self.position += width;
        (value, wire)
    }
    fn polys(
        &mut self,
        c: &mut ConstraintContext<'_, '_>,
        n: usize,
        width: usize,
        q: u64,
    ) -> Vec<Polynomial<ResidueValue>> {
        (0..n)
            .map(|_| {
                core::array::from_fn(|_| {
                    let start = self.position;
                    let (value, _) = self.get(c, width);
                    let bits: Vec<_> = (start..start + width)
                        .map(|i| self.bytes[i / 8].constrained.bits()[i % 8])
                        .collect();
                    let constrained = modular::canonical_from_bits(
                        c.builder,
                        &bits,
                        modular::Modulus::new(q as u32).unwrap(),
                    )
                    .unwrap();
                    ResidueValue { value, constrained }
                })
            })
            .collect()
    }
    fn signed(
        &mut self,
        c: &mut ConstraintContext<'_, '_>,
        n: usize,
        width: usize,
        bound: u32,
    ) -> Vec<Polynomial<SignedValue>> {
        (0..n)
            .map(|_| {
                core::array::from_fn(|_| {
                    let start = self.position;
                    let (encoded, _) = self.get(c, width);
                    // The offset encoding is injective as an integer, including negative
                    // values: both encoded and 2*bound are well below the field modulus.
                    let bits: Vec<_> = (start..start + width)
                        .map(|i| self.bytes[i / 8].constrained.bits()[i % 8])
                        .collect();
                    let constrained =
                        modular::signed_from_offset_bits(c.builder, &bits, bound).unwrap();
                    SignedValue {
                        value: encoded as i64 - i64::from(bound),
                        constrained,
                    }
                })
            })
            .collect()
    }
}

fn bind_serial_inequality(c: &mut ConstraintContext<'_, '_>, serials: &[[ByteValue; 32]; 2]) {
    let mut sum = c.builder.constant(Val::ZERO);
    for i in 0..32 {
        let left = serials[0][i].constrained.to_wire(c.builder);
        let right = serials[1][i].constrained.to_wire(c.builder);
        let difference = c.builder.sub(left, right);
        let square = c.builder.mul(difference, difference);
        sum = c.builder.add(sum, square);
    }
    // Each square <=255^2; the sum <=2,080,800 cannot wrap Goldilocks.
    let inverse = c.builder.inverse(sum);
    let product = c.builder.mul(sum, inverse);
    let one = c.builder.constant(Val::ONE);
    c.builder.assert_equal(product, one);
}

fn bind_context(
    c: &mut ConstraintContext<'_, '_>,
    context: [u8; 32],
    public: [Wire; 8],
) -> [ByteValue; 32] {
    let context = context.map(|b| c.byte(b));
    for (bytes, public) in context.chunks_exact(4).zip(public) {
        let actual = word(c, bytes);
        c.builder.assert_equal(actual, public);
    }
    context
}

fn bind_setup(c: &mut ConstraintContext<'_, '_>, seed: &[ByteValue; 32]) {
    for (actual, expected) in seed.iter().zip(c.crypto.fixed_setup_seed) {
        let actual = actual.constrained.to_wire(c.builder);
        let expected = c.builder.constant(Val::from_u8(expected));
        c.builder.assert_equal(actual, expected);
    }
}

pub fn decode_packet(
    c: &mut ConstraintContext<'_, '_>,
    statement: &[u8],
    proof: &[u8],
    context: [u8; 32],
    public_context: [Wire; 8],
) -> Result<DecodedPacket, VerifyError> {
    // Validate length/canonicality before indexing and hint arithmetic. These
    // host checks do not replace any acceptance constraint below.
    Statement::decode(statement)?;
    Proof::decode(proof)?;
    let statement_bytes: Vec<_> = statement.iter().map(|&b| c.byte(b)).collect();
    let proof_bytes: Vec<_> = proof.iter().map(|&b| c.byte(b)).collect();
    let context = bind_context(c, context, public_context);
    let statement_words = statement_bytes
        .chunks_exact(4)
        .map(|bytes| word(c, bytes))
        .collect();
    let mut r = Reader {
        bytes: &statement_bytes,
        position: 0,
    };
    let seed: [ByteValue; 32] = r.take();
    bind_setup(c, &seed);
    let ring = (0..10).map(|_| [r.account(c), r.account(c)]).collect();
    let recipients = vec![r.polys(c, 4), r.polys(c, 4)];
    let coins = vec![r.polys(c, 5), r.polys(c, 5)];
    let serials = [r.take(), r.take()];
    bind_serial_inequality(c, &serials);
    assert_eq!(r.position, statement_bytes.len());
    let statement = GStatement {
        seed,
        ring,
        recipients,
        coins,
        serials,
    };

    let mut r = Bits {
        bytes: &proof_bytes,
        position: 0,
    };
    let c_poly = r.polys(c, 1, 28, Q)[0];
    let v = r.polys(c, 4, 28, Q);
    let v1 = r.polys(c, 1, 28, Q)[0];
    let v2 = r.polys(c, 1, 28, Q)[0];
    let b = r.polys(c, 5, 32, QHAT);
    assert_eq!(r.position % 8, 0);
    let alpha = r.bytes[r.position / 8..r.position / 8 + 32]
        .try_into()
        .unwrap();
    r.position += 32 * 8;
    let x = r.signed(c, 1, 2, 1)[0];
    let z_out = vec![r.signed(c, 9, 17, 38346), r.signed(c, 9, 17, 38346)];
    let z0 = r.signed(c, 9, 17, 38346);
    let z1 = r.signed(c, 11, 17, 38346);
    let z2 = r.signed(c, 11, 17, 38346);
    let f1 = r.signed(c, 11, 11, 565);
    let zb = r.signed(c, 10, 17, 38346);
    let z = r.signed(c, 8, 24, 6212586);
    assert_eq!(r.position, proof_bytes.len() * 8);
    let proof = GProof {
        c: c_poly,
        v,
        v1,
        v2,
        b,
        alpha,
        x,
        z_out,
        z0,
        z1,
        z2,
        f1,
        zb,
        z,
    };
    Ok(DecodedPacket {
        statement,
        proof,
        context,
        statement_words,
    })
}
