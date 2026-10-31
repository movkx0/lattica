//! Ordinary execution backend for the shared opaque-value relation.
use super::{arithmetic, generic::*, primitives, Poly, Proof, SignedPoly, Statement, VerifyError};
pub struct NativeBackend;
pub fn statement(s: &Statement) -> GStatement<u64, u8> {
    GStatement {
        seed: s.seed,
        ring: s
            .ring
            .iter()
            .map(|pair| {
                pair.each_ref().map(|a| GAccount {
                    pk: a.pk.clone(),
                    cn: a.cn.clone(),
                })
            })
            .collect(),
        recipients: s.recipients.clone(),
        coins: s.coins.clone(),
        serials: s.serials,
    }
}
pub fn proof(p: &Proof) -> GProof<u64, i64, u8> {
    GProof {
        c: p.c,
        v: p.v.clone(),
        v1: p.v1,
        v2: p.v2,
        b: p.b.clone(),
        alpha: p.alpha,
        x: p.x,
        z_out: p.z_out.clone(),
        z0: p.z0.clone(),
        z1: p.z1.clone(),
        z2: p.z2.clone(),
        f1: p.f1.clone(),
        zb: p.zb.clone(),
        z: p.z.clone(),
    }
}
fn required(ok: bool) -> Result<(), VerifyError> {
    if ok {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}
impl Backend for NativeBackend {
    type Residue = u64;
    type Signed = i64;
    type Byte = u8;
    fn constant(&mut self, value: u64, q: u64) -> u64 {
        value % q
    }
    fn add(&mut self, a: u64, b: u64, q: u64) -> u64 {
        arithmetic::add(a, b, q)
    }
    fn sub(&mut self, a: u64, b: u64, q: u64) -> u64 {
        arithmetic::sub(a, b, q)
    }
    fn mont(&mut self, a: u64, b: u64, q: u64) -> u64 {
        arithmetic::mont(a, b, q)
    }
    fn to_residue(&mut self, a: i64, q: u64) -> u64 {
        arithmetic::signed(a, q)
    }
    fn signed_neg(&mut self, a: i64) -> i64 {
        -a
    }
    fn signed_sub(&mut self, a: i64, b: i64) -> i64 {
        a - b
    }
    fn norm(&mut self, a: &[SignedPoly], maximum: u64) -> Result<(), VerifyError> {
        required(
            a.iter()
                .flatten()
                .map(|&x| (i128::from(x) * i128::from(x)) as u128)
                .sum::<u128>()
                <= u128::from(maximum),
        )
    }
    fn g_bound(&mut self, f: &SignedPoly, x: &SignedPoly, bound: u32) -> Result<(), VerifyError> {
        let other = std::array::from_fn(|i| x[i] - f[i]);
        required(
            arithmetic::signed_mul(f, &other)
                .iter()
                .all(|&v| v >= -i64::from(bound) && v <= i64::from(bound)),
        )
    }
    fn equal_bytes(&mut self, a: &[u8; 32], b: &[u8; 32]) -> Result<(), VerifyError> {
        required(a == b)
    }
    fn equal_signed(&mut self, a: &SignedPoly, b: &SignedPoly) -> Result<(), VerifyError> {
        required(a == b)
    }
    fn parameters(
        &mut self,
        seed: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<GParameters<u64, u8>, VerifyError> {
        let p = primitives::parameters(seed, context)?;
        Ok(GParameters {
            mat1: p.mat1,
            mat2: p.mat2,
            mat3: p.mat3,
            pp: p.pp,
        })
    }
    fn sample_g(&mut self, seed: &[u8; 32]) -> Result<Vec<Poly>, VerifyError> {
        primitives::sample_g(seed)
    }
    fn expand_alpha(&mut self, seed: &[u8; 32]) -> Result<(Vec<Poly>, SignedPoly), VerifyError> {
        primitives::expand_alpha(seed)
    }
    fn hash_alpha(
        &mut self,
        pp: &[u8; 32],
        s: &GStatement<u64, u8>,
        w_out: &[Vec<Poly>],
        w0: &[Poly],
        v: &[Poly],
        v2: &Poly,
        c: &Poly,
        w: &Poly,
        w1: &[Poly],
        w2: &[Poly],
    ) -> [u8; 32] {
        let native = Statement {
            seed: s.seed,
            ring: s
                .ring
                .iter()
                .map(|pair| {
                    pair.each_ref().map(|a| super::Account {
                        pk: a.pk.clone(),
                        cn: a.cn.clone(),
                    })
                })
                .collect(),
            recipients: s.recipients.clone(),
            coins: s.coins.clone(),
            serials: s.serials,
        };
        primitives::hash_alpha(pp, &native, w_out, w0, v, v2, c, w, w1, w2)
    }
    fn hash_x(
        &mut self,
        alpha: &[u8; 32],
        v0: &Poly,
        v1: &Poly,
        a: &[Poly],
        b: &[Poly],
        e: &[Poly],
    ) -> Result<SignedPoly, VerifyError> {
        primitives::hash_x(alpha, v0, v1, a, b, e)
    }
}
