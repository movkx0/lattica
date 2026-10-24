//! One verifier relation shared by ordinary Rust and constrained backends.
//!
//! All branches depend only on the frozen profile. Backend values are opaque;
//! the relation cannot inspect witness values or use a native acceptance bit.
use super::{constants::*, VerifyError, D, Q, QHAT};

pub type Polynomial<R> = [R; D];

#[derive(Clone)]
pub struct GAccount<R: Copy> {
    pub pk: Vec<Polynomial<R>>,
    pub cn: Vec<Polynomial<R>>,
}
#[derive(Clone)]
pub struct GStatement<R: Copy, B: Copy> {
    pub seed: [B; 32],
    pub ring: Vec<[GAccount<R>; 2]>,
    pub recipients: Vec<Vec<Polynomial<R>>>,
    pub coins: Vec<Vec<Polynomial<R>>>,
    pub serials: [[B; 32]; 2],
}
#[derive(Clone)]
pub struct GProof<R: Copy, S: Copy, B: Copy> {
    pub c: Polynomial<R>,
    pub v: Vec<Polynomial<R>>,
    pub v1: Polynomial<R>,
    pub v2: Polynomial<R>,
    pub b: Vec<Polynomial<R>>,
    pub alpha: [B; 32],
    pub x: Polynomial<S>,
    pub z_out: Vec<Vec<Polynomial<S>>>,
    pub z0: Vec<Polynomial<S>>,
    pub z1: Vec<Polynomial<S>>,
    pub z2: Vec<Polynomial<S>>,
    pub f1: Vec<Polynomial<S>>,
    pub zb: Vec<Polynomial<S>>,
    pub z: Vec<Polynomial<S>>,
}
pub struct GParameters<R: Copy, B: Copy> {
    pub mat1: Vec<Vec<Polynomial<R>>>,
    pub mat2: Vec<Vec<Polynomial<R>>>,
    pub mat3: Vec<Vec<Polynomial<R>>>,
    pub pp: [B; 32],
}

pub trait Backend {
    type Residue: Copy;
    type Signed: Copy;
    type Byte: Copy;
    fn ntt_poly(&mut self, input: &Polynomial<Self::Signed>, q: u64) -> Polynomial<Self::Residue>
    where
        Self: Sized,
    {
        let residues = input.map(|value| self.to_residue(value, q));
        ntt_residues(self, &residues, q)
    }
    fn mul_poly(
        &mut self,
        a: &Polynomial<Self::Residue>,
        b: &Polynomial<Self::Residue>,
        q: u64,
    ) -> Polynomial<Self::Residue>
    where
        Self: Sized,
    {
        mul_residues(self, a, b, q)
    }
    fn add_poly(
        &mut self,
        a: &Polynomial<Self::Residue>,
        c: &Polynomial<Self::Residue>,
        q: u64,
    ) -> Polynomial<Self::Residue>
    where
        Self: Sized,
    {
        plus_residues(self, a, c, q)
    }
    fn sub_poly(
        &mut self,
        a: &Polynomial<Self::Residue>,
        c: &Polynomial<Self::Residue>,
        q: u64,
    ) -> Polynomial<Self::Residue>
    where
        Self: Sized,
    {
        minus_residues(self, a, c, q)
    }
    fn aut_poly(&mut self, input: &Polynomial<Self::Residue>) -> Polynomial<Self::Residue>
    where
        Self: Sized,
    {
        aut_residues(self, input)
    }
    fn constant(&mut self, value: u64, q: u64) -> Self::Residue;
    fn add(&mut self, a: Self::Residue, b: Self::Residue, q: u64) -> Self::Residue;
    fn sub(&mut self, a: Self::Residue, b: Self::Residue, q: u64) -> Self::Residue;
    /// Exact multiplication by R^-1 modulo q, where R=2^32.
    fn mont(&mut self, a: Self::Residue, b: Self::Residue, q: u64) -> Self::Residue;
    fn to_residue(&mut self, a: Self::Signed, q: u64) -> Self::Residue;
    fn signed_neg(&mut self, a: Self::Signed) -> Self::Signed;
    fn signed_sub(&mut self, a: Self::Signed, b: Self::Signed) -> Self::Signed;
    fn norm(&mut self, a: &[Polynomial<Self::Signed>], maximum: u64) -> Result<(), VerifyError>;
    fn g_bound(
        &mut self,
        f: &Polynomial<Self::Signed>,
        x: &Polynomial<Self::Signed>,
        bound: u32,
    ) -> Result<(), VerifyError>;
    fn equal_bytes(
        &mut self,
        a: &[Self::Byte; 32],
        b: &[Self::Byte; 32],
    ) -> Result<(), VerifyError>;
    fn equal_signed(
        &mut self,
        a: &Polynomial<Self::Signed>,
        b: &Polynomial<Self::Signed>,
    ) -> Result<(), VerifyError>;
    fn parameters(
        &mut self,
        seed: &[Self::Byte; 32],
        context: &[Self::Byte; 32],
    ) -> Result<GParameters<Self::Residue, Self::Byte>, VerifyError>;
    fn sample_g(
        &mut self,
        seed: &[Self::Byte; 32],
    ) -> Result<Vec<Polynomial<Self::Residue>>, VerifyError>;
    fn expand_alpha(
        &mut self,
        seed: &[Self::Byte; 32],
    ) -> Result<(Vec<Polynomial<Self::Residue>>, Polynomial<Self::Signed>), VerifyError>;
    #[allow(clippy::too_many_arguments)]
    fn hash_alpha(
        &mut self,
        pp: &[Self::Byte; 32],
        statement: &GStatement<Self::Residue, Self::Byte>,
        w_out: &[Vec<Polynomial<Self::Residue>>],
        w0: &[Polynomial<Self::Residue>],
        v: &[Polynomial<Self::Residue>],
        v2: &Polynomial<Self::Residue>,
        c: &Polynomial<Self::Residue>,
        w: &Polynomial<Self::Residue>,
        w1: &[Polynomial<Self::Residue>],
        w2: &[Polynomial<Self::Residue>],
    ) -> [Self::Byte; 32];
    fn hash_x(
        &mut self,
        alpha: &[Self::Byte; 32],
        v0: &Polynomial<Self::Residue>,
        v1: &Polynomial<Self::Residue>,
        a: &[Polynomial<Self::Residue>],
        b: &[Polynomial<Self::Residue>],
        e: &[Polynomial<Self::Residue>],
    ) -> Result<Polynomial<Self::Signed>, VerifyError>;
}

pub fn plus<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    b.add_poly(a, c, q)
}
pub fn plus_residues<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    std::array::from_fn(|i| b.add(a[i], c[i], q))
}
pub fn minus<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    b.sub_poly(a, c, q)
}
pub fn minus_residues<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    std::array::from_fn(|i| b.sub(a[i], c[i], q))
}
pub fn ntt<B: Backend>(b: &mut B, input: &Polynomial<B::Signed>, q: u64) -> Polynomial<B::Residue> {
    b.ntt_poly(input, q)
}

/// Inline transform on canonical residues, used by the standalone NTT
/// component. This deliberately bypasses the backend's delegation hook.
pub fn ntt_residues<B: Backend>(
    b: &mut B,
    input: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    let mut a = *input;
    let omega = if q == Q { &OMEGA_Q } else { &OMEGA_QHAT };
    let conversion = b.constant(if q == Q { 138_438_709 } else { 2_333_348_873 }, q);
    let initial = b.constant(omega[1], q);
    for i in 0..128 {
        let u = b.mont(a[i], conversion, q);
        let v = b.mont(a[i + 128], initial, q);
        a[i] = b.add(u, v, q);
        a[i + 128] = b.sub(u, v, q);
    }
    let mut stride = 128;
    let mut groups = 2;
    while groups < 64 {
        stride >>= 1;
        for group in 0..groups {
            let first = 2 * group * stride;
            let twiddle = b.constant(omega[groups + group], q);
            for j in first..first + stride {
                let u = a[j];
                let v = b.mont(a[j + stride], twiddle, q);
                a[j] = b.add(u, v, q);
                a[j + stride] = b.sub(u, v, q);
            }
        }
        groups <<= 1;
    }
    if q == Q {
        std::array::from_fn(|i| a[PERM_NTT[i / 4] as usize * 4 + i % 4])
    } else {
        a
    }
}
pub fn ntt_many<B: Backend>(
    b: &mut B,
    input: &[Polynomial<B::Signed>],
    q: u64,
) -> Vec<Polynomial<B::Residue>> {
    input.iter().map(|p| ntt(b, p, q)).collect()
}
pub fn mul<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    b.mul_poly(a, c, q)
}
/// Exact inline product, bypassing the optional backend proof-component hook.
pub fn mul_residues<B: Backend>(
    b: &mut B,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) -> Polynomial<B::Residue> {
    let mut out = [b.constant(0, q); D];
    for block in 0..64 {
        let (negative, position) = if q == Q {
            MUL_Q[block]
        } else {
            (block % 2 != 0, 32 + block / 2)
        };
        let omega = b.constant(
            if q == Q {
                OMEGA_Q[position]
            } else {
                OMEGA_QHAT[position]
            },
            q,
        );
        for i in 0..4 {
            for j in 0..4 {
                let mut value = b.mont(a[block * 4 + i], c[block * 4 + j], q);
                let degree = i + j;
                if degree >= 4 {
                    value = b.mont(value, omega, q);
                }
                let target = &mut out[block * 4 + degree % 4];
                *target = if degree >= 4 && negative {
                    b.sub(*target, value, q)
                } else {
                    b.add(*target, value, q)
                };
            }
        }
    }
    out
}
pub fn multiply_add<B: Backend>(
    b: &mut B,
    out: &mut Polynomial<B::Residue>,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) {
    let product = mul(b, a, c, q);
    *out = plus(b, out, &product, q);
}
pub fn multiply_sub<B: Backend>(
    b: &mut B,
    out: &mut Polynomial<B::Residue>,
    a: &Polynomial<B::Residue>,
    c: &Polynomial<B::Residue>,
    q: u64,
) {
    let product = mul(b, a, c, q);
    *out = minus(b, out, &product, q);
}
pub fn aut<B: Backend>(b: &mut B, a: &Polynomial<B::Residue>) -> Polynomial<B::Residue> {
    b.aut_poly(a)
}
pub fn aut_residues<B: Backend>(b: &mut B, a: &Polynomial<B::Residue>) -> Polynomial<B::Residue> {
    let zero = b.constant(0, Q);
    let mut out = [zero; D];
    for block in 0..64 {
        let source = (block / 32 * 32 + (block + 1) % 32) * 4;
        let target = block * 4;
        let (negative, position) = AUT_Q[block];
        let odd_twiddle = b.constant(
            if position % 2 == 0 {
                OMEGA_Q[position / 2]
            } else {
                Q - OMEGA_Q[position / 2]
            },
            Q,
        );
        out[target] = a[source];
        out[target + 1] = b.mont(a[source + 3], odd_twiddle, Q);
        let twiddle = b.constant(OMEGA_Q[position], Q);
        let term = b.mont(a[source + 2], twiddle, Q);
        out[target + 2] = if negative { b.sub(zero, term, Q) } else { term };
        out[target + 3] = a[source + 1];
    }
    out
}
fn linear<B: Backend>(
    b: &mut B,
    y: &[Polynomial<B::Residue>],
    mat: &[Vec<Polynomial<B::Residue>>],
    columns: usize,
) -> Vec<Polynomial<B::Residue>> {
    let mut out = y[..4].to_vec();
    for i in 0..columns {
        for j in 0..4 {
            multiply_add(b, &mut out[j], &mat[i][j], &y[4 + i], Q);
        }
    }
    out
}
fn auxiliary<B: Backend>(
    b: &mut B,
    y: &[Polynomial<B::Residue>],
    mat: &[Vec<Polynomial<B::Residue>>],
    column: usize,
) -> Polynomial<B::Residue> {
    let mut out = y[4 + column];
    if column == 2 {
        let zero = b.constant(0, Q);
        out[..4].fill(zero);
        out[128..132].fill(zero);
    }
    for i in 0..y.len() - 7 {
        multiply_add(b, &mut out, &mat[i][column], &y[7 + i], Q);
    }
    out
}

pub fn verify_relation<B: Backend>(
    b: &mut B,
    context: &[B::Byte; 32],
    statement: &GStatement<B::Residue, B::Byte>,
    proof: &GProof<B::Residue, B::Signed, B::Byte>,
) -> Result<(), VerifyError> {
    // These are compiler/encoding dimensions, never secret-value branches.
    // A caller still must constrain canonical decoding, serial uniqueness and
    // the public statement/context commitment at its acceptance boundary.
    if statement.ring.len() != 10
        || statement
            .ring
            .iter()
            .flatten()
            .any(|a| a.pk.len() != 4 || a.cn.len() != 5)
        || statement.recipients.len() != 2
        || statement.recipients.iter().any(|a| a.len() != 4)
        || statement.coins.len() != 2
        || statement.coins.iter().any(|a| a.len() != 5)
        || proof.v.len() != 4
        || proof.b.len() != 5
        || proof.z_out.len() != 2
        || proof.z_out.iter().any(|z| z.len() != 9)
        || proof.z0.len() != 9
        || proof.z1.len() != 11
        || proof.z2.len() != 11
        || proof.f1.len() != 11
        || proof.zb.len() != 10
        || proof.z.len() != 8
    {
        return Err(VerifyError::Length);
    }
    for p in [&proof.z_out[0], &proof.z_out[1], &proof.z0] {
        b.norm(p, 135_519_727_172)?;
    }
    for p in [&proof.z1, &proof.z2] {
        b.norm(p, 165_635_222_099)?;
    }
    b.norm(&proof.z, 3_161_803_581_581_766)?;
    let mut f0 = proof.x;
    for f in proof.f1.iter().take(9) {
        for j in 0..D {
            f0[j] = b.signed_sub(f0[j], f[j]);
        }
    }
    let mut f = vec![f0];
    f.extend_from_slice(&proof.f1);
    for (i, polynomial) in f.iter().enumerate() {
        b.g_bound(
            polynomial,
            &proof.x,
            if i == 0 { 6_825_771 } else { 1_137_628 },
        )?;
    }
    let GParameters {
        mat1,
        mat2,
        mat3,
        pp,
    } = b.parameters(&statement.seed, context)?;
    let mut c = proof.c;
    let zero = b.constant(0, Q);
    c[..4].fill(zero);
    c[128..132].fill(zero);
    let x = ntt(b, &proof.x, Q);
    let x_qhat = ntt(b, &proof.x, QHAT);
    let inv_x = std::array::from_fn(|i| {
        if (86..171).contains(&i) {
            b.signed_neg(proof.x[(3 * i) % D])
        } else {
            proof.x[(3 * i) % D]
        }
    });
    let inverse_x = ntt(b, &inv_x, Q);
    let z_out: Vec<_> = proof.z_out.iter().map(|p| ntt_many(b, p, Q)).collect();
    let z0 = ntt_many(b, &proof.z0, Q);
    let mut w_out = vec![
        linear(b, &z_out[0], &mat1, 5),
        linear(b, &z_out[1], &mat1, 5),
    ];
    let mut w0 = linear(b, &z0, &mat1, 5);
    for i in 0..2 {
        for j in 0..4 {
            multiply_sub(b, &mut w_out[i][j], &x, &statement.coins[i][j], Q);
        }
    }
    let t_in: Vec<Vec<_>> = statement
        .ring
        .iter()
        .map(|pair| {
            (0..5)
                .map(|j| plus(b, &pair[0].cn[j], &pair[1].cn[j], Q))
                .collect()
        })
        .collect();
    let f_ntt = ntt_many(b, &f, Q);
    let f_qhat = ntt_many(b, &f, QHAT);
    for i in 0..10 {
        for j in 0..4 {
            multiply_sub(b, &mut w0[j], &f_ntt[i], &t_in[i][j], Q);
        }
    }
    let z1 = ntt_many(b, &proof.z1, Q);
    let z2 = ntt_many(b, &proof.z2, Q);
    let mut w1 = linear(b, &z1, &mat1, 7);
    let mut w2 = linear(b, &z2, &mat1, 7);
    for i in 0..4 {
        multiply_sub(b, &mut w1[i], &x, &proof.v[i], Q);
        multiply_sub(b, &mut w2[i], &inverse_x, &proof.v[i], Q);
    }
    let a3z1 = auxiliary(b, &z1, &mat2, 2);
    let a3z2 = auxiliary(b, &z2, &mat2, 2);
    let aut_a3z2 = aut(b, &a3z2);
    let mut w = std::array::from_fn(|i| {
        let twice = b.add(aut_a3z2[i], aut_a3z2[i], Q);
        let mut value = b.sub(a3z1[i], twice, Q);
        value = b.add(value, z_out[0][4][i], Q);
        value = b.add(value, z_out[1][4][i], Q);
        b.sub(value, z0[4][i], Q)
    });
    for i in 0..2 {
        let sum = plus(b, &z_out[0][7 + i], &z_out[1][7 + i], Q);
        let term = minus(b, &sum, &z0[7 + i], Q);
        multiply_add(b, &mut w, &mat2[i][0], &term, Q);
    }
    let aut_c = aut(b, &c);
    let term = std::array::from_fn(|i| {
        let mut value = b.add(aut_c[i], aut_c[i], Q);
        value = b.sub(value, statement.coins[0][4][i], Q);
        value = b.sub(value, statement.coins[1][4][i], Q);
        b.sub(value, c[i], Q)
    });
    multiply_add(b, &mut w, &x, &term, Q);
    for i in 0..10 {
        multiply_add(b, &mut w, &f_ntt[i], &t_in[i][4], Q);
    }
    for i in 0..4 {
        let j = 124 + i;
        let delta = b.sub(f_ntt[10][j], f_ntt[11][j], Q);
        let twice = b.add(delta, delta, Q);
        w[j] = b.add(w[j], twice, Q);
        let j = 128 + i;
        let delta = b.sub(f_ntt[11][j], f_ntt[10][j], Q);
        w[j] = b.add(w[j], delta, Q);
    }
    let alpha_hash = b.hash_alpha(
        &pp, statement, &w_out, &w0, &proof.v, &proof.v2, &proof.c, &w, &w1, &w2,
    );
    b.equal_bytes(&alpha_hash, &proof.alpha)?;
    let (alpha, alpha_prime) = b.expand_alpha(&alpha_hash)?;
    let mut h = Vec::with_capacity(3);
    for i in 0..2 {
        let mut term = auxiliary(b, &z_out[i], &mat2, 0);
        multiply_sub(b, &mut term, &x, &statement.coins[i][4], Q);
        h.push(term);
    }
    let xc = mul(b, &x, &c, Q);
    h.push(minus(b, &a3z1, &xc, Q));
    let hx: Vec<_> = h
        .iter()
        .map(|p| {
            let sum = plus(b, p, &x, Q);
            mul(b, p, &sum, Q)
        })
        .collect();
    let difference = minus(b, &h[2], &x, Q);
    let mut v0 = mul(b, &hx[2], &difference, Q);
    multiply_add(b, &mut v0, &alpha[0], &hx[0], Q);
    multiply_add(b, &mut v0, &alpha[1], &hx[1], Q);
    let mut term = auxiliary(b, &z1, &mat2, 1);
    multiply_sub(b, &mut term, &x, &proof.v2, Q);
    term = minus(b, &term, &proof.v1, Q);
    multiply_add(b, &mut v0, &x, &term, Q);
    let extra = auxiliary(b, &z1, &mat2, 0);
    v0 = plus(b, &v0, &extra, Q);
    let zb = ntt_many(b, &proof.zb, QHAT);
    let g_qhat: Vec<_> = f_qhat
        .iter()
        .map(|p| {
            let diff = minus(b, &x_qhat, p, QHAT);
            mul(b, p, &diff, QHAT)
        })
        .collect();
    let mut a = zb[..5].to_vec();
    for i in 0..5 {
        for j in 0..5 {
            multiply_add(b, &mut a[j], &mat3[i][j], &zb[5 + i], QHAT);
        }
    }
    // Exact author offsets, including row-4 overlap. See MATRICT_REVIEW.md.
    for i in 0..12 {
        for j in 0..5 {
            multiply_add(b, &mut a[j], &mat3[4 + i][j], &f_qhat[i], QHAT);
            multiply_add(b, &mut a[j], &mat3[16 + i][j], &g_qhat[i], QHAT);
        }
    }
    for i in 0..5 {
        multiply_sub(b, &mut a[i], &x_qhat, &proof.b[i], QHAT);
    }
    let gamma0 = b.sample_g(&statement.serials[0])?;
    let gamma1 = b.sample_g(&statement.serials[1])?;
    let alpha_prime = ntt(b, &alpha_prime, Q);
    let mut p = Vec::with_capacity(10);
    for pair in &statement.ring {
        p.push(
            (0..4)
                .map(|j| {
                    let first = minus(b, &pair[0].pk[j], &gamma0[j], Q);
                    let second = minus(b, &pair[1].pk[j], &gamma1[j], Q);
                    let product = mul(b, &alpha_prime, &first, Q);
                    plus(b, &product, &second, Q)
                })
                .collect::<Vec<_>>(),
        );
    }
    let z = ntt_many(b, &proof.z, Q);
    let mut e = linear(b, &z, &mat1, 4);
    for i in 0..10 {
        for j in 0..4 {
            multiply_sub(b, &mut e[j], &f_ntt[i], &p[i][j], Q);
        }
    }
    let expected_x = b.hash_x(&alpha_hash, &v0, &proof.v1, &a, &proof.b, &e)?;
    b.equal_signed(&expected_x, &proof.x)
}
