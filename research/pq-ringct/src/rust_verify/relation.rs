//! Direct fixed-profile translation of vendor/matrict-plus/n10/verify.c.
//! Bounds are established by the canonical decoder before signed arithmetic.

use super::{
    arithmetic::*, primitives::*, Poly, Proof, SignedPoly, Statement, VerifyError, D, Q, QHAT,
};

fn norm(polys: &[SignedPoly]) -> u128 {
    polys
        .iter()
        .flatten()
        .map(|&value| (i128::from(value) * i128::from(value)) as u128)
        .sum()
}

fn linear(y: &[Poly], mat: &[Vec<Poly>], columns: usize) -> Vec<Poly> {
    let mut out = y[..4].to_vec();
    for i in 0..columns {
        for j in 0..4 {
            multiply_add(&mut out[j], &mat[i][j], &y[4 + i], Q);
        }
    }
    out
}

fn auxiliary(y: &[Poly], mat: &[Vec<Poly>], column: usize) -> Poly {
    let mut out = y[4 + column];
    if column == 2 {
        out[..4].fill(0);
        out[128..132].fill(0);
    }
    for i in 0..y.len() - 7 {
        multiply_add(&mut out, &mat[i][column], &y[7 + i], Q);
    }
    out
}

pub fn verify(
    context: &[u8; 32],
    statement: &Statement,
    proof: &Proof,
) -> Result<bool, VerifyError> {
    if norm(&proof.z_out[0]) > 135_519_727_172
        || norm(&proof.z_out[1]) > 135_519_727_172
        || norm(&proof.z0) > 135_519_727_172
        || norm(&proof.z1) > 165_635_222_099
        || norm(&proof.z2) > 165_635_222_099
        || norm(&proof.z) > 3_161_803_581_581_766
    {
        return Ok(false);
    }
    let mut f0 = proof.x;
    for f in proof.f1.iter().take(9) {
        for j in 0..D {
            f0[j] -= f[j];
        }
    }
    let mut f = vec![f0];
    f.extend_from_slice(&proof.f1);
    for (i, polynomial) in f.iter().enumerate() {
        let other = std::array::from_fn(|j| proof.x[j] - polynomial[j]);
        let g = signed_mul(polynomial, &other);
        let bound = if i == 0 { 6_825_771 } else { 1_137_628 };
        if g.iter().any(|&value| value < -bound || value > bound) {
            return Ok(false);
        }
    }

    let Parameters {
        mat1,
        mat2,
        mat3,
        pp,
    } = parameters(&statement.seed, context)?;
    let mut c = proof.c;
    c[..4].fill(0);
    c[128..132].fill(0);
    let x = ntt(&proof.x, Q);
    let x_qhat = ntt(&proof.x, QHAT);
    let inverse_x = ntt(&inverse_aut(&proof.x), Q);
    let z_out: Vec<_> = proof.z_out.iter().map(|polys| ntt_many(polys, Q)).collect();
    let z0 = ntt_many(&proof.z0, Q);
    let mut w_out = vec![linear(&z_out[0], &mat1, 5), linear(&z_out[1], &mat1, 5)];
    let mut w0 = linear(&z0, &mat1, 5);
    for i in 0..2 {
        for j in 0..4 {
            multiply_sub(&mut w_out[i][j], &x, &statement.coins[i][j], Q);
        }
    }
    let t_in: Vec<Vec<Poly>> = statement
        .ring
        .iter()
        .map(|pair| {
            (0..5)
                .map(|j| plus(&pair[0].cn[j], &pair[1].cn[j], Q))
                .collect()
        })
        .collect();
    let f_ntt = ntt_many(&f, Q);
    let f_qhat = ntt_many(&f, QHAT);
    for i in 0..10 {
        for j in 0..4 {
            multiply_sub(&mut w0[j], &f_ntt[i], &t_in[i][j], Q);
        }
    }

    let z1 = ntt_many(&proof.z1, Q);
    let z2 = ntt_many(&proof.z2, Q);
    let mut w1 = linear(&z1, &mat1, 7);
    let mut w2 = linear(&z2, &mat1, 7);
    for i in 0..4 {
        multiply_sub(&mut w1[i], &x, &proof.v[i], Q);
        multiply_sub(&mut w2[i], &inverse_x, &proof.v[i], Q);
    }
    let a3z1 = auxiliary(&z1, &mat2, 2);
    let aut_a3z2 = aut(&auxiliary(&z2, &mat2, 2));
    let mut w = std::array::from_fn(|i| {
        signed(
            a3z1[i] as i64 - 2 * aut_a3z2[i] as i64 + z_out[0][4][i] as i64 + z_out[1][4][i] as i64
                - z0[4][i] as i64,
            Q,
        )
    });
    for i in 0..2 {
        let term = minus(&plus(&z_out[0][7 + i], &z_out[1][7 + i], Q), &z0[7 + i], Q);
        multiply_add(&mut w, &mat2[i][0], &term, Q);
    }
    let aut_c = aut(&c);
    let term = std::array::from_fn(|i| {
        signed(
            2 * aut_c[i] as i64
                - statement.coins[0][4][i] as i64
                - statement.coins[1][4][i] as i64
                - c[i] as i64,
            Q,
        )
    });
    multiply_add(&mut w, &x, &term, Q);
    for i in 0..10 {
        multiply_add(&mut w, &f_ntt[i], &t_in[i][4], Q);
    }
    for i in 0..4 {
        let j = 31 * 4 + i;
        w[j] = signed(
            w[j] as i64 + 2 * (f_ntt[10][j] as i64 - f_ntt[11][j] as i64),
            Q,
        );
        let j = 32 * 4 + i;
        w[j] = signed(w[j] as i64 - f_ntt[10][j] as i64 + f_ntt[11][j] as i64, Q);
    }
    let alpha_hash = hash_alpha(
        &pp, statement, &w_out, &w0, &proof.v, &proof.v2, &proof.c, &w, &w1, &w2,
    );
    if alpha_hash != proof.alpha {
        return Ok(false);
    }
    let (alpha, alpha_prime) = expand_alpha(&alpha_hash)?;

    let mut h = Vec::with_capacity(3);
    for i in 0..2 {
        let mut term = auxiliary(&z_out[i], &mat2, 0);
        multiply_sub(&mut term, &x, &statement.coins[i][4], Q);
        h.push(term);
    }
    h.push(minus(&a3z1, &mul(&x, &c, Q), Q));
    let hx: Vec<_> = h
        .iter()
        .map(|poly| mul(poly, &plus(poly, &x, Q), Q))
        .collect();
    let mut v0 = mul(&hx[2], &minus(&h[2], &x, Q), Q);
    multiply_add(&mut v0, &alpha[0], &hx[0], Q);
    multiply_add(&mut v0, &alpha[1], &hx[1], Q);
    let mut term = auxiliary(&z1, &mat2, 1);
    multiply_sub(&mut term, &x, &proof.v2, Q);
    term = minus(&term, &proof.v1, Q);
    multiply_add(&mut v0, &x, &term, Q);
    v0 = plus(&v0, &auxiliary(&z1, &mat2, 0), Q);

    let zb = ntt_many(&proof.zb, QHAT);
    let g_qhat: Vec<_> = f_qhat
        .iter()
        .map(|poly| mul(poly, &minus(&x_qhat, poly, QHAT), QHAT))
        .collect();
    let mut a = zb[..5].to_vec();
    for i in 0..5 {
        for j in 0..5 {
            multiply_add(&mut a[j], &mat3[i][j], &zb[5 + i], QHAT);
        }
    }
    // Preserve the author's K=4 offsets exactly, including their overlap with
    // the fifth randomizer column. This is not a reinterpretation of MatRiCT+.
    for i in 0..12 {
        for j in 0..5 {
            multiply_add(&mut a[j], &mat3[4 + i][j], &f_qhat[i], QHAT);
        }
    }
    for i in 0..12 {
        for j in 0..5 {
            multiply_add(&mut a[j], &mat3[16 + i][j], &g_qhat[i], QHAT);
        }
    }
    for i in 0..5 {
        multiply_sub(&mut a[i], &x_qhat, &proof.b[i], QHAT);
    }

    let gamma0 = sample_g(&statement.serials[0])?;
    let gamma1 = sample_g(&statement.serials[1])?;
    let alpha_prime = ntt(&alpha_prime, Q);
    let mut p = Vec::with_capacity(10);
    for pair in &statement.ring {
        p.push(
            (0..4)
                .map(|j| {
                    let first = minus(&pair[0].pk[j], &gamma0[j], Q);
                    let second = minus(&pair[1].pk[j], &gamma1[j], Q);
                    plus(&mul(&alpha_prime, &first, Q), &second, Q)
                })
                .collect::<Vec<_>>(),
        );
    }
    let z = ntt_many(&proof.z, Q);
    let mut e = linear(&z, &mat1, 4);
    for i in 0..10 {
        for j in 0..4 {
            multiply_sub(&mut e[j], &f_ntt[i], &p[i][j], Q);
        }
    }
    Ok(hash_x(&alpha_hash, &v0, &proof.v1, &a, &proof.b, &e)? == proof.x)
}
