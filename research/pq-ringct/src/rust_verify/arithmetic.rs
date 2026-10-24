use super::{constants::*, Poly, SignedPoly, D, Q, QHAT};

pub fn add(a: u64, b: u64, q: u64) -> u64 {
    (a + b) % q
}
pub fn sub(a: u64, b: u64, q: u64) -> u64 {
    (a + q - b) % q
}
pub fn signed(value: i64, q: u64) -> u64 {
    value.rem_euclid(q as i64) as u64
}

/// Exact Montgomery multiplication, using a wide native intermediate. The
/// constrained backend must establish the corresponding integer reduction.
pub fn mont(a: u64, b: u64, q: u64) -> u64 {
    let factor = if q == Q {
        2_887_272_321_u64
    } else {
        1_071_660_929_u64
    };
    let product = u128::from(a) * u128::from(b);
    let correction = (product as u64 & 0xffff_ffff).wrapping_mul(factor) & 0xffff_ffff;
    let value = (product >> 32) as i128 - ((u128::from(correction) * u128::from(q)) >> 32) as i128;
    value.rem_euclid(i128::from(q)) as u64
}

pub fn ntt(input: &SignedPoly, q: u64) -> Poly {
    let mut a = input.map(|value| signed(value, q));
    let omega = if q == Q { &OMEGA_Q } else { &OMEGA_QHAT };
    let conversion = if q == Q { 138_438_709 } else { 2_333_348_873 };
    for i in 0..128 {
        let u = mont(a[i], conversion, q);
        let v = mont(a[i + 128], omega[1], q);
        a[i] = add(u, v, q);
        a[i + 128] = sub(u, v, q);
    }
    let mut stride = 128;
    let mut groups = 2;
    while groups < 64 {
        stride >>= 1;
        for group in 0..groups {
            let first = 2 * group * stride;
            for j in first..first + stride {
                let u = a[j];
                let v = mont(a[j + stride], omega[groups + group], q);
                a[j] = add(u, v, q);
                a[j + stride] = sub(u, v, q);
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

pub fn mul(a: &Poly, b: &Poly, q: u64) -> Poly {
    let mut out = [0; D];
    for block in 0..64 {
        let (negative, position) = if q == Q {
            MUL_Q[block]
        } else {
            (block % 2 != 0, 32 + block / 2)
        };
        let omega = if q == Q {
            OMEGA_Q[position]
        } else {
            OMEGA_QHAT[position]
        };
        for i in 0..4 {
            for j in 0..4 {
                let mut value = mont(a[block * 4 + i], b[block * 4 + j], q);
                let degree = i + j;
                if degree >= 4 {
                    value = mont(value, omega, q);
                }
                let output = &mut out[block * 4 + degree % 4];
                *output = if degree >= 4 && negative {
                    sub(*output, value, q)
                } else {
                    add(*output, value, q)
                };
            }
        }
    }
    out
}

pub fn plus(a: &Poly, b: &Poly, q: u64) -> Poly {
    std::array::from_fn(|i| add(a[i], b[i], q))
}
pub fn minus(a: &Poly, b: &Poly, q: u64) -> Poly {
    std::array::from_fn(|i| sub(a[i], b[i], q))
}
pub fn multiply_add(out: &mut Poly, a: &Poly, b: &Poly, q: u64) {
    *out = plus(out, &mul(a, b, q), q);
}
pub fn multiply_sub(out: &mut Poly, a: &Poly, b: &Poly, q: u64) {
    *out = minus(out, &mul(a, b, q), q);
}

pub fn aut(a: &Poly) -> Poly {
    let mut out = [0; D];
    for block in 0..64 {
        let source = (block / 32 * 32 + (block + 1) % 32) * 4;
        let target = block * 4;
        let (negative, position) = AUT_Q[block];
        let odd_twiddle = if position % 2 == 0 {
            OMEGA_Q[position / 2]
        } else {
            sub(0, OMEGA_Q[position / 2], Q)
        };
        out[target] = a[source];
        out[target + 1] = mont(a[source + 3], odd_twiddle, Q);
        let term = mont(a[source + 2], OMEGA_Q[position], Q);
        out[target + 2] = if negative { sub(0, term, Q) } else { term };
        out[target + 3] = a[source + 1];
    }
    out
}

pub fn inverse_aut(a: &SignedPoly) -> SignedPoly {
    std::array::from_fn(|i| {
        if (86..171).contains(&i) {
            -a[(3 * i) % D]
        } else {
            a[(3 * i) % D]
        }
    })
}

pub fn signed_mul(a: &SignedPoly, b: &SignedPoly) -> SignedPoly {
    let mut out = [0_i64; D];
    for i in 0..D {
        for j in 0..D {
            let value = a[i] * b[j];
            if i + j < D {
                out[i + j] += value;
            } else {
                out[i + j - D] -= value;
            }
        }
    }
    out
}

pub fn ntt_many(input: &[SignedPoly], q: u64) -> Vec<Poly> {
    input.iter().map(|p| ntt(p, q)).collect()
}
pub fn serialize_polys(out: &mut Vec<u8>, polys: &[Poly]) {
    for poly in polys {
        for value in poly {
            out.extend_from_slice(&(*value as u32).to_le_bytes());
        }
    }
}

#[allow(dead_code)]
const _: u64 = QHAT;
