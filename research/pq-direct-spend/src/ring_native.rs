//! Host oracle only. Reuses the existing generic MatRiCT ring arithmetic;
//! these methods are not a cryptographic verifier.
use crate::Error;
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};
use lattica_pq_ringct_research::rust_verify::{
    generic::{self, Backend, GParameters, GStatement, Polynomial},
    VerifyError, D, Q, QHAT,
};

pub(crate) struct Native;
impl Backend for Native {
    type Residue = u64;
    type Signed = i64;
    type Byte = u8;
    fn constant(&mut self, value: u64, q: u64) -> u64 {
        value % q
    }
    fn add(&mut self, a: u64, b: u64, q: u64) -> u64 {
        (a + b) % q
    }
    fn sub(&mut self, a: u64, b: u64, q: u64) -> u64 {
        (a + q - b) % q
    }
    fn mont(&mut self, a: u64, b: u64, q: u64) -> u64 {
        // Author Montgomery radix R=2^32, unchanged for both fixed moduli.
        let factor = match q {
            Q => 2_887_272_321,
            QHAT => 1_071_660_929,
            _ => unreachable!(),
        };
        let product = u128::from(a) * u128::from(b);
        let correction = (product as u64 & 0xffff_ffff).wrapping_mul(factor) & 0xffff_ffff;
        let v = (product >> 32) as i128 - ((u128::from(correction) * u128::from(q)) >> 32) as i128;
        v.rem_euclid(i128::from(q)) as u64
    }
    fn to_residue(&mut self, a: i64, q: u64) -> u64 {
        a.rem_euclid(q as i64) as u64
    }
    fn signed_neg(&mut self, a: i64) -> i64 {
        -a
    }
    fn signed_sub(&mut self, a: i64, b: i64) -> i64 {
        a - b
    }
    fn norm(&mut self, _: &[Polynomial<i64>], _: u64) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn g_bound(
        &mut self,
        _: &Polynomial<i64>,
        _: &Polynomial<i64>,
        _: u32,
    ) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn equal_bytes(&mut self, a: &[u8; 32], b: &[u8; 32]) -> Result<(), VerifyError> {
        if a == b {
            Ok(())
        } else {
            Err(VerifyError::Rejected)
        }
    }
    fn equal_signed(
        &mut self,
        a: &Polynomial<i64>,
        b: &Polynomial<i64>,
    ) -> Result<(), VerifyError> {
        if a == b {
            Ok(())
        } else {
            Err(VerifyError::Rejected)
        }
    }
    fn parameters(
        &mut self,
        _: &[u8; 32],
        _: &[u8; 32],
    ) -> Result<GParameters<u64, u8>, VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn sample_g(&mut self, _: &[u8; 32]) -> Result<Vec<Polynomial<u64>>, VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn expand_alpha(
        &mut self,
        _: &[u8; 32],
    ) -> Result<(Vec<Polynomial<u64>>, Polynomial<i64>), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn hash_alpha(
        &mut self,
        _: &[u8; 32],
        _: &GStatement<u64, u8>,
        _: &[Vec<Polynomial<u64>>],
        _: &[Polynomial<u64>],
        _: &[Polynomial<u64>],
        _: &Polynomial<u64>,
        _: &Polynomial<u64>,
        _: &Polynomial<u64>,
        _: &[Polynomial<u64>],
        _: &[Polynomial<u64>],
    ) -> [u8; 32] {
        // The direct relation never invokes the old spend-proof transcript.
        // Keeping this adapter private prevents use as a full verifier backend.
        panic!("MatRiCT verifier transcript is outside the direct-spend oracle")
    }
    fn hash_x(
        &mut self,
        _: &[u8; 32],
        _: &Polynomial<u64>,
        _: &Polynomial<u64>,
        _: &[Polynomial<u64>],
        _: &[Polynomial<u64>],
        _: &[Polynomial<u64>],
    ) -> Result<Polynomial<i64>, VerifyError> {
        Err(VerifyError::Rejected)
    }
}

pub(crate) type Poly = [u64; D];
pub(crate) type Signed = [i64; D];

pub(crate) fn ntt<B: Backend>(b: &mut B, input: &Polynomial<B::Signed>) -> Polynomial<B::Residue> {
    let residue = input.map(|x| b.to_residue(x, Q));
    // Deliberately inline, never an unverified NTT request/commitment.
    generic::ntt_residues(b, &residue, Q)
}
pub(crate) fn multiply_add<B: Backend>(
    b: &mut B,
    target: &mut Polynomial<B::Residue>,
    a: &Polynomial<B::Residue>,
    rhs: &Polynomial<B::Residue>,
) {
    let product = generic::mul_residues(b, a, rhs, Q);
    *target = generic::plus_residues(b, target, &product, Q);
}

pub(crate) struct Parameters {
    pub mat1: Vec<[Poly; 4]>,
    pub mat2: Vec<[Poly; 3]>,
}

fn stream(seed: &[u8; 32], domain: u64, count: usize) -> Vec<u8> {
    let cipher = Aes256::new(seed.into());
    let mut result = Vec::with_capacity(count.div_ceil(16) * 16);
    for counter in 0..count.div_ceil(16) {
        let mut input = [0; 16];
        input[..4].copy_from_slice(&(counter as u32).to_le_bytes());
        input[8..].copy_from_slice(&domain.to_le_bytes());
        let mut block = input.into();
        cipher.encrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    result.truncate(count);
    result
}

struct Sampler {
    bytes: Vec<u8>,
    offset: usize,
}
impl Sampler {
    fn sample(&mut self) -> Result<u64, Error> {
        loop {
            let bytes = self
                .bytes
                .get(self.offset..self.offset + 4)
                .ok_or(Error::SamplingExhausted)?;
            self.offset += 4;
            let x = u32::from_le_bytes(bytes.try_into().unwrap()) as u64;
            if x < 4_194_256_025 {
                return Ok(x % Q);
            }
        }
    }
    fn poly(&mut self) -> Result<Poly, Error> {
        let mut p = [0; D];
        for v in &mut p {
            *v = self.sample()?;
        }
        Ok(p)
    }
}

pub(crate) fn parameters(seed: &[u8; 32]) -> Result<Parameters, Error> {
    let mut s = Sampler {
        bytes: stream(seed, 0x4d617431, 7648 * 4),
        offset: 0,
    };
    let mut mat1 = Vec::with_capacity(7);
    for _ in 0..7 {
        mat1.push([s.poly()?, s.poly()?, s.poly()?, s.poly()?]);
    }
    let mut s = Sampler {
        bytes: stream(seed, 0x4d617432, 3366 * 4),
        offset: 0,
    };
    let mut mat2 = vec![[[0; D]; 3]; 4];
    for row in &mut mat2 {
        for p in &mut row[..2] {
            *p = s.poly()?;
        }
    }
    for row in &mut mat2 {
        for k in 4..128 {
            row[2][k] = s.sample()?;
            row[2][128 + k] = s.sample()?;
        }
    }
    Ok(Parameters { mat1, mat2 })
}

/// G(gamma) uses the exact bounded AES-256 stream and rejection threshold.
/// Gamma is the *public* transaction serial. Its derivation is verifier-side
/// public preprocessing, never a witness-supplied digest accepted on trust.
pub(crate) fn serial_image(serial: &[u8; 32]) -> Result<[Poly; 4], Error> {
    let mut s = Sampler {
        bytes: stream(serial, 0, 1197 * 4),
        offset: 0,
    };
    Ok([s.poly()?, s.poly()?, s.poly()?, s.poly()?])
}

pub(crate) fn public_key<B: Backend>(
    b: &mut B,
    spending: &[Polynomial<B::Signed>; 8],
    mat1: &[[Polynomial<B::Residue>; 4]],
    g: &[Polynomial<B::Residue>; 4],
) -> [Polynomial<B::Residue>; 4] {
    let r = spending.each_ref().map(|p| ntt(b, p));
    let mut pk = [r[0], r[1], r[2], r[3]];
    for i in 0..4 {
        for j in 0..4 {
            multiply_add(b, &mut pk[j], &mat1[i][j], &r[4 + i]);
        }
    }
    for j in 0..4 {
        pk[j] = generic::plus_residues(b, &pk[j], &g[j], Q);
    }
    pk
}

/// Value is represented by 64 bit residues; bits 52..64 are fixed zero.
pub(crate) fn commitment<B: Backend>(
    b: &mut B,
    opening: &[Polynomial<B::Signed>; 9],
    bits: &[B::Residue; 64],
    mat1: &[[Polynomial<B::Residue>; 4]],
    mat2: &[[Polynomial<B::Residue>; 3]],
) -> [Polynomial<B::Residue>; 5] {
    let r = opening.each_ref().map(|p| ntt(b, p));
    let mut cn = [r[0], r[1], r[2], r[3], r[4]];
    for i in 0..5 {
        for j in 0..4 {
            multiply_add(b, &mut cn[j], &mat1[i][j], &r[4 + i]);
        }
    }
    for i in 0..2 {
        multiply_add(b, &mut cn[4], &mat2[i][0], &r[7 + i]);
    }
    // Original mint adds bit * (2^32 mod Q) at every fourth NTT coefficient.
    let radix_squared = b.constant(
        (((1u128 << 32) % u128::from(Q)).pow(2) % u128::from(Q)) as u64,
        Q,
    );
    for i in 0..64 {
        // `mont` divides by R: multiply by R^2 to obtain bit * R.
        let encoded = b.mont(bits[i], radix_squared, Q);
        cn[4][i * 4] = b.add(cn[4][i * 4], encoded, Q);
    }
    cn
}

pub(crate) fn key(
    spending: &[Signed; 8],
    params: &Parameters,
    serial: &[u8; 32],
) -> Result<[Poly; 4], Error> {
    Ok(public_key(
        &mut Native,
        spending,
        &params.mat1,
        &serial_image(serial)?,
    ))
}
pub(crate) fn coin(opening: &[Signed; 9], value: u64, params: &Parameters) -> [Poly; 5] {
    commitment(
        &mut Native,
        opening,
        &std::array::from_fn(|i| (value >> i) & 1),
        &params.mat1,
        &params.mat2,
    )
}

#[cfg(all(test, feature = "native-reference"))]
mod reference_tests {
    use super::*;
    extern "C" {
        fn direct_spend_reference(
            seed: *const u8,
            private_seed: *const u8,
            value: u64,
            pk: *mut u64,
            sk: *mut i64,
            serial: *mut u8,
            cn: *mut u64,
            ck: *mut i64,
        );
    }
    #[test]
    fn direct_account_and_opening_match_vendored_keygen_and_mint() {
        assert!(
            lattica_pq_ringct_research::native::available(),
            "native oracle requires AVX2/AES/FMA"
        );
        // Only this test invokes reference global RNG state. Tests use public
        // deterministic seeds; no spend proof or production entropy is involved.
        for value in [0, 1, (1u64 << 52) - 1] {
            let seed = [7; 32];
            let private_seed = [13; 32];
            let mut pk = [[0; D]; 4];
            let mut sk = [[0; D]; 8];
            let mut serial = [0; 32];
            let mut cn = [[0; D]; 5];
            let mut ck = [[0; D]; 9];
            unsafe {
                direct_spend_reference(
                    seed.as_ptr(),
                    private_seed.as_ptr(),
                    value,
                    pk.as_mut_ptr().cast(),
                    sk.as_mut_ptr().cast(),
                    serial.as_mut_ptr(),
                    cn.as_mut_ptr().cast(),
                    ck.as_mut_ptr().cast(),
                );
            }
            let params = parameters(&seed).unwrap();
            assert_eq!(
                key(&sk, &params, &serial).unwrap(),
                pk,
                "ownership equation and AES serial derivation"
            );
            assert_eq!(
                coin(&ck, value, &params),
                cn,
                "commitment equation and 52-bit boundary"
            );
        }
    }
}
