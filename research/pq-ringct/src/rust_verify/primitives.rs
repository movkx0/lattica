use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use super::{arithmetic::serialize_polys, Poly, SignedPoly, Statement, VerifyError, D, Q, QHAT};

pub fn shake(input: &[u8], count: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    state.update(input);
    let mut output = vec![0; count];
    state.finalize_xof().read(&mut output);
    output
}

/// Matches the author AES-NI stream: low little-endian u32 counter, zero next
/// word, and little-endian domain in the high u64. Every call discards unused
/// bytes from its final AES block, exactly as fastrandombytes.c does.
pub struct AesStream {
    cipher: Aes256,
    domain: u64,
    counter: u32,
}
impl AesStream {
    pub fn new(seed: &[u8; 32], domain: u64) -> Self {
        Self {
            cipher: Aes256::new(seed.into()),
            domain,
            counter: 0,
        }
    }
    pub fn bytes(&mut self, count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count.div_ceil(16) * 16);
        for _ in 0..count.div_ceil(16) {
            let mut input = [0; 16];
            input[..4].copy_from_slice(&self.counter.to_le_bytes());
            input[8..].copy_from_slice(&self.domain.to_le_bytes());
            let mut block = input.into();
            self.cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            self.counter = self.counter.wrapping_add(1);
        }
        out.truncate(count);
        out
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Cursor<'_> {
    fn load(&mut self, width: usize) -> Result<u64, VerifyError> {
        let chunk = self
            .bytes
            .get(self.offset..self.offset + width)
            .ok_or(VerifyError::SamplingExhausted)?;
        self.offset += width;
        Ok(chunk
            .iter()
            .enumerate()
            .fold(0, |value, (i, byte)| value | (u64::from(*byte) << (8 * i))))
    }
    fn sample(&mut self, width: usize, bound: u64, q: u64) -> Result<u64, VerifyError> {
        loop {
            let x = self.load(width)?;
            if x < bound {
                return Ok(x % q);
            }
        }
    }
    fn polys(
        &mut self,
        count: usize,
        width: usize,
        bound: u64,
        q: u64,
    ) -> Result<Vec<Poly>, VerifyError> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut poly = [0; D];
            for x in &mut poly {
                *x = self.sample(width, bound, q)?;
            }
            out.push(poly);
        }
        Ok(out)
    }
}

pub struct Parameters {
    pub mat1: Vec<Vec<Poly>>,
    pub mat2: Vec<Vec<Poly>>,
    pub mat3: Vec<Vec<Poly>>,
    pub pp: [u8; 32],
}

pub fn parameters(seed: &[u8; 32], context: &[u8; 32]) -> Result<Parameters, VerifyError> {
    let mut setup = seed.to_vec();
    setup.extend_from_slice(&[64, 4, 4, 4, 5, 5]);
    setup.extend_from_slice(&256_u16.to_le_bytes());
    setup.extend_from_slice(&(Q as u32).to_le_bytes());
    setup.extend_from_slice(&(QHAT as u32).to_le_bytes());
    setup.push(44);
    let mut binding = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".to_vec();
    binding.extend_from_slice(&shake(&setup, 32));
    binding.extend_from_slice(context);
    let pp = shake(&binding, 32).try_into().expect("fixed SHAKE output");

    let bytes = AesStream::new(seed, 0x4d617431).bytes(7648 * 4);
    let mut stream = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    let mut mat1 = Vec::with_capacity(7);
    for _ in 0..7 {
        mat1.push(stream.polys(4, 4, 4194256025, Q)?);
    }

    let bytes = AesStream::new(seed, 0x4d617432).bytes(3366 * 4);
    let mut stream = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    let mut mat2 = vec![vec![[0; D]; 3]; 4];
    for row in &mut mat2 {
        for poly in row.iter_mut().take(2) {
            for value in poly {
                *value = stream.sample(4, 4194256025, Q)?;
            }
        }
    }
    for row in &mut mat2 {
        for k in 4..128 {
            row[2][k] = stream.sample(4, 4194256025, Q)?;
            row[2][128 + k] = stream.sample(4, 4194256025, Q)?;
        }
    }

    let bytes = AesStream::new(seed, 0x4d617433).bytes(37232 * 5);
    let mut stream = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    let mut mat3 = Vec::with_capacity(29);
    for _ in 0..29 {
        mat3.push(stream.polys(5, 5, 1099243232955, QHAT)?);
    }
    Ok(Parameters {
        mat1,
        mat2,
        mat3,
        pp,
    })
}

pub fn sample_g(seed: &[u8; 32]) -> Result<Vec<Poly>, VerifyError> {
    let bytes = AesStream::new(seed, 0).bytes(1197 * 4);
    Cursor {
        bytes: &bytes,
        offset: 0,
    }
    .polys(4, 4, 4194256025, Q)
}

pub fn expand_alpha(seed: &[u8; 32]) -> Result<(Vec<Poly>, SignedPoly), VerifyError> {
    let mut aes = AesStream::new(seed, 0x4368);
    let bytes = aes.bytes(643 * 4);
    let alpha = Cursor {
        bytes: &bytes,
        offset: 0,
    }
    .polys(2, 4, 4194256025, Q)?;
    let bytes = aes.bytes(127);
    let mut stream = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    let signs = stream.load(5)?;
    let mut output = [0; D];
    let mut used = [false; D];
    for i in 0..39 {
        let index = loop {
            let index = stream.load(1)? as usize;
            if !used[index] {
                break index;
            }
        };
        used[index] = true;
        output[index] = 1 - 2 * ((signs >> i) & 1) as i64;
    }
    Ok((alpha, output))
}

#[allow(clippy::too_many_arguments)]
pub fn hash_alpha(
    pp: &[u8; 32],
    statement: &Statement,
    w_out: &[Vec<Poly>],
    w0: &[Poly],
    v: &[Poly],
    v2: &Poly,
    c: &Poly,
    w: &Poly,
    w1: &[Poly],
    w2: &[Poly],
) -> [u8; 32] {
    let mut input = pp.to_vec();
    for pair in &statement.ring {
        for account in pair {
            serialize_polys(&mut input, &account.pk);
            serialize_polys(&mut input, &account.cn);
        }
    }
    for serial in &statement.serials {
        input.extend_from_slice(serial);
    }
    for account in &statement.recipients {
        serialize_polys(&mut input, account);
    }
    for coin in &statement.coins {
        serialize_polys(&mut input, coin);
    }
    for polys in w_out {
        serialize_polys(&mut input, polys);
    }
    serialize_polys(&mut input, w0);
    serialize_polys(&mut input, v);
    for poly in [v2, c, w] {
        serialize_polys(&mut input, std::slice::from_ref(poly));
    }
    serialize_polys(&mut input, w1);
    serialize_polys(&mut input, w2);
    shake(&input, 32).try_into().expect("fixed SHAKE output")
}

pub fn hash_x(
    alpha: &[u8; 32],
    v0: &Poly,
    v1: &Poly,
    a: &[Poly],
    b: &[Poly],
    e: &[Poly],
) -> Result<SignedPoly, VerifyError> {
    let mut input = alpha.to_vec();
    serialize_polys(&mut input, std::slice::from_ref(v0));
    serialize_polys(&mut input, std::slice::from_ref(v1));
    serialize_polys(&mut input, a);
    serialize_polys(&mut input, b);
    serialize_polys(&mut input, e);
    let bytes = shake(&input, 137);
    let mut stream = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    let signs = stream.load(6)?;
    let mut output = [0; D];
    let mut used = [[false; 64]; 4];
    for group in 0..4 {
        let index = (stream.load(1)? & 63) as usize;
        used[group][index] = true;
        output[index * 4 + group] = 1 - 2 * ((signs >> group) & 1) as i64;
    }
    let mut count = 4;
    for group in 0..4 {
        for _ in 1..11 {
            let index = loop {
                let index = (stream.load(1)? & 63) as usize;
                if !used[group][index] {
                    break index;
                }
            };
            used[group][index] = true;
            output[index * 4 + group] = 1 - 2 * ((signs >> count) & 1) as i64;
            count += 1;
        }
    }
    Ok(output)
}
