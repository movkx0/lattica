use super::{Poly, SignedPoly, VerifyError, D, Q, QHAT};
use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};

#[derive(Clone, Debug)]
pub struct Account {
    pub pk: Vec<Poly>,
    pub cn: Vec<Poly>,
}

#[derive(Clone, Debug)]
pub struct Statement {
    pub seed: [u8; 32],
    pub ring: Vec<[Account; 2]>,
    pub recipients: Vec<Vec<Poly>>,
    pub coins: Vec<Vec<Poly>>,
    pub serials: [[u8; 32]; 2],
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub c: Poly,
    pub v: Vec<Poly>,
    pub v1: Poly,
    pub v2: Poly,
    pub b: Vec<Poly>,
    pub alpha: [u8; 32],
    pub x: SignedPoly,
    pub z_out: Vec<Vec<SignedPoly>>,
    pub z0: Vec<SignedPoly>,
    pub z1: Vec<SignedPoly>,
    pub z2: Vec<SignedPoly>,
    pub f1: Vec<SignedPoly>,
    pub zb: Vec<SignedPoly>,
    pub z: Vec<SignedPoly>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], VerifyError> {
        let end = self.position.checked_add(N).ok_or(VerifyError::Length)?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(VerifyError::Length)?
            .try_into()
            .map_err(|_| VerifyError::Length)?;
        self.position = end;
        Ok(result)
    }
    fn canonical(&mut self) -> Result<u64, VerifyError> {
        let value = u32::from_le_bytes(self.take()?) as u64;
        if value >= Q {
            return Err(VerifyError::NonCanonical);
        }
        Ok(value)
    }
    fn polys(&mut self, n: usize) -> Result<Vec<Poly>, VerifyError> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let mut poly = [0; D];
            for value in &mut poly {
                *value = self.canonical()?;
            }
            result.push(poly);
        }
        Ok(result)
    }
    fn matches_polys(&mut self, polynomials: &[Poly]) -> Result<bool, VerifyError> {
        let mut same = true;
        for polynomial in polynomials {
            for &value in polynomial {
                same &= self.canonical()? == value;
            }
        }
        Ok(same)
    }
    fn account(&mut self) -> Result<Account, VerifyError> {
        Ok(Account {
            pk: self.polys(4)?,
            cn: self.polys(5)?,
        })
    }
}

impl Statement {
    pub fn decode(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() != STATEMENT_BYTES {
            return Err(VerifyError::Length);
        }
        let mut r = Reader { bytes, position: 0 };
        let seed = r.take()?;
        let mut ring = Vec::with_capacity(10);
        for _ in 0..10 {
            ring.push([r.account()?, r.account()?]);
        }
        let recipients = vec![r.polys(4)?, r.polys(4)?];
        let coins = vec![r.polys(5)?, r.polys(5)?];
        let serials = [r.take()?, r.take()?];
        if serials[0] == serials[1] {
            return Err(VerifyError::DuplicateSerial);
        }
        if r.position != bytes.len() {
            return Err(VerifyError::Length);
        }
        Ok(Self {
            seed,
            ring,
            recipients,
            coins,
            serials,
        })
    }

    /// Allocation-free equality to the maintained canonical decoder. This
    /// checks source identity only and does not verify the spend relation.
    pub(crate) fn matches_encoded(&self, bytes: &[u8]) -> Result<bool, VerifyError> {
        if bytes.len() != STATEMENT_BYTES {
            return Err(VerifyError::Length);
        }
        if self.ring.len() != 10
            || self.ring.iter().flatten().any(|a| a.pk.len() != 4 || a.cn.len() != 5)
            || self.recipients.len() != 2
            || self.recipients.iter().any(|row| row.len() != 4)
            || self.coins.len() != 2
            || self.coins.iter().any(|row| row.len() != 5)
        {
            return Ok(false);
        }
        let mut r = Reader { bytes, position: 0 };
        let mut same = r.take::<32>()? == self.seed;
        for account in self.ring.iter().flatten() {
            same &= r.matches_polys(&account.pk)?;
            same &= r.matches_polys(&account.cn)?;
        }
        for row in self.recipients.iter().chain(&self.coins) {
            same &= r.matches_polys(row)?;
        }
        let serials = [r.take::<32>()?, r.take::<32>()?];
        if serials[0] == serials[1] {
            return Err(VerifyError::DuplicateSerial);
        }
        same &= serials == self.serials;
        if r.position != bytes.len() {
            return Err(VerifyError::Length);
        }
        Ok(same)
    }
}

struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Bits<'_> {
    fn get(&mut self, width: usize) -> Result<u64, VerifyError> {
        let end = self
            .position
            .checked_add(width)
            .ok_or(VerifyError::Length)?;
        if width > 32 || end > self.bytes.len() * 8 {
            return Err(VerifyError::Length);
        }
        let mut value = 0;
        for i in 0..width {
            let bit = self.position + i;
            value |= u64::from((self.bytes[bit / 8] >> (bit % 8)) & 1) << i;
        }
        self.position = end;
        Ok(value)
    }
    fn canonical(&mut self, width: usize, modulus: u64) -> Result<u64, VerifyError> {
        let value = self.get(width)?;
        if value >= modulus {
            return Err(VerifyError::NonCanonical);
        }
        Ok(value)
    }
    fn signed_value(&mut self, width: usize, bound: i64) -> Result<i64, VerifyError> {
        let encoded = self.get(width)?;
        if encoded > 2 * bound as u64 {
            return Err(VerifyError::NonCanonical);
        }
        Ok(encoded as i64 - bound)
    }
    fn polys(&mut self, n: usize, width: usize, modulus: u64) -> Result<Vec<Poly>, VerifyError> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let mut poly = [0; D];
            for value in &mut poly {
                *value = self.canonical(width, modulus)?;
            }
            result.push(poly);
        }
        Ok(result)
    }
    fn signed(
        &mut self,
        n: usize,
        width: usize,
        bound: i64,
    ) -> Result<Vec<SignedPoly>, VerifyError> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let mut poly = [0; D];
            for value in &mut poly {
                *value = self.signed_value(width, bound)?;
            }
            result.push(poly);
        }
        Ok(result)
    }
    fn matches_polys(
        &mut self,
        polynomials: &[Poly],
        width: usize,
        modulus: u64,
    ) -> Result<bool, VerifyError> {
        let mut same = true;
        for polynomial in polynomials {
            for &value in polynomial {
                same &= self.canonical(width, modulus)? == value;
            }
        }
        Ok(same)
    }
    fn matches_signed(
        &mut self,
        polynomials: &[SignedPoly],
        width: usize,
        bound: i64,
    ) -> Result<bool, VerifyError> {
        let mut same = true;
        for polynomial in polynomials {
            for &value in polynomial {
                same &= self.signed_value(width, bound)? == value;
            }
        }
        Ok(same)
    }
}

impl Proof {
    pub fn decode(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() != PROOF_BYTES {
            return Err(VerifyError::Length);
        }
        let mut r = Bits { bytes, position: 0 };
        let c = r.polys(1, 28, Q)?[0];
        let v = r.polys(4, 28, Q)?;
        let v1 = r.polys(1, 28, Q)?[0];
        let v2 = r.polys(1, 28, Q)?[0];
        let b = r.polys(5, 32, QHAT)?;
        let mut alpha = [0; 32];
        for byte in &mut alpha {
            *byte = r.get(8)? as u8;
        }
        let x = r.signed(1, 2, 1)?[0];
        let z_out = vec![r.signed(9, 17, 38346)?, r.signed(9, 17, 38346)?];
        let z0 = r.signed(9, 17, 38346)?;
        let z1 = r.signed(11, 17, 38346)?;
        let z2 = r.signed(11, 17, 38346)?;
        let f1 = r.signed(11, 11, 565)?;
        let zb = r.signed(10, 17, 38346)?;
        let z = r.signed(8, 24, 6212586)?;
        if r.position != bytes.len() * 8 {
            return Err(VerifyError::Length);
        }
        Ok(Self {
            c,
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
        })
    }

    /// Exact packed source equality without another decoded allocation. Both
    /// paths use the same scalar bit reader and canonical/signed checks.
    pub(crate) fn matches_encoded(&self, bytes: &[u8]) -> Result<bool, VerifyError> {
        if bytes.len() != PROOF_BYTES {
            return Err(VerifyError::Length);
        }
        if self.v.len() != 4
            || self.b.len() != 5
            || self.z_out.len() != 2
            || self.z_out.iter().any(|row| row.len() != 9)
            || self.z0.len() != 9
            || self.z1.len() != 11
            || self.z2.len() != 11
            || self.f1.len() != 11
            || self.zb.len() != 10
            || self.z.len() != 8
        {
            return Ok(false);
        }
        let mut r = Bits { bytes, position: 0 };
        let mut same = r.matches_polys(core::slice::from_ref(&self.c), 28, Q)?;
        same &= r.matches_polys(&self.v, 28, Q)?;
        same &= r.matches_polys(core::slice::from_ref(&self.v1), 28, Q)?;
        same &= r.matches_polys(core::slice::from_ref(&self.v2), 28, Q)?;
        same &= r.matches_polys(&self.b, 32, QHAT)?;
        for &byte in &self.alpha {
            same &= r.get(8)? == u64::from(byte);
        }
        same &= r.matches_signed(core::slice::from_ref(&self.x), 2, 1)?;
        for row in self.z_out.iter().chain([&self.z0, &self.z1, &self.z2]) {
            same &= r.matches_signed(row, 17, 38346)?;
        }
        same &= r.matches_signed(&self.f1, 11, 565)?;
        same &= r.matches_signed(&self.zb, 17, 38346)?;
        same &= r.matches_signed(&self.z, 24, 6212586)?;
        if r.position != bytes.len() * 8 {
            return Err(VerifyError::Length);
        }
        Ok(same)
    }
}

#[cfg(test)]
mod encoding_tests;
