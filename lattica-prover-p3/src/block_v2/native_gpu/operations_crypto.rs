//! Bounded raw crypto witness arithmetic, without constructing a proof or trace.
use super::OperationContext;

/// Fixed rejection-sampling profiles from the registered MatRiCT relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniformProfile {
    Q32,
    Qhat40,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparseProfile {
    AlphaPrime39,
    ChallengeX44,
}

fn host_bytes(input: usize, output: usize) -> Result<usize, String> {
    output
        .checked_add(1)
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| n.checked_add(input))
        .and_then(|n| n.checked_add(80 << 10))
        .ok_or_else(|| "raw crypto host bound overflow".into())
}

struct RawWords(Vec<u64>);
impl Drop for RawWords {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: the conversion staging remains exclusively owned here.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
fn bytes(words: Vec<u64>) -> Result<Vec<u8>, String> {
    let words = RawWords(words);
    if words.0.iter().any(|&word| word > 255) {
        return Err("raw crypto output is not bytes".into());
    }
    Ok(words.0.iter().map(|&word| word as u8).collect())
}

impl OperationContext<'_> {
    pub fn aes256_ctr(
        &self,
        key: &[u8; 32],
        domain: u64,
        start_counter: u32,
        output_len: usize,
    ) -> Result<Vec<u8>, String> {
        self.execute(|| {
            self.admit_host_bytes(host_bytes(key.len(), output_len)?)?;
            bytes(self.session.raw_crypto_output(
                0,
                key,
                domain,
                start_counter,
                output_len,
                self.host_allowance,
                self.run,
            )?)
        })
    }

    pub fn shake256(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, String> {
        self.execute(|| {
            self.admit_host_bytes(host_bytes(input.len(), output_len)?)?;
            bytes(self.session.raw_crypto_output(
                1,
                input,
                0,
                0,
                output_len,
                self.host_allowance,
                self.run,
            )?)
        })
    }

    /// Return exactly `count` coefficients or reject an exhausted byte stream.
    /// The cursor spans the whole output, including polynomial boundaries.
    pub fn uniform_coefficients(
        &self,
        input: &[u8],
        profile: UniformProfile,
        count: usize,
    ) -> Result<Vec<u64>, String> {
        self.execute(|| {
            self.admit_host_bytes(host_bytes(input.len(), count)?)?;
            let mut words = RawWords(self.session.raw_crypto_output(
                match profile {
                    UniformProfile::Q32 => 2,
                    UniformProfile::Qhat40 => 3,
                },
                input,
                0,
                0,
                count,
                self.host_allowance,
                self.run,
            )?);
            let modulus = match profile {
                UniformProfile::Q32 => 167_770_241,
                UniformProfile::Qhat40 => 3_489_661_057,
            };
            if words.0.iter().any(|&word| word >= modulus) {
                return Err("raw uniform output is not canonical".into());
            }
            Ok(std::mem::take(&mut words.0))
        })
    }

    pub fn sparse_polynomial(
        &self,
        input: &[u8],
        kind: SparseProfile,
    ) -> Result<[i64; 256], String> {
        self.execute(|| {
            self.admit_host_bytes(host_bytes(input.len(), 256)?)?;
            let words = RawWords(self.session.raw_crypto_output(
                match kind {
                    SparseProfile::AlphaPrime39 => 4,
                    SparseProfile::ChallengeX44 => 5,
                },
                input,
                0,
                0,
                256,
                self.host_allowance,
                self.run,
            )?);
            if words.0.len() != 256 || words.0.iter().any(|&word| word > 2) {
                return Err("raw sparse output encoding".into());
            }
            // Decode the device's 0/positive/negative representation only.
            Ok(core::array::from_fn(|i| match words.0[i] {
                0 => 0,
                1 => 1,
                _ => -1,
            }))
        })
    }
}
