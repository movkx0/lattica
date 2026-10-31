use super::super::{radix, Error};

pub(super) const NATIVE_BYTES: usize = 11_424;
pub(super) const COMPACT_BYTES: usize = 11_204;
const Q: u32 = 167_770_241;
const QHAT: u32 = 3_489_661_057;

/// Omit eight coefficients only when they are actually zero. Other canonical
/// native proofs remain representable through the unchanged v2 fallback.
pub(super) fn encode(native: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if native.len() != NATIVE_BYTES {
        return Err(Error::Length);
    }
    let c = radix::unpack_bits(&native[..896], 28)?;
    if c[..4].iter().chain(&c[128..132]).any(|&d| d != 0) {
        return Ok(None);
    }
    let mut digits = [0; 256];
    digits[..124].copy_from_slice(&c[4..128]);
    digits[124..248].copy_from_slice(&c[132..]);
    let mut out = vec![0; COMPACT_BYTES];
    radix::encode(&digits, Q, &mut out[..847])?;
    let (mut src, mut dst) = (896, 847);
    for (count, width, base, bytes) in [(6, 28, Q, 875), (5, 32, QHAT, 1015)] {
        for _ in 0..count {
            let n = 32 * width;
            let digits = radix::unpack_bits(&native[src..src + n], width)?;
            radix::encode(&digits, base, &mut out[dst..dst + bytes])?;
            src += n;
            dst += bytes;
        }
    }
    out[dst..].copy_from_slice(&native[src..]);
    Ok(Some(out))
}

pub(super) fn decode(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded.len() != COMPACT_BYTES {
        return Err(Error::Length);
    }
    let compact_c = radix::decode(&encoded[..847], Q)?;
    if compact_c[248..].iter().any(|&d| d != 0) {
        return Err(Error::NonCanonical);
    }
    let mut c = [0; 256];
    c[4..128].copy_from_slice(&compact_c[..124]);
    c[132..].copy_from_slice(&compact_c[124..248]);
    let mut out = vec![0; NATIVE_BYTES];
    radix::pack_bits(&c, 28, &mut out[..896])?;
    let (mut src, mut dst) = (847, 896);
    for (count, width, base, bytes) in [(6, 28, Q, 875), (5, 32, QHAT, 1015)] {
        for _ in 0..count {
            let digits = radix::decode(&encoded[src..src + bytes], base)?;
            let n = 32 * width;
            radix::pack_bits(&digits, width, &mut out[dst..dst + n])?;
            src += bytes;
            dst += n;
        }
    }
    out[dst..].copy_from_slice(&encoded[src..]);
    Ok(out)
}
