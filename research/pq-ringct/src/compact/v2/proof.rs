use super::{
    super::{proof as v1, radix, Error},
    bits::{Reader, Writer},
};
use crate::native_packet;
use v1::{Part, PARTS};

/// Parser bound, not an attainable-size claim for valid cryptographic proofs.
pub const MIN_PROOF_BYTES: usize = 13_766;
/// Mode byte plus the v1 payload; worst case is one byte larger than v1.
pub const MAX_PROOF_BYTES: usize = 1 + v1::PROOF_BYTES;
pub(super) const NATIVE_HEAD: usize = 11_424;
pub(super) const RADIX_HEAD: usize = 11_232;
pub(super) const RICE_PREFIX: usize = 6 + RADIX_HEAD;

pub(super) struct Plan {
    pub params: [u8; 5],
    pub bits: usize,
}

impl Plan {
    fn bytes(&self) -> usize {
        RICE_PREFIX + self.bits.div_ceil(8)
    }
}

fn zigzag(digit: u32, base: u32) -> u32 {
    let center = (base - 1) / 2;
    if digit >= center {
        2 * (digit - center)
    } else {
        2 * (center - digit) - 1
    }
}

/// Fixed group geometry; sizes and bounds come from the existing native codec.
pub(super) fn groups() -> impl Iterator<Item = (usize, usize, u32)> {
    PARTS[3..].iter().map(|part| match *part {
        Part::Polys {
            count, width, base, ..
        } => (count, width, base),
        Part::Raw(_) => unreachable!("signed groups are polynomial-only"),
    })
}

pub(super) fn plan(input: &[u8]) -> Result<Plan, Error> {
    if input.len() != native_packet::PROOF_BYTES {
        return Err(Error::Length);
    }
    let mut params = [0; 5];
    let mut bits = 0;
    let mut position = NATIVE_HEAD;
    for (group, (count, width, base)) in groups().enumerate() {
        let mut costs = [0u64; 32];
        for _ in 0..count {
            let end = position + radix::DEGREE * width / 8;
            for digit in radix::unpack_bits(&input[position..end], width)? {
                if digit >= base {
                    return Err(Error::NonCanonical);
                }
                let u = zigzag(digit, base);
                for (k, cost) in costs[..width].iter_mut().enumerate() {
                    *cost += u64::from(u >> k) + 1 + k as u64;
                }
            }
            position = end;
        }
        // min_by_key returns the first minimum: ties use the smaller k.
        let k = (0..width).min_by_key(|&k| costs[k]).unwrap();
        params[group] = k as u8;
        bits += usize::try_from(costs[k]).map_err(|_| Error::Capacity)?;
    }
    debug_assert_eq!(position, input.len());
    Ok(Plan { params, bits })
}

fn head(input: &[u8], encode: bool) -> Result<Vec<u8>, Error> {
    let expected = if encode { NATIVE_HEAD } else { RADIX_HEAD };
    if input.len() != expected {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(if encode { RADIX_HEAD } else { NATIVE_HEAD });
    let mut position = 0;
    for part in &PARTS[..3] {
        match *part {
            Part::Raw(n) => {
                out.extend_from_slice(&input[position..position + n]);
                position += n;
            }
            Part::Polys {
                count,
                width,
                base,
                bytes,
            } => {
                let native_bytes = radix::DEGREE * width / 8;
                let (source, target) = if encode {
                    (native_bytes, bytes)
                } else {
                    (bytes, native_bytes)
                };
                for _ in 0..count {
                    let block = &input[position..position + source];
                    let start = out.len();
                    out.resize(start + target, 0);
                    if encode {
                        let digits = radix::unpack_bits(block, width)?;
                        radix::encode(&digits, base, &mut out[start..])?;
                    } else {
                        let digits = radix::decode(block, base)?;
                        radix::pack_bits(&digits, width, &mut out[start..])?;
                    }
                    position += source;
                }
            }
        }
    }
    debug_assert_eq!(position, input.len());
    Ok(out)
}

/// Encode all originally canonical native coefficients. This does not verify
/// the proof. Neither mode changes a byte of the reconstructed native proof.
pub fn encode_proof(input: &[u8]) -> Result<Vec<u8>, Error> {
    let plan = plan(input)?;
    if plan.bytes() >= MAX_PROOF_BYTES {
        let mut out = Vec::with_capacity(MAX_PROOF_BYTES);
        out.push(0);
        out.extend_from_slice(&v1::encode_proof(input)?);
        return Ok(out);
    }
    let mut out = Vec::with_capacity(plan.bytes());
    out.push(1);
    out.extend_from_slice(&plan.params);
    out.extend_from_slice(&head(&input[..NATIVE_HEAD], true)?);
    let mut writer = Writer::new(plan.bits);
    let mut position = NATIVE_HEAD;
    for (group, (count, width, base)) in groups().enumerate() {
        for _ in 0..count {
            let end = position + radix::DEGREE * width / 8;
            for digit in radix::unpack_bits(&input[position..end], width)? {
                writer.rice(zigzag(digit, base), plan.params[group])?;
            }
            position = end;
        }
    }
    out.extend_from_slice(&writer.finish()?);
    debug_assert_eq!(out.len(), plan.bytes());
    Ok(out)
}

/// Strict bounded decoding, including optimal-parameter and mode canonicality.
/// The caller must still run the native proof verifier on the returned bytes.
pub fn decode_proof(input: &[u8]) -> Result<Vec<u8>, Error> {
    if !(MIN_PROOF_BYTES..=MAX_PROOF_BYTES).contains(&input.len()) {
        return Err(Error::Length);
    }
    match input[0] {
        0 => {
            let out = v1::decode_proof(&input[1..])?;
            if plan(&out)?.bytes() < MAX_PROOF_BYTES {
                return Err(Error::NonCanonical);
            }
            Ok(out)
        }
        1 => {
            if input.len() >= MAX_PROOF_BYTES {
                return Err(Error::NonCanonical);
            }
            for (group, (_, width, _)) in groups().enumerate() {
                if usize::from(input[1 + group]) >= width {
                    return Err(Error::NonCanonical);
                }
            }
            let mut out = Vec::with_capacity(native_packet::PROOF_BYTES);
            out.extend_from_slice(&head(&input[6..RICE_PREFIX], false)?);
            let mut reader = Reader::new(&input[RICE_PREFIX..]);
            for (group, (count, width, base)) in groups().enumerate() {
                for _ in 0..count {
                    let mut digits = [0; radix::DEGREE];
                    for digit in &mut digits {
                        let u = reader.rice(input[1 + group], base - 1)?;
                        let center = (base - 1) / 2;
                        *digit = if u & 1 == 0 {
                            center + u / 2
                        } else {
                            center - u.div_ceil(2)
                        };
                    }
                    let start = out.len();
                    out.resize(start + radix::DEGREE * width / 8, 0);
                    radix::pack_bits(&digits, width, &mut out[start..])?;
                }
            }
            reader.finish()?;
            let plan = plan(&out)?;
            if input[1..6] != plan.params || plan.bytes() != input.len() {
                return Err(Error::NonCanonical);
            }
            Ok(out)
        }
        _ => Err(Error::Format),
    }
}
