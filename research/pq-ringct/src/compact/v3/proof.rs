use super::super::{radix, v2, Error};
use super::{ans, head, models::GROUPS};
use crate::native_packet;

pub const MIN_PROOF_BYTES: usize = v2::MIN_PROOF_BYTES;
pub const MAX_PROOF_BYTES: usize = v2::MAX_PROOF_BYTES;
pub(super) const LOW_BYTES: usize = 24_640;
pub(super) const ANS_START: usize = 1 + head::COMPACT_BYTES + LOW_BYTES;

fn zigzag(digit: u32, base: u32) -> u32 {
    let center = (base - 1) / 2;
    if digit >= center {
        2 * (digit - center)
    } else {
        2 * (center - digit) - 1
    }
}

/// Build mode 2 only if it strictly beats the canonical v2 encoding. That
/// comparison also fixes the output capacity before entropy encoding begins.
pub(super) fn candidate(native: &[u8], previous_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
    let Some(limit) = previous_bytes.checked_sub(ANS_START + 1) else {
        return Ok(None);
    };
    if limit < 4 {
        return Ok(None);
    }
    let Some(encoded_head) = head::encode(&native[..head::NATIVE_BYTES])? else {
        return Ok(None);
    };
    let mut low = vec![0; LOW_BYTES];
    let mut symbols = Vec::with_capacity(20_224);
    let (mut src, mut dst) = (head::NATIVE_BYTES, 0);
    for group in GROUPS {
        for _ in 0..group.count {
            let end = src + 32 * group.width;
            let digits = radix::unpack_bits(&native[src..end], group.width)?;
            let values = digits.map(|d| zigzag(d, group.base));
            symbols.extend(values.iter().map(|&u| u >> group.low_bits));
            if group.low_bits != 0 {
                let remainders = values.map(|u| u & ((1 << group.low_bits) - 1));
                let end = dst + 32 * group.low_bits;
                radix::pack_bits(&remainders, group.low_bits, &mut low[dst..end])?;
                dst = end;
            }
            src = end;
        }
    }
    debug_assert_eq!((src, dst, symbols.len()), (native.len(), LOW_BYTES, 20_224));
    let mut encoder = ans::Encoder::new(limit)?;
    let mut end = symbols.len();
    for group in GROUPS.iter().rev() {
        let start = end - group.count * 256;
        for &symbol in symbols[start..end].iter().rev() {
            if !encoder.symbol(symbol as usize, group.cdf)? {
                return Ok(None);
            }
        }
        end = start;
    }
    let stream = encoder.finish();
    let mut out = Vec::with_capacity(ANS_START + stream.len());
    out.push(2);
    out.extend_from_slice(&encoded_head);
    out.extend_from_slice(&low);
    out.extend_from_slice(&stream);
    debug_assert!(out.len() < previous_bytes);
    Ok(Some(out))
}

/// Reversible transport only. The original native verifier is still required.
/// This never exceeds the v2 size for the same native input.
pub fn encode_proof(native: &[u8]) -> Result<Vec<u8>, Error> {
    let previous = v2::encode_proof(native)?;
    Ok(candidate(native, previous.len())?.unwrap_or(previous))
}

pub fn decode_proof(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if !(MIN_PROOF_BYTES..=MAX_PROOF_BYTES).contains(&encoded.len()) {
        return Err(Error::Length);
    }
    let native = match encoded[0] {
        0 | 1 => v2::decode_proof(encoded)?,
        2 => {
            if encoded.len() < ANS_START + 4 {
                return Err(Error::Length);
            }
            let mut native = head::decode(&encoded[1..1 + head::COMPACT_BYTES])?;
            native.reserve(native_packet::PROOF_BYTES - native.len());
            let mut decoder = ans::Decoder::new(&encoded[ANS_START..])?;
            let mut src = 1 + head::COMPACT_BYTES;
            for group in GROUPS {
                for _ in 0..group.count {
                    let remainders = if group.low_bits == 0 {
                        [0; 256]
                    } else {
                        let end = src + 32 * group.low_bits;
                        let values = radix::unpack_bits(&encoded[src..end], group.low_bits)?;
                        src = end;
                        values
                    };
                    let mut digits = [0; 256];
                    for (digit, remainder) in digits.iter_mut().zip(remainders) {
                        let u = (decoder.symbol(group.cdf)? << group.low_bits) | remainder;
                        if u >= group.base {
                            return Err(Error::NonCanonical);
                        }
                        let center = (group.base - 1) / 2;
                        *digit = if u & 1 == 0 {
                            center + u / 2
                        } else {
                            center - u.div_ceil(2)
                        };
                    }
                    let start = native.len();
                    native.resize(start + 32 * group.width, 0);
                    radix::pack_bits(&digits, group.width, &mut native[start..])?;
                }
            }
            debug_assert_eq!((src, native.len()), (ANS_START, native_packet::PROOF_BYTES));
            decoder.finish()?;
            native
        }
        _ => return Err(Error::Format),
    };
    // Also rules out a valid older encoding when mode 2 is smaller, as well as
    // alternative entropy streams or a more expensive mode 2 representation.
    if encode_proof(&native)? != encoded {
        return Err(Error::NonCanonical);
    }
    Ok(native)
}
