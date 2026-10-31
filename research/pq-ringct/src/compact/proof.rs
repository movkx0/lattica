use super::{radix, Error};
use crate::{
    native_packet,
    rust_verify::{Q, QHAT},
};

/// Fixed lossless native proof payload, excluding transport framing.
pub const PROOF_BYTES: usize = 51_578;

#[derive(Clone, Copy)]
pub(super) enum Part {
    Polys {
        count: usize,
        width: usize,
        base: u32,
        bytes: usize,
    },
    Raw(usize),
}

// Exact order in rust_verify::Proof::decode. Signed coefficients retain the
// original nonnegative offset encoding; no distribution assumption is used.
pub(super) const PARTS: [Part; 8] = [
    Part::Polys {
        count: 7,
        width: 28,
        base: Q as u32,
        bytes: 875,
    },
    Part::Polys {
        count: 5,
        width: 32,
        base: QHAT as u32,
        bytes: 1015,
    },
    Part::Raw(32),
    Part::Polys {
        count: 1,
        width: 2,
        base: 3,
        bytes: 51,
    },
    Part::Polys {
        count: 49,
        width: 17,
        base: 76_693,
        bytes: 520,
    },
    Part::Polys {
        count: 11,
        width: 11,
        base: 1_131,
        bytes: 325,
    },
    Part::Polys {
        count: 10,
        width: 17,
        base: 76_693,
        bytes: 520,
    },
    Part::Polys {
        count: 8,
        width: 24,
        base: 12_425_173,
        bytes: 755,
    },
];

/// Canonical encoding only; this does not establish that a spend proof is valid.
pub fn encode_proof(input: &[u8]) -> Result<Vec<u8>, Error> {
    transcode(input, true)
}

/// Reconstruct the exact original 53,600-byte proof, rejecting noncanonical blocks.
pub fn decode_proof(input: &[u8]) -> Result<Vec<u8>, Error> {
    transcode(input, false)
}

fn transcode(input: &[u8], encode: bool) -> Result<Vec<u8>, Error> {
    let (input_bytes, output_bytes) = if encode {
        (native_packet::PROOF_BYTES, PROOF_BYTES)
    } else {
        (PROOF_BYTES, native_packet::PROOF_BYTES)
    };
    if input.len() != input_bytes {
        return Err(Error::Length);
    }
    let mut out = vec![0; output_bytes];
    let (mut src, mut dst) = (0, 0);
    for part in PARTS {
        match part {
            Part::Raw(n) => {
                out[dst..dst + n].copy_from_slice(&input[src..src + n]);
                src += n;
                dst += n;
            }
            Part::Polys {
                count,
                width,
                base,
                bytes,
            } => {
                let legacy = radix::DEGREE * width / 8;
                for _ in 0..count {
                    if encode {
                        let digits = radix::unpack_bits(&input[src..src + legacy], width)?;
                        radix::encode(&digits, base, &mut out[dst..dst + bytes])?;
                        src += legacy;
                        dst += bytes;
                    } else {
                        let digits = radix::decode(&input[src..src + bytes], base)?;
                        radix::pack_bits(&digits, width, &mut out[dst..dst + legacy])?;
                        src += bytes;
                        dst += legacy;
                    }
                }
            }
        }
    }
    debug_assert_eq!((src, dst), (input_bytes, output_bytes));
    Ok(out)
}
