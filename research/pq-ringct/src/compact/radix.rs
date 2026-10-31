//! Bounded base conversion: 256 digits, at most 256 u32 limbs, no bigint heap.
use super::Error;

pub(super) const DEGREE: usize = 256;
const MAX_BYTES: usize = DEGREE * 4;

pub(super) fn encode(digits: &[u32; DEGREE], base: u32, out: &mut [u8]) -> Result<(), Error> {
    if base < 2 || out.len() > MAX_BYTES {
        return Err(Error::Capacity);
    }
    let mut limbs = [0u32; DEGREE];
    let mut used = 0;
    for &digit in digits.iter().rev() {
        if digit >= base {
            return Err(Error::NonCanonical);
        }
        let mut carry = u64::from(digit);
        for word in &mut limbs[..used] {
            let value = u64::from(*word) * u64::from(base) + carry;
            *word = value as u32;
            carry = value >> 32;
        }
        if carry != 0 {
            if used == DEGREE {
                return Err(Error::Capacity);
            }
            limbs[used] = carry as u32;
            used += 1;
        }
    }
    // Do not silently truncate when a caller chooses an insufficient block.
    for i in out.len()..used * 4 {
        if ((limbs[i / 4] >> ((i % 4) * 8)) & 255) != 0 {
            return Err(Error::Capacity);
        }
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (limbs[i / 4] >> ((i % 4) * 8)) as u8;
    }
    Ok(())
}

pub(super) fn decode(input: &[u8], base: u32) -> Result<[u32; DEGREE], Error> {
    if base < 2 || input.len() > MAX_BYTES {
        return Err(Error::Capacity);
    }
    let mut limbs = [0u32; DEGREE];
    for (i, &byte) in input.iter().enumerate() {
        limbs[i / 4] |= u32::from(byte) << ((i % 4) * 8);
    }
    let mut used = input.len().div_ceil(4);
    let mut digits = [0; DEGREE];
    for digit in &mut digits {
        let mut remainder = 0u64;
        for word in limbs[..used].iter_mut().rev() {
            let value = (remainder << 32) | u64::from(*word);
            *word = (value / u64::from(base)) as u32;
            remainder = value % u64::from(base);
        }
        *digit = remainder as u32;
        while used != 0 && limbs[used - 1] == 0 {
            used -= 1;
        }
    }
    // Integers >= base^256 are alternate/invalid encodings, never reduced mod it.
    if used != 0 {
        return Err(Error::NonCanonical);
    }
    Ok(digits)
}

pub(super) fn unpack_bits(input: &[u8], width: usize) -> Result<[u32; DEGREE], Error> {
    if !(1..=32).contains(&width) || input.len() != DEGREE * width / 8 {
        return Err(Error::Length);
    }
    let mut result = [0; DEGREE];
    for (i, value) in result.iter_mut().enumerate() {
        // At most five bytes; all bounds derive from the fixed polynomial size.
        let bit = i * width;
        let start = bit / 8;
        let end = (bit + width).div_ceil(8);
        let mut word = 0u64;
        for (j, &byte) in input[start..end].iter().enumerate() {
            word |= u64::from(byte) << (j * 8);
        }
        *value = ((word >> (bit % 8)) & ((1u64 << width) - 1)) as u32;
    }
    Ok(result)
}

pub(super) fn pack_bits(digits: &[u32; DEGREE], width: usize, out: &mut [u8]) -> Result<(), Error> {
    if !(1..=32).contains(&width) || out.len() != DEGREE * width / 8 {
        return Err(Error::Length);
    }
    out.fill(0);
    for (i, &digit) in digits.iter().enumerate() {
        if u64::from(digit) >= 1u64 << width {
            return Err(Error::NonCanonical);
        }
        let bit = i * width;
        let start = bit / 8;
        let end = (bit + width).div_ceil(8);
        let value = u64::from(digit) << (bit % 8);
        for (j, byte) in out[start..end].iter_mut().enumerate() {
            *byte |= (value >> (j * 8)) as u8;
        }
    }
    Ok(())
}
