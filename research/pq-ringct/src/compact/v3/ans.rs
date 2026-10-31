use super::super::Error;

const SCALE: u32 = 16;
const MASK: u32 = (1 << SCALE) - 1;
pub(super) const LOWER: u32 = 1 << 23;
const UPPER: u32 = LOWER << 8;

/// Byte rANS with a fixed output cap, including the four-byte final state.
pub(super) struct Encoder {
    state: u32,
    bytes: Vec<u8>,
    limit: usize,
}

impl Encoder {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit < 4 {
            return Err(Error::Capacity);
        }
        Ok(Self {
            state: LOWER,
            bytes: Vec::with_capacity(limit - 4),
            limit: limit - 4,
        })
    }

    /// Symbols arrive in reverse decoding order. False means the candidate
    /// cannot beat the existing encoding; no byte beyond its cap is allocated.
    pub fn symbol(&mut self, symbol: usize, cdf: &[u32]) -> Result<bool, Error> {
        let start = *cdf.get(symbol).ok_or(Error::NonCanonical)?;
        let end = *cdf.get(symbol + 1).ok_or(Error::NonCanonical)?;
        let frequency = end - start;
        let threshold = ((LOWER >> SCALE) << 8) * frequency;
        while self.state >= threshold {
            if self.bytes.len() == self.limit {
                return Ok(false);
            }
            self.bytes.push(self.state as u8);
            self.state >>= 8;
        }
        self.state = ((self.state / frequency) << SCALE) + self.state % frequency + start;
        debug_assert!((LOWER..UPPER).contains(&self.state));
        Ok(true)
    }

    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes.len() + 4);
        out.extend_from_slice(&self.state.to_le_bytes());
        out.extend(self.bytes.into_iter().rev());
        out
    }
}

pub(super) struct Decoder<'a> {
    state: u32,
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let initial = bytes.get(..4).ok_or(Error::Length)?;
        let state = u32::from_le_bytes(initial.try_into().unwrap());
        if !(LOWER..UPPER).contains(&state) {
            return Err(Error::NonCanonical);
        }
        Ok(Self {
            state,
            bytes,
            position: 4,
        })
    }

    pub fn symbol(&mut self, cdf: &[u32]) -> Result<u32, Error> {
        let slot = self.state & MASK;
        let symbol = cdf.partition_point(|&start| start <= slot) - 1;
        let start = cdf[symbol];
        let frequency = cdf[symbol + 1] - start;
        self.state = frequency * (self.state >> SCALE) + slot - start;
        while self.state < LOWER {
            let byte = *self.bytes.get(self.position).ok_or(Error::Length)?;
            self.position += 1;
            self.state = (self.state << 8) | u32::from(byte);
        }
        Ok(symbol as u32)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.position != self.bytes.len() {
            return Err(Error::Length);
        }
        if self.state != LOWER {
            return Err(Error::NonCanonical);
        }
        Ok(())
    }
}
