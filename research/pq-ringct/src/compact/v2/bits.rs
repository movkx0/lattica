use super::super::Error;

/// Pre-sized, zero-filled output. No writes can extend the admitted payload.
pub(super) struct Writer {
    bytes: Vec<u8>,
    position: usize,
    limit: usize,
}

impl Writer {
    pub fn new(bits: usize) -> Self {
        Self {
            bytes: vec![0; bits.div_ceil(8)],
            position: 0,
            limit: bits,
        }
    }

    fn bit(&mut self, value: u32) -> Result<(), Error> {
        if self.position >= self.limit {
            return Err(Error::Capacity);
        }
        self.bytes[self.position / 8] |= (value as u8) << (self.position % 8);
        self.position += 1;
        Ok(())
    }

    pub fn rice(&mut self, value: u32, k: u8) -> Result<(), Error> {
        for _ in 0..(value >> k) {
            self.bit(1)?;
        }
        self.bit(0)?;
        for i in 0..k {
            self.bit((value >> i) & 1)?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.position != self.limit {
            return Err(Error::Length);
        }
        Ok(self.bytes)
    }
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bit(&mut self) -> Result<u32, Error> {
        let byte = *self.bytes.get(self.position / 8).ok_or(Error::Length)?;
        let value = (byte >> (self.position % 8)) & 1;
        self.position += 1;
        Ok(u32::from(value))
    }

    pub fn rice(&mut self, k: u8, maximum: u32) -> Result<u32, Error> {
        let mut q = 0;
        while self.bit()? != 0 {
            // Bound both the unary run and the subsequent shift by the native
            // coefficient domain, in addition to the overall payload bound.
            if q >= maximum >> k {
                return Err(Error::NonCanonical);
            }
            q += 1;
        }
        let mut value = q << k;
        for i in 0..k {
            value |= self.bit()? << i;
        }
        if value > maximum {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.position.div_ceil(8) != self.bytes.len() {
            return Err(Error::Length);
        }
        let used = self.position % 8;
        if used != 0 && self.bytes[self.position / 8] >> used != 0 {
            return Err(Error::NonCanonical);
        }
        Ok(())
    }
}
