//! Exact-capacity byte buffers for local coordinator persistence.
//!
//! These bounds cover payload backing, not filesystem caches, paths, retained
//! graph/store metadata, allocator overhead or complete process RSS.

use crate::block_v2::recursive::Error;
use std::io::{ErrorKind, Read};

pub(super) fn byte_capacity(capacity: usize, limit: usize) -> Result<Vec<u8>, Error> {
    if capacity > limit {
        return Err("coordinator byte buffer exceeds limit".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    if bytes.capacity() != capacity {
        return Err("coordinator byte buffer capacity rounding".into());
    }
    Ok(bytes)
}

/// Read exactly the already-checked regular-file length. A single stack byte
/// detects growth without letting read_to_end grow the admitted allocation.
pub(super) fn read_file(
    reader: &mut impl Read,
    length: usize,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = byte_capacity(length, limit)?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    let mut extra = [0];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err("coordinator file grew beyond checked length".into()),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn exact_read_rejects_truncation_growth_and_limit_before_reading() {
        for len in [0, 1, 52, 4096, 1 << 20] {
            let input = vec![0x5a; len];
            let output = read_file(&mut Cursor::new(&input), len, len).unwrap();
            assert_eq!(output, input);
            assert_eq!(output.capacity(), len);
            let mut grown = input.clone();
            grown.extend([1, 2, 3]);
            let mut reader = Cursor::new(grown);
            assert!(read_file(&mut reader, len, len).is_err());
            assert_eq!(reader.position(), (len + 1) as u64);
            if len != 0 {
                assert!(read_file(&mut Cursor::new(&input[..len - 1]), len, len).is_err());
                let mut reader = Cursor::new(&input);
                assert!(read_file(&mut reader, len, len - 1).is_err());
                assert_eq!(reader.position(), 0);
            }
        }
        assert!(byte_capacity(usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn eof_probe_retries_interrupted_reads_without_growing_storage() {
        struct Interrupted(bool);
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    Err(ErrorKind::Interrupted.into())
                } else {
                    Ok(0)
                }
            }
        }
        assert!(read_file(&mut Interrupted(false), 0, 0).unwrap().is_empty());
    }
}
