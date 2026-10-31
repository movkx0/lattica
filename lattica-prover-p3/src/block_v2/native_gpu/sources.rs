//! Typed source witness APIs. No entry point accepts a precomputed host trace.
use super::{GeneratedTrace, TraceContext};

pub enum TranscriptPart<'a> {
    Bytes32(&'a [u8; 32]),
    PolynomialQ(&'a [u64; 256]),
    PolynomialQhat(&'a [u64; 256]),
}
struct RawWords(Vec<u64>);
impl Drop for RawWords {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
impl TraceContext<'_> {
    fn source(&self, words: RawWords, geometry: Vec<u64>) -> Result<GeneratedTrace, String> {
        if geometry[1] != self.width as u64
            || geometry[2] != self.rows as u64
            || geometry[3] != self.public_count as u64
        {
            return Err("native source AIR geometry mismatch".into());
        }
        let (trace, public) =
            self.session
                .pq_source_trace(&words.0, &geometry, self.host_allowance, self.run)?;
        Ok(GeneratedTrace { trace, public })
    }
    fn source_host_admit(&self, words: usize, geometry: usize) -> Result<(), String> {
        let bytes = words
            .checked_add(geometry)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(8))
            .ok_or("source input size overflow")?;
        if bytes > self.host_allowance {
            return Err("source input exceeds admitted host allowance".into());
        }
        Ok(())
    }
    pub fn statement_source(
        &self,
        bytes: &[u8],
        setup_seed: &[u8; 32],
    ) -> Result<GeneratedTrace, String> {
        if bytes.len() != 202848 {
            return Err("statement source length".into());
        }
        self.source_host_admit(50713, 12)?;
        let mut raw = RawWords(Vec::with_capacity(50713));
        raw.0.push(bytes.len() as u64);
        raw.0.extend(
            bytes
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
        );
        let mut geometry = vec![0, 496, 16384, 8];
        geometry.extend(
            setup_seed
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
        );
        self.source(raw, geometry)
    }
    pub fn private_source(
        &self,
        polynomials: &[[i64; 256]],
        alpha: &[u8; 32],
    ) -> Result<GeneratedTrace, String> {
        if polynomials.len() != 91 {
            return Err("private source polynomial count".into());
        }
        self.source_host_admit(23304, 4)?;
        let mut words = RawWords(Vec::with_capacity(23304));
        for (p, values) in polynomials.iter().enumerate() {
            let offset = match p {
                0..=11 => 0,
                12 => 1,
                13..=61 | 73..=82 => 38346,
                62..=72 => 565,
                _ => 6212586,
            };
            for &v in values {
                words.0.push(
                    v.checked_add(offset)
                        .and_then(|x| u32::try_from(x).ok())
                        .ok_or("private source coefficient encoding")? as u64,
                );
            }
        }
        words.0.extend(
            alpha
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
        );
        self.source(words, vec![1, 469, 8192, 4])
    }
    pub fn transcript_source(
        &self,
        parts: &[TranscriptPart<'_>],
    ) -> Result<GeneratedTrace, String> {
        if parts.is_empty() || parts.len() > 256 {
            return Err("transcript source count".into());
        }
        self.source_host_admit(parts.len() * 256, 8 + 2 * parts.len())?;
        let kinds: Vec<u64> = parts
            .iter()
            .map(|p| match p {
                TranscriptPart::Bytes32(_) => 0,
                TranscriptPart::PolynomialQ(_) => 1,
                TranscriptPart::PolynomialQhat(_) => 2,
            })
            .collect();
        let events: Vec<u64> = (0..parts.len())
            .filter(|&i| kinds.get(i + 1).copied().unwrap_or(3) != kinds[i])
            .map(|i| i as u64)
            .collect();
        let bytes: usize = parts
            .iter()
            .map(|p| {
                if matches!(p, TranscriptPart::Bytes32(_)) {
                    32
                } else {
                    1024
                }
            })
            .sum();
        let mut words = RawWords(vec![0; parts.len() * 256]);
        for (p, part) in parts.iter().enumerate() {
            match part {
                TranscriptPart::Bytes32(b) => {
                    for (j, c) in b.chunks_exact(4).enumerate() {
                        words.0[p * 256 + j] = u32::from_le_bytes(c.try_into().unwrap()) as u64;
                    }
                }
                TranscriptPart::PolynomialQ(v) | TranscriptPart::PolynomialQhat(v) => {
                    for (j, &x) in v.iter().enumerate() {
                        words.0[p * 256 + j] =
                            u32::try_from(x).map_err(|_| "transcript u32 encoding")? as u64;
                    }
                }
            }
        }
        let mut geometry = vec![
            2,
            (383 + 2 * events.len()) as u64,
            (parts.len().next_power_of_two() * 128) as u64,
            8,
            parts.len() as u64,
            events.len() as u64,
            bytes as u64,
            0,
        ];
        geometry.extend(kinds);
        geometry.extend(events);
        self.source(words, geometry)
    }
}
