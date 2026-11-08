//! Stack-only batches; the original immutable schedule remains authoritative.
use std::ops::Range;
pub(super) struct Batch {
    pub first: u32,
    pub ends: [u32; 32],
    pub count: usize,
    pub threads: usize,
}
pub(super) fn next(waves: &[Range<usize>], offset: usize) -> Option<Batch> {
    let first = waves.get(offset)?;
    let mut batch = Batch {
        first: first.start.try_into().ok()?,
        ends: [0; 32],
        count: 0,
        threads: 32,
    };
    let mut end = first.start;
    for wave in waves[offset..].iter().take(32) {
        if wave.start != end || wave.is_empty() || wave.len() > 256 {
            break;
        }
        batch.ends[batch.count] = wave.end.try_into().ok()?;
        batch.count += 1;
        batch.threads = batch.threads.max(wave.len().next_power_of_two());
        end = wave.end;
    }
    (batch.count >= 2).then_some(batch)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_boundaries_and_wide_wave_barriers() {
        let waves = [0..4, 4..7, 7..520, 520..521, 521..777, 777..778];
        let b = next(&waves, 0).unwrap();
        assert_eq!((b.first, b.count, b.threads), (0, 2, 32));
        assert_eq!(&b.ends[..2], &[4, 7]);
        assert!(next(&waves, 2).is_none());
        let b = next(&waves, 3).unwrap();
        assert_eq!((b.first, b.count, b.threads), (520, 3, 256));
        assert!(next(&waves, 5).is_none());
        assert!(next(&[0..2, 3..4], 0).is_none());
    }
    #[test]
    fn bounded_tail_and_overflow() {
        let waves: Vec<_> = (0..65).map(|i| i..i + 1).collect();
        assert_eq!(next(&waves, 0).unwrap().count, 32);
        assert_eq!(next(&waves, 32).unwrap().count, 32);
        assert!(next(&waves, 64).is_none());
        assert!(next(&[0..0, 0..1], 0).is_none());
        assert!(next(&[u32::MAX as usize..u32::MAX as usize + 1, 0..1], 0).is_none());
    }
}
