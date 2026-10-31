//! Complete fresh-stream cursor bounds for the fixed quadratic note profile.
//! Replayed salts use a private cursor and never advance any of these streams.
use super::{Error, Geometry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct StreamBounds {
    pub requests: usize,
    pub field_words: u128,
    pub maximum_u32_words: u128,
}

impl StreamBounds {
    fn requests(requests: &[usize]) -> Result<Self, Error> {
        let mut result = Self { requests: requests.len(), field_words: 0, maximum_u32_words: 0 };
        for &count in requests {
            if count == 0 || count > crate::gpu_random::MAX_OUTPUT_WORDS {
                return Err(Error::Randomness);
            }
            result.field_words = result.field_words.checked_add(count as u128).ok_or(Error::Overflow)?;
            // One Goldilocks candidate consumes two u32 words. The runtime
            // checks the rejection ceiling independently for EVERY request.
            let request = (count as u128)
                .checked_add(crate::gpu_random::MAX_REJECTIONS as u128)
                .and_then(|n| n.checked_mul(2)).ok_or(Error::Overflow)?;
            result.maximum_u32_words = result.maximum_u32_words.checked_add(request).ok_or(Error::Overflow)?;
        }
        result.admit_start(0)?;
        Ok(result)
    }

    fn admit_start(self, initial: u128) -> Result<u128, Error> {
        initial.checked_add(self.maximum_u32_words)
            .filter(|end| *end <= crate::gpu_random::STREAM_WORDS)
            .ok_or(Error::Randomness)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RandomnessBounds {
    pub hiding: StreamBounds,
    pub quotient: StreamBounds,
    pub original_salts: StreamBounds,
    pub fri_salts: StreamBounds,
    pub initial_u32_position: u128,
    pub fri_log_arities: [usize; 4],
    pub fri_log_heights: [usize; 4],
}

impl RandomnessBounds {
    pub(super) fn new(g: Geometry) -> Result<Self, Error> {
        g.check()?;
        let h = g.rows;
        let hidden = 2 * h;
        let n = hidden << g.log_blowup;
        let hiding = StreamBounds::requests(&[
            h * (g.width + 2 * g.random_codewords),
            hidden * (g.extension_degree + g.random_codewords),
        ])?;
        let quotient = StreamBounds::requests(&[
            h * g.quotient_chunks * g.random_codewords,
            h * (g.extension_degree + g.random_codewords) * (g.quotient_chunks - 1),
        ])?;
        let original_salts = StreamBounds::requests(&[n * 4; 18])?;
        let mut arities = [0; 4];
        let mut heights = [0; 4];
        let mut requests = [0; 4];
        let mut height = n.ilog2() as usize;
        for i in 0..4 {
            let arity = p3_fri::compute_log_arity_for_round(height, None, g.log_blowup, g.max_log_arity);
            if !(1..=4).contains(&arity) { return Err(Error::Geometry); }
            height = height.checked_sub(arity).ok_or(Error::Geometry)?;
            arities[i] = arity;
            heights[i] = height;
            requests[i] = (1usize << height) * 4;
        }
        if height != g.log_blowup || arities != [4, 4, 4, 1] || heights != [13, 9, 5, 4] {
            return Err(Error::Geometry);
        }
        Ok(Self {
            hiding, quotient, original_salts,
            fri_salts: StreamBounds::requests(&requests)?,
            initial_u32_position: 0, fri_log_arities: arities, fri_log_heights: heights,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fresh_request_includes_its_own_rejection_allowance() {
        let bounds = RandomnessBounds::new(Geometry::pinned().unwrap()).unwrap();
        assert_eq!(bounds.hiding.maximum_u32_words, 323_584);
        assert_eq!(bounds.quotient.maximum_u32_words, 1_265_664);
        assert_eq!(bounds.original_salts.maximum_u32_words, 18_911_232);
        assert_eq!(bounds.fri_salts.maximum_u32_words, 78_208);
        assert_eq!(bounds.original_salts.requests, 18);
        assert_eq!(bounds.fri_salts.requests, 4);
        for stream in [bounds.hiding, bounds.quotient, bounds.original_salts, bounds.fri_salts] {
            assert_eq!(stream.maximum_u32_words, 2 * (stream.field_words + stream.requests as u128 * 1024));
            let last = crate::gpu_random::STREAM_WORDS - stream.maximum_u32_words;
            assert_eq!(stream.admit_start(last).unwrap(), crate::gpu_random::STREAM_WORDS);
            assert_eq!(stream.admit_start(last + 1), Err(Error::Randomness));
            assert_eq!(stream.admit_start(u128::MAX), Err(Error::Randomness));
        }
    }

    #[test]
    fn stream_plan_has_no_allocation_or_entropy_side_effects() {
        let (bounds, census) = crate::spill_alloc::allocation_requests::measure(|| {
            RandomnessBounds::new(Geometry::pinned().unwrap()).unwrap()
        });
        assert_eq!(census.calls, 0);
        assert!(!census.overflow);
        assert_eq!(bounds.initial_u32_position, 0);
        assert_eq!(StreamBounds::requests(&[0]), Err(Error::Randomness));
    }
}
