//! Shared allocation-free admission for ordered random draws and salt replay.
//! Stream positions are minimum consumption: runtime still checks rejections,
//! exhaustion and poisoned cursors under its existing locks.
use super::Plan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldStoragePlan {
    pub(crate) requests: usize,
    pub(crate) largest_request_words: usize,
    pub(crate) retained_output_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) max_allocation_bytes: usize,
    pub(crate) minimum_end_position: u128,
}

impl FieldStoragePlan {
    pub(crate) fn new(
        requests: impl ExactSizeIterator<Item = usize>,
        pending: &[usize],
        retain_outputs: bool,
        mut position: u128,
        mut live: usize,
        limit: usize,
        max_alloc: usize,
    ) -> Result<Self, String> {
        let count = requests.len();
        if count == 0 || count > 512 {
            return Err("GPU random batch requires 1..512 requests".into());
        }
        let mut largest = 0;
        for &bytes in pending {
            live = live
                .checked_add(bytes)
                .ok_or("GPU random pending allocation overflow")?;
            if bytes > max_alloc || live > limit {
                return Err("GPU random pending inputs exceed admission".into());
            }
            largest = largest.max(bytes);
        }
        let mut result = Self {
            requests: count,
            largest_request_words: 0,
            retained_output_bytes: 0,
            peak_bytes: live,
            max_allocation_bytes: largest,
            minimum_end_position: position,
        };
        for words in requests {
            let plan = Plan::new(words, position, live, limit, max_alloc)?;
            result.peak_bytes = result.peak_bytes.max(plan.peak_bytes);
            result.largest_request_words = result.largest_request_words.max(words);
            // These are the sampler's five separately allocated buffers.
            for size in [plan.output_words, plan.raw_words, plan.tiles, plan.tiles, 1] {
                result.max_allocation_bytes = result.max_allocation_bytes.max(size * 8);
            }
            if retain_outputs {
                live = live
                    .checked_add(words * 8)
                    .ok_or("GPU random batch output overflow")?;
                result.retained_output_bytes = result
                    .retained_output_bytes
                    .checked_add(words * 8)
                    .ok_or("GPU random retained output overflow")?;
            }
            position = position
                .checked_add(words as u128 * 2)
                .ok_or("GPU random batch cursor overflow")?;
        }
        result.minimum_end_position = position;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
