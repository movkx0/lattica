//! Backend-independent bounds and byte admission for exact ChaCha20 field sampling.
pub(crate) const STREAM_WORDS: u128 = 1 << 68; // rand_chacha positions count u32 words.
pub(crate) const MAX_OUTPUT_WORDS: usize = 1 << 28;
pub(crate) const BATCH_WORDS: usize = 1 << 20;
// Keep the Rust admission bound within the OpenCL offset scan's local array.
const _: () = assert!(TILE_WORDS == 256 && BATCH_WORDS <= TILE_WORDS * 4096);
pub(crate) const TILE_WORDS: usize = 256;
// Two words per lane for counts/scatter; their local arrays use at most 1 KiB.
// The offset scan has a separate 16 KiB local array plus compiler overhead.
// Fail explicitly instead of letting a faulty/adversarial stream retry forever.
// Rejected words never enter a proof; the complete attempt must be retired.
pub(crate) const MAX_REJECTIONS: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) output_words: usize,
    pub(crate) batch_words: usize,
    pub(crate) raw_words: usize,
    pub(crate) tiles: usize,
    pub(crate) peak_bytes: usize,
}

impl Plan {
    pub(crate) fn new(
        count: usize,
        position: u128,
        live: usize,
        limit: usize,
        max_alloc: usize,
    ) -> Result<Self, String> {
        if count == 0
            || count > MAX_OUTPUT_WORDS
            || position > STREAM_WORDS
            || (count as u128) * 2 > STREAM_WORDS - position
        {
            return Err("GPU random request exceeds bounded stream or output length".into());
        }
        let batch_words = count.min(BATCH_WORDS);
        // A request can start at any u32 position, including an odd word.
        let raw_words = (batch_words * 2 + 15).div_ceil(16) * 8;
        let tiles = batch_words.div_ceil(TILE_WORDS);
        let mut peak_bytes = live;
        for words in [count, raw_words, tiles, tiles, 1] {
            let bytes = words
                .checked_mul(8)
                .ok_or("GPU random allocation overflow")?;
            peak_bytes = peak_bytes
                .checked_add(bytes)
                .ok_or("GPU random live-byte overflow")?;
            if bytes > max_alloc || peak_bytes > limit {
                return Err("GPU random output and scratch exceed admission".into());
            }
        }
        Ok(Self {
            output_words: count,
            batch_words,
            raw_words,
            tiles,
            peak_bytes,
        })
    }
}

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
