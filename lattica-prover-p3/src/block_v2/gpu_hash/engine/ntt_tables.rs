//! Context-owned, bounded public power tables. Keys contain actual root values;
//! a recycled OpenCL buffer address is never an identity. All arithmetic stays
//! on the GPU and a full cache or tight budget falls back to the existing kernel.
use super::*;

pub(super) const MAX_BYTES: usize = 64 << 20;
const SLOTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Key {
    pub roots: [u64; 32],
    pub log_height: u32,
    pub inverse: bool,
    pub stage: usize,
    pub count: usize,
}
impl Key {
    fn words(self) -> Option<usize> {
        if self.count == 0
            || self.count > 12
            || self.log_height > 31
            || self.stage.checked_add(self.count)? > self.log_height as usize
        {
            return None;
        }
        let words = (1usize << (self.count - 1))
            .checked_add((1usize << self.stage).checked_mul(self.count)?)?;
        (words <= MAX_BYTES / 8).then_some(words)
    }
}
struct Entry {
    key: Key,
    allocation: Allocation,
    used: u64,
}
pub(super) struct Cache {
    entries: [Option<Entry>; SLOTS],
    tick: u64,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            tick: 0,
        }
    }
}
impl Cache {
    pub(super) fn bytes(&self) -> usize {
        self.entries
            .iter()
            .flatten()
            .map(|e| e.allocation.buffer.len() * 8)
            .sum()
    }
    fn evict(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e.used)))
            .min_by_key(|(_, used)| *used);
        if let Some((i, _)) = oldest {
            self.entries[i] = None;
            true
        } else {
            false
        }
    }
}
impl Engine {
    pub(super) fn ntt_table(
        &mut self,
        roots: &Buffer<u64>,
        key: Key,
    ) -> Result<Option<Buffer<u64>>, String> {
        let Some(words) = key.words() else {
            return Ok(None);
        };
        let bytes = words * 8;
        if bytes > self.max_alloc {
            return Ok(None);
        }
        self.ntt_tables.tick = self.ntt_tables.tick.saturating_add(1);
        let tick = self.ntt_tables.tick;
        if let Some(entry) = self
            .ntt_tables
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.key == key)
        {
            entry.used = tick;
            return Ok(Some(entry.allocation.buffer.clone()));
        }
        // The previous NTT event is complete before this method is called; no
        // table buffer escapes the current transform launch. Drain on eviction
        // as well to keep this ownership rule safe if timing changes later.
        while self.ntt_tables.bytes() + bytes > MAX_BYTES
            || self.ntt_tables.entries.iter().all(Option::is_some)
            || self
                .accounting
                .lock()
                .unwrap()
                .live
                .checked_add(bytes)
                .is_none_or(|n| n > self.limits.managed_bytes)
        {
            self.fence().finish()?;
            if !self.ntt_tables.evict() {
                return Ok(None);
            }
        }
        let allocation = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            words,
            compute::flags::MEM_READ_WRITE,
        )?;
        let fence = self.fence();
        let mut event = Event::empty();
        // SAFETY: the bounded key indexes only the supplied public root table.
        unsafe {
            self.pq
                .kernel_builder("ntt_fill_table")
                .arg(roots)
                .arg(&allocation.buffer)
                .arg(key.stage as u32)
                .arg(key.count as u32)
                .arg((1u32 << (key.count - 1)) as u32)
                .arg(words as u32)
                .global_work_size(words)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        self.timeline.launch("ntt_fill_table", words, None, bytes);
        self.stats.lde_transform_ns += self.timeline.record("ntt_table_setup", &event)?;
        fence.finish()?;
        let buffer = allocation.buffer.clone();
        *self
            .ntt_tables
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .unwrap() = Some(Entry {
            key,
            allocation,
            used: tick,
        });
        Ok(Some(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_identity_and_capacity_include_roots_direction_and_geometry() {
        let key = Key {
            roots: [1; 32],
            log_height: 23,
            inverse: false,
            stage: 16,
            count: 7,
        };
        assert_eq!(key.words(), Some(64 + 65536 * 7));
        let mut other = key;
        other.roots[6] = 2;
        assert_ne!(key, other);
        let mut other = key;
        other.inverse = true;
        assert_ne!(key, other);
        assert!(Key {
            stage: 30,
            count: 1,
            log_height: 31,
            ..key
        }
        .words()
        .is_none());
        assert!(Key { count: 0, ..key }.words().is_none());
        assert!(Key { stage: 23, ..key }.words().is_none());
        assert_eq!(Cache::default().bytes(), 0);
        assert!(core::mem::size_of::<Cache>() < 32 << 10);
    }

    #[test]
    #[ignore = "requires selected OpenCL GPU; run serially with gpu-tuning"]
    #[cfg(feature = "gpu-tuning")]
    fn gpu_public_ntt_tables_reuse_evict_and_fall_back_under_pressure() {
        use p3_field::{PrimeField64, TwoAdicField};
        let _shutdown = TestShutdownGuard;
        crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 64 << 10,
        })
        .unwrap();
        let mut slot = ENGINE.get().unwrap().lock().unwrap();
        let engine = slot.as_mut().unwrap();
        let roots = std::array::from_fn(|i| Val::two_adic_generator(i + 1).as_canonical_u64());
        let input = allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            32,
            compute::flags::MEM_READ_WRITE,
        )
        .unwrap();
        input.buffer.write(&roots[..]).enq().unwrap();
        let base = engine.accounting.lock().unwrap().live;
        let key = Key {
            roots,
            log_height: 16,
            inverse: false,
            stage: 8,
            count: 8,
        };
        let first = engine.ntt_table(&input.buffer, key).unwrap().unwrap();
        let charged = engine.accounting.lock().unwrap().live;
        let repeated = engine.ntt_table(&input.buffer, key).unwrap().unwrap();
        assert_eq!(charged, engine.accounting.lock().unwrap().live);
        let mut actual = vec![0u64; key.words().unwrap()];
        repeated.read(&mut actual).enq().unwrap();
        let inner = 1 << (key.count - 1);
        for (i, value) in actual.into_iter().enumerate() {
            let (root, power) = if i < inner {
                (roots[key.count - 1], i)
            } else {
                (
                    roots[key.stage + (i - inner) % key.count],
                    (i - inner) / key.count,
                )
            };
            assert_eq!(Val::new(value), Val::new(root).exp_u64(power as u64));
        }
        drop((first, repeated));
        for inverse in [false, true] {
            for log_height in 2..=31 {
                drop(
                    engine
                        .ntt_table(
                            &input.buffer,
                            Key {
                                roots,
                                log_height,
                                inverse,
                                stage: 0,
                                count: 1,
                            },
                        )
                        .unwrap(),
                );
            }
        }
        assert_eq!(engine.ntt_tables.entries.iter().flatten().count(), SLOTS);
        assert!(engine.ntt_tables.bytes() <= MAX_BYTES);
        let old_limit = engine.limits.managed_bytes;
        engine.limits.managed_bytes = base;
        assert!(engine.ntt_table(&input.buffer, key).unwrap().is_none());
        assert_eq!(engine.ntt_tables.bytes(), 0);
        assert_eq!(engine.accounting.lock().unwrap().live, base);
        engine.limits.managed_bytes = old_limit;
        assert!(engine.ntt_table(&input.buffer, key).unwrap().is_some());
    }
}
