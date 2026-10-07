//! Explicit research policy. Defaults and the production ABI are unchanged.
use super::*;

pub fn enabled() -> bool {
    std::env::var("LATTICA_V2_METAL_PIPELINE").as_deref() == Ok("resident")
}

pub(super) fn validate() -> Result<()> {
    match std::env::var("LATTICA_V2_METAL_PIPELINE").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("reference") => Ok(()),
        Ok("resident") if MemoryMode::from_env()? == MemoryMode::Shared => Ok(()),
        _ => Err("Metal pipeline must be reference or resident (shared storage required)".into()),
    }
}

pub(super) fn workgroup() -> Result<usize> {
    match std::env::var("LATTICA_V2_METAL_WORKGROUP").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("256") => Ok(256),
        Ok("128") => Ok(128),
        _ => Err("Metal workgroup must be 128 or 256".into()),
    }
}

fn choice(name: &str, absent: &str, allowed: &[&str]) -> Result<String> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => absent.to_owned(),
        Err(_) => return Err(format!("{name} must be valid UTF-8")),
    };
    if !allowed.contains(&value.as_str()) {
        return Err(format!("{name} must be one of {}", allowed.join(", ")));
    }
    Ok(value)
}

/// Orthogonal research switches. Absent variables preserve historical policy.
pub(super) struct Tuning {
    pub specialized_diagonal: bool,
    pub ntt_tables: bool,
    pub ntt_tile_log2: usize,
    pub prefix_fusion: bool,
    pub gpu_quotient: bool,
}
impl Tuning {
    pub fn from_env(optimized: bool) -> Result<Self> {
        let tables = choice(
            "LATTICA_V2_METAL_NTT_TABLES",
            "auto",
            &["auto", "off", "on"],
        )?;
        Ok(Self {
            specialized_diagonal: choice(
                "LATTICA_V2_METAL_POSEIDON_DIAGONAL",
                "reference",
                &["reference", "specialized"],
            )? == "specialized",
            ntt_tables: tables == "on" || (tables == "auto" && enabled() && optimized),
            ntt_tile_log2: choice("LATTICA_V2_METAL_NTT_TILE_LOG2", "12", &["10", "11", "12"])?
                .parse()
                .unwrap(),
            prefix_fusion: choice(
                "LATTICA_V2_METAL_PREFIX_STORE",
                "separate",
                &["separate", "fused"],
            )? == "fused",
            gpu_quotient: gpu_quotient()?,
        })
    }
}

pub fn gpu_quotient() -> Result<bool> {
    Ok(
        match choice("LATTICA_V2_METAL_QUOTIENT", "auto", &["auto", "cpu", "gpu"])?.as_str() {
            "gpu" => true,
            "cpu" => false,
            _ => enabled(),
        },
    )
}

/// Owned canonical words, shared by CPU views and Metal dispatches. A view is
/// borrowed only while the serial queue is drained; the owner outlives all
/// dispatches and its budget permit is released only after completion.
pub struct SharedWords {
    buffer: Buffer<u64>,
}
impl SharedWords {
    pub fn new(queue: &Queue, len: usize) -> Result<Self> {
        Ok(Self {
            buffer: Buffer::builder()
                .queue(queue.clone())
                .flags(flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR)
                .len(len)
                .build()?,
        })
    }
    pub fn buffer(&self) -> &Buffer<u64> {
        &self.buffer
    }
    pub fn with_cpu<R>(&self, f: impl FnOnce(&[u64]) -> R) -> Result<R> {
        let _access = self
            .buffer
            .inner
            .queue
            .0
            .operation_lock
            .lock()
            .map_err(|_| "Metal operation poisoned")?;
        self.buffer.inner.queue.finish()?;
        // SAFETY: queue is drained and the operation lock excludes encoding.
        Ok(f(unsafe {
            std::slice::from_raw_parts(
                self.buffer.inner.raw.contents().as_ptr().cast(),
                self.buffer.len,
            )
        }))
    }
    pub fn with_cpu_mut<R>(&mut self, f: impl FnOnce(&mut [u64]) -> R) -> Result<R> {
        let _access = self
            .buffer
            .inner
            .queue
            .0
            .operation_lock
            .lock()
            .map_err(|_| "Metal operation poisoned")?;
        self.buffer.inner.queue.finish()?;
        // SAFETY: exclusive owner access, queue drained, encoding excluded.
        Ok(f(unsafe {
            std::slice::from_raw_parts_mut(
                self.buffer.inner.raw.contents().as_ptr().cast(),
                self.buffer.len,
            )
        }))
    }
}

pub(super) const TABLE_LIMIT: usize = 256 << 20;
#[derive(Default)]
pub(super) struct Tables {
    pub(super) entries: Vec<(Vec<u64>, Buffer<u64>)>,
    pub(super) bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl ProQue {
    /// Space for the current cache plus the tables this operation may create.
    /// Engine reservations account ordinary buffers and transfer staging; these
    /// backend-owned tables must also fit before choosing a maximal query tile.
    pub(crate) fn ntt_cache_reserve(&self, heights: &[usize]) -> Result<usize> {
        if !self.tuning.ntt_tables {
            return Ok(0);
        }
        let tables = self.tables.lock().map_err(|_| "Metal table cache poisoned")?;
        let mut bytes = tables.bytes;
        for &height in heights {
            let required = height
                .checked_mul(2)
                .and_then(|n| n.checked_sub(1))
                .and_then(|n| n.checked_mul(8))
                .ok_or("Metal table reservation overflow")?;
            if required <= TABLE_LIMIT {
                bytes = bytes.saturating_add(required).min(TABLE_LIMIT);
            }
        }
        Ok(bytes)
    }

    /// Stage tables occupy h-1 words, followed by h post-scaling words.
    pub fn ntt_tables(
        &self,
        roots: &Buffer<u64>,
        inverse: bool,
        height: usize,
        c: u64,
        b: u64,
    ) -> Result<Option<Buffer<u64>>> {
        if !self.tuning.ntt_tables || (2 * height - 1) * 8 > TABLE_LIMIT {
            return Ok(None);
        }
        // Private callers upload the fixed Goldilocks two-adic generator chain
        // (or its inverse). Key that immutable definition, not a CPU readback
        // of the roots buffer, which would fence unrelated queued work.
        let key = vec![u64::from(inverse), height as u64, c, b];
        let mut tables = self
            .tables
            .lock()
            .map_err(|_| "Metal table cache poisoned")?;
        if let Some(index) = tables.entries.iter().position(|(k, _)| *k == key) {
            tables.hits += 1;
            let entry = tables.entries.remove(index);
            let result = entry.1.clone();
            tables.entries.push(entry);
            return Ok(Some(result));
        }
        tables.misses += 1;
        let bytes = (2 * height - 1) * 8;
        while tables.bytes + bytes > TABLE_LIMIT {
            let (_, old) = tables.entries.remove(0);
            tables.bytes -= old.len() * 8;
            tables.evictions += 1;
        }
        let out = Buffer::builder()
            .queue(self.queue().clone())
            .len(2 * height - 1)
            .build()?;
        let kernel = self
            .kernel_builder("ntt_tables")
            .arg(roots)
            .arg(&out)
            .arg(height as u32)
            .arg(c)
            .arg(b)
            .global_work_size(height)
            .build()?;
        unsafe {
            kernel.cmd().enq()?;
        }
        tables.bytes += bytes;
        tables.entries.push((key, out.clone()));
        Ok(Some(out))
    }
}

/// Sealed storage: after construction no writer or mutable buffer handle escapes.
pub struct FrozenWords {
    buffer: Buffer<u64>,
}
impl SharedWords {
    pub fn freeze(self) -> Result<FrozenWords> {
        self.buffer.inner.queue.finish()?;
        if Arc::strong_count(&self.buffer.inner) != 1 {
            return Err("cannot freeze aliased Metal storage".into());
        }
        Ok(FrozenWords {
            buffer: self.buffer,
        })
    }
}
impl FrozenWords {
    pub fn words(&self) -> &[u64] {
        // SAFETY: freeze drained all writers; the buffer is private and immutable.
        unsafe {
            std::slice::from_raw_parts(
                self.buffer.inner.raw.contents().as_ptr().cast(),
                self.buffer.len,
            )
        }
    }
    pub fn prefix(&self, len: usize) -> Result<Self> {
        if len == 0 || len > self.buffer.len {
            return Err("invalid frozen prefix".into());
        }
        let out = SharedWords::new(&self.buffer.inner.queue, len)?;
        self.buffer
            .cmd()
            .copy(&out.buffer, Some(0), Some(len))
            .enq()?;
        out.freeze()
    }
}
