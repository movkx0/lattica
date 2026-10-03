//! Phase 2 of the streaming-prover plan: an **out-of-core global allocator** that spills large
//! allocations (the trace / quotient / Merkle LDE buffers) to a memory-mapped file on NVMe, so the
//! prover's peak RSS is bounded by page-cache pressure (a cgroup `memory.high`) instead of the whole
//! multi-hundred-GB LDE living in RAM.
//!
//! # Byte-identity (the non-negotiable invariant)
//! BYTE-IDENTICAL BY CONSTRUCTION. A `Vec` backed by `mmap(MAP_SHARED)` has the exact same observable
//! contents, length, and iteration order as a malloc-backed `Vec` — only the *physical pages* differ,
//! and the kernel writes dirty pages back to the backing file under memory pressure. The proof depends
//! only on the field values, never on their address, so `prove` under this allocator yields the same
//! `Proof` bytes as under the system allocator (asserted by `spill_prove_byte_identical`).
//!
//! # No reentrancy
//! The spill path (`alloc_big`/`dealloc`) uses only raw libc syscalls (`open`/`ftruncate`/`mmap`/…) and
//! a stack path buffer — it never touches the Rust heap, so it can't recurse into this allocator. The
//! hot path (`size < THRESHOLD`) is a single const compare + delegate to `System`, and never calls
//! `cfg()` (whose one-time init allocates a small `String` for the env lookup — which routes to `System`
//! precisely because it is below `THRESHOLD`).
//!
//! # Deterministic free
//! Every `>= THRESHOLD` allocation carries a one-page header (`magic | fd | total_len`) *before* the
//! returned pointer, so `dealloc` disambiguates the mmap vs system path purely from `layout.size()` —
//! correct regardless of whether the arming window has since closed.
//!
//! # Measured behavior (the Fork Decision)
//! This allocator is byte-correct and, with RAM to spare, adds only modest overhead (a full 64-tx batch
//! proves in ~47 s vs ~57 s baseline, spilling 16.4 GiB through mmap and verifying). BUT it does NOT
//! deliver a low-RAM floor under pressure: under a cgroup below the working set it THRASHES — a 14 GiB
//! cap against a 17 GiB working set failed to complete in 220 s, while the backing NVMe measures
//! 2.7 GiB/s. The cause is reclaim churn, not I/O: p3 re-touches whole stage buffers (trace LDE → quotient
//! eval → Merkle → FRI), and the OS — which cannot see that access pattern from below the `Vec` types —
//! evicts pages it immediately needs back. This is the streaming-prover plan's Fork Decision bar #1,
//! confirmed empirically; the deterministic low-RAM floor needs the Phase 3 fork (frontier Merkle keeping
//! only digests resident + seek-based query reads + controlled buffer lifetimes), which this cannot do.
//!
//! Feature-gated (`stream`, off by default) and installed as the `#[global_allocator]` only in stream
//! builds; the production staticlib and the 10 frozen externs never see it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// mmap/allocation page granularity. All spill mappings are page-aligned, so the returned pointer
/// (`base + PAGE`) satisfies any alignment up to `PAGE`; larger alignments fall through to `System`.
const PAGE: usize = 4096;

/// Only allocations at least this large are candidates for spilling — chosen so that only the prover's
/// big LDE/quotient/Merkle buffers qualify, while the verifier, the 10 frozen externs, and all
/// incidental small allocations pass straight through to `System` untouched.
const THRESHOLD: usize = 64 << 20; // 64 MiB

// Header magics (written at the base of every >= THRESHOLD allocation, before the returned pointer).
const MAGIC_MMAP: u64 = 0x4C41545F53504C4D; // "LAT_SPLM" — mmap(MAP_SHARED) file-backed
const MAGIC_SYS: u64 = 0x4C41545F53504C53; //  "LAT_SPLS" — System.alloc (disarmed, or mmap failed)

/// Depth counter: spilling is active while `> 0`. A global (not thread-local) so allocations on rayon
/// worker threads inside `prove` also spill; nesting is supported so overlapping `SpillScope`s compose.
static ARMED: AtomicUsize = AtomicUsize::new(0);
/// Per-process monotonic spill-file discriminator (with the pid) — atomic, no heap.
static COUNTER: AtomicU64 = AtomicU64::new(0);
/// Diagnostics: number and total byte size of live mmap spills, plus the high-water mark (for
/// benches/tests — the big buffers are freed inside `prove` before it returns, so `live` reads ~0 after).
static MMAP_COUNT: AtomicU64 = AtomicU64::new(0);
static MMAP_BYTES: AtomicU64 = AtomicU64::new(0);
static MMAP_PEAK: AtomicU64 = AtomicU64::new(0);

/// Cached spill configuration — the scratch directory, resolved once. Init runs outside the big-alloc
/// path (from `SpillScope::arm`, or the first spill candidate), so its small internal allocations route
/// to `System` and never re-enter this `OnceLock`.
struct Cfg {
    dir: [u8; 256],
    dir_len: usize,
    // Benchmark portability: anonymous RAM mappings substitute for Linux tmpfs.
    // Explicit opt-in; the existing file-backed streaming path remains the default.
    memory_backed: bool,
    // Opt-in ceiling for controlled research jobs. A configured spill failure
    // must fail closed rather than silently falling back to heap allocation.
    max_bytes: Option<u64>,
}
static CFG: OnceLock<Cfg> = OnceLock::new();

fn cfg() -> &'static Cfg {
    CFG.get_or_init(|| {
        let dir = std::env::var("LATTICA_SPILL_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned());
        let bytes = dir.as_bytes();
        let n = bytes.len().min(255);
        let mut buf = [0u8; 256];
        buf[..n].copy_from_slice(&bytes[..n]);
        Cfg {
            dir: buf,
            dir_len: n,
            memory_backed: match std::env::var("LATTICA_SPILL_BACKING").as_deref() {
                Err(std::env::VarError::NotPresent) | Ok("file") => false,
                Ok("memory") => true,
                _ => panic!("LATTICA_SPILL_BACKING must be file or memory"),
            },
            max_bytes: std::env::var("LATTICA_SPILL_MAX_BYTES")
                .ok()
                .map(|v| v.parse().unwrap_or(0)),
        }
    })
}

/// Append the decimal ASCII of `v` into `buf` at `p`; returns the new offset. No heap.
fn put_u64(buf: &mut [u8], p: usize, v: u64) -> usize {
    if v == 0 {
        buf[p] = b'0';
        return p + 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 20;
    let mut n = v;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = 20 - i;
    buf[p..p + len].copy_from_slice(&tmp[i..]);
    p + len
}

/// Open + unlink + size + map a fresh spill file of `total` bytes; `MAP_SHARED` so dirty pages write
/// back to the file (freeing RAM under pressure). Returns `(base, fd)`, or `None` on any failure (the
/// caller falls back to a `System` allocation, so a full/absent scratch dir degrades gracefully). No
/// heap: the path is built in a stack buffer.
unsafe fn map_file(total: usize) -> Option<(*mut u8, i64)> {
    let c = cfg();
    if c.memory_backed {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        return (addr != libc::MAP_FAILED).then_some((addr as *mut u8, -1));
    }
    let mut path = [0u8; 384];
    let mut p = c.dir_len.min(path.len());
    path[..p].copy_from_slice(&c.dir[..p]);
    for &b in b"/lat-spill-" {
        path[p] = b;
        p += 1;
    }
    p = put_u64(&mut path, p, libc::getpid() as u64);
    path[p] = b'-';
    p += 1;
    p = put_u64(&mut path, p, COUNTER.fetch_add(1, Ordering::Relaxed));
    for &b in b".tmp\0" {
        path[p] = b;
        p += 1;
    }
    let cpath = path.as_ptr() as *const libc::c_char;
    let fd = libc::open(cpath, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600);
    if fd < 0 {
        return None;
    }
    // Immediately unlink: the mapping keeps the inode alive, and the file is reclaimed on close/crash.
    libc::unlink(cpath);
    if libc::ftruncate(fd, total as libc::off_t) != 0 {
        libc::close(fd);
        return None;
    }
    let addr = libc::mmap(
        std::ptr::null_mut(),
        total,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if addr == libc::MAP_FAILED {
        libc::close(fd);
        return None;
    }
    Some((addr as *mut u8, fd as i64))
}

#[inline]
unsafe fn write_hdr(base: *mut u8, magic: u64, fd: i64, total: u64) {
    let h = base as *mut u64;
    h.write(magic);
    h.add(1).write(fd as u64);
    h.add(2).write(total);
}

#[inline]
unsafe fn read_hdr(base: *const u8) -> (u64, i64, u64) {
    let h = base as *const u64;
    (h.read(), h.add(1).read() as i64, h.add(2).read())
}

/// The out-of-core global allocator. See the module docs.
pub struct SpillAlloc;

/// Explicit heap workspace for bounded, repeatedly modified temporary buffers.
/// Unlike disarming the allocator, this does not affect any other allocation or
/// thread. The normal allocator can free the returned Vec after its scope ends.
/// This is not a mapping-failure fallback. Callers still need a process RAM cap.
#[cfg(any(feature = "block-v2", test))]
pub(crate) fn copy_to_heap<T: Copy>(source: &[T], byte_limit: usize) -> Option<Vec<T>> {
    let mut values = heap_with_capacity(source.len(), byte_limit)?;
    values.extend_from_slice(source);
    Some(values)
}

/// Explicit bounded heap storage, including while spilling is armed. The caller
/// owns initialization and must account for retained buffers in its host/RSS
/// budget. This never retries a failed mapped allocation on the heap.
#[cfg(any(feature = "block-v2", test))]
pub(crate) fn heap_with_capacity<T>(capacity: usize, byte_limit: usize) -> Option<Vec<T>> {
    const MAX_WORKSPACE: usize = 2 << 30;
    let layout = Layout::array::<T>(capacity).ok()?;
    if byte_limit > MAX_WORKSPACE || layout.size() > byte_limit {
        return None;
    }
    if layout.size() < THRESHOLD || layout.align() > PAGE {
        // These allocations already take the direct System path, even armed.
        let mut values = Vec::new();
        values.try_reserve_exact(capacity).ok()?;
        return Some(values);
    }
    let payload = layout.size().checked_add(PAGE - 1)? & !(PAGE - 1);
    let total = payload.checked_add(PAGE)?;
    let system_layout = Layout::from_size_align(total, PAGE).ok()?;
    // SAFETY: the allocation has the exact header layout expected by SpillAlloc
    // for this Vec's capacity/alignment. Length is zero, so no uninitialized
    // element is exposed or dropped. Ownership moves to Vec exactly once.
    unsafe {
        let base = System.alloc(system_layout);
        if base.is_null() {
            return None;
        }
        write_hdr(base, MAGIC_SYS, -1, total as u64);
        let data = base.add(PAGE).cast::<T>();
        Some(Vec::from_raw_parts(data, 0, capacity))
    }
}

impl SpillAlloc {
    /// Cold path for `>= THRESHOLD` allocations: an mmap-backed block if armed (else a `System` block),
    /// each carrying a one-page header before the returned (page-aligned) payload pointer.
    #[inline(never)]
    unsafe fn alloc_big(&self, layout: Layout) -> *mut u8 {
        let payload = (layout.size() + PAGE - 1) & !(PAGE - 1);
        let total = PAGE + payload;
        if ARMED.load(Ordering::Relaxed) > 0 {
            let limit = cfg().max_bytes;
            if MMAP_BYTES
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |live| {
                    live.checked_add(total as u64)
                        .filter(|&next| next <= limit.unwrap_or(u64::MAX))
                })
                .is_err()
            {
                return std::ptr::null_mut();
            }
            if let Some((base, fd)) = map_file(total) {
                write_hdr(base, MAGIC_MMAP, fd, total as u64);
                MMAP_COUNT.fetch_add(1, Ordering::Relaxed);
                let live = MMAP_BYTES.load(Ordering::Relaxed);
                MMAP_PEAK.fetch_max(live, Ordering::Relaxed);
                return base.add(PAGE);
            }
            MMAP_BYTES.fetch_sub(total as u64, Ordering::Relaxed);
            if limit.is_some() {
                return std::ptr::null_mut();
            }
            // mmap failed (e.g. scratch full) → fall through to a plain in-RAM System block.
        }
        let Ok(l) = Layout::from_size_align(total, PAGE) else {
            return System.alloc(layout);
        };
        let base = System.alloc(l);
        if base.is_null() {
            return base;
        }
        write_hdr(base, MAGIC_SYS, -1, total as u64);
        base.add(PAGE)
    }
}

// SAFETY: `SpillAlloc` holds no state; the spill path uses only syscalls + stack memory, so it never
// re-enters the allocator; the header scheme makes `dealloc` mirror `alloc` deterministically.
unsafe impl GlobalAlloc for SpillAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() < THRESHOLD || layout.align() > PAGE {
            return System.alloc(layout); // hot path: no cfg(), no atomics
        }
        self.alloc_big(layout)
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() < THRESHOLD || layout.align() > PAGE {
            return System.dealloc(ptr, layout);
        }
        let base = ptr.sub(PAGE);
        let (magic, fd, total) = read_hdr(base);
        match magic {
            MAGIC_MMAP => {
                libc::munmap(base as *mut libc::c_void, total as usize);
                if fd >= 0 {
                    libc::close(fd as libc::c_int);
                }
                MMAP_COUNT.fetch_sub(1, Ordering::Relaxed);
                MMAP_BYTES.fetch_sub(total, Ordering::Relaxed);
            }
            MAGIC_SYS => {
                System.dealloc(
                    base,
                    Layout::from_size_align_unchecked(total as usize, PAGE),
                );
            }
            // Should be unreachable (every >= THRESHOLD alloc writes a header); fall back rather than UB.
            _ => System.dealloc(ptr, layout),
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() < THRESHOLD || layout.align() > PAGE {
            return System.alloc_zeroed(layout); // calloc for small allocs
        }
        let ptr = self.alloc_big(layout);
        if ptr.is_null() {
            return ptr;
        }
        let (magic, _, _) = read_hdr(ptr.sub(PAGE));
        if magic == MAGIC_SYS {
            // System.alloc leaves the payload uninitialized; the zeroing contract requires a memset.
            std::ptr::write_bytes(ptr, 0, layout.size());
        }
        // MMAP path: a fresh `ftruncate`'d file reads as zero — skip the memset so the (often huge,
        // e.g. the quotient `zero_vec`) pages stay lazy instead of all faulting in eagerly.
        ptr
    }
}

/// RAII arming guard: spilling is active for the lifetime of the returned scope (and any nested ones).
/// Bracket the aggregator/batch `prove(...)` call with `let _g = SpillScope::arm();` so only proving
/// spills — the verifier and the 10 frozen externs never do.
pub struct SpillScope {
    _priv: (),
}

impl SpillScope {
    /// Arm spilling. Initializes the (heap-touching) config *before* incrementing the counter, so the
    /// init runs outside any armed big-alloc window.
    pub fn arm() -> Self {
        let _ = cfg();
        ARMED.fetch_add(1, Ordering::SeqCst);
        SpillScope { _priv: () }
    }
}

impl Drop for SpillScope {
    fn drop(&mut self) {
        ARMED.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `true` while spilling is armed.
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Relaxed) > 0
}

/// `(live mmap spill count, live mmap spill bytes)` — for benches/tests to confirm spilling engaged.
pub fn spill_stats() -> (u64, u64) {
    (
        MMAP_COUNT.load(Ordering::Relaxed),
        MMAP_BYTES.load(Ordering::Relaxed),
    )
}

/// High-water mark of concurrently-mapped spill bytes since the last reset — the real "how much did we
/// keep off the heap" figure (live bytes read ~0 after `prove` frees its buffers).
pub fn spill_peak_bytes() -> u64 {
    MMAP_PEAK.load(Ordering::Relaxed)
}

/// Reset the peak high-water mark (call before a measured prove).
pub fn reset_spill_peak() {
    MMAP_PEAK.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_heap_copy_preserves_ownership_without_disarming_other_allocations() {
        let scope = SpillScope::arm();
        let n = THRESHOLD / core::mem::size_of::<u64>();
        let source: Vec<u64> = (0..n as u64).collect();
        let mut copied = copy_to_heap(&source, THRESHOLD).unwrap();
        assert_eq!(source, copied);
        unsafe {
            assert_eq!(
                read_hdr(copied.as_ptr().cast::<u8>().sub(PAGE)).0,
                MAGIC_SYS
            );
        }
        let another: Vec<u64> = vec![7; n];
        unsafe {
            assert_eq!(
                read_hdr(another.as_ptr().cast::<u8>().sub(PAGE)).0,
                MAGIC_MMAP
            );
        }
        assert!(copy_to_heap(&source, THRESHOLD - 1).is_none());
        assert!(copy_to_heap(&[1u8], (2 << 30) + 1).is_none());
        drop(scope);
        copied[0] = 91;
        assert_eq!(source[0], 0);
        // Growing and dropping the explicitly owned Vec uses the normal global
        // allocator/header machinery; no special caller-side free is needed.
        copied.push(93);
        assert_eq!(copied[n], 93);
        drop((source, copied, another));
        assert_eq!(copy_to_heap(&[(); 4], 0).unwrap().len(), 4);
    }

    #[test]
    fn spill_budget_is_enforced_in_subprocess() {
        const FLAG: &str = "LATTICA_SPILL_BUDGET_TEST";
        if let Ok(mode) = std::env::var(FLAG) {
            let _scope = SpillScope::arm();
            let layout = Layout::from_size_align(THRESHOLD, PAGE).unwrap();
            let allocator = SpillAlloc;
            unsafe {
                let first = allocator.alloc(layout);
                if mode != "budget" {
                    assert!(first.is_null());
                    assert_eq!(spill_stats(), (0, 0));
                    return;
                }
                assert!(!first.is_null());
                assert_eq!(spill_stats(), (1, (THRESHOLD + PAGE) as u64));
                assert!(allocator.alloc(layout).is_null());
                assert_eq!(spill_stats(), (1, (THRESHOLD + PAGE) as u64));
                allocator.dealloc(first, layout);
                assert_eq!(spill_stats(), (0, 0));
                let again = allocator.alloc(layout);
                assert!(!again.is_null());
                allocator.dealloc(again, layout);
                assert_eq!(spill_stats(), (0, 0));
            }
            return;
        }
        for mode in ["budget", "invalid", "failed_mapping"] {
            let executable = std::env::current_exe().unwrap();
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "spill_alloc::tests::spill_budget_is_enforced_in_subprocess",
                    "--test-threads=1",
                ])
                .env(FLAG, mode)
                .env(
                    "LATTICA_SPILL_MAX_BYTES",
                    if mode == "invalid" {
                        "invalid".to_string()
                    } else {
                        (THRESHOLD + PAGE).to_string()
                    },
                );
            if mode == "failed_mapping" {
                command.env("LATTICA_SPILL_BACKING", "file");
                command.env("LATTICA_SPILL_DIR", executable.join("not-a-directory"));
            }
            assert!(command.status().unwrap().success(), "mode={mode}");
        }
    }

    /// The allocator round-trips large armed (mmap) and unarmed (system-with-header) allocations without
    /// corruption, and spilling actually engages while armed.
    #[test]
    fn spill_roundtrip_armed_and_unarmed() {
        // unarmed: a >= THRESHOLD Vec still allocates/frees correctly (system-with-header path)
        {
            let n = (THRESHOLD / 8) + 4096; // > THRESHOLD bytes of u64
            let mut v: Vec<u64> = (0..n as u64).collect();
            v.iter_mut().for_each(|x| *x = x.wrapping_mul(3));
            assert_eq!(v[n - 1], (n as u64 - 1).wrapping_mul(3));
        }
        // armed: the same allocation spills to mmap; stats show a live spill during its lifetime
        {
            let _g = SpillScope::arm();
            let n = (THRESHOLD / 8) + 4096;
            let v: Vec<u64> = (0..n as u64).collect();
            let (count, bytes) = spill_stats();
            assert!(
                count >= 1,
                "an armed >= THRESHOLD alloc must spill to mmap (count={count})"
            );
            assert!(
                bytes as usize >= n * 8,
                "spill bytes {bytes} should cover the {n}-u64 buffer"
            );
            assert_eq!(v[123], 123); // contents intact through the mmap backing
            drop(v);
        }
        // NB: no assertion on the *global* `is_armed()` here — `ARMED` is process-global, so a parallel
        // prove test (which arms via `proof_to_bytes`) can hold it set; correctness never depends on it
        // (dealloc keys off the per-allocation header, not the arm state).
    }

    /// A zeroed large allocation is actually zero on the mmap path (fresh ftruncate'd file), so
    /// `alloc_zeroed`'s memset skip is sound.
    #[test]
    fn spill_alloc_zeroed_is_zero() {
        let _g = SpillScope::arm();
        let n = (THRESHOLD / 8) + 4096;
        let v: Vec<u64> = vec![0u64; n]; // hits alloc_zeroed
        assert!(
            v.iter().all(|&x| x == 0),
            "mmap-backed zeroed alloc must read as zero"
        );
    }
}
