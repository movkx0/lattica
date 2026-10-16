//! Allocator observations at quiescent worker boundaries. These counters are
//! not RSS or an admission bound: arenas may retain freed capacity, libc scope
//! is version-dependent, and other threads can allocate during observation.
//! Keep this outside GlobalAlloc; reporting itself uses ordinary allocations.
use serde::Serialize;
use std::sync::OnceLock;

type ReadInfo = unsafe extern "C" fn() -> libc::mallinfo2;
static READER: OnceLock<Option<ReadInfo>> = OnceLock::new();

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    arena_system_bytes: u64,
    mapped_system_bytes: u64,
    reported_system_bytes: u64,
    arena_in_use_bytes: u64,
    arena_free_bytes: u64,
    main_top_releasable_bytes: u64,
    mapped_regions: u64,
}

impl Snapshot {
    fn from_raw(raw: libc::mallinfo2) -> Result<Self, &'static str> {
        let arena = raw.arena as u64;
        let mapped = raw.hblkhd as u64;
        let used = raw.uordblks as u64;
        let free = raw.fordblks as u64;
        if used.checked_add(free) != Some(arena) {
            return Err("inconsistent allocator arena counters");
        }
        Ok(Self {
            arena_system_bytes: arena,
            mapped_system_bytes: mapped,
            reported_system_bytes: arena
                .checked_add(mapped)
                .ok_or("allocator backing overflow")?,
            arena_in_use_bytes: used,
            arena_free_bytes: free,
            main_top_releasable_bytes: raw.keepcost as u64,
            mapped_regions: raw.hblks as u64,
        })
    }

    fn current() -> Result<Self, &'static str> {
        // Optional diagnostics must not raise the runtime's minimum glibc
        // version. Older libc versions need not export mallinfo2 at all.
        let reader = READER
            .get_or_init(|| {
                // SAFETY: the name is NUL-terminated. A non-null result is the
                // GNU mallinfo2 function with the declared C signature.
                let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mallinfo2".as_ptr()) };
                if pointer.is_null() {
                    None
                } else {
                    Some(unsafe { std::mem::transmute::<*mut libc::c_void, ReadInfo>(pointer) })
                }
            })
            .ok_or("glibc mallinfo2 unavailable")?;
        // SAFETY: the resolved function has no arguments and returns an
        // initialized structure. Its per-arena locks do not make the aggregate
        // atomic or establish a bound for future allocations.
        Self::from_raw(unsafe { reader() })
    }
}

pub(crate) fn report(boundary: &str, job_index: u64) {
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() != Ok("1") {
        return;
    }
    let snapshot = Snapshot::current();
    let rust_system_requests = super::system_requests::snapshot();
    eprintln!(
        "native_allocator_snapshot {}",
        serde_json::json!({
            "schema": "lattica-host-allocator-v1", "source": "glibc_mallinfo2",
            "pid": std::process::id(), "boundary": boundary, "job_index": job_index,
            "observation_only": true, "is_rss": false, "admission_bound": false,
            "snapshot": snapshot.as_ref().ok(), "error": snapshot.as_ref().err(),
            "rust_system_requests": rust_system_requests,
            "rust_system_request_budget": super::system_budget::snapshot(),
            "combined_host_request_budget": super::host_budget::snapshot(),
            "rust_system_scope": "SpillAlloc-to-System requests, including explicit heap reservations",
            "rust_system_excludes": "spill mappings, System metadata/retention, foreign allocations and direct runtime mappings",
        })
    );
}

fn startup_decision(
    observed: &Result<Snapshot, &'static str>,
    accounting_valid: bool,
) -> Result<(), &'static str> {
    let snapshot = observed.as_ref().map_err(|error| *error)?;
    if !accounting_valid {
        return Err("invalid Rust System ownership at worker startup");
    }
    if snapshot.reported_system_bytes > crate::host_memory::RETAINED_SYSTEM_HOST_BYTES {
        return Err("cold allocator backing exceeds retained System reservation");
    }
    Ok(())
}

/// Validate current reported backing before admitting more startup ownership.
/// Recheck before thread creation because admission may move between callers.
/// This bounds the observed starting baseline, not later growth or process RSS.
pub(crate) fn admit_worker_startup(boundary: &str) -> Result<(), &'static str> {
    let observed = Snapshot::current();
    let ownership = super::system_requests::snapshot();
    let accounting_valid =
        ownership.accounting_valid && super::host_budget::snapshot().accounting_valid;
    let result = startup_decision(&observed, accounting_valid);
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_allocator_startup {}",
            serde_json::json!({
                "schema": "lattica-allocator-startup-v1", "pid": std::process::id(),
                "boundary": boundary, "limit_bytes": crate::host_memory::RETAINED_SYSTEM_HOST_BYTES,
                "reported_system_bytes": observed.as_ref().ok().map(|s| s.reported_system_bytes),
                "accounting_valid": accounting_valid,
                "allowed": result.is_ok(), "error": result.as_ref().err(),
                "is_rss_bound": false, "is_lifetime_admission": false,
            })
        );
    }
    result
}

/// A warm-reuse gate, not a bound on allocations during the next job or on RSS.
/// Keep the baseline allocator capacity plus explicitly reserved extra caches.
fn reuse_decision(
    observed: &Result<Snapshot, &'static str>,
    accounting_valid: bool,
    worker_bytes: u64,
    extra_cache_bytes: u64,
) -> (Option<u64>, bool) {
    let limit = crate::host_memory::RETAINED_SYSTEM_HOST_BYTES
        .checked_add(extra_cache_bytes)
        .map(|n| n.min(worker_bytes))
        .filter(|n| *n > 0);
    let allowed = accounting_valid
        && limit.is_some_and(|limit| {
            observed
                .as_ref()
                .is_ok_and(|s| s.reported_system_bytes <= limit)
        });
    (limit, allowed)
}

pub(crate) fn worker_reuse_allowed(worker_bytes: u64, extra_cache_bytes: u64) -> bool {
    let observed = Snapshot::current();
    let ownership = super::system_requests::snapshot();
    let accounting_valid =
        ownership.accounting_valid && super::host_budget::snapshot().accounting_valid;
    let (limit, allowed) =
        reuse_decision(&observed, accounting_valid, worker_bytes, extra_cache_bytes);
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_allocator_reuse {}",
            serde_json::json!({
                "schema": "lattica-allocator-reuse-v1", "pid": std::process::id(),
                "limit_bytes": limit, "extra_cache_bytes": extra_cache_bytes,
                "reported_system_bytes": observed.as_ref().ok().map(|s| s.reported_system_bytes),
                "accounting_valid": accounting_valid,
                "allowed": allowed, "error": observed.as_ref().err(),
                "is_rss_bound": false, "is_lifetime_admission": false,
            })
        );
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(arena: usize, used: usize, free: usize, mapped: usize) -> libc::mallinfo2 {
        libc::mallinfo2 {
            arena,
            ordblks: 0,
            smblks: 0,
            hblks: usize::from(mapped > 0),
            hblkhd: mapped,
            usmblks: 0,
            fsmblks: 0,
            uordblks: used,
            fordblks: free,
            keepcost: 0,
        }
    }

    #[test]
    fn cold_start_checks_retained_and_mapped_backing_before_more_ownership() {
        let mib = 1usize << 20;
        let boundary = Snapshot::from_raw(raw(384 * mib, 1, 384 * mib - 1, 128 * mib));
        assert!(startup_decision(&boundary, true).is_ok());
        let over = Snapshot::from_raw(raw(384 * mib, 1, 384 * mib - 1, 128 * mib + 1));
        assert_eq!(
            startup_decision(&over, true),
            Err("cold allocator backing exceeds retained System reservation")
        );
        assert!(startup_decision(&boundary, false).is_err());
        assert!(startup_decision(&Err("unavailable"), true).is_err());
        assert!(startup_decision(&Snapshot::from_raw(raw(100, 10, 89, 0)), true).is_err());
        // Extra future cache capacity can permit warm reuse, but cannot lend
        // its reservation to an already retained, unclassified cold heap.
        assert!(reuse_decision(&over, true, 3 << 30, 1).1);
        assert!(startup_decision(&over, true).is_err());
    }

    #[test]
    fn warm_reuse_checks_total_backing_cache_allowance_and_missing_observations() {
        let mib = 1usize << 20;
        // Both free arena capacity and separately mapped System allocations
        // count; this is not merely the live payload or the free-arena total.
        let sample = Snapshot::from_raw(raw(384 * mib, 256 * mib, 128 * mib, 128 * mib));
        assert_eq!(
            reuse_decision(&sample, true, 3 << 30, 0),
            (Some(512 << 20), true)
        );
        let over = Snapshot::from_raw(raw(384 * mib, 256 * mib, 128 * mib, 128 * mib + 1));
        assert!(!reuse_decision(&over, true, 3 << 30, 0).1);
        assert!(reuse_decision(&over, true, 3 << 30, 1).1);
        assert!(!reuse_decision(&over, true, 512 << 20, 1).1);
        assert!(!reuse_decision(&sample, false, 3 << 30, 0).1);
        assert!(!reuse_decision(&Err("unavailable"), true, 3 << 30, 0).1);
        assert_eq!(reuse_decision(&sample, true, 0, 0), (None, false));
        assert_eq!(
            reuse_decision(&sample, true, 3 << 30, u64::MAX),
            (None, false)
        );
    }

    #[test]
    fn retained_free_arenas_are_part_of_backing_not_live_payload_or_rss() {
        let snapshot = Snapshot::from_raw(raw(1000, 100, 900, 500)).unwrap();
        assert_eq!(snapshot.reported_system_bytes, 1500);
        assert_eq!(snapshot.arena_in_use_bytes, 100);
        assert_eq!(snapshot.arena_free_bytes, 900);
        assert_eq!(snapshot.mapped_regions, 1);
    }

    #[test]
    fn inconsistent_or_overflowing_observations_are_rejected() {
        assert!(Snapshot::from_raw(raw(1000, 100, 899, 0)).is_err());
        assert!(Snapshot::from_raw(raw(usize::MAX, usize::MAX, 1, 0)).is_err());
        if usize::BITS == 64 {
            assert!(Snapshot::from_raw(raw(usize::MAX, usize::MAX, 0, 1)).is_err());
        }
    }

    #[test]
    fn current_observation_does_not_allocate_through_rust() {
        let (snapshot, requests) = super::super::allocation_requests::measure(Snapshot::current);
        assert_eq!(requests.bytes, 0);
        assert_eq!(requests.calls, 0);
        assert!(!requests.overflow);
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                assert_eq!(error, "glibc mallinfo2 unavailable");
                return;
            }
        };
        assert_eq!(
            snapshot.arena_in_use_bytes + snapshot.arena_free_bytes,
            snapshot.arena_system_bytes
        );
    }
}
