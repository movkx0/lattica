//! Resource interpretation shared by the typed CLI and native public service.
//! Uses the existing assignment schema; the runtime must enforce physical caps.
use super::resources::Resources;
use crate::block_v2::recursive::Error;
/// Qualified Linux Rayon stacks. Include both guards and a bounded alternate
/// signal stack. This is separate from allocator, main-thread and driver storage.
pub const RAYON_STACK_BYTES: usize = 2 << 20;
pub const RAYON_STACK_AUX_BYTES: usize = 64 << 10;
pub const RAYON_THREAD_HOST_BYTES: u64 = (RAYON_STACK_BYTES + 3 * RAYON_STACK_AUX_BYTES) as u64;
/// The blocking caller's stack persists through startup, jobs and shutdown.
/// Other caller-owned threads and allocator/driver storage remain separate.
pub const CALLER_STACK_BYTES: usize = 8 << 20;
pub const CALLER_STACK_HOST_BYTES: u64 = (CALLER_STACK_BYTES + 3 * RAYON_STACK_AUX_BYTES) as u64;

pub fn rayon_stack_host_bytes(threads: u32) -> Result<u64, Error> {
    if threads == 0 {
        return Err("Rayon stack reservation requires positive thread count".into());
    }
    RAYON_THREAD_HOST_BYTES
        .checked_mul(u64::from(threads))
        .ok_or_else(|| "Rayon stack reservation overflow".into())
}

/// Ceiling for live/in-flight Rust System requests, including protocol and
/// startup owners. Physical allocator retention and stacks keep their own
/// reservations. This does not bound allocator metadata, drivers or RSS.
pub fn system_request_limit_bytes(worker_bytes: u64, threads: u32) -> Result<u64, Error> {
    worker_bytes
        .checked_sub(rayon_stack_host_bytes(threads)?)
        .and_then(|n| n.checked_sub(CALLER_STACK_HOST_BYTES))
        .and_then(|n| n.checked_sub(crate::host_memory::RETAINED_SYSTEM_HOST_BYTES))
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            "worker RAM cannot admit Rust System requests beside stacks and retention".into()
        })
}

/// Full System + spill request backing shares one ceiling. Reserve the known
/// mapped GPU staging separately; the ceiling is not complete allocator/RSS
/// admission and does not lend nonresident spill capacity to other owners.
pub fn host_request_limit_bytes(worker_bytes: u64, threads: u32) -> Result<u64, Error> {
    system_request_limit_bytes(worker_bytes, threads)?
        .checked_sub(crate::host_memory::GPU_MAPPED_HOST_BYTES)
        .filter(|n| *n > 0)
        .ok_or_else(|| "worker RAM cannot admit combined requests beside mapped staging".into())
}

/// Kernel private writable data envelope, including retained/foreign allocators.
/// Reserve the full spill allowance and mapped staging outside this envelope:
/// file-backed shared mappings need not count against Linux RLIMIT_DATA. Disk
/// backing does not prove those pages stay nonresident. Other shared/read-only
/// mappings, kernel ownership and complete process RSS remain separate.
pub fn private_data_limit_bytes(
    worker_bytes: u64,
    threads: u32,
    spill_bytes: u64,
) -> Result<u64, Error> {
    if spill_bytes == 0 {
        return Err("private data partition requires a positive spill allowance".into());
    }
    worker_bytes
        .checked_sub(rayon_stack_host_bytes(threads)?)
        .and_then(|n| n.checked_sub(CALLER_STACK_HOST_BYTES))
        .and_then(|n| n.checked_sub(spill_bytes))
        .and_then(|n| n.checked_sub(crate::host_memory::GPU_MAPPED_HOST_BYTES))
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            "worker RAM cannot admit private data beside stacks, spill and mapped staging".into()
        })
}

// Kept outside the local-process runtime so a planner can validate assignments
// without Linux IPC or the stream feature. Full process RSS is still separate.
pub(crate) const COORDINATOR_PACKET_BYTES: u64 = 16 << 20;
/// Floor for known shared coordinator owners; not a complete lifetime profile.
/// The fleet also checks its compiled component sum against this reservation.
pub const COORDINATOR_SHARED_BYTES: u64 = 512 << 20;
// Conservatively charge decoding alongside a verifier that also counts its
// already-owned proof. The independent verifier component is source qualified
// for release x86_64; this floor does not qualify other platforms' lifetimes.
pub(crate) const COORDINATOR_JOB_BYTES: u64 = COORDINATOR_PACKET_BYTES
    + crate::block_v2::codec::proofs::INPUT_STORAGE_LIMIT as u64
    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES;

pub(crate) fn admit_coordinator_job(bytes: u64) -> Result<(), Error> {
    if bytes < COORDINATOR_JOB_BYTES {
        return Err("typed coordinator job needs packet, decode and CPU verifier storage".into());
    }
    Ok(())
}

pub fn resources(assignment: &serde_json::Value) -> Result<(Resources, Resources), Error> {
    let number = |group: &str, key: &str| -> Result<u64, Error> {
        assignment[group][key]
            .as_u64()
            .ok_or_else(|| format!("missing typed worker budget {group}.{key}").into())
    };
    let threads = u32::try_from(number("cpu", "rayon_threads")?)?;
    let peak = Resources {
        ram_bytes: number("host", "worker_bytes")?,
        vram_bytes: number("gpu", "managed_bytes")?,
        scratch_bytes: number("host", "spill_bytes")?,
        threads,
    };
    let coordinator_bytes = number("host", "coordinator_bytes")?;
    let shared_bytes = match assignment["host"].get("coordinator_shared_bytes") {
        Some(value) => {
            let bytes = value.as_u64().ok_or("invalid coordinator shared RAM")?;
            if bytes < COORDINATOR_SHARED_BYTES {
                return Err("coordinator shared RAM below known-owner floor".into());
            }
            bytes
        }
        // Existing standalone assignments have no shared fleet partition.
        None => 0,
    };
    let available = coordinator_bytes
        .checked_sub(shared_bytes)
        .ok_or("coordinator shared RAM exceeds physical assignment")?;
    let packet_bytes = match assignment["host"].get("coordinator_job_bytes") {
        Some(value) => value.as_u64().ok_or("invalid coordinator job RAM")?,
        None => available,
    };
    if packet_bytes == 0 || packet_bytes > available {
        return Err("coordinator job RAM exceeds its physical assignment".into());
    }
    let jobs = Resources {
        ram_bytes: packet_bytes,
        vram_bytes: 0,
        scratch_bytes: 0,
        threads,
    };
    peak.validate_capacity()?;
    jobs.validate_capacity()?;
    admit_coordinator_job(jobs.ram_bytes)?;
    if peak.vram_bytes == 0 || peak.scratch_bytes == 0 {
        return Err("typed GPU runtime requires admitted VRAM and spill".into());
    }
    Resources {
        ram_bytes: peak
            .ram_bytes
            .checked_add(jobs.ram_bytes)
            .ok_or("worker RAM overflow")?,
        vram_bytes: peak.vram_bytes,
        scratch_bytes: peak.scratch_bytes,
        threads: peak.threads,
    }
    .validate_capacity()?;
    Ok((peak, jobs))
}

pub(super) fn preprocessing_cache(assignment: &serde_json::Value) -> Result<(usize, u64), Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CacheAdmission {
        entries: usize,
        reserve_bytes: u64,
    }
    let cache = match assignment.get("preprocessing_cache") {
        Some(value) => serde_json::from_value::<CacheAdmission>(value.clone())?,
        None => CacheAdmission {
            entries: 1,
            reserve_bytes: 0,
        },
    };
    Ok((cache.entries, cache.reserve_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn system_request_ceiling_keeps_stacks_and_retention_outside_the_heap() {
        let reserved = rayon_stack_host_bytes(4).unwrap()
            + CALLER_STACK_HOST_BYTES
            + crate::host_memory::RETAINED_SYSTEM_HOST_BYTES;
        for total in [0, reserved - 1, reserved] {
            assert!(system_request_limit_bytes(total, 4).is_err());
        }
        assert!(system_request_limit_bytes(3 << 30, 0).is_err());
        assert_eq!(system_request_limit_bytes(reserved + 1, 4).unwrap(), 1);
        assert_eq!(system_request_limit_bytes(3 << 30, 4).unwrap(), 2666594304);
        assert_eq!(host_request_limit_bytes(3 << 30, 4).unwrap(), 2599485440);
        let mapped = crate::host_memory::GPU_MAPPED_HOST_BYTES;
        assert!(host_request_limit_bytes(reserved + mapped, 4).is_err());
        assert!(host_request_limit_bytes(3 << 30, 0).is_err());
        assert_eq!(
            host_request_limit_bytes(reserved + mapped + 1, 4).unwrap(),
            1
        );
        let spill = 1 << 30;
        assert_eq!(
            private_data_limit_bytes(3 << 30, 4, spill).unwrap(),
            2062614528
        );
        let separate = rayon_stack_host_bytes(4).unwrap()
            + CALLER_STACK_HOST_BYTES
            + spill
            + crate::host_memory::GPU_MAPPED_HOST_BYTES;
        assert!(private_data_limit_bytes(separate, 4, spill).is_err());
        assert!(private_data_limit_bytes(3 << 30, 0, spill).is_err());
        assert!(private_data_limit_bytes(3 << 30, 4, 0).is_err());
        assert!(private_data_limit_bytes(3 << 30, 4, u64::MAX).is_err());
        assert_eq!(private_data_limit_bytes(separate + 1, 4, spill).unwrap(), 1);
        assert_eq!(
            private_data_limit_bytes(3 << 30, 4, spill).unwrap() + separate,
            3 << 30
        );
    }

    #[test]
    fn coordinator_shared_storage_is_subtracted_without_growing_physical_ram() {
        let total = COORDINATOR_SHARED_BYTES + COORDINATOR_JOB_BYTES;
        let base = json!({
            "host": {"worker_bytes": 3u64 << 30, "coordinator_bytes": total,
                "coordinator_shared_bytes": COORDINATOR_SHARED_BYTES,
                "coordinator_job_bytes": COORDINATOR_JOB_BYTES, "spill_bytes": 4u64 << 30},
            "gpu": {"managed_bytes": 1u64 << 30}, "cpu": {"rayon_threads": 4}
        });
        assert_eq!(resources(&base).unwrap().1.ram_bytes, COORDINATOR_JOB_BYTES);
        assert_eq!(base["host"]["coordinator_bytes"], json!(total));
        let mut default_job = base.clone();
        default_job["host"]
            .as_object_mut()
            .unwrap()
            .remove("coordinator_job_bytes");
        assert_eq!(
            resources(&default_job).unwrap().1.ram_bytes,
            COORDINATOR_JOB_BYTES
        );
        for invalid in [
            json!(0),
            json!(COORDINATOR_SHARED_BYTES - 1),
            json!(total + 1),
            json!(-1),
            json!(true),
            json!("536870912"),
            json!(536870912.0),
            serde_json::Value::Null,
        ] {
            let mut bad = base.clone();
            bad["host"]["coordinator_shared_bytes"] = invalid;
            assert!(resources(&bad).is_err());
        }
        let mut overlap = base;
        overlap["host"]["coordinator_job_bytes"] = json!(COORDINATOR_JOB_BYTES + 1);
        assert!(resources(&overlap).is_err());
        assert_eq!(overlap["host"]["coordinator_bytes"], json!(total));
    }

    #[test]
    fn coordinator_assignment_floor_does_not_depend_on_local_process_runtime() {
        let mut assigned = json!({
            "host": {"worker_bytes": 3u64 << 30, "coordinator_bytes": COORDINATOR_JOB_BYTES,
                "coordinator_job_bytes": COORDINATOR_JOB_BYTES, "spill_bytes": 4u64 << 30},
            "gpu": {"managed_bytes": 7u64 << 30}, "cpu": {"rayon_threads": 4}
        });
        assert_eq!(
            resources(&assigned).unwrap().1.ram_bytes,
            COORDINATOR_JOB_BYTES
        );
        assigned["host"]["coordinator_job_bytes"] = json!(COORDINATOR_JOB_BYTES - 1);
        assert!(resources(&assigned).is_err());
        assigned["host"]
            .as_object_mut()
            .unwrap()
            .remove("coordinator_job_bytes");
        assert_eq!(
            resources(&assigned).unwrap().1.ram_bytes,
            COORDINATOR_JOB_BYTES
        );
        assigned["host"]["coordinator_bytes"] = json!(COORDINATOR_JOB_BYTES - 1);
        assert!(resources(&assigned).is_err());
    }
}
