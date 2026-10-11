//! Resource interpretation shared by the typed CLI and native public service.
//! Uses the existing assignment schema; the runtime must enforce physical caps.
use super::resources::Resources;
use crate::block_v2::recursive::Error;

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
