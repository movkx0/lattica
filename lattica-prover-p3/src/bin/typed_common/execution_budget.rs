//! Trusted runtime limits shared by proving and CPU recovery. Never read these
//! limits from a checkpoint; the host supplies the independently pinned budget.
use super::*;

pub(super) const ARTIFACT_BYTES: u64 = 256 << 20;
pub(super) const ARTIFACT_ENTRIES: usize = 512;
pub(super) const SNAPSHOT_BYTES: usize = 1 << 20;
pub(super) const RECOVERY_WINDOW_MS: u64 = 3_600_000;

pub(super) fn resources(assignment: &serde_json::Value) -> Result<(Resources, Resources), Error> {
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
    let packet_bytes = match assignment["host"].get("coordinator_job_bytes") {
        Some(value) => value.as_u64().ok_or("invalid coordinator job RAM")?,
        None => coordinator_bytes,
    };
    if packet_bytes == 0 || packet_bytes > coordinator_bytes {
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
    if peak.vram_bytes == 0 || peak.scratch_bytes == 0 {
        return Err("typed GPU runtime requires admitted VRAM and spill".into());
    }
    limits(peak, jobs)?.workers.validate_capacity()?;
    Ok((peak, jobs))
}

pub(super) fn limits(peak: Resources, jobs: Resources) -> Result<Limits, Error> {
    Ok(Limits {
        jobs: 256,
        candidates: 8,
        attempts: 256,
        artifact_bytes: usize::try_from(ARTIFACT_BYTES)?,
        recovery_window_ms: RECOVERY_WINDOW_MS,
        workers: Resources {
            ram_bytes: peak
                .ram_bytes
                .checked_add(jobs.ram_bytes)
                .ok_or("worker RAM overflow")?,
            vram_bytes: peak.vram_bytes,
            scratch_bytes: peak.scratch_bytes,
            threads: peak.threads,
        },
    })
}

pub(super) fn fleet_limits(assignments: &[(Resources, Resources)]) -> Result<Limits, Error> {
    if assignments.is_empty() || assignments.len() > 16 {
        return Err("typed fleet worker count out of bounds".into());
    }
    let (mut peak, mut jobs) = (Resources::default(), Resources::default());
    for (worker_peak, worker_jobs) in assignments {
        peak = add_resources(peak, *worker_peak)?;
        jobs = add_resources(jobs, *worker_jobs)?;
    }
    let limits = limits(peak, jobs)?;
    limits.workers.validate_capacity()?;
    Ok(limits)
}

pub(super) fn add_resources(left: Resources, right: Resources) -> Result<Resources, Error> {
    Ok(Resources {
        ram_bytes: left
            .ram_bytes
            .checked_add(right.ram_bytes)
            .ok_or("fleet RAM overflow")?,
        vram_bytes: left
            .vram_bytes
            .checked_add(right.vram_bytes)
            .ok_or("fleet VRAM overflow")?,
        scratch_bytes: left
            .scratch_bytes
            .checked_add(right.scratch_bytes)
            .ok_or("fleet spill overflow")?,
        threads: left
            .threads
            .checked_add(right.threads)
            .ok_or("fleet CPU overflow")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assigned() -> serde_json::Value {
        json!({"host":{"worker_bytes":48_318_382_080u64,"coordinator_bytes":1_073_741_824u64,
            "spill_bytes":30_870_077_440u64},"gpu":{"managed_bytes":7_516_192_768u64},
            "cpu":{"rayon_threads":23}})
    }

    #[test]
    fn host_assignment_preserves_runtime_limits_and_device_reservations() {
        let (peak, jobs) = resources(&assigned()).unwrap();
        let limits = limits(peak, jobs).unwrap();
        assert_eq!(limits.workers.ram_bytes, 49_392_123_904);
        assert_eq!(limits.workers.vram_bytes, peak.vram_bytes);
        assert_eq!(limits.workers.scratch_bytes, peak.scratch_bytes);
        assert_eq!(jobs.threads, 23);
        assert_eq!(jobs.vram_bytes, 0);
    }

    #[test]
    fn parallel_packets_share_the_coordinator_ram_and_sum_device_limits() {
        let mut assignment = assigned();
        assignment["host"]["coordinator_job_bytes"] = json!(536_870_912u64);
        let one = resources(&assignment).unwrap();
        let limits = fleet_limits(&[one, one]).unwrap();
        assert_eq!(
            limits.workers.ram_bytes,
            2 * one.0.ram_bytes + 1_073_741_824
        );
        assert_eq!(limits.workers.threads, 46);
        assert_eq!(limits.workers.vram_bytes, 2 * one.0.vram_bytes);
        for value in [
            json!(0),
            json!(-1),
            json!(1_073_741_825u64),
            json!("536870912"),
        ] {
            assignment["host"]["coordinator_job_bytes"] = value;
            assert!(resources(&assignment).is_err());
        }
        assert!(fleet_limits(&[]).is_err());
        assert!(fleet_limits(&vec![one; 17]).is_err());
    }

    #[test]
    fn malformed_or_unrepresentable_host_assignments_fail_closed() {
        for (group, key, invalid) in [
            ("host", "worker_bytes", json!(-1)),
            ("host", "coordinator_bytes", json!(0)),
            ("host", "spill_bytes", json!(0)),
            ("gpu", "managed_bytes", json!(0)),
            ("cpu", "rayon_threads", json!(0)),
            ("cpu", "rayon_threads", json!(u64::MAX)),
            ("host", "worker_bytes", json!(i64::MAX)),
        ] {
            let mut assignment = assigned();
            assignment[group][key] = invalid;
            assert!(resources(&assignment).is_err(), "{group}.{key}");
        }
        assert!(resources(&json!({})).is_err());
    }
}
