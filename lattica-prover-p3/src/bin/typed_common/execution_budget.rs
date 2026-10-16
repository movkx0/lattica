//! Trusted runtime limits shared by proving and CPU recovery. Never read these
//! limits from a checkpoint; the host supplies the independently pinned budget.
use super::*;

// A full paired block retains C wallets and C-1 recursive proofs. Publication
// temporarily counts one additional proof name, even for a hard link. Reserve
// the wire-size ceiling for all 2*C names: 256 MiB at 64, 512 MiB at 128.
pub(super) const ARTIFACT_BYTES: u64 =
    2 * commitment::CAPACITY as u64 * profile::MAX_PROOF_BYTES as u64;
pub(super) const ARTIFACT_ENTRIES: usize = 512;
pub(super) const SNAPSHOT_BYTES: usize = 1 << 20;
pub(super) const RECOVERY_WINDOW_MS: u64 = 3_600_000;

pub(super) fn resources(assignment: &serde_json::Value) -> Result<(Resources, Resources), Error> {
    lattica_prover_p3::block_v2::execution::worker_budget::resources(assignment)
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
