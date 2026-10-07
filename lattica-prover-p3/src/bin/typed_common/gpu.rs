//! Explicit, serial GPU bootstrap for the typed registry. A grouped-eight
//! qualification is never accepted as a typed qualification. The controller
//! must retain an independent CPU audit before using any resulting root.
use super::{body, read_json, run_inner, tasks, Error, Expected, FINALIZER, KEY_COUNT, PAIRED};
use lattica_prover_p3::{
    block_v2::{
        gpu_hash,
        machine::{analysis, programs},
        perf::Profiler,
        profile, quotient_pcs,
    },
    spill_alloc,
};
use serde_json::Value;
use std::{fs, path::Path, time::Instant};

#[path = "../grouped_common/adaptive.rs"]
mod adaptive;

pub(crate) const WORKLOAD: &str = if PAIRED {
    "typed-paired-depth-six-bootstrap-v1"
} else if FINALIZER {
    "typed-finalizer-depth-six-bootstrap-v1"
} else {
    "typed-depth-six-bootstrap-v1"
};
const COMPACT_WORKLOAD: &str = if PAIRED {
    "typed-paired-compact-depth-six-bootstrap-v1"
} else if FINALIZER {
    "typed-finalizer-compact-depth-six-bootstrap-v1"
} else {
    "typed-compact-depth-six-bootstrap-v1"
};

fn command(args: &[String]) -> Result<(Vec<String>, u64), Error> {
    let values: Vec<_> = args.iter().skip(1).map(String::as_str).collect();
    let (verb, budget) = match values.as_slice() {
        ["register-gpu", _, mode, budget] if (1..=KEY_COUNT as u64).contains(&mode.parse::<u64>()?) =>
            ("register", budget.parse::<u64>()?),
        ["prove-gpu", _, _, _, budget] => ("prove-cpu", budget.parse::<u64>()?),
        ["prove-execution-gpu", _, _, _, budget]
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) =>
            ("prove-execution", budget.parse::<u64>()?),
        ["prove-process-gpu", _, _, _, budget]
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) =>
            ("prove-process", budget.parse::<u64>()?),
        ["serve-process-gpu", _, _, _, budget]
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) =>
            ("serve-process", budget.parse::<u64>()?),
        ["serve-shared-process-gpu", _, _, _, budget]
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) =>
            ("serve-shared-process", budget.parse::<u64>()?),
        _ => return Err("typed GPU work requires register-gpu DIR MODE WORKER_BYTES or prove-gpu DIR EXPECTED OUT WORKER_BYTES".into()),
    };
    if budget == 0 {
        return Err("missing typed GPU worker budget".into());
    }
    let mut normalized = args.to_vec();
    normalized[1] = verb.into();
    Ok((normalized, budget))
}

fn validate_assignment(assignment: &Value, budget: u64) -> Result<bool, Error> {
    let compact = match (
        assignment["workload_kind"].as_str(),
        assignment.get("typed_ram_admission"),
    ) {
        (Some(WORKLOAD), None) => false,
        (Some(WORKLOAD), Some(Value::String(mode))) if mode == "full" => false,
        (Some(COMPACT_WORKLOAD), Some(Value::String(mode))) if mode == "compact" => true,
        _ => return Err("typed GPU workload and RAM admission model differ".into()),
    };
    if assignment["qualification_capacity_test"].as_bool() != Some(true)
        || assignment["host"]["worker_bytes"].as_u64() != Some(budget)
    {
        return Err("typed GPU bootstrap requires its own explicit qualification assignment and matching worker budget".into());
    }
    Ok(compact)
}

fn shared_job_limit(assignment: &Value, single_candidate: u64) -> Result<u64, Error> {
    match assignment.get("pool_job_limit") {
        None => Ok(single_candidate),
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=16384).contains(n))
            .ok_or_else(|| "invalid persistent pool job limit".into()),
    }
}

fn fri_workspace(assignment: &Value) -> Result<u64, Error> {
    match assignment.get("gpu_fri_fold") {
        None | Some(Value::Bool(false)) => Ok(0),
        Some(Value::Bool(true)) => Ok(1 << 20),
        _ => Err("invalid GPU FRI folding assignment".into()),
    }
}

fn require_limits(budget: u64) -> Result<bool, Error> {
    let assignment: Value = read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
    let compact = validate_assignment(&assignment, budget)?;
    let fri = fri_workspace(&assignment)? != 0;
    if std::env::var("LATTICA_V2_GPU_FRI_FOLD").unwrap_or_else(|_| "0".into())
        != if fri { "1" } else { "0" }
    {
        return Err("GPU FRI folding differs from resource assignment".into());
    }
    let workspace = match assignment.get("lde_workspace_bytes") {
        Some(value) => value.as_u64().ok_or("invalid LDE workspace reservation")?,
        None => 0,
    };
    if std::env::var("LATTICA_V2_GPU_LDE_WORKSPACE_BYTES")
        .unwrap_or_else(|_| "0".into())
        .parse::<u64>()?
        != workspace
        || workspace
            > assignment["gpu"]["managed_bytes"]
                .as_u64()
                .ok_or("missing GPU managed budget")?
                / 4
    {
        return Err("GPU workspace cache differs from resource assignment".into());
    }
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let groups: Vec<_> = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect();
    if groups.len() != 1 {
        return Err("typed GPU bootstrap requires cgroup v2".into());
    }
    let group = Path::new("/sys/fs/cgroup").join(groups[0].trim_start_matches('/'));
    let parent = group.parent().ok_or("missing typed GPU resource slice")?;
    // This checks the actual CPU quota/cpuset, memory/swap caps, selected GPU,
    // readback mode, scratch filesystem, and spill allowance, then starts Rayon.
    adaptive::validate(&group, parent)?;
    Ok(compact)
}

fn require_backend() -> Result<(), Error> {
    for (key, required) in [
        ("LATTICA_V2_GPU_HASH", "1"),
        ("LATTICA_V2_GPU_RETAIN_TREES", "1"),
        ("LATTICA_V2_GPU_PIPELINE", "0"),
        ("LATTICA_V2_GPU_RESIDENT_LDE", "1"),
        ("LATTICA_V2_GPU_OPENINGS", "1"),
        ("LATTICA_V2_GPU_OPENING_COMPACT", "1"),
        ("LATTICA_V2_GPU_OPENING_PINNED", "0"),
        ("LATTICA_V2_GPU_COMPACT_PROVER_DATA", "1"),
        ("LATTICA_V2_GPU_PARALLEL_READBACK", "1"),
        ("LATTICA_V2_GPU_QUOTIENT_LDE", "1"),
        ("LATTICA_V2_QUOTIENT_FUSION", "1"),
    ] {
        if std::env::var(key).as_deref() != Ok(required) {
            return Err(format!("typed GPU bootstrap requires {key}={required}").into());
        }
    }
    Ok(())
}

fn require_geometry(directory: &Path, budget: u64, compact: bool) -> Result<(), Error> {
    let assignment: Value = read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
    let budget = budget
        .checked_sub(fri_workspace(&assignment)?)
        .ok_or("GPU FRI host workspace exceeds worker budget")?;
    let height: usize = read_json(&directory.join("height.json"))?;
    if height != 262144 {
        return Err("typed GPU bootstrap model requires height 262144".into());
    }
    let measured = analysis::analyze(&programs::shape(height)?).map_err(|e| format!("{e:?}"))?;
    if measured.main_width != 94
        || measured.preprocessed_width != 200
        || measured.permutation_width_base + 4 > 55
        || measured.quotient_chunks != 16
        || profile::LOG_BLOWUP != 4
        || measured.fri_ali_bits < profile::MIN_TREE_SECURITY_BITS
    {
        return Err("compiled typed GPU geometry differs from the bootstrap model".into());
    }
    if compact {
        measured.check_compact_ram_lower_bound_with_budget(budget)
    } else {
        measured.check_ram_lower_bound_with_budget(budget)
    }
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

struct GpuGuard(bool);
impl GpuGuard {
    fn finish(&mut self) -> Result<(), Error> {
        gpu_hash::shutdown()?;
        self.0 = false;
        Ok(())
    }
}
impl Drop for GpuGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = gpu_hash::shutdown();
        }
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), Error> {
    if args.len() == 2 && args[1] == "--gpu-inventory" {
        let devices = lattica_prover_p3::gpu_device::devices()?;
        println!(
            "{}",
            serde_json::to_string(
                &devices
                    .into_iter()
                    .map(|(_, _, info)| info)
                    .collect::<Vec<_>>()
            )?
        );
        return Ok(());
    }
    let started = Instant::now();
    let (normalized, budget) = command(args)?;
    #[cfg(all(target_os = "linux", feature = "stream"))]
    if normalized[1] == "serve-shared-process" {
        let assignment: Value = read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
        if let Some(path) = assignment.get("startup_guard") {
            lattica_prover_p3::block_v2::execution::startup::enter_until_process_exit(
                Path::new(
                    path.as_str()
                        .ok_or("invalid persistent startup guard path")?,
                ),
                &args[1..],
                &assignment,
            )?;
        }
    }
    require_backend()?;
    let compact = require_limits(budget)?;
    require_geometry(Path::new(&normalized[2]), budget, compact)?;
    if normalized[1] == "prove-process" {
        #[cfg(all(target_os = "linux", feature = "stream"))]
        return super::execution::prove_process(
            Path::new(&normalized[2]),
            Path::new(&normalized[3]),
            Path::new(&normalized[4]),
            budget,
        );
        #[cfg(not(all(target_os = "linux", feature = "stream")))]
        return Err("typed process execution requires Linux and stream".into());
    }
    // Compute the required work before initializing the device. Registration
    // has no openings; a proving invocation must produce every planned node.
    let shared_worker = normalized[1] == "serve-shared-process";
    let mut expected_proofs = if normalized[1] == "register" {
        0
    } else {
        let expected: Expected = read_json(Path::new(&normalized[3]))?;
        tasks(&body(Path::new(&normalized[2]))?, &expected)?.len() as u64
    };
    let shared_limit = if shared_worker {
        let assignment: Value = read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
        shared_job_limit(&assignment, expected_proofs)?
    } else {
        expected_proofs
    };
    let fusion = quotient_pcs::initialize_research_from_env()?;
    if !fusion || !quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)? {
        return Err("typed GPU bootstrap did not enable quotient commitments".into());
    }
    let _spill = spill_alloc::SpillScope::arm();
    gpu_hash::initialize_from_env()?;
    let mut guard = GpuGuard(true);
    if !gpu_hash::initialize_resident_from_env()? {
        return Err("typed GPU bootstrap did not select resident LDE commitments".into());
    }
    let profiler = Profiler::from_env()?;
    let mut execution_stats = None;
    let result = if normalized[1] == "serve-process" || shared_worker {
        #[cfg(all(target_os = "linux", feature = "stream"))]
        {
            super::execution::serve_process(
                Path::new(&normalized[2]),
                Path::new(&normalized[3]),
                Path::new(&normalized[4]),
                budget,
                || {
                    execution_stats = gpu_hash::report("typed persistent GPU workspace");
                    if execution_stats.is_none() {
                        return Err("missing persistent GPU telemetry".into());
                    }
                    guard.finish()
                },
            )
            .and_then(|count| {
                if shared_worker && count <= shared_limit {
                    expected_proofs = count;
                } else if count != expected_proofs {
                    return Err("typed process completed work count".into());
                }
                Ok(())
            })
        }
        #[cfg(not(all(target_os = "linux", feature = "stream")))]
        {
            Err("typed process execution requires Linux and stream".into())
        }
    } else if normalized[1] == "prove-execution" {
        #[cfg(all(target_os = "linux", feature = "stream"))]
        {
            super::execution::prove(
                Path::new(&normalized[2]),
                Path::new(&normalized[3]),
                Path::new(&normalized[4]),
                budget,
                true,
                || {
                    execution_stats = gpu_hash::report("typed GPU execution workspace");
                    if execution_stats.is_none() {
                        return Err("missing typed execution GPU telemetry".into());
                    }
                    Ok(())
                },
            )
        }
        #[cfg(not(all(target_os = "linux", feature = "stream")))]
        {
            Err("typed execution requires Linux and stream".into())
        }
    } else {
        run_inner(&normalized, true)
    };
    if let Some(profiler) = profiler {
        profiler.report("typed GPU process");
    }
    let stats = execution_stats
        .or_else(|| gpu_hash::report("typed GPU process"))
        .ok_or("missing typed GPU telemetry")?;
    guard.finish()?;
    result?;
    validate_completed_work(&stats, shared_worker, expected_proofs)?;
    println!(
        "{}",
        serde_json::json!({"event":"typed_gpu_work_complete",
        "seconds":started.elapsed().as_secs_f64(), "recursive_proofs":expected_proofs,
        "spill_peak_bytes":spill_alloc::spill_peak_bytes(), "cpu_only":false,
        "qualification_bootstrap":true, "production_ready":false})
    );
    Ok(())
}

fn validate_completed_work(
    stats: &gpu_hash::Snapshot,
    shared_worker: bool,
    expected_proofs: u64,
) -> Result<(), Error> {
    let work_required = !shared_worker || expected_proofs > 0;
    if (work_required
        && (stats.commits == 0
            || stats.lde_commits == 0
            || stats.lde_parallel_decode_bytes == 0
            || stats.lde_parallel_decode_chunks == 0))
        || stats.quotient_lde_commits != expected_proofs
        || stats.opening_calls != expected_proofs
        || stats.opening_compact_calls != expected_proofs
        || stats.opening_pinned_uploaded_bytes != 0
        || stats.opening_pinned_upload_chunks != 0
    {
        return Err("typed GPU execution differs from its assigned backend/work count".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_job_and_fri_workspace_admission_is_explicit_and_bounded() {
        assert_eq!(shared_job_limit(&serde_json::json!({}), 4).unwrap(), 4);
        assert_eq!(
            shared_job_limit(&serde_json::json!({"pool_job_limit": 16384}), 4).unwrap(),
            16384
        );
        for value in [
            serde_json::json!(0),
            serde_json::json!(16385),
            serde_json::json!(true),
            serde_json::json!("16384"),
        ] {
            assert!(shared_job_limit(&serde_json::json!({"pool_job_limit": value}), 4).is_err());
        }
        assert_eq!(fri_workspace(&serde_json::json!({})).unwrap(), 0);
        assert_eq!(
            fri_workspace(&serde_json::json!({"gpu_fri_fold": true})).unwrap(),
            1 << 20
        );
        assert!(fri_workspace(&serde_json::json!({"gpu_fri_fold": 1})).is_err());
    }

    #[test]
    fn idle_shared_worker_can_close_without_proving() {
        let stats = gpu_hash::Snapshot::default();
        validate_completed_work(&stats, true, 0).unwrap();
        assert!(validate_completed_work(&stats, false, 0).is_err());
        assert!(validate_completed_work(&stats, true, 1).is_err());
        let unexpected_proof = gpu_hash::Snapshot {
            quotient_lde_commits: 1,
            ..stats
        };
        assert!(validate_completed_work(&unexpected_proof, true, 0).is_err());
    }

    #[test]
    fn active_shared_worker_requires_complete_gpu_telemetry() {
        let stats = gpu_hash::Snapshot {
            commits: 1,
            lde_commits: 1,
            lde_parallel_decode_bytes: 8,
            lde_parallel_decode_chunks: 1,
            quotient_lde_commits: 1,
            opening_calls: 1,
            opening_compact_calls: 1,
            ..Default::default()
        };
        validate_completed_work(&stats, true, 1).unwrap();
        for invalid in [
            gpu_hash::Snapshot {
                lde_parallel_decode_bytes: 0,
                ..stats
            },
            gpu_hash::Snapshot {
                lde_parallel_decode_chunks: 0,
                ..stats
            },
            gpu_hash::Snapshot {
                opening_compact_calls: 0,
                ..stats
            },
            gpu_hash::Snapshot {
                opening_pinned_uploaded_bytes: 8,
                ..stats
            },
        ] {
            assert!(validate_completed_work(&invalid, true, 1).is_err());
        }
        assert!(validate_completed_work(&stats, true, 0).is_err());
        assert!(validate_completed_work(&stats, true, 2).is_err());
    }

    fn args(values: &[&str]) -> Vec<String> {
        std::iter::once("probe")
            .chain(values.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn only_explicit_gpu_work_is_parsed_before_initialization() {
        for (verb, normalized) in [
            ("prove-process-gpu", "prove-process"),
            ("serve-process-gpu", "serve-process"),
            ("serve-shared-process-gpu", "serve-shared-process"),
        ] {
            let result = command(&args(&[
                verb,
                "fixture",
                "expected",
                "output",
                "34359738368",
            ]));
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) {
                assert_eq!(result.unwrap().0[1], normalized);
            } else {
                assert!(result.is_err());
            }
        }
        for mode in 1..=KEY_COUNT {
            let mode = mode.to_string();
            let (normalized, budget) =
                command(&args(&["register-gpu", "fixture", &mode, "34359738368"])).unwrap();
            assert_eq!(normalized[1], "register");
            assert_eq!(budget, 1 << 35);
        }
        assert_eq!(
            command(&args(&["register-gpu", "fixture", "6", "1"])).is_ok(),
            FINALIZER
        );
        let (normalized, _) =
            command(&args(&["prove-gpu", "fixture", "expected", "out", "1"])).unwrap();
        assert_eq!(normalized[1], "prove-cpu");
        for input in [
            vec!["fixture", "dir"],
            vec!["audit-root", "registry", "expected", "body", "root"],
            vec!["register-gpu", "fixture", "0", "1"],
            vec!["register-gpu", "fixture", "13", "1"],
            vec!["register-gpu", "fixture", "1", "0"],
            vec!["prove-gpu", "fixture", "expected", "out"],
            vec!["prove-gpu", "fixture", "expected", "out", "-1"],
        ] {
            assert!(command(&args(&input)).is_err());
        }
    }

    #[test]
    fn grouped_qualification_and_budget_mismatch_cannot_authorize_typed_work() {
        let valid = serde_json::json!({"workload_kind":WORKLOAD,
            "qualification_capacity_test":true, "host":{"worker_bytes":4096}});
        validate_assignment(&valid, 4096).unwrap();
        assert!(validate_assignment(&valid, 8192).is_err());
        let other = if FINALIZER {
            "typed-depth-six-bootstrap-v1"
        } else {
            "typed-finalizer-depth-six-bootstrap-v1"
        };
        let mut wrong_registry = valid.clone();
        wrong_registry["workload_kind"] = serde_json::json!(other);
        assert!(validate_assignment(&wrong_registry, 4096).is_err());
        for (field, value) in [
            ("workload_kind", serde_json::json!("grouped-eight")),
            ("qualification_capacity_test", serde_json::json!(false)),
            ("workload_kind", Value::Null),
        ] {
            let mut altered = valid.clone();
            altered[field] = value;
            assert!(validate_assignment(&altered, 4096).is_err());
        }
    }

    #[test]
    fn compact_admission_requires_its_own_explicit_workload_and_model() {
        let valid = serde_json::json!({
            "workload_kind": COMPACT_WORKLOAD,
            "typed_ram_admission": "compact",
            "qualification_capacity_test": true,
            "host": {"worker_bytes": 4096}
        });
        assert!(validate_assignment(&valid, 4096).unwrap());
        for value in [
            Value::Null,
            serde_json::json!("full"),
            serde_json::json!("other"),
        ] {
            let mut wrong = valid.clone();
            wrong["typed_ram_admission"] = value;
            assert!(validate_assignment(&wrong, 4096).is_err());
        }
        let mut wrong = valid.clone();
        wrong["workload_kind"] = serde_json::json!(WORKLOAD);
        assert!(validate_assignment(&wrong, 4096).is_err());
        wrong["typed_ram_admission"] = serde_json::json!(true);
        assert!(validate_assignment(&wrong, 4096).is_err());
        wrong["typed_ram_admission"] = serde_json::json!("compact");
        wrong["workload_kind"] = serde_json::json!(if FINALIZER {
            "typed-compact-depth-six-bootstrap-v1"
        } else {
            "typed-finalizer-compact-depth-six-bootstrap-v1"
        });
        assert!(validate_assignment(&wrong, 4096).is_err());
    }
}
