//! Enforce the scheduler's immutable per-attempt resource assignment before
//! initializing Rayon, the spill allocator or an OpenCL context.
use super::Error;
use serde_json::Value;
use std::{fs, path::Path};

pub(crate) fn validate(group: &Path, parent: &Path) -> Result<(), Error> {
    let path = std::env::var("LATTICA_V2_WORKER_BUDGET")?;
    let budget: Value = serde_json::from_slice(&fs::read(path)?)?;
    let number = |section: &str, key: &str| -> Result<u64, Error> {
        budget[section][key]
            .as_u64()
            .ok_or_else(|| format!("invalid budget {section}.{key}").into())
    };
    let string = |section: &str, key: &str| -> Result<&str, Error> {
        budget[section][key]
            .as_str()
            .ok_or_else(|| format!("invalid budget {section}.{key}").into())
    };
    let text = |path| fs::read_to_string(path).map(|s| s.trim().to_owned());
    for section in ["gpu", "cpu", "host"] {
        if number(section, "version")? != 1 {
            return Err("unsupported resource budget version".into());
        }
    }
    let layout = match budget.get("readback_layout") {
        None => "banded",
        Some(value) => value.as_str().ok_or("invalid readback layout assignment")?,
    };
    let direct = match layout {
        "banded" => false,
        "direct" => true,
        _ => return Err("unsupported readback layout assignment".into()),
    };
    let configured_direct = match std::env::var("LATTICA_V2_GPU_DIRECT_READBACK").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => return Err("LATTICA_V2_GPU_DIRECT_READBACK must be 0 or 1".into()),
    };
    if direct != configured_direct {
        return Err("readback layout differs from resource assignment".into());
    }
    let unit = budget["unit"].as_str().ok_or("missing budget unit")?;
    let slice = budget["slice"].as_str().ok_or("missing budget slice")?;
    if !unit.starts_with("lattica-v2-multi-")
        || !unit.ends_with(".service")
        || slice != "lattica-v2-multi.slice"
        || group.file_name().and_then(|v| v.to_str()) != Some(unit)
        || parent.file_name().and_then(|v| v.to_str()) != Some(slice)
        || std::env::var("LATTICA_V2_ACCOUNTING_UNIT")? != unit
    {
        return Err("worker cgroup does not match its budget assignment".into());
    }
    for (file, expected) in [
        (group.join("memory.max"), number("host", "worker_bytes")?),
        (parent.join("memory.max"), number("host", "fleet_bytes")?),
        (group.join("memory.swap.max"), 0),
        (parent.join("memory.swap.max"), 0),
    ] {
        if text(file)?.parse::<u64>()? != expected {
            return Err("actual memory cgroup differs from assigned budget".into());
        }
    }
    let quota = text(group.join("cpu.max"))?;
    let fields: Vec<_> = quota.split_whitespace().collect();
    let actual = fields[0].parse::<u64>()? as f64 / fields[1].parse::<u64>()? as f64;
    let assigned = string("cpu", "quota_percent")?
        .trim_end_matches('%')
        .parse::<f64>()?
        / 100.0;
    if (actual - assigned).abs() > 0.00002 {
        return Err("actual CPU quota differs from budget".into());
    }
    let allowed: Vec<u64> = budget["cpu"]["allowed_cpus"]
        .as_array()
        .ok_or("missing CPU set")?
        .iter()
        .map(|v| v.as_u64().ok_or("invalid CPU id"))
        .collect::<Result<_, _>>()?;
    let cpuset = text(group.join("cpuset.cpus.effective"))?;
    let mut actual_cpus = Vec::new();
    for range in cpuset.split(',') {
        let bounds: Vec<_> = range
            .split('-')
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()?;
        let first = bounds[0];
        let last = *bounds.last().unwrap();
        if last < first {
            return Err("invalid effective CPU set".into());
        }
        actual_cpus.extend(first..=last);
    }
    if actual_cpus != allowed {
        return Err("effective CPU set differs from assignment".into());
    }
    let threads = number("cpu", "rayon_threads")? as usize;
    if threads == 0 || std::env::var("RAYON_NUM_THREADS")?.parse::<usize>()? != threads {
        return Err("Rayon thread environment differs from budget".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    if rayon::current_num_threads() != threads {
        return Err("actual Rayon pool differs from budget".into());
    }
    if std::env::var("LATTICA_GPU_DEVICE_UUID")? != string("gpu", "uuid")?
        || std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")?.parse::<u64>()?
            != number("gpu", "managed_bytes")?
        || std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES")?.parse::<u64>()?
            != number("gpu", "context_bytes")?
        || std::env::var("LATTICA_V2_HOST_OUTPUT_BYTES")?.parse::<u64>()?
            != number("host", "worker_bytes")?
        || std::env::var("LATTICA_SPILL_MAX_BYTES")?.parse::<u64>()?
            != number("host", "spill_bytes")?
    {
        return Err("GPU/spill environment differs from resource assignment".into());
    }
    use std::os::unix::fs::MetadataExt;
    let scratch = std::env::var("LATTICA_SPILL_DIR")?;
    if fs::metadata(&scratch)?.dev() != number("host", "scratch_device")? {
        return Err("scratch filesystem changed since admission".into());
    }
    println!(
        "adaptive_worker_budget={} actual_rayon_threads={threads} actual_cpu_max={quota:?}",
        serde_json::to_string(&budget)?
    );
    Ok(())
}
