//! Linux admission for the existing public GPU worker assignment.
//!
//! This is a startup check, not a registry approval or a GPU initializer. The
//! runtime must keep the environment, assignment, cgroup and scratch allocation
//! fixed for the worker's lifetime. Validate everything before starting Rayon,
//! the spill allocator or the device. Private wallet startup is a separate API.

use crate::block_v2::recursive::Error;
use serde_json::Value;
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

const MAX_ASSIGNMENT_BYTES: u64 = 1 << 20;
const MAX_CGROUP_BYTES: u64 = 64 << 10;

mod assignment;

/// An assignment checked against the current process, before any thread starts.
/// Construction is deliberately private: callers cannot substitute a snapshot
/// of a different worker's cgroup for their own resource enforcement.
pub struct Admission {
    assignment: Value,
    threads: usize,
    cpu_max: String,
}

impl Admission {
    pub fn from_env() -> Result<Self, Error> {
        if std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_some() {
            return Err(
                "public GPU worker admission does not admit private wallet assignments".into(),
            );
        }
        let path = std::env::var_os("LATTICA_V2_WORKER_BUDGET")
            .ok_or("missing public GPU worker assignment")?;
        let environment = Environment::from_env()?;
        let observed = Observed::current(Path::new(&std::env::var("LATTICA_SPILL_DIR")?))?;
        assignment::admit_host(observed.memory)?;
        let assignment = read_assignment(File::open(path)?)?;
        Self::validate(assignment, &environment, observed)
    }

    pub fn assignment(&self) -> &Value {
        &self.assignment
    }

    pub fn rayon_threads(&self) -> usize {
        self.threads
    }

    pub fn cpu_max(&self) -> &str {
        &self.cpu_max
    }

    /// Call once, at process startup. An already initialized global Rayon pool
    /// rejects, as it did in the CLI runtime; this never silently borrows a pool.
    pub fn initialize_rayon(&self) -> Result<(), Error> {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.threads)
            .build_global()?;
        if rayon::current_num_threads() != self.threads {
            return Err("actual Rayon pool differs from budget".into());
        }
        Ok(())
    }

    fn validate(
        assignment: Value,
        environment: &Environment,
        observed: Observed,
    ) -> Result<Self, Error> {
        assignment::admit_host(observed.memory)?;
        let number = |section: &str, key: &str| -> Result<u64, Error> {
            assignment[section][key]
                .as_u64()
                .ok_or_else(|| format!("invalid budget {section}.{key}").into())
        };
        let string = |section: &str, key: &str| -> Result<&str, Error> {
            assignment[section][key]
                .as_str()
                .ok_or_else(|| format!("invalid budget {section}.{key}").into())
        };
        for section in ["gpu", "cpu", "host"] {
            if number(section, "version")? != 1 {
                return Err("unsupported resource budget version".into());
            }
        }
        if number("gpu", "max_allocation_bytes")? == 0 {
            return Err("GPU assignment requires a positive per-allocation limit".into());
        }
        let direct = match assignment.get("readback_layout") {
            None => false,
            Some(Value::String(layout)) if layout == "banded" => false,
            Some(Value::String(layout)) if layout == "direct" => true,
            _ => return Err("unsupported readback layout assignment".into()),
        };
        if direct != environment.direct {
            return Err("readback layout differs from resource assignment".into());
        }
        let unit = assignment["unit"].as_str().ok_or("missing budget unit")?;
        let slice = assignment["slice"].as_str().ok_or("missing budget slice")?;
        if !unit.starts_with("lattica-v2-multi-")
            || !unit.ends_with(".service")
            || !worker_slice(slice)
            || observed.unit != unit
            || observed.slice != slice
            || environment.unit != unit
        {
            return Err("worker cgroup does not match its budget assignment".into());
        }
        if observed.memory != number("host", "worker_bytes")?
            || observed.fleet_memory != number("host", "fleet_bytes")?
            || observed.swap != 0
            || observed.fleet_swap != 0
        {
            return Err("actual memory cgroup differs from assigned budget".into());
        }
        validate_quota(&observed.cpu_max, string("cpu", "quota_percent")?)?;
        validate_cpuset(&observed.cpus, &assignment["cpu"]["allowed_cpus"])?;
        let threads = usize::try_from(number("cpu", "rayon_threads")?)?;
        if threads == 0 || environment.threads != threads {
            return Err("Rayon thread environment differs from budget".into());
        }
        if environment.gpu_uuid != string("gpu", "uuid")?
            || environment.managed != number("gpu", "managed_bytes")?
            || environment.context != number("gpu", "context_bytes")?
            || environment.host_output != number("host", "worker_bytes")?
            || environment.spill != number("host", "spill_bytes")?
        {
            return Err("GPU/spill environment differs from resource assignment".into());
        }
        if observed.scratch_device != number("host", "scratch_device")? {
            return Err("scratch filesystem changed since admission".into());
        }
        Ok(Self {
            assignment,
            threads,
            cpu_max: observed.cpu_max,
        })
    }
}

// A fleet may have its own capped slice without changing a shared fleet's
// limits. The observed parent must still exactly match this assigned name.
fn worker_slice(name: &str) -> bool {
    name == "lattica-v2-multi.slice"
        || (name.starts_with("lattica-v2-multi-")
            && name.ends_with(".slice")
            && name.len() <= 255
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_')))
}

struct Environment {
    unit: String,
    direct: bool,
    threads: usize,
    gpu_uuid: String,
    managed: u64,
    context: u64,
    host_output: u64,
    spill: u64,
}

impl Environment {
    fn from_env() -> Result<Self, Error> {
        let direct = match std::env::var("LATTICA_V2_GPU_DIRECT_READBACK").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("0") => false,
            Ok("1") => true,
            _ => return Err("LATTICA_V2_GPU_DIRECT_READBACK must be 0 or 1".into()),
        };
        Ok(Self {
            unit: std::env::var("LATTICA_V2_ACCOUNTING_UNIT")?,
            direct,
            threads: std::env::var("RAYON_NUM_THREADS")?.parse()?,
            gpu_uuid: std::env::var("LATTICA_GPU_DEVICE_UUID")?,
            managed: std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")?.parse()?,
            context: std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES")?.parse()?,
            host_output: std::env::var("LATTICA_V2_HOST_OUTPUT_BYTES")?.parse()?,
            spill: std::env::var("LATTICA_SPILL_MAX_BYTES")?.parse()?,
        })
    }
}

struct Observed {
    unit: String,
    slice: String,
    memory: u64,
    fleet_memory: u64,
    swap: u64,
    fleet_swap: u64,
    cpu_max: String,
    cpus: String,
    scratch_device: u64,
}

impl Observed {
    fn current(scratch: &Path) -> Result<Self, Error> {
        let membership = read_cgroup(Path::new("/proc/self/cgroup"))?;
        let group = current_group(&membership)?;
        let parent = group.parent().ok_or("missing worker resource slice")?;
        let name = |path: &Path| -> Result<String, Error> {
            Ok(path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("invalid worker cgroup name")?
                .into())
        };
        let metadata = fs::metadata(scratch)?;
        if !metadata.is_dir() {
            return Err("worker scratch path is not a directory".into());
        }
        Ok(Self {
            unit: name(&group)?,
            slice: name(parent)?,
            memory: read_limit(&group.join("memory.max"))?,
            fleet_memory: read_limit(&parent.join("memory.max"))?,
            swap: read_limit(&group.join("memory.swap.max"))?,
            fleet_swap: read_limit(&parent.join("memory.swap.max"))?,
            cpu_max: read_cgroup(&group.join("cpu.max"))?,
            cpus: read_cgroup(&group.join("cpuset.cpus.effective"))?,
            scratch_device: metadata.dev(),
        })
    }
}

fn read_assignment(reader: impl Read) -> Result<Value, Error> {
    assignment::read(reader)
}

fn read_cgroup(path: &Path) -> Result<String, Error> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_CGROUP_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CGROUP_BYTES {
        return Err("worker cgroup metadata exceeds limit".into());
    }
    Ok(std::str::from_utf8(&bytes)?.trim().to_owned())
}

fn read_limit(path: &Path) -> Result<u64, Error> {
    read_cgroup(path)?.parse().map_err(|_| {
        format!(
            "worker cgroup limit {} must be finite bytes",
            path.display()
        )
        .into()
    })
}

fn current_group(membership: &str) -> Result<PathBuf, Error> {
    let mut groups = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let path = groups.next().ok_or("GPU worker requires cgroup v2")?;
    if groups.next().is_some()
        || !path.starts_with('/')
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("invalid worker cgroup v2 membership".into());
    }
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

fn validate_quota(actual: &str, assigned: &str) -> Result<(), Error> {
    let fields: Vec<_> = actual.split_whitespace().collect();
    if fields.len() != 2 {
        return Err("invalid worker CPU quota".into());
    }
    let quota = fields[0].parse::<u64>()?;
    let period = fields[1].parse::<u64>()?;
    let assigned = assigned.trim_end_matches('%').parse::<f64>()? / 100.0;
    // NaN and a zero period previously made the comparison silently pass.
    if quota == 0 || period == 0 || !assigned.is_finite() || assigned <= 0.0 {
        return Err("invalid worker CPU quota".into());
    }
    let actual = quota as f64 / period as f64;
    if (actual - assigned).abs() > 0.00002 {
        return Err("actual CPU quota differs from budget".into());
    }
    Ok(())
}

fn validate_cpuset(actual: &str, assigned: &Value) -> Result<(), Error> {
    let assigned = assigned.as_array().ok_or("missing CPU set")?;
    if assigned.is_empty() {
        return Err("empty worker CPU set".into());
    }
    let mut offset: usize = 0;
    let mut previous = None;
    for range in actual.split(',') {
        let bounds: Vec<_> = range.split('-').collect();
        if bounds.is_empty() || bounds.len() > 2 {
            return Err("invalid effective CPU set".into());
        }
        let first = bounds[0].parse::<u64>()?;
        let last = bounds.last().unwrap().parse::<u64>()?;
        if last < first || previous.is_some_and(|end| first <= end) {
            return Err("invalid effective CPU set".into());
        }
        let length = usize::try_from(last - first)?
            .checked_add(1)
            .ok_or("effective CPU set overflow")?;
        let end = offset
            .checked_add(length)
            .filter(|&end| end <= assigned.len())
            .ok_or("effective CPU set differs from assignment")?;
        for (index, value) in assigned[offset..end].iter().enumerate() {
            if value.as_u64() != Some(first + index as u64) {
                return Err("effective CPU set differs from assignment".into());
            }
        }
        offset = end;
        previous = Some(last);
    }
    if offset != assigned.len() {
        return Err("effective CPU set differs from assignment".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "gpu_admission_tests.rs"]
mod tests;
