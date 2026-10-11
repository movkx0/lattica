//! Shared admission of the complete owned OpenCL path; no worker authority.
use super::{gpu_hash, machine::symbolic, quotient_pcs, resident_pcs};

// Native initialization admits the complete owned path. It never sets environment
// variables, selects a default device, or silently initializes a partial backend.
const REQUIRED_SWITCHES: &[&str] = &[
    "LATTICA_V2_GPU_HASH",
    "LATTICA_V2_GPU_RETAIN_TREES",
    "LATTICA_V2_GPU_RESIDENT_LDE",
    "LATTICA_V2_GPU_OPENINGS",
    "LATTICA_V2_QUOTIENT_FUSION",
    "LATTICA_V2_GPU_QUOTIENT_LDE",
    "LATTICA_V2_GPU_QUOTIENT_EVAL",
    "LATTICA_V2_GPU_QUOTIENT_RESIDENT",
    "LATTICA_V2_GPU_LOOKUP",
    "LATTICA_V2_GPU_OPENING_EVAL",
    "LATTICA_V2_GPU_FRI_RESIDENT",
    "LATTICA_V2_GPU_PCS_DEVICE_ONLY",
    "LATTICA_V2_GPU_WITNESS",
    "LATTICA_V2_GPU_RANDOMNESS",
    "LATTICA_V2_GPU_TRANSCRIPT",
];

pub(crate) fn preflight() -> Result<(), String> {
    for name in REQUIRED_SWITCHES {
        if std::env::var(name).as_deref() != Ok("1") {
            return Err(format!("native GPU startup requires {name}=1"));
        }
    }
    let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID")
        .map_err(|_| "native GPU startup requires an explicit device UUID")?;
    if uuid.len() != 40
        || !uuid.starts_with("GPU-")
        || !uuid[4..].chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return Err("invalid native GPU device UUID".into());
    }
    if std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|bytes| bytes == 0)
    {
        return Err(
            "native GPU startup requires an explicit positive managed byte allowance".into(),
        );
    }
    resident_pcs::preflight_research_from_env()?;
    if resident_pcs::host_output_budget() < symbolic::HOST_BYTES as usize {
        return Err("native GPU host allowance is too small".into());
    }
    Ok(())
}

pub(crate) fn select() -> Result<(), String> {
    let fusion = quotient_pcs::initialize_research_from_env()?;
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)?;
    Ok(())
}

pub(crate) struct Startup(bool);
impl Startup {
    pub(crate) fn begin() -> Result<Self, String> {
        gpu_hash::initialize_tracked_from_env().map(Self)
    }

    pub(crate) fn accept(&mut self) {
        self.0 = false;
    }
}
impl Drop for Startup {
    fn drop(&mut self) {
        if self.0 {
            // Includes unwinding. Never retire a borrowed engine; shutdown also
            // refuses to invalidate a concurrent retained device session.
            let _ = gpu_hash::shutdown();
        }
    }
}
