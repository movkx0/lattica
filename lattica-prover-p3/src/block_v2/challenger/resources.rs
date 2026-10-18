//! Fixed conservative additions for the supported owned transcript profile.
//! No overlap credits or reductions to existing witness/PCS/RNG reservations.
use serde::{Deserialize, Serialize};

pub(crate) use crate::transcript_limits::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bounds {
    pub live_states: u64,
    pub batch_words: u64,
    pub scalar_outputs: u64,
    pub partition_cosets: u64,
    pub grind_batch: u64,
    pub grind_bits: u64,
    pub grind_candidates: u64,
}
pub(crate) const BOUNDS: Bounds = Bounds {
    live_states: LIVE_STATES as u64,
    batch_words: BATCH_WORDS as u64,
    scalar_outputs: SCALAR_OUTPUTS as u64,
    partition_cosets: PARTITION_COSETS as u64,
    grind_batch: GRIND_BATCH as u64,
    grind_bits: GRIND_BITS as u64,
    grind_candidates: GRIND_CANDIDATES as u64,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub managed_bytes: u64,
    pub max_allocation_bytes: u64,
    pub host_bytes: u64,
}
pub(crate) fn reservation() -> Reservation {
    let states = LIVE_STATES * STATE_WORDS * 8;
    let transcript_io = 2 * BATCH_WORDS * 8;
    // A cubic point, one root per output, and three output coefficients.
    let scalar_io = (3 + 4 * SCALAR_OUTPUTS) * 8;
    let grinding = (GRIND_BATCH + GRIND_BATCH.div_ceil(GRIND_TILE) + 2) * 8;
    Reservation {
        managed_bytes: (states + transcript_io + scalar_io + grinding) as u64,
        max_allocation_bytes: (GRIND_BATCH * 8) as u64,
        host_bytes: HOST_BYTES as u64,
    }
}

pub(crate) fn validate_assignment(value: &serde_json::Value, selected: bool) -> Result<(), String> {
    let assigned = value
        .get("gpu_transcript")
        .map(|v| v.as_bool().ok_or("invalid GPU transcript assignment"))
        .transpose()?
        .unwrap_or(false);
    if assigned != selected {
        return Err("GPU transcript selection differs from worker assignment".into());
    }
    if !selected {
        return Ok(());
    }
    if value["gpu_randomness"].as_bool() != Some(true) {
        return Err("GPU transcript requires registered GPU randomness".into());
    }
    super::super::randomness::resources::validate_assignment(value, true, None)?;
    let bounds: Bounds = serde_json::from_value(value["transcript_bounds"].clone())
        .map_err(|e| format!("invalid GPU transcript bounds: {e}"))?;
    let assigned_reserve: Reservation =
        serde_json::from_value(value["transcript_reservation"].clone())
            .map_err(|e| format!("invalid GPU transcript reservation: {e}"))?;
    let expected = reservation();
    if bounds != BOUNDS || assigned_reserve != expected {
        return Err(
            "GPU transcript bounds or reservation differ from the supported profile".into(),
        );
    }
    let number = |parent: &str, key: &str| {
        value[parent][key]
            .as_u64()
            .ok_or_else(|| format!("missing or invalid worker {parent}.{key}"))
    };
    let mut managed = expected.managed_bytes;
    let mut host = expected.host_bytes;
    for parent in [
        "owned_quotient_reservation",
        "witness_reservation",
        "randomness_reservation",
    ] {
        managed = managed
            .checked_add(number(parent, "managed_bytes")?)
            .ok_or("GPU transcript aggregate reservation overflow")?;
    }
    for parent in ["witness_reservation", "randomness_reservation"] {
        host = host
            .checked_add(number(parent, "host_bytes")?)
            .ok_or("GPU transcript host reservation overflow")?;
    }
    if managed > number("gpu", "managed_bytes")?
        || expected.max_allocation_bytes > number("gpu", "max_allocation_bytes")?
        || host > number("host", "worker_bytes")?
    {
        return Err("simultaneous GPU transcript reservations exceed worker allowance".into());
    }
    Ok(())
}

pub(crate) fn check_worker(selected: bool) -> Result<(), String> {
    use std::io::Read;
    let Some(path) = std::env::var_os("LATTICA_V2_WORKER_BUDGET") else {
        return Ok(());
    };
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut encoded = Vec::new();
    file.take((1 << 20) + 1)
        .read_to_end(&mut encoded)
        .map_err(|e| e.to_string())?;
    if encoded.len() > 1 << 20 {
        return Err("worker assignment exceeds 1 MiB".into());
    }
    validate_assignment(
        &serde_json::from_slice(&encoded).map_err(|e| e.to_string())?,
        selected,
    )
}

#[cfg(test)]
mod tests;
