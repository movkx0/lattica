//! Additional simultaneous storage for device samples and retained salts.
//! Existing witness/PCS reservations remain additive; no host savings assumed.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bounds {
    pub rows: u64,
    pub main_columns: u64,
    pub preprocessing_columns: u64,
    /// Flattened base-field columns (three per cubic lookup column).
    pub lookup_columns: u64,
    pub quotient_rows: u64,
    pub quotient_chunks: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub managed_bytes: u64,
    pub max_allocation_bytes: u64,
    pub host_bytes: u64,
}

impl Bounds {
    pub(crate) fn reservation(self, cached_programs: u64) -> Result<Reservation, String> {
        if !self.rows.is_power_of_two()
            || self.rows > 1 << 20
            || self.main_columns == 0
            || [
                self.main_columns,
                self.preprocessing_columns,
                self.lookup_columns,
            ]
            .into_iter()
            .any(|n| n > 4096)
            || !self.quotient_rows.is_power_of_two()
            || !self.quotient_chunks.is_power_of_two()
            || !(2..=16).contains(&self.quotient_chunks)
            || self.quotient_rows < self.rows * 2
            || self.quotient_rows > self.rows * 512
            || self.quotient_rows < self.quotient_chunks * 2
            || !(1..=12).contains(&cached_programs)
        {
            return Err("GPU randomness bounds exceed the supported proof geometry".into());
        }
        // The above bounded integers keep every following operation within u64.
        let prefix = self.rows * 2;
        let chunk_rows = self.quotient_rows / self.quotient_chunks;
        let height = prefix.max(chunk_rows * 2) * 16;
        if height > 1 << 25 {
            return Err("GPU randomness salt height exceeds 2^25".into());
        }
        let samples = [
            self.rows * (self.main_columns + 8),
            self.rows * (self.lookup_columns + 8),
            self.quotient_rows * 4,
            chunk_rows * (self.quotient_chunks - 1) * 7,
            prefix * 7,
            height * 4,
        ];
        let largest_sample = *samples.iter().max().unwrap();
        if largest_sample > 1 << 28 {
            return Err("GPU randomness sample request exceeds 2^28 words".into());
        }
        // Only cached public preprocessing salts remain resident. Private
        // main, lookup, randomization, quotient and FRI salts retain recipes and replay one
        // matrix at a time, alongside the commitment/query workspace.
        let salt_rows = prefix * 16 * cached_programs + height;
        let retained_salts = salt_rows * 4 * 8;
        // Quotient random columns and masks coexist. Other stages draw one
        // hiding/randomization input at a time; salts are already counted above.
        let sample_outputs = samples[0]
            .max(samples[1])
            .max(samples[2] + samples[3])
            .max(samples[4])
            * 8;
        // Mirrors random::Plan, including an odd u32 starting cursor. Scratch
        // is per request, including replay inside commitment/query execution.
        let batch = largest_sample.min(1 << 20);
        let raw_bytes = (batch * 2 + 15).div_ceil(16) * 8 * 8;
        let scratch = raw_bytes + batch.div_ceil(256) * 16 + 8;
        Ok(Reservation {
            managed_bytes: retained_salts + sample_outputs + scratch + 5 * 32,
            max_allocation_bytes: (largest_sample * 8).max(raw_bytes),
            // Also covers bounded replay metadata (at most four commitment
            // batches of 256 recipes and at most 25 FRI layers); recipes
            // share the existing GPU keys.
            host_bytes: 1 << 20,
        })
    }

    fn covers(self, actual: Self) -> bool {
        self.rows >= actual.rows
            && self.main_columns >= actual.main_columns
            && self.preprocessing_columns >= actual.preprocessing_columns
            && self.lookup_columns >= actual.lookup_columns
            && self.quotient_rows >= actual.quotient_rows
            && self.quotient_chunks >= actual.quotient_chunks
            && self.quotient_rows / self.quotient_chunks
                >= actual.quotient_rows / actual.quotient_chunks
    }
}

pub(crate) fn validate_assignment(
    value: &serde_json::Value,
    selected: bool,
    actual: Option<Bounds>,
) -> Result<(), String> {
    let assigned = match value.get("gpu_randomness") {
        None => false,
        Some(value) => value.as_bool().ok_or("invalid GPU randomness assignment")?,
    };
    if assigned != selected {
        return Err("GPU randomness selection differs from worker assignment".into());
    }
    if !selected {
        return Ok(());
    }
    if [
        "gpu_witness",
        "gpu_pcs_device_only",
        "gpu_quotient_eval",
        "gpu_quotient_resident",
        "gpu_lookup",
        "gpu_opening_eval",
        "gpu_fri_resident",
    ]
    .iter()
    .any(|key| value[key].as_bool() != Some(true))
    {
        return Err("GPU randomness requires all owned witness and PCS consumers".into());
    }
    let bounds: Bounds = serde_json::from_value(value["randomness_bounds"].clone())
        .map_err(|e| format!("invalid GPU randomness bounds: {e}"))?;
    let reserve: Reservation = serde_json::from_value(value["randomness_reservation"].clone())
        .map_err(|e| format!("invalid GPU randomness reservation: {e}"))?;
    let entries = match value.get("preprocessing_cache") {
        None => 1,
        Some(cache) => cache["entries"]
            .as_u64()
            .ok_or("invalid preprocessing cache count")?,
    };
    if bounds.reservation(entries)? != reserve {
        return Err("GPU randomness reservation differs from its bounds".into());
    }
    if let Some(actual) = actual {
        actual.reservation(1)?;
        if !bounds.covers(actual) {
            return Err("proof exceeds assigned GPU randomness bounds".into());
        }
    }
    let number = |parent: &str, key: &str| {
        value[parent][key]
            .as_u64()
            .ok_or_else(|| format!("missing or invalid worker {parent}.{key}"))
    };
    if bounds.rows < number("witness_bounds", "rows")?
        || bounds.main_columns < number("witness_bounds", "main_columns")?
        || bounds.preprocessing_columns < number("witness_bounds", "preprocessing_columns")?
    {
        return Err("GPU randomness bounds do not cover assigned witness bounds".into());
    }
    let managed = reserve
        .managed_bytes
        .checked_add(number("owned_quotient_reservation", "managed_bytes")?)
        .and_then(|n| n.checked_add(value["witness_reservation"]["managed_bytes"].as_u64()?))
        .ok_or("GPU randomness aggregate reservation overflow")?;
    let host = reserve
        .host_bytes
        .checked_add(number("witness_reservation", "host_bytes")?)
        .ok_or("GPU randomness host reservation overflow")?;
    if managed > number("gpu", "managed_bytes")?
        || reserve.max_allocation_bytes > number("gpu", "max_allocation_bytes")?
        || host > number("host", "worker_bytes")?
    {
        return Err("simultaneous GPU randomness reservations exceed worker allowance".into());
    }
    Ok(())
}

pub(crate) fn check_worker(selected: bool, actual: Option<Bounds>) -> Result<(), String> {
    use std::io::Read;
    if let Some(actual) = actual {
        actual.reservation(1)?;
    }
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
    let value = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
    validate_assignment(&value, selected, actual)
}

/// Hiding MMCS pads every salt matrix to the largest matrix in its commitment.
/// Normalize heights before adding AIR reservations; summing unpadded AIRs
/// would undercount unequal-height batches. Host sampling scratch is shared.
pub(crate) fn batch_reservation(actual: &[Bounds]) -> Result<Reservation, String> {
    if actual.is_empty() || actual.len() > 256 {
        return Err("GPU randomness AIR count exceeded".into());
    }
    for bounds in actual {
        bounds.reservation(1)?;
    }
    let rows = actual.iter().map(|b| b.rows).max().unwrap();
    let chunk_rows = actual
        .iter()
        .map(|b| b.quotient_rows / b.quotient_chunks)
        .max()
        .unwrap();
    let mut total = Reservation::default();
    for bounds in actual {
        let normalized = Bounds {
            rows,
            quotient_rows: chunk_rows
                .checked_mul(bounds.quotient_chunks)
                .ok_or("GPU randomness batch geometry overflow")?
                .max(rows * 2),
            ..*bounds
        };
        let reserve = normalized.reservation(1)?;
        total.managed_bytes = total
            .managed_bytes
            .checked_add(reserve.managed_bytes)
            .ok_or("GPU randomness batch reservation overflow")?;
        total.max_allocation_bytes = total.max_allocation_bytes.max(reserve.max_allocation_bytes);
        total.host_bytes = total.host_bytes.max(reserve.host_bytes);
    }
    Ok(total)
}

pub(crate) fn validate_batch_assignment(
    value: &serde_json::Value,
    selected: bool,
    actual: &[Bounds],
) -> Result<(), String> {
    let needed = batch_reservation(actual)?;
    for bounds in actual {
        validate_assignment(value, selected, Some(*bounds))?;
    }
    if selected {
        let reserved: Reservation = serde_json::from_value(value["randomness_reservation"].clone())
            .map_err(|e| format!("invalid GPU randomness reservation: {e}"))?;
        if needed.managed_bytes > reserved.managed_bytes
            || needed.max_allocation_bytes > reserved.max_allocation_bytes
            || needed.host_bytes > reserved.host_bytes
        {
            return Err("AIR batch exceeds assigned GPU randomness reservation".into());
        }
    }
    Ok(())
}

pub(crate) fn check_batch_worker(selected: bool, actual: &[Bounds]) -> Result<(), String> {
    use std::io::Read;
    batch_reservation(actual)?;
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
    let value = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
    validate_batch_assignment(&value, selected, actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomness_batch_admission_pads_salts_to_shared_maximum_height() {
        let small = bounds();
        let large = Bounds {
            rows: small.rows * 4,
            quotient_rows: small.quotient_rows * 4,
            ..small
        };
        let actual = batch_reservation(&[small, large]).unwrap();
        let normalized = large.reservation(1).unwrap();
        assert_eq!(actual.managed_bytes, normalized.managed_bytes * 2);
        assert_eq!(actual.max_allocation_bytes, normalized.max_allocation_bytes);
        assert_eq!(actual.host_bytes, normalized.host_bytes);
        assert!(
            actual.managed_bytes
                > small.reservation(1).unwrap().managed_bytes + normalized.managed_bytes
        );
        assert_eq!(
            batch_reservation(&[small]).unwrap(),
            small.reservation(1).unwrap()
        );
        assert!(batch_reservation(&[]).is_err());
        assert!(batch_reservation(&vec![small; 257]).is_err());
        let value = assignment();
        validate_assignment(&value, true, Some(small)).unwrap();
        assert!(validate_batch_assignment(&value, true, &[small, small])
            .unwrap_err()
            .contains("AIR batch"));
        let mut roomy = value.clone();
        let declared = Bounds {
            rows: 256,
            quotient_rows: 4096,
            ..small
        };
        roomy["randomness_bounds"] = serde_json::to_value(declared).unwrap();
        roomy["randomness_reservation"] =
            serde_json::to_value(declared.reservation(1).unwrap()).unwrap();
        validate_batch_assignment(&roomy, true, &[small, large]).unwrap();
    }
    fn bounds() -> Bounds {
        Bounds {
            rows: 16,
            main_columns: 98,
            preprocessing_columns: 200,
            lookup_columns: 55,
            quotient_rows: 256,
            quotient_chunks: 16,
        }
    }
    fn assignment() -> serde_json::Value {
        serde_json::json!({
            "gpu_randomness":true,"gpu_witness":true,"gpu_pcs_device_only":true,
            "gpu_quotient_eval":true,"gpu_quotient_resident":true,"gpu_lookup":true,
            "gpu_opening_eval":true,"gpu_fri_resident":true,
            "randomness_bounds":bounds(),"randomness_reservation":bounds().reservation(1).unwrap(),
            "witness_bounds":{"rows":16,"main_columns":98,"preprocessing_columns":200},
            "owned_quotient_reservation":{"managed_bytes":1073741824},
            "witness_reservation":{"managed_bytes":2097152,"host_bytes":2097152},
            "gpu":{"managed_bytes":2147483648u64,"max_allocation_bytes":67108864},
            "host":{"worker_bytes":8388608}
        })
    }
    #[test]
    fn reservations_cover_salt_lifetimes_sampling_scratch_and_match_python() {
        assert_eq!(
            bounds().reservation(1).unwrap(),
            Reservation {
                managed_bytes: 71144,
                max_allocation_bytes: 16448,
                host_bytes: 1048576
            }
        );
        assert_eq!(bounds().reservation(3).unwrap().managed_bytes, 103912);
        let large = Bounds {
            rows: 16384,
            main_columns: 94,
            preprocessing_columns: 200,
            lookup_columns: 60,
            quotient_rows: 262144,
            quotient_chunks: 16,
        };
        assert_eq!(
            large.reservation(12).unwrap(),
            Reservation {
                managed_bytes: 248709352,
                max_allocation_bytes: 16777216,
                host_bytes: 1048576
            }
        );
        for invalid in [
            Bounds {
                rows: 0,
                ..bounds()
            },
            Bounds {
                rows: 3,
                ..bounds()
            },
            Bounds {
                quotient_chunks: 1,
                ..bounds()
            },
            Bounds {
                quotient_rows: 1 << 40,
                ..bounds()
            },
            Bounds {
                rows: 1 << 20,
                quotient_rows: 1 << 24,
                main_columns: 4096,
                ..bounds()
            },
        ] {
            assert!(invalid.reservation(1).is_err());
        }
        assert!(bounds().reservation(13).is_err());
    }
    #[test]
    fn worker_randomness_admission_rejects_aggregate_and_actual_geometry_drift() {
        let valid = assignment();
        validate_assignment(&valid, true, Some(bounds())).unwrap();
        assert!(validate_assignment(&valid, false, None).is_err());
        validate_assignment(&serde_json::json!({}), false, None).unwrap();
        for actual in [
            Bounds {
                main_columns: 99,
                ..bounds()
            },
            Bounds {
                lookup_columns: 56,
                ..bounds()
            },
            Bounds {
                quotient_rows: 128,
                quotient_chunks: 2,
                ..bounds()
            },
        ] {
            assert!(validate_assignment(&valid, true, Some(actual)).is_err());
        }
        for key in [
            "gpu_witness",
            "gpu_pcs_device_only",
            "gpu_lookup",
            "gpu_fri_resident",
        ] {
            let mut bad = valid.clone();
            bad[key] = false.into();
            assert!(validate_assignment(&bad, true, None).is_err());
        }
        let mut bad = valid.clone();
        bad["randomness_reservation"]["managed_bytes"] = 1.into();
        assert!(validate_assignment(&bad, true, None).is_err());
        let mut bad = valid.clone();
        bad["gpu"]["managed_bytes"] = (1073741824u64 + 2097152 + 71144 - 1).into();
        assert!(validate_assignment(&bad, true, None).is_err());
        let mut bad = valid.clone();
        bad["host"]["worker_bytes"] = (2097152 + 1048576 - 1).into();
        assert!(validate_assignment(&bad, true, None).is_err());
        let mut bad = valid.clone();
        bad["gpu"]["max_allocation_bytes"] = 16447.into();
        assert!(validate_assignment(&bad, true, None).is_err());
        let mut bad = valid;
        bad["witness_bounds"]["rows"] = 32.into();
        assert!(validate_assignment(&bad, true, None).is_err());
    }
}
