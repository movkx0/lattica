//! Additional witness resources. These are additive to the existing
//! commitment/opening phase plan, never a reason to reduce its allowance.
use super::super::{air, gpu_program, program::*};
use crate::block_v2::gpu_hash::device::{
    public_hash, PERIODIC_MAX_ALLOCATION_BYTES, PERIODIC_WORKSPACE_BYTES,
};
use serde::{Deserialize, Serialize};

#[cfg(all(test, feature = "stream"))]
#[path = "resources/lookup_tests.rs"]
mod lookup_tests;
#[cfg(all(test, feature = "stream"))]
#[path = "resources/retained_tests.rs"]
mod retained_tests;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bounds {
    pub rows: u64,
    pub main_columns: u64,
    pub preprocessing_columns: u64,
    pub metadata_bytes: u64,
    pub compiler_host_bytes: u64,
    /// Compact launch schedule retained after upload. Zero preserves the
    /// historical compiler_host_bytes - metadata_bytes cache allowance.
    #[serde(default)]
    pub compiler_retained_host_bytes: u64,
    /// Cached PCS/common/provenance metadata. Zero uses the conservative host
    /// salt path; an explicit device-salt bound must cover the actual setup.
    #[serde(default)]
    pub pcs_retained_host_bytes: u64,
    /// Construction/packing peak or retained source, whichever is larger.
    pub program_host_bytes: u64,
    /// Retained Arc-owned source per cache entry, including spare capacities.
    /// Zero (also the historical omitted field) uses program_host_bytes.
    #[serde(default)]
    pub program_retained_host_bytes: u64,
    pub wires: u64,
    pub input_values: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub managed_bytes: u64,
    pub max_allocation_bytes: u64,
    pub host_bytes: u64,
}

/// The existing witness component and PCS must fit the same assigned host RAM.
/// This partitions known payloads; it is not a complete process-RSS plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostPartition {
    pub total_bytes: u64,
    pub reserved_bytes: u64,
    pub pcs_bytes: u64,
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| "GPU witness resource overflow".into())
}
fn mul(a: u64, b: u64) -> Result<u64, String> {
    a.checked_mul(b)
        .ok_or_else(|| "GPU witness resource overflow".into())
}
#[cfg(test)]
fn bytes<T>(capacity: usize) -> Result<u64, String> {
    mul(capacity as u64, std::mem::size_of::<T>() as u64)
}

impl Bounds {
    /// Count public layout/capacities without evaluating fields, compiling
    /// instructions, or allocating matrices. Reuse the compiler's exact row
    /// and port layout, including partially filled rows and padded traces.
    pub(crate) fn for_program(program: &Program) -> Result<Self, String> {
        Self::for_program_with_device_salts(program, false)
    }

    pub(crate) fn for_program_with_device_salts(
        program: &Program,
        device_salts: bool,
    ) -> Result<Self, String> {
        let layout = gpu_program::Layout::new(program)
            .map_err(|e| format!("invalid GPU witness layout: {e:?}"))?;
        let source = program.source_host_bytes()? as u64;
        let bounds = Self {
            rows: program.height as u64,
            main_columns: air::WIDTH as u64,
            preprocessing_columns: air::PREPROCESSED_WIDTH as u64,
            metadata_bytes: mul(layout.words as u64, 8)?,
            compiler_host_bytes: layout.host_peak_bytes as u64,
            compiler_retained_host_bytes: layout.schedule_host_bytes as u64,
            pcs_retained_host_bytes: crate::block_v2::gpu_hash::cache_metadata::bound(
                program.height as u64,
                device_salts,
            )?,
            program_host_bytes: source.max(program.construction_host_bytes() as u64),
            program_retained_host_bytes: source,
            wires: program.references.len() as u64,
            input_values: add(program.publics as u64, program.witnesses as u64)?,
        };
        bounds.reservation(1)?;
        Ok(bounds)
    }

    pub(crate) fn reservation(&self, cached_programs: u64) -> Result<Reservation, String> {
        if !(8..=1 << 24).contains(&self.rows)
            || !self.rows.is_power_of_two()
            || !(1..=4096).contains(&self.main_columns)
            || !(1..=4096).contains(&self.preprocessing_columns)
            || self.metadata_bytes < 24 * 8
            || self.metadata_bytes % 8 != 0
            || self.compiler_host_bytes < self.metadata_bytes
            || self.compiler_retained_host_bytes
                > self.compiler_host_bytes.saturating_sub(self.metadata_bytes)
            || self.program_host_bytes == 0
            || self.program_retained_host_bytes > self.program_host_bytes
            || self.wires > MAX_WIRES as u64
            || self.input_values > self.wires
            || !(1..=12).contains(&cached_programs)
        {
            return Err("invalid GPU witness resource bounds".into());
        }
        let trace = mul(mul(self.rows, self.main_columns)?, 8)?;
        let preprocessing = mul(mul(self.rows, self.preprocessing_columns)?, 8)?;
        let wires = mul(self.wires.max(1), 8)?;
        let inputs = mul(self.input_values.max(1), 8)?;
        let samples = mul(mul(self.rows, add(self.main_columns, 8)?)?, 8)?;
        let work = add(trace, add(wires, add(inputs, 8)?)?)?
            .max(add(preprocessing, 8)?)
            .max(add(trace, add(samples, 8)?)?);
        let managed = add(
            add(mul(self.metadata_bytes, cached_programs)?, work)?,
            // Periodic inverse NTT and public hashing are sequential compiler
            // operations. Reserve their maximum, not simultaneous payloads.
            public_hash::WORKSPACE_BYTES.max(PERIODIC_WORKSPACE_BYTES),
        )?;
        // Uploaded instruction words are not retained on the host. The
        // compact launch schedule has a separate retained allowance. Historical
        // assignments conservatively include discarded compiler work arrays. Keep a
        // retained source and schedule per cache entry. Construction history
        // is transient, not persistent cache storage. A compiler-sized manifest and
        // staging can coexist during setup; incoming source/input data can
        // instead coexist with the full cache before a hit or eviction.
        // Explicit debug readbacks remain covered by the staging bound.
        // Cached lookup graphs survive into incoming source construction,
        // symbolic setup, proving and independent verification. Packing caps
        // each retained graph; moving it into CommonData preserves ownership.
        // Keep a full symbolic workspace as well, including its new output.
        let retained_lookups = crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES;
        let retained_pcs = self.retained_pcs_bytes()?;
        let retained_compiler = self.retained_compiler_bytes();
        let input_staging = add(mul(inputs, 3)?, 8)?;
        let staging = input_staging.max(samples).max(mul(trace, 2)?);
        let transient = add(self.compiler_host_bytes, staging)?
            .max(add(self.program_host_bytes, input_staging)?);
        // Independent result verification overlaps the proving cache and its
        // retained metadata. Reserve one lifecycle per serial worker, not one
        // per cached program; the verifier is dropped before the next job.
        let host = add(
            add(
                mul(
                    add(
                        add(self.retained_program_bytes(), retained_compiler)?,
                        add(retained_lookups, retained_pcs)?,
                    )?,
                    cached_programs,
                )?,
                transient,
            )?,
            (1 << 20)
                + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
                + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES
                + public_hash::HOST_BYTES
                + crate::block_v2::machine::symbolic::HOST_BYTES
                + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES,
        )?;
        Ok(Reservation {
            managed_bytes: managed,
            max_allocation_bytes: [
                self.metadata_bytes,
                trace,
                preprocessing,
                wires,
                inputs,
                samples,
                public_hash::MAX_ALLOCATION_BYTES,
                PERIODIC_MAX_ALLOCATION_BYTES,
                8,
            ]
            .into_iter()
            .max()
            .unwrap(),
            host_bytes: host,
        })
    }

    /// Admit host scratch before constructing PCS state or a device session.
    pub(crate) fn admit_host(&self, allowance: u64) -> Result<Reservation, String> {
        let reservation = self.reservation(1)?;
        if reservation.host_bytes > allowance {
            return Err("GPU witness source/compiler/staging exceeds host allowance".into());
        }
        Ok(reservation)
    }

    pub(crate) fn partition_host(&self, allowance: u64) -> Result<HostPartition, String> {
        let reserved_bytes = self.admit_host(allowance)?.host_bytes;
        let pcs_bytes = allowance
            .checked_sub(reserved_bytes)
            .filter(|bytes| *bytes != 0)
            .ok_or("GPU registered PCS requires RAM after witness reservation")?;
        Ok(HostPartition {
            total_bytes: allowance,
            reserved_bytes,
            pcs_bytes,
        })
    }

    fn covers(&self, actual: &Self) -> bool {
        let (Ok(declared_pcs), Ok(actual_pcs)) =
            (self.retained_pcs_bytes(), actual.retained_pcs_bytes())
        else {
            return false;
        };
        self.rows >= actual.rows
            && declared_pcs >= actual_pcs
            && self.main_columns >= actual.main_columns
            && self.preprocessing_columns >= actual.preprocessing_columns
            && self.metadata_bytes >= actual.metadata_bytes
            && self.compiler_host_bytes >= actual.compiler_host_bytes
            && self.retained_compiler_bytes() >= actual.retained_compiler_bytes()
            && self.program_host_bytes >= actual.program_host_bytes
            && self.retained_program_bytes() >= actual.retained_program_bytes()
            && self.wires >= actual.wires
            && self.input_values >= actual.input_values
    }

    fn retained_program_bytes(&self) -> u64 {
        if self.program_retained_host_bytes == 0 {
            self.program_host_bytes
        } else {
            self.program_retained_host_bytes
        }
    }

    fn retained_pcs_bytes(&self) -> Result<u64, String> {
        use crate::block_v2::gpu_hash::cache_metadata::{bound, METADATA_BYTES};
        let conservative = bound(self.rows, false)?;
        if self.pcs_retained_host_bytes == 0 {
            Ok(conservative)
        } else if (METADATA_BYTES..=conservative).contains(&self.pcs_retained_host_bytes) {
            Ok(self.pcs_retained_host_bytes)
        } else {
            Err("invalid retained PCS metadata allowance".into())
        }
    }

    fn retained_compiler_bytes(&self) -> u64 {
        if self.compiler_retained_host_bytes == 0 {
            self.compiler_host_bytes.saturating_sub(self.metadata_bytes)
        } else {
            self.compiler_retained_host_bytes
        }
    }
}

pub(crate) fn validate_assignment(
    value: &serde_json::Value,
    selected: bool,
    actual: Option<&Bounds>,
) -> Result<(), String> {
    let assigned = match value.get("gpu_witness") {
        None => false,
        Some(value) => value.as_bool().ok_or("invalid GPU witness assignment")?,
    };
    if assigned != selected {
        return Err("GPU witness selection differs from worker assignment".into());
    }
    if !selected {
        return Ok(());
    }
    if [
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
        return Err("GPU witness assignment lacks its owned device-only consumers".into());
    }
    let bounds: Bounds = serde_json::from_value(
        value
            .get("witness_bounds")
            .ok_or("missing GPU witness bounds")?
            .clone(),
    )
    .map_err(|e| e.to_string())?;
    let reservation: Reservation = serde_json::from_value(
        value
            .get("witness_reservation")
            .ok_or("missing GPU witness reservation")?
            .clone(),
    )
    .map_err(|e| e.to_string())?;
    let entries = match value.get("preprocessing_cache") {
        None => 1,
        Some(cache) => cache["entries"]
            .as_u64()
            .ok_or("invalid GPU witness cache count")?,
    };
    if reservation != bounds.reservation(entries)?
        || actual.is_some_and(|actual| !bounds.covers(actual))
    {
        return Err("program exceeds its assigned GPU witness bounds or reservation".into());
    }
    let owned = value["owned_quotient_reservation"]["managed_bytes"]
        .as_u64()
        .ok_or("missing owned GPU reservation")?;
    if add(reservation.managed_bytes, owned)?
        > value["gpu"]["managed_bytes"]
            .as_u64()
            .ok_or("missing GPU allowance")?
        || reservation.max_allocation_bytes
            > value["gpu"]["max_allocation_bytes"]
                .as_u64()
                .ok_or("missing GPU allocation allowance")?
        || reservation.host_bytes
            > value["host"]["worker_bytes"]
                .as_u64()
                .ok_or("missing host allowance")?
    {
        return Err("GPU witness reservation exceeds worker allowance".into());
    }
    Ok(())
}

/// Reserve every live program and trace. Summing full per-program peaks also
/// covers the compiler and staging scratch used sequentially during setup.
pub(crate) fn batch_reservation(actual: &[Bounds]) -> Result<Reservation, String> {
    if actual.is_empty() || actual.len() > 256 {
        return Err("GPU witness AIR count exceeded".into());
    }
    let mut total = Reservation {
        managed_bytes: 0,
        max_allocation_bytes: 0,
        host_bytes: 0,
    };
    for bounds in actual {
        let reserve = bounds.reservation(1)?;
        total.managed_bytes = add(total.managed_bytes, reserve.managed_bytes)?;
        total.max_allocation_bytes = total.max_allocation_bytes.max(reserve.max_allocation_bytes);
        total.host_bytes = add(total.host_bytes, reserve.host_bytes)?;
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
        validate_assignment(value, selected, Some(bounds))?;
    }
    if selected {
        let reserved: Reservation = serde_json::from_value(value["witness_reservation"].clone())
            .map_err(|e| format!("invalid GPU witness reservation: {e}"))?;
        if needed.managed_bytes > reserved.managed_bytes
            || needed.max_allocation_bytes > reserved.max_allocation_bytes
            || needed.host_bytes > reserved.host_bytes
        {
            return Err("AIR batch exceeds assigned GPU witness reservation".into());
        }
    }
    Ok(())
}

fn worker_assignment() -> Result<Option<serde_json::Value>, String> {
    use std::io::Read;
    let Some(path) = std::env::var_os("LATTICA_V2_WORKER_BUDGET") else {
        return Ok(None);
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
    Ok(Some(value))
}

pub(crate) fn check_worker(selected: bool, actual: Option<&Bounds>) -> Result<(), String> {
    match worker_assignment()? {
        Some(value) => validate_assignment(&value, selected, actual),
        None => Ok(()),
    }
}

/// The same admitted program allowance bounds construction before an actual
/// immutable Program exists. Do not infer a budget from a measured peak.
pub(crate) fn construction_bounds() -> Result<Option<Bounds>, String> {
    let Some(value) = worker_assignment()? else {
        return Ok(None);
    };
    validate_assignment(&value, true, None)?;
    serde_json::from_value(value["witness_bounds"].clone())
        .map(Some)
        .map_err(|e| format!("invalid program construction bounds: {e}"))
}

pub(crate) fn check_batch_worker(selected: bool, actual: &[Bounds]) -> Result<(), String> {
    match worker_assignment()? {
        Some(value) => validate_batch_assignment(&value, selected, actual),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn compiled_program_bound_uses_the_selected_preprocessing_salt_storage() {
        let program = ProgramBuilder::new(0).unwrap().finish(None).unwrap();
        let host = Bounds::for_program(&program).unwrap();
        let device = Bounds::for_program_with_device_salts(&program, true).unwrap();
        assert_eq!(device.pcs_retained_host_bytes, 1 << 20);
        assert_eq!(
            host.pcs_retained_host_bytes - device.pcs_retained_host_bytes,
            host.rows * 1024
        );
        assert!(host.covers(&device));
        assert!(!device.covers(&host));
        let mut json = serde_json::to_value(&host).unwrap();
        for bad in [
            serde_json::json!(true),
            serde_json::json!(-1),
            serde_json::json!("1048576"),
        ] {
            json["pcs_retained_host_bytes"] = bad;
            assert!(serde_json::from_value::<Bounds>(json.clone()).is_err());
        }
    }

    #[test]
    fn pcs_cache_bounds_separate_public_device_handles_from_host_salt_matrices() {
        let historical = bounds();
        let mut device = historical.clone();
        device.pcs_retained_host_bytes = 1 << 20;
        for entries in [1, 3, 12] {
            let old = historical.reservation(entries).unwrap();
            let new = device.reservation(entries).unwrap();
            assert_eq!(
                old.host_bytes - new.host_bytes,
                entries * historical.rows * 1024
            );
            assert_eq!(old.managed_bytes, new.managed_bytes);
            assert_eq!(old.max_allocation_bytes, new.max_allocation_bytes);
        }
        assert!(historical.covers(&device));
        assert!(!device.covers(&historical));
        device.compiler_host_bytes *= 2;
        assert!(!device.covers(&historical));
        for bad in [
            1,
            (1 << 20) - 1,
            historical.retained_pcs_bytes().unwrap() + 1,
            u64::MAX,
        ] {
            let mut invalid = historical.clone();
            invalid.pcs_retained_host_bytes = bad;
            assert!(invalid.reservation(1).is_err());
        }
        let mut json = serde_json::to_value(&historical).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("pcs_retained_host_bytes");
        let decoded: Bounds = serde_json::from_value(json).unwrap();
        assert_eq!(
            decoded.reservation(3).unwrap(),
            historical.reservation(3).unwrap()
        );
        eprintln!("cached_pcs_reservation entries=1,3,12 host_salts_separate=true compiler_peak_cannot_hide_understatement=true legacy_default_conservative=true");
    }

    #[test]
    fn witness_batch_admission_checks_all_live_programs() {
        let b = bounds();
        let one = b.reservation(1).unwrap();
        assert_eq!(batch_reservation(&[b.clone()]).unwrap(), one);
        let two = batch_reservation(&[b.clone(), b.clone()]).unwrap();
        assert_eq!(two.managed_bytes, one.managed_bytes * 2);
        assert_eq!(two.host_bytes, one.host_bytes * 2);
        assert_eq!(two.max_allocation_bytes, one.max_allocation_bytes);
        assert!(batch_reservation(&[]).is_err());
        assert!(batch_reservation(&vec![b.clone(); 257]).is_err());
        let mut value = serde_json::json!({
            "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
            "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
            "witness_bounds":b,"witness_reservation":one,
            "owned_quotient_reservation":{"managed_bytes":67108864},
            "gpu":{"managed_bytes":2147483648u64,"max_allocation_bytes":1073741824u64},
            "host":{"worker_bytes":2147483648u64}
        });
        validate_assignment(&value, true, Some(&b)).unwrap();
        assert!(
            validate_batch_assignment(&value, true, &[b.clone(), b.clone()])
                .unwrap_err()
                .contains("AIR batch")
        );
        // A larger existing assignment can admit a batch without a schema change.
        let mut declared = b.clone();
        declared.rows *= 4;
        declared.metadata_bytes *= 4;
        declared.compiler_host_bytes = 512 << 20;
        declared.program_host_bytes *= 16;
        value["witness_bounds"] = serde_json::to_value(&declared).unwrap();
        value["witness_reservation"] =
            serde_json::to_value(declared.reservation(1).unwrap()).unwrap();
        validate_batch_assignment(&value, true, &[b.clone(), b.clone()]).unwrap();
        assert!(validate_batch_assignment(&value, false, &[b]).is_err());
    }

    fn bounds() -> Bounds {
        Bounds {
            rows: 16,
            main_columns: 98,
            preprocessing_columns: 200,
            metadata_bytes: 65536,
            compiler_host_bytes: 262144,
            compiler_retained_host_bytes: 0,
            pcs_retained_host_bytes: 0,
            program_host_bytes: 1048576,
            program_retained_host_bytes: 0,
            wires: 4096,
            input_values: 64,
        }
    }

    #[test]
    fn witness_bounds_cover_compiler_storage_and_shared_python_reservation() {
        let mut b = ProgramBuilder::new(33).unwrap();
        let x = b.input();
        let c = b.constant(Val::ONE);
        let product = b.mul(x, c);
        let bit = b.bit_hint(product, 63);
        let _hint = b.select_hint(vec![x, product], &[bit]);
        let _hash = b.poseidon([x; 8]);
        let original = b.finish(None).unwrap();
        for height in [original.height(), 256] {
            let program = original.clone().pad_to(height).unwrap();
            let estimated = Bounds::for_program(&program).unwrap();
            let compiled = gpu_program::WitnessProgram::compile(&program, usize::MAX).unwrap();
            assert_eq!(estimated.metadata_bytes, compiled.words.len() as u64 * 8);
            assert_eq!(
                estimated.compiler_host_bytes,
                compiled.host_peak_bytes as u64
            );
            assert_eq!(
                estimated.metadata_bytes,
                Bounds::for_program(&original).unwrap().metadata_bytes
            );
            assert!(estimated.program_host_bytes > std::mem::size_of::<Program>() as u64);
            assert!(estimated.program_host_bytes >= program.construction_host_bytes() as u64);
            assert_eq!(estimated.wires, program.wire_count() as u64);
            assert_eq!(estimated.input_values, 34);
        }
        let b = bounds();
        assert_eq!(
            b.reservation(1).unwrap(),
            Reservation {
                managed_bytes: 897816,
                max_allocation_bytes: 524288,
                host_bytes: 3409416
                    + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
                    + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES
                    + crate::block_v2::machine::symbolic::HOST_BYTES
                    + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
                    + b.retained_pcs_bytes().unwrap()
                    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES,
            }
        );
        let single = b.reservation(1).unwrap();
        assert_eq!(b.admit_host(single.host_bytes).unwrap(), single);
        assert!(b.admit_host(single.host_bytes - 1).is_err());
        let cached = b.reservation(3).unwrap();
        assert_eq!(cached.managed_bytes, 897816 + 2 * 65536);
        assert_eq!(
            cached.host_bytes,
            3409416
                + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
                + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES
                + crate::block_v2::machine::symbolic::HOST_BYTES
                + 3 * crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
                + 3 * b.retained_pcs_bytes().unwrap()
                + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES
                + 2 * (1048576 + 262144 - 65536)
        );
        for entries in [0, 13, u64::MAX] {
            assert!(b.reservation(entries).is_err());
        }
        let mut bad = b;
        bad.program_host_bytes = u64::MAX;
        assert!(bad.reservation(1).is_err());
    }

    #[test]
    fn host_partition_preserves_both_components_at_exact_boundaries() {
        let b = bounds();
        let reserved = b.reservation(1).unwrap().host_bytes;
        for total in [0, reserved - 1, reserved] {
            assert!(b.partition_host(total).is_err());
        }
        for pcs in [1, 1024, 1 << 30, u64::MAX - reserved] {
            let plan = b.partition_host(reserved + pcs).unwrap();
            assert_eq!(plan.reserved_bytes, reserved);
            assert_eq!(plan.pcs_bytes, pcs);
            assert_eq!(plan.reserved_bytes + plan.pcs_bytes, plan.total_bytes);
        }
        let total = reserved + (1 << 30);
        let mut larger = b.clone();
        larger.program_host_bytes += 1024;
        let enlarged = larger.partition_host(total).unwrap();
        assert!(enlarged.reserved_bytes > reserved);
        assert!(enlarged.pcs_bytes < 1 << 30);
        assert_eq!(enlarged.total_bytes, total);
        larger.program_host_bytes = u64::MAX;
        assert!(larger.partition_host(u64::MAX).is_err());
        eprintln!("registered_host_partition_boundaries short_rejections=3 exact_remainders=4 component_growth_reduces_pcs=true overflow_rejected=true");
    }

    #[test]
    fn program_allowance_covers_construction_history_and_current_retained_storage() {
        let mut builder = ProgramBuilder::new(0).unwrap();
        builder
            .with_digest_scratch(&[[Wire(0); 4]; 128], |_, _| Ok(()))
            .unwrap();
        let program = builder.finish(None).unwrap();
        let construction = program.construction_host_bytes() as u64;
        let original = Bounds::for_program(&program).unwrap();
        assert_eq!(original.program_host_bytes, construction);
        assert!(original.program_retained_host_bytes < construction);
        let mut cloned = program.clone().pad_to(256).unwrap();
        assert_eq!(
            Bounds::for_program(&cloned).unwrap().program_host_bytes,
            construction
        );
        // Extra retained capacity can exceed the original construction peak.
        // Admission must count that capacity even though identity is unchanged.
        cloned.operations.reserve_exact(1024);
        let expanded = Bounds::for_program(&cloned).unwrap();
        assert!(expanded.program_host_bytes > construction);
        assert_eq!(
            expanded.program_host_bytes,
            expanded.program_retained_host_bytes
        );
        assert!(expanded.program_host_bytes >= bytes::<Op>(cloned.operations.capacity()).unwrap());
        assert_eq!(cloned, program.pad_to(256).unwrap());
        assert!(
            expanded.reservation(1).unwrap().host_bytes
                > original.reservation(1).unwrap().host_bytes
        );
    }

    #[test]
    fn retained_schedule_bounds_cannot_be_reduced_by_inflating_metadata() {
        let actual = bounds();
        let mut declared = actual.clone();
        declared.metadata_bytes += 8;
        assert!(!declared.covers(&actual));
        declared.compiler_host_bytes += 8;
        assert!(declared.covers(&actual));
    }

    #[test]
    fn full_size_merge_reserves_incoming_source_while_cache_is_live() {
        let b = Bounds {
            rows: 262144,
            main_columns: 94,
            preprocessing_columns: 200,
            metadata_bytes: 621708376,
            compiler_host_bytes: 734973680,
            compiler_retained_host_bytes: 0,
            pcs_retained_host_bytes: 0,
            program_host_bytes: 1142607740,
            program_retained_host_bytes: 0,
            wires: 3669207,
            input_values: 419117,
        };
        assert_eq!(
            b.reservation(1).unwrap(),
            Reservation {
                managed_bytes: 1041925232,
                max_allocation_bytes: 621708376,
                host_bytes: 2610980304
                    + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
                    + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES
                    + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
                    + b.retained_pcs_bytes().unwrap()
                    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES,
            }
        );
        // A second incoming source grows the transient peak as well as the
        // retained cache; it cannot be hidden by the released upload buffer.
        let mut larger = b.clone();
        larger.program_host_bytes += 1 << 20;
        assert_eq!(
            larger.reservation(1).unwrap().host_bytes,
            b.reservation(1).unwrap().host_bytes + (2 << 20)
        );
    }

    #[test]
    fn worker_witness_assignment_rejects_mode_geometry_reservation_and_aggregate_drift() {
        let b = bounds();
        let mut value = serde_json::json!({
            "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
            "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
            "witness_bounds":b,"witness_reservation":b.reservation(1).unwrap(),
            "owned_quotient_reservation":{"managed_bytes":67108864},
            "gpu":{"version":1,"managed_bytes":268435456,"max_allocation_bytes":67108864},
            "host":{"worker_bytes":1073741824}
        });
        validate_assignment(&value, true, Some(&b)).unwrap();
        assert!(validate_assignment(&value, false, None).is_err());
        for key in [
            "metadata_bytes",
            "compiler_host_bytes",
            "program_host_bytes",
            "wires",
            "input_values",
            "rows",
            "main_columns",
            "preprocessing_columns",
        ] {
            let mut actual = serde_json::to_value(&b).unwrap();
            actual[key] = serde_json::json!(actual[key].as_u64().unwrap() + 1);
            let actual = serde_json::from_value(actual).unwrap();
            assert!(
                validate_assignment(&value, true, Some(&actual)).is_err(),
                "{key}"
            );
        }
        for key in [
            "gpu_pcs_device_only",
            "gpu_quotient_eval",
            "gpu_quotient_resident",
            "gpu_lookup",
            "gpu_opening_eval",
            "gpu_fri_resident",
        ] {
            let mut changed = value.clone();
            changed[key] = false.into();
            assert!(validate_assignment(&changed, true, Some(&b)).is_err());
        }
        for key in ["managed_bytes", "max_allocation_bytes", "host_bytes"] {
            let mut changed = value.clone();
            changed["witness_reservation"][key] = 1.into();
            assert!(validate_assignment(&changed, true, Some(&b)).is_err());
        }
        value["gpu"]["managed_bytes"] =
            (67108864u64 + b.reservation(1).unwrap().managed_bytes - 1).into();
        assert!(validate_assignment(&value, true, Some(&b)).is_err());
        validate_assignment(&serde_json::json!({}), false, None).unwrap();
    }
}
