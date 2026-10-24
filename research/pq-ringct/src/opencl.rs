//! Opt-in qualification of existing portable OpenCL proving for PQ components.
//!
//! The small byte/modular relation is a diagnostic. The AES stage recursively
//! verifies the existing typed AES component proof. Neither accepts a complete
//! MatRiCT spend, changes the protocol, nor establishes an AMD speedup.
//! Call from a fresh, externally memory-limited process, after exclusive proof
//! admission. Initialization is explicit and a failed GPU request never falls back.

use lattica_prover_p3::{
    block_v2::{
        gpu_hash,
        machine::{
            backend::RegisteredProgram, pq_bytes::Byte, pq_modular, program::Val, MachineAir,
            Program, ProgramBuilder,
        },
        profile, quotient_pcs,
    },
    proving::{Policy, Request},
};
use p3_field::PrimeCharacteristicRing;
use serde_json::{json, Value};
use std::time::Instant;

mod aes_component;
mod session;
pub use session::Session;

pub const SCHEMA: &str = "lattica-pq-opencl-qualification-v1";
// Existing portable NTT launches cap their workgroup at this fixed size.
// This is only a device-level admission floor, not per-kernel qualification.
const REQUIRED_DEVICE_WORK_GROUP_SIZE: usize = 256;
/// Full owned path. Missing switches are errors, never CPU compatibility mode.
pub const REQUIRED_SWITCHES: &[&str] = &[
    "LATTICA_V2_GPU_HASH",
    "LATTICA_V2_GPU_RETAIN_TREES",
    "LATTICA_V2_GPU_QUERY_GATHER",
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
    "LATTICA_V2_GPU_FRI_FOLD",
    "LATTICA_PROVING_REPORT",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    PqByte,
    PqAesComponent,
}
impl Stage {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "pq-byte" => Ok(Self::PqByte),
            "pq-aes-component" => Ok(Self::PqAesComponent),
            _ => Err("stage must be pq-byte or pq-aes-component".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::PqByte => "pq-byte",
            Self::PqAesComponent => "pq-aes-component",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub host_bytes: u64,
    pub device_bytes: u64,
    pub max_rows: usize,
}
impl Limits {
    pub fn validate(self) -> Result<(), String> {
        require(
            (1_u64 << 30..=32_u64 << 30).contains(&self.host_bytes),
            "host allowance must be between 1 and 32 GiB",
        )?;
        require(
            (256_u64 << 20..=12_u64 << 30).contains(&self.device_bytes),
            "device allowance must be between 256 MiB and 12 GiB",
        )?;
        require(
            self.max_rows.is_power_of_two() && self.max_rows <= 1 << 22,
            "max rows must be a positive power of two at most 2^22",
        )
    }
    pub fn check_rows(self, rows: usize) -> Result<(), String> {
        require(
            rows.is_power_of_two(),
            "compiled rows must be a positive power of two",
        )?;
        require(
            rows <= self.max_rows,
            "compiled relation exceeds admitted row limit",
        )
    }
}
fn err(value: impl std::fmt::Debug) -> String {
    format!("{value:?}")
}
fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
/// The tamper probe needs a genuine extension-field lookup opening. Reject an
/// unexpected proof shape explicitly rather than substituting a header mutation.
fn lookup_opening_mut(
    proof: &mut p3_batch_stark::BatchProof<profile::Config>,
) -> Result<&mut profile::Challenge, String> {
    proof
        .opened_values
        .instances
        .first_mut()
        .and_then(|instance| instance.permutation_local.first_mut())
        .ok_or_else(|| "qualification proof is missing its lookup opening".into())
}
fn strict() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    }
}

/// Every registration and proof in an OpenCL session must use this policy.
pub fn strict_request() -> Request {
    strict()
}

fn check_environment(limits: Limits) -> Result<(), String> {
    limits.validate()?;
    require(
        !cfg!(debug_assertions),
        "GPU qualification requires a release build; debug constraint audits use CPU",
    )?;
    for name in REQUIRED_SWITCHES {
        require(
            std::env::var(name).as_deref() == Ok("1"),
            &format!("{name}=1 is required"),
        )?;
    }
    require(
        std::env::var("LATTICA_PROVING_POLICY").as_deref() == Ok("gpu-required"),
        "LATTICA_PROVING_POLICY=gpu-required is required",
    )?;
    let bytes = std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")
        .map_err(err)?
        .parse::<u64>()
        .map_err(err)?;
    require(
        bytes == limits.device_bytes,
        "managed device bytes differ from explicit allowance",
    )?;
    let host_output = std::env::var("LATTICA_V2_HOST_OUTPUT_BYTES")
        .map_err(err)?
        .parse::<u64>()
        .map_err(err)?;
    require(
        host_output > 0 && host_output <= limits.host_bytes,
        "host output allowance must be positive and no larger than the admitted host allowance",
    )?;
    require(
        std::env::var_os("LATTICA_V2_GPU_DEVICE").is_some()
            || std::env::var_os("LATTICA_GPU_DEVICE_UUID").is_some(),
        "an explicit OpenCL GPU index or UUID is required",
    )?;
    require(
        profile::NUM_QUERIES == 128
            && profile::LOG_BLOWUP == 4
            && profile::CHALLENGE_FIELD_BITS == 191
            && profile::NUM_RANDOM_CODEWORDS == 4,
        "qualification requires the unchanged hiding cubic profile",
    )
}

fn initialize() -> Result<(), String> {
    let fusion = quotient_pcs::initialize_research_from_env()?;
    require(fusion, "quotient fusion was not selected")?;
    require(
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)?,
        "GPU quotient was not selected",
    )?;
    gpu_hash::initialize_from_env()?;
    require(
        gpu_hash::initialize_resident_from_env()?,
        "resident GPU PCS was not selected",
    )
}

/// Two byte witnesses and an exact modular product under MatRiCT's actual Q.
/// The high residue makes the quotient nonzero, exercising bounded reduction.
fn byte_fixture() -> Result<(Program, Vec<Val>, Vec<Val>), String> {
    let mut b = ProgramBuilder::new(2).map_err(err)?;
    let x = Byte::input(&mut b);
    let y = Byte::input(&mut b);
    let xor = x.xor(&mut b, y).to_wire(&mut b);
    let expected_xor = b.public(0).map_err(err)?;
    b.assert_equal(xor, expected_xor);
    let x = x.to_wire(&mut b);
    let modulus = pq_modular::Modulus::new(crate::rust_verify::Q as u32).map_err(err)?;
    let x = pq_modular::canonical(&mut b, x, modulus);
    let high = b.input();
    let high = pq_modular::canonical(&mut b, high, modulus);
    let quotient = b.input();
    let remainder = b.public(1).map_err(err)?;
    pq_modular::mul(&mut b, x, high, quotient, remainder).map_err(err)?;
    let a = 173_u64;
    let c = crate::rust_verify::Q - 1;
    let public = vec![
        Val::from_u64(a ^ 91),
        Val::from_u64((a * c) % crate::rust_verify::Q),
    ];
    let witness = vec![
        Val::from_u64(a),
        Val::from_u64(91),
        Val::from_u64(c),
        Val::from_u64((a * c) / crate::rust_verify::Q),
    ];
    Ok((b.finish(None).map_err(err)?, public, witness))
}

fn byte_proof(limits: Limits) -> Result<Value, String> {
    let (program, public, witness) = byte_fixture()?;
    limits.check_rows(program.height())?;
    let rows = program.height();
    let air = MachineAir::new(program);
    // This explicit CPU oracle checks fixture construction, not GPU coverage.
    // Use the public trace constructor; Program::evaluate is crate-private.
    drop(air.trace(&public, &witness).map_err(err)?);
    let registered =
        RegisteredProgram::new_with_request(air, limits.host_bytes, strict()).map_err(err)?;
    let started = Instant::now();
    let mut proof = registered
        .prove_with_request(&public, &witness, strict())
        .map_err(err)?;
    let proving_seconds = started.elapsed().as_secs_f64();
    let verifier = registered.verifier();
    drop(registered);
    verifier.verify(&proof, &public)?;
    let mut wrong = public.clone();
    wrong[0] += Val::ONE;
    require(
        verifier.verify(&proof, &wrong).is_err(),
        "changed byte public value accepted",
    )?;
    let opening = lookup_opening_mut(&mut proof)?;
    let original = *opening;
    *opening += profile::Challenge::ONE;
    require(
        verifier.verify(&proof, &public).is_err(),
        "changed byte proof accepted",
    )?;
    *lookup_opening_mut(&mut proof)? = original;
    verifier.verify(&proof, &public)?;
    Ok(
        json!({"scope": "PQ byte decomposition/XOR and production-modulus reduction diagnostic",
        "recursive_component": false, "rows": rows, "proving_seconds": proving_seconds,
        "native_child_backend": null, "proof_json_bytes": serde_json::to_vec(&proof).map_err(err)?.len()}),
    )
}

/// Executes only after the caller has independently admitted the complete job.
/// The harness must also validate native strict `proving_stage_report` records.
pub fn qualify(stage: Stage, limits: Limits) -> Result<Value, String> {
    check_environment(limits)?;
    let (_, device, identity) = lattica_prover_p3::gpu_device::select()?;
    let device_max_work_group_size = device.max_wg_size().map_err(err)?;
    require(
        device_max_work_group_size >= REQUIRED_DEVICE_WORK_GROUP_SIZE,
        &format!(
            "selected OpenCL device reports maximum workgroup {device_max_work_group_size}; existing NTT path requires at least {REQUIRED_DEVICE_WORK_GROUP_SIZE}"
        ),
    )?;
    // Match the engine's default and minimum; this reserve is separate from
    // managed buffers and is not inferred from currently unused VRAM.
    let reserve = match std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES") {
        Ok(value) => value.parse::<u64>().map_err(err)?,
        Err(std::env::VarError::NotPresent) => 4_u64 << 30,
        Err(error) => return Err(err(error)),
    };
    require(
        reserve >= 512 << 20,
        "GPU context allowance below engine minimum",
    )?;
    require(
        limits
            .device_bytes
            .checked_add(reserve)
            .is_some_and(|n| n <= identity.global_bytes),
        "managed GPU budget plus driver reserve exceeds device memory",
    )?;
    // Fail unavailable-device/resource checks before doing native proof work.
    // CPU generation/compilation is explicit and precedes GPU initialization.
    let aes = if stage == Stage::PqAesComponent {
        Some(aes_component::prepare(limits)?)
    } else {
        None
    };
    let outcome: Result<Value, String> = (|| {
        initialize()?;
        let details = match aes {
            Some(prepared) => prepared.prove(limits)?,
            None => byte_proof(limits)?,
        };
        gpu_hash::drain()?;
        let snapshot = gpu_hash::report("pq-opencl qualification complete")
            .ok_or("missing initialized OpenCL engine observations")?;
        require(
            snapshot.commits > 0 && snapshot.allocations > 0,
            "no completed GPU commitment work observed",
        )?;
        Ok(
            json!({"schema": SCHEMA, "stage": stage.name(), "passed": true,
            "cpu_verification": true, "changed_public_rejected": true,
            "changed_proof_rejected": true, "complete_transaction_qualified": false,
            "original_profile": true, "num_queries": 128, "blowup": 16,
            "extension": "Goldilocks cubic trinomial", "hiding": true,
            "strict_stage_reports_required": true, "device": identity,
            "device_work_group_admission": {
                "observed_max": device_max_work_group_size,
                "required_min": REQUIRED_DEVICE_WORK_GROUP_SIZE,
                "scope": "Device-level limit only; per-kernel limits and AMD execution remain unqualified"
            },
            "host_allowance_bytes": limits.host_bytes, "device_allowance_bytes": limits.device_bytes,
            "max_rows": limits.max_rows, "gpu_context_allowance_bytes": reserve, "details": details,
            "gpu": {"commits": snapshot.commits, "allocations": snapshot.allocations,
                "managed_peak_bytes": snapshot.managed_peak_bytes,
                "uploaded_bytes": snapshot.uploaded_bytes, "downloaded_bytes": snapshot.downloaded_bytes},
            "claims": "Component qualification only; no complete spend, transaction-size, throughput, or cross-vendor speedup claim"}),
        )
    })();
    let shutdown = gpu_hash::shutdown();
    match (outcome, shutdown) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!("GPU shutdown failed: {error}")),
        (Err(error), Err(cleanup)) => Err(format!("{error}; GPU shutdown failed: {cleanup}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_reject_unbounded_or_invalid_geometry() {
        let valid = Limits {
            host_bytes: 4 << 30,
            device_bytes: 2 << 30,
            max_rows: 1 << 20,
        };
        valid.validate().unwrap();
        for invalid in [
            Limits {
                host_bytes: 0,
                ..valid
            },
            Limits {
                device_bytes: 13 << 30,
                ..valid
            },
            Limits {
                max_rows: 0,
                ..valid
            },
            Limits {
                max_rows: 17,
                ..valid
            },
        ] {
            assert!(invalid.validate().is_err());
        }
        assert!(valid.check_rows((1 << 20) + 1).is_err());
        assert!(valid.check_rows(0).is_err());
        assert!(valid.check_rows(3).is_err());
        assert!(valid.check_rows(1 << 20).is_ok());
        assert!(Stage::parse("pq-byte-recursive").is_err());
    }
    #[test]
    fn real_pq_gadgets_bind_byte_ranges_modulus_and_public_values() {
        let (program, public, witness) = byte_fixture().unwrap();
        let air = MachineAir::new(program);
        air.trace(&public, &witness).unwrap();
        for index in 0..public.len() {
            let mut bad = public.clone();
            bad[index] += Val::ONE;
            assert!(air.trace(&bad, &witness).is_err());
        }
        // Same low eight bits and public outputs: only the byte range binding
        // distinguishes this witness from the valid one.
        for (index, value) in [(0, 173 + 256), (3, 0)] {
            let mut bad = witness.clone();
            bad[index] = Val::from_u64(value);
            assert!(air.trace(&public, &bad).is_err());
        }
        // Preserve the integer product equality while violating canonicality:
        // 173 * Q = 173 * Q + 0. The residue range must reject it.
        let mut noncanonical = witness;
        noncanonical[2] = Val::from_u64(crate::rust_verify::Q);
        noncanonical[3] = Val::from_u64(173);
        let mut matching_public = public;
        matching_public[1] = Val::ZERO;
        assert!(air.trace(&matching_public, &noncanonical).is_err());
    }
}
