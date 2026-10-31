//! Separate single-case matched profile. C024's seven-case baseline remains
//! independently selected; this entry never relabels its evidence.
use super::*;
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::REGISTERED_GPU_CALLER_HOST_BYTES;
use serde::Serialize;
use std::{io::Write, path::Path, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Baseline,
    ReceiptV1,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::ReceiptV1 => "receipt-v1",
        }
    }
    fn check(self, value: &[u8]) -> Result<()> {
        if value != self.name().as_bytes() {
            return Err("identity selector and exact mode differ".into());
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct SingleCaseReport {
    schema: &'static str,
    mode: &'static str,
    research_only: bool,
    case_count: usize,
    public_preprocessing_reused: bool,
    reused_preprocessing_part: &'static str,
    fresh_preprocessing_cap: bool,
    complete_faithful_ringct_workflow: bool,
    protocol_redesign_twofold_qualified: bool,
    production_acceptance_changed: bool,
    original_shared_ledger_receipt: bool,
    source_identity_host_bytes: usize,
    receipt_sublimit_bytes: usize,
    combined_metadata_limit_bytes: usize,
    caller_reserved_bytes: usize,
    validated_gpu_registration_receipts: usize,
    validated_gpu_proof_receipts: usize,
    identity_receipt_hits: usize,
    full_gpu_identity_hashes_required: usize,
    retired_gpu_sessions: usize,
    independent_cpu_acceptances: usize,
    mutation_rejections: usize,
    evidence_files: [&'static str; 4],
    orchestration_payload_bytes: usize,
    complete_single_case_screen_ns: u128,
    timing_boundary: &'static str,
    workflow: workflow::CaseReport,
}

fn orchestration(root_capacity: usize, paths: Option<&io::Paths>) -> Result<usize> {
    let path_bytes = paths.map_or(8 * (io::MAX_OUTPUT_BYTES + 64), io::Paths::capacity_bytes);
    let bytes = root_capacity
        + path_bytes
        + (io::MAX_OUTPUT_BYTES + 64)
        + 2 * size_of::<SingleCaseReport>()
        + 4 * size_of::<workflow::CaseReport>()
        + 2 * size_of::<fixtures::Manifest>()
        + size_of::<io::Paths>()
        + 2 * size_of::<bounds::Staging>()
        + 4 * size_of::<std::path::PathBuf>()
        + 8 * size_of::<Instant>()
        + 2 * size_of::<sha3::Sha3_256>()
        + 2 * size_of::<std::io::StdoutLock<'static>>()
        + 2 * size_of::<Mode>()
        + (4 << 10);
    if bytes > ring_circuit::verification::CALLER_ORCHESTRATION_BYTES {
        return Err("identity screen owners exceed the existing 32 KiB orchestration slice".into());
    }
    // The separate receipt/move/report source charge lives inside the existing
    // 1 MiB caller envelope in both registration phases and codec/compilation.
    ring_circuit::identity_reuse::source_host_bytes()?;
    if CAPACITY.limits().required_host_bytes as usize
        + REGISTERED_GPU_CALLER_HOST_BYTES
        + ring::RING_PAIRS * size_of::<[ring::Account; 2]>()
        + size_of::<ring::Statement>()
        + size_of::<ring::Witness>()
        > WORKER_HOST_BYTES
    {
        return Err(Error::ResourceLimit.into());
    }
    Ok(bytes)
}

fn run(mode: Mode) -> Result<()> {
    orchestration(io::MAX_OUTPUT_BYTES, None)?;
    bounds::Staging::new()?;
    let (selected, length) = io::environment::<16>(c"LATTICA_DIRECT_RING_IDENTITY_MODE")?;
    mode.check(&selected[..length])?;
    let root = io::identity_output()?;
    let orchestration_payload_bytes = orchestration(root.capacity(), None)?;
    std::fs::create_dir(&root)?;
    let started = Instant::now();
    let manifest = fixtures::preflight()?;
    io::root_report(&root, "preflight.json", &manifest)?;
    let paths = io::Paths::new(Path::new(&root), 0)?;
    orchestration(root.capacity(), Some(&paths))?;
    std::fs::create_dir(&paths.directory)?;
    let reused = mode == Mode::ReceiptV1;
    let workflow = workflow::case_selected(manifest[0].ok_or(Error::Geometry)?, &paths, reused)?;
    io::report(&paths.files[6], &workflow)?;
    drop(paths);
    let report = SingleCaseReport {
        schema: "lattica-research-direct-ring-identity-screen-v1", mode: mode.name(),
        research_only: true, case_count: 1, public_preprocessing_reused: reused,
        reused_preprocessing_part: if reused { "protocol-program-identity-only" } else { "none" },
        fresh_preprocessing_cap: true, complete_faithful_ringct_workflow: false,
        protocol_redesign_twofold_qualified: false, production_acceptance_changed: false,
        original_shared_ledger_receipt: false,
        source_identity_host_bytes: ring_circuit::identity_reuse::source_host_bytes()?,
        receipt_sublimit_bytes: ring_circuit::identity_reuse::RECEIPT_LIMIT_BYTES,
        combined_metadata_limit_bytes: ring_circuit::identity_reuse::METADATA_LIMIT_BYTES,
        caller_reserved_bytes: REGISTERED_GPU_CALLER_HOST_BYTES,
        validated_gpu_registration_receipts: 2, validated_gpu_proof_receipts: 1,
        identity_receipt_hits: usize::from(reused), full_gpu_identity_hashes_required: if reused { 1 } else { 2 },
        retired_gpu_sessions: 2, independent_cpu_acceptances: 1, mutation_rejections: 2,
        evidence_files: ["case-0/proving.json", "case-0/verification.json", "case-0/workflow.json", "case-0/proof.bin"],
        orchestration_payload_bytes,
        complete_single_case_screen_ns: started.elapsed().as_nanos(),
        timing_boundary: "preflight through one fresh proof, artifact roundtrip, independently reconstructed cap, CPU acceptance/mutations and retirement; excludes final summary serialization and process launch",
        workflow,
    };
    io::root_report(&root, "identity-screen.json", &report)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(b"DIRECT_RING_IDENTITY_SCREEN ")?;
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_modes_are_exact_and_source_owners_fit_existing_allowances() {
        assert!(Mode::Baseline.check(b"baseline").is_ok());
        assert!(Mode::ReceiptV1.check(b"receipt-v1").is_ok());
        for invalid in [
            b"".as_slice(),
            b"receipt",
            b"receipt-v1 ",
            b"baseline,receipt-v1",
        ] {
            assert!(Mode::Baseline.check(invalid).is_err());
            assert!(Mode::ReceiptV1.check(invalid).is_err());
        }
        assert!(Mode::Baseline.check(b"receipt-v1").is_err());
        assert!(Mode::ReceiptV1.check(b"baseline").is_err());
        assert!(orchestration(io::MAX_OUTPUT_BYTES, None).is_ok());
        assert!(orchestration(usize::MAX / 2, None).is_err());
    }

    #[test]
    #[ignore = "exact coordinator direct-full identity baseline guard; serialized RTX 5080 only"]
    fn gpu_direct_ring_identity_cold_baseline() {
        run(Mode::Baseline).unwrap();
    }

    #[test]
    #[ignore = "exact coordinator cross-session opaque identity receipt guard; serialized RTX 5080 only"]
    fn gpu_direct_ring_identity_receipt_cross_session() {
        run(Mode::ReceiptV1).unwrap();
    }
}
