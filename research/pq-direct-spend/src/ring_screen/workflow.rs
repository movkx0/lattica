use super::*;
use fixtures::{Identity, Manifest};
use lattica_prover_p3::{
    block_v2::{gpu_hash::PublicHashExecution, machine::REGISTERED_GPU_CALLER_HOST_BYTES},
    proving::Policy,
};
use p3_field::PrimeField64;
use ring_circuit::{
    artifact::{self, ProofDescriptor},
    proving::{FreshGpuProofInput, TerminalReceipt},
    verification,
};
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::{io::Write, path::Path, time::Instant};

#[derive(Serialize)]
pub(super) struct CaseReport {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_reuse_profile: Option<&'static str>,
    identity: Identity,
    research_only: bool,
    complete_faithful_ringct_workflow: bool,
    recursive_aggregate_proofs: u32,
    fresh_relation_proofs: u32,
    proof_generation: &'static str,
    proving_policy: Policy,
    public_hash: PublicHashExecution,
    descriptor: ProofDescriptor,
    public_binding: [u64; 4],
    independent_cpu_verified: bool,
    reused_prover_state: bool,
    artifact_roundtrip: bool,
    cryptographic_mutation_checks: u32,
    artifact_bytes: usize,
    artifact_sha3_256: [u8; 32],
    encode_required_host_bytes: usize,
    decode_required_host_bytes: usize,
    fixture_regeneration_ns: u128,
    compilation_ns: u128,
    prover_setup_ns: u128,
    proving_ns: u128,
    prover_lifecycle_ns: u128,
    codec_and_disk_ns: u128,
    verifier_reconstruction_ns: u128,
    verifier_setup_ns: u128,
    cpu_verification_ns: u128,
    mutation_checks_ns: u128,
    verifier_lifecycle_ns: u128,
    complete_research_workflow_ns: u128,
    prover_terminal: TerminalReceipt,
    verifier_terminal: TerminalReceipt,
}

#[derive(Serialize)]
pub(super) struct SuiteReport {
    schema: &'static str,
    profile: &'static str,
    representation: &'static str,
    context: [u8; 32],
    research_only: bool,
    production_acceptance_changed: bool,
    complete_faithful_ringct_workflow: bool,
    cryptographic_security_review_complete: bool,
    protocol_adoption_qualified: bool,
    protocol_redesign_twofold_qualified: bool,
    n3_n4_aggregate_qualification: bool,
    recursive_aggregate_proofs: u32,
    fresh_relation_proofs: usize,
    distinct_public_statements: usize,
    distinct_serials: usize,
    public_preprocessing_reused: bool,
    public_hash_kernel: &'static str,
    caller_reserved_bytes: usize,
    orchestration_payload_bytes: usize,
    fixture_staging: bounds::Staging,
    original_quota_receipt: bool,
    process_host_peak_bytes: Option<u64>,
    managed_gpu_peak_bytes: u64,
    preflight_fixture_generation_ns: u128,
    complete_seven_case_screen_ns: u128,
    timing_boundary: &'static str,
    manifest: Manifest,
    cases: [Option<CaseReport>; CASES],
}

fn terminal(receipt: TerminalReceipt, proof_completed: bool) -> Result<()> {
    if receipt.host_allowance_bytes != WORKER_HOST_BYTES as u64
        || receipt.device_allowance_bytes != 8 << 30
        || receipt.gpu_context_allowance_bytes != 4 << 30
        || receipt.max_rows != 1 << 20
        || receipt.managed_peak_bytes > 8 << 30
        || receipt.managed_peak_bytes == 0
        || receipt.commits == 0
        || receipt.allocations == 0
        || !receipt.context_closed
        || !receipt.queue_drained
        || receipt.completion_claimed != proof_completed
    {
        return Err("screen lifecycle did not retire within the unchanged envelope".into());
    }
    Ok(())
}

#[test]
fn reconstruction_receipt_does_not_claim_a_fresh_proof() {
    let mut receipt = TerminalReceipt {
        host_allowance_bytes: WORKER_HOST_BYTES as u64,
        device_allowance_bytes: 8 << 30,
        gpu_context_allowance_bytes: 4 << 30,
        max_rows: 1 << 20,
        commits: 1,
        allocations: 1,
        managed_peak_bytes: 1,
        uploaded_bytes: 1,
        downloaded_bytes: 1,
        context_closed: true,
        queue_drained: true,
        completion_claimed: false,
    };
    assert!(terminal(receipt, false).is_ok());
    assert!(terminal(receipt, true).is_err());
    receipt.completion_claimed = true;
    assert!(terminal(receipt, true).is_ok());
    assert!(terminal(receipt, false).is_err());
    receipt.queue_drained = false;
    assert!(terminal(receipt, true).is_err());
}

fn case(expected: Identity, paths: &io::Paths) -> Result<CaseReport> {
    case_selected(expected, paths, false)
}

pub(super) fn case_selected(
    expected: Identity,
    paths: &io::Paths,
    reuse: bool,
) -> Result<CaseReport> {
    let started = Instant::now();
    let fixture_started = Instant::now();
    let (statement, witness) = fixtures::generate(expected.case)?;
    ring::check_relation(&statement, &witness, CONTEXT)?;
    if fixtures::identity(expected.case, &statement) != expected {
        return Err("fixture regeneration changed the preflight statement or serials".into());
    }
    let fixture_regeneration_ns = fixture_started.elapsed().as_nanos();
    let compilation_started = Instant::now();
    let relation = match ring_circuit::compile_with_representation_diagnostics(
        &statement,
        &witness,
        CONTEXT,
        CAPACITY,
        REPRESENTATION,
        usize::try_from(CAPACITY.limits().required_host_bytes)?,
    ) {
        Ok(relation) => relation,
        Err(failure) => {
            io::report(&paths.files[0], &failure)?;
            return Err(failure.error.into());
        }
    };
    let compilation_ns = compilation_started.elapsed().as_nanos();
    drop(witness);
    let mut identity: Option<ring_circuit::identity_reuse::Transfer> = if reuse {
        #[cfg(feature = "gpu-identity-reuse-experiment")]
        {
            Some(ring_circuit::identity_reuse::Transfer::new(
                &statement,
                CONTEXT,
                REPRESENTATION,
            )?)
        }
        #[cfg(not(feature = "gpu-identity-reuse-experiment"))]
        {
            return Err("identity receipt experiment was not compiled".into());
        }
    } else {
        None
    };
    let input = FreshGpuProofInput::new(statement, CONTEXT, relation)?;
    let attempt = match identity.as_mut() {
        #[cfg(feature = "gpu-identity-reuse-experiment")]
        Some(identity) => input.prove_capturing_identity(identity),
        #[cfg(not(feature = "gpu-identity-reuse-experiment"))]
        Some(_) => return Err("identity receipt experiment was not compiled".into()),
        None => input.prove(),
    };
    let proved = match attempt {
        Ok(proved) => proved,
        Err(failure) => {
            io::report(&paths.files[1], &failure)?;
            return Err(failure.into());
        }
    };
    let (statement, descriptor, proof, proving) = proved.into_parts();
    io::report(&paths.files[2], &proving)?;
    terminal(proving.terminal, true)?;
    if proving.public_hash.kernel() != "baseline"
        || proving.proof_generation != "fresh-only"
        || proving.policy != Policy::GpuRequired
        || !proving.witness_instructions_retired_before_quotient
    {
        return Err("screen proving receipt changed the fresh baseline policy".into());
    }
    let (public_hash, prover_terminal, prover_setup_ns, proving_ns, prover_lifecycle_ns) = (
        proving.public_hash,
        proving.terminal,
        proving.setup_ns,
        proving.proving_ns,
        proving.total_proving_lifecycle_ns,
    );
    drop(proving);

    let codec_started = Instant::now();
    let codec_allowance = WORKER_HOST_BYTES
        .checked_sub(REGISTERED_GPU_CALLER_HOST_BYTES)
        .ok_or(Error::ResourceLimit)?;
    let encode_required_host_bytes = artifact::encoding_required_host_bytes(&proof)?;
    let packet = artifact::encode(
        &statement,
        CONTEXT,
        REPRESENTATION,
        descriptor,
        &proof,
        codec_allowance,
    )?;
    drop(proof);
    let artifact_bytes = packet.len();
    let artifact_sha3_256: [u8; 32] = Sha3_256::digest(&packet).into();
    io::write_packet(&paths.files[3], &packet)?;
    drop(packet);
    let packet = io::read_packet(&paths.files[3], codec_allowance)?;
    if packet.len() != artifact_bytes
        || <[u8; 32]>::from(Sha3_256::digest(&packet)) != artifact_sha3_256
    {
        return Err("screen artifact disk round trip changed proof bytes".into());
    }
    let decode_required_host_bytes = artifact::decoding_required_host_bytes(&packet)?;
    let mut decoded = artifact::Artifact::decode(packet, codec_allowance)?;
    let public_binding = decoded.public().map(|v| v.as_canonical_u64());
    if decoded.descriptor() != descriptor
        || decoded.context() != CONTEXT
        || decoded.representation() != REPRESENTATION
    {
        return Err("screen artifact decoded a different profile or descriptor".into());
    }
    let codec_and_disk_ns = codec_started.elapsed().as_nanos();
    let verification_attempt = match identity {
        #[cfg(feature = "gpu-identity-reuse-experiment")]
        Some(identity) => verification::verify_reusing_identity(
            &mut decoded,
            &statement,
            CONTEXT,
            CAPACITY,
            REPRESENTATION,
            identity,
        ),
        #[cfg(not(feature = "gpu-identity-reuse-experiment"))]
        Some(_) => return Err("identity receipt experiment was not compiled".into()),
        None => verification::verify(&mut decoded, &statement, CONTEXT, CAPACITY, REPRESENTATION),
    };
    let verified = match verification_attempt {
        Ok(verified) => verified,
        Err(failure) => {
            io::report(&paths.files[4], &failure)?;
            return Err(failure.into());
        }
    };
    io::report(&paths.files[5], &verified)?;
    // Independent GPU reconstruction performs public setup, not a new proof.
    terminal(verified.terminal, false)?;
    if !verified.verified
        || verified.reused_prover_state != reuse
        || verified.identity_reuse.is_some() != reuse
        || verified.synthetic_hints_evaluated
        || verified.proof_verification_backend != "cpu"
        || verified.mutation_checks != 2
        || verified.expected_public_binding != public_binding
        || verified.expected_context != CONTEXT.0
        || verified.descriptor != descriptor
        || (!reuse && verified.public_hash != Some(public_hash))
        || verified
            .public_hash
            .is_some_and(|actual| actual != public_hash)
    {
        return Err(
            "screen independent verification receipt did not match the expected relation".into(),
        );
    }
    let mut report = CaseReport {
        schema: if reuse {
            "lattica-research-direct-ring-identity-reuse-workflow-v1"
        } else {
            "lattica-research-direct-ring-seven-case-workflow-v1"
        },
        identity_reuse_profile: reuse.then_some(ring_circuit::identity_reuse::PROFILE),
        identity: expected,
        research_only: true,
        complete_faithful_ringct_workflow: false,
        recursive_aggregate_proofs: 0,
        fresh_relation_proofs: 1,
        proof_generation: "fresh-only",
        proving_policy: Policy::GpuRequired,
        public_hash,
        descriptor,
        public_binding,
        independent_cpu_verified: true,
        reused_prover_state: reuse,
        artifact_roundtrip: true,
        cryptographic_mutation_checks: verified.mutation_checks,
        artifact_bytes,
        artifact_sha3_256,
        encode_required_host_bytes,
        decode_required_host_bytes,
        fixture_regeneration_ns,
        compilation_ns,
        prover_setup_ns,
        proving_ns,
        prover_lifecycle_ns,
        codec_and_disk_ns,
        verifier_reconstruction_ns: verified.reconstruction_ns,
        verifier_setup_ns: verified.gpu_preprocessing_ns,
        cpu_verification_ns: verified.cpu_verification_ns,
        mutation_checks_ns: verified.mutation_checks_ns,
        verifier_lifecycle_ns: verified.total_verification_lifecycle_ns,
        complete_research_workflow_ns: 0,
        prover_terminal,
        verifier_terminal: verified.terminal,
    };
    drop(verified);
    drop(decoded);
    drop(statement);
    report.complete_research_workflow_ns = started.elapsed().as_nanos();
    Ok(report)
}

pub(super) fn run() -> Result<()> {
    // The fixed path/report bound precedes even the first retained path allocation.
    bounds::orchestration(io::MAX_OUTPUT_BYTES, None)?;
    let staging = bounds::Staging::new()?;
    let root = io::guarded_output()?;
    let orchestration_payload_bytes = bounds::orchestration(root.capacity(), None)?;
    std::fs::create_dir(&root)?;
    let started = Instant::now();
    let preflight_started = Instant::now();
    let manifest = fixtures::preflight()?;
    let preflight_fixture_generation_ns = preflight_started.elapsed().as_nanos();
    io::root_report(&root, "preflight.json", &manifest)?;
    let mut report = SuiteReport {
        schema: "lattica-research-direct-ring-seven-case-screen-v1", profile: Profile::RingDirectV1.tag(),
        representation: REPRESENTATION.name(), context: CONTEXT.0,
        research_only: true, production_acceptance_changed: false, complete_faithful_ringct_workflow: false,
        cryptographic_security_review_complete: false, protocol_adoption_qualified: false,
        protocol_redesign_twofold_qualified: false, n3_n4_aggregate_qualification: false,
        recursive_aggregate_proofs: 0, fresh_relation_proofs: 0, distinct_public_statements: CASES,
        distinct_serials: 2 * CASES, public_preprocessing_reused: false, public_hash_kernel: "baseline",
        caller_reserved_bytes: REGISTERED_GPU_CALLER_HOST_BYTES, orchestration_payload_bytes,
        fixture_staging: staging, original_quota_receipt: false, process_host_peak_bytes: None,
        managed_gpu_peak_bytes: 0, preflight_fixture_generation_ns, complete_seven_case_screen_ns: 0,
        timing_boundary: "preflight through seven retired proof/codec/verifier owners and per-case reports; excludes final summary serialization and process launch",
        manifest, cases: std::array::from_fn(|_| None),
    };
    for index in 0..CASES {
        let paths = io::Paths::new(Path::new(&root), index)?;
        bounds::orchestration(root.capacity(), Some(&paths))?;
        std::fs::create_dir(&paths.directory)?;
        let result = case(manifest[index].ok_or(Error::Geometry)?, &paths)?;
        for previous in report.cases.iter().flatten() {
            if previous.artifact_sha3_256 == result.artifact_sha3_256 {
                return Err("screen requires seven distinct fresh proof artifacts".into());
            }
        }
        io::report(&paths.files[6], &result)?;
        report.managed_gpu_peak_bytes = report
            .managed_gpu_peak_bytes
            .max(result.prover_terminal.managed_peak_bytes)
            .max(result.verifier_terminal.managed_peak_bytes);
        report.cases[index] = Some(result);
        report.fresh_relation_proofs += 1;
        drop(paths);
    }
    report.complete_seven_case_screen_ns = started.elapsed().as_nanos();
    io::root_report(&root, "screen.json", &report)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(b"DIRECT_RING_SEVEN_CASE_SCREEN ")?;
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
