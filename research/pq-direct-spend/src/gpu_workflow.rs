//! A complete, fresh research relation proof and independent artifact verifier.
//! This command does not produce a production RingCT transaction or aggregate.
use lattica_pq_direct_spend_research::{
    ring,
    ring_circuit::{
        self, artifact, proving::FreshGpuProofInput, verification, CompilerCapacityProfile,
        CompilerMemoryProfile, CompilerRepresentation, CompilerWireProfile,
    },
    Context,
};
use lattica_prover_p3::block_v2::gpu_hash::PublicHashExecution;
use lattica_prover_p3::block_v2::machine::REGISTERED_GPU_CALLER_HOST_BYTES;
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const WORKER_HOST_BYTES: usize = 32 << 30;
// Includes the one public statement, short CLI arguments/paths, the scalar
// workflow report, stream writers and bounded lifecycle reports. The large
// proving report is emitted and destroyed before independent reconstruction.
const CALLER_HOST_BYTES: usize = REGISTERED_GPU_CALLER_HOST_BYTES;
const MAX_ARGUMENT_BYTES: usize = 4 << 10;
const MAX_REPORT_BYTES: usize = 1 << 20;
const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;

struct Options {
    output: PathBuf,
    capacity: CompilerCapacityProfile,
}

fn options(args: &[&str]) -> Result<Options, Box<dyn Error>> {
    let bytes = args
        .iter()
        .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()));
    if bytes.is_none_or(|bytes| bytes > MAX_ARGUMENT_BYTES) {
        return Err("proof command arguments exceed the caller reservation".into());
    }
    let (mut output, mut memory, mut wires) = (None, None, None);
    let mut args = args.iter();
    while let Some(&key) = args.next() {
        let value = args.next().ok_or("proof option requires a value")?;
        match key {
            "--output-dir" if output.is_none() => output = Some(PathBuf::from(*value)),
            "--memory-profile" if memory.is_none() => memory = Some(value.parse()?),
            "--wire-profile" if wires.is_none() => wires = Some(value.parse()?),
            _ => return Err("unknown or repeated proof option; expected --output-dir, --memory-profile or --wire-profile".into()),
        }
    }
    Ok(Options {
        output: output.ok_or("--prove requires --output-dir pointing to a new directory")?,
        capacity: CompilerCapacityProfile::new(
            memory.unwrap_or(CompilerMemoryProfile::Program2GiB),
            wires.unwrap_or(CompilerWireProfile::Research16M),
        ),
    })
}

#[derive(Serialize)]
struct WorkflowReport {
    public_hash: PublicHashExecution,
    schema: &'static str,
    profile: &'static str,
    representation: &'static str,
    research_only: bool,
    production_acceptance_changed: bool,
    complete_faithful_ringct_workflow: bool,
    fresh_relation_proofs: u32,
    recursive_aggregate_proofs: u32,
    independently_verified: bool,
    artifact_roundtrip: bool,
    cryptographic_mutation_checks: u32,
    active_rows: u64,
    padded_rows: u64,
    wires: u64,
    caller_reserved_bytes: usize,
    artifact_bytes: usize,
    artifact_sha3_256: [u8; 32],
    artifact_encode_required_host_bytes: usize,
    artifact_decode_required_host_bytes: usize,
    fixture_ns: u128,
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
}

pub fn run(
    context: Context,
    args: &[&str],
    argument_host_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let options = options(args)?;
    let paths = [
        "compilation-failure.json",
        "proving-failure.json",
        "proving.json",
        "proof.bin",
        "verification-failure.json",
        "verification.json",
        "workflow.json",
    ]
    .map(|name| options.output.join(name));
    // Charge actual allocated argument/path capacities, including retained spare
    // storage, before compilation or device dispatch. All subsequent report
    // writes borrow these paths and stream directly without a JSON buffer.
    let orchestration_bytes = paths
        .iter()
        .try_fold(
            argument_host_bytes
                .checked_add(options.output.capacity())
                .ok_or("CLI capacity overflow")?,
            |sum, path| sum.checked_add(path.capacity()),
        )
        .and_then(|sum| {
            sum.checked_add(
                std::mem::size_of_val(&paths)
                    + std::mem::size_of::<WorkflowReport>()
                    + std::mem::size_of::<Options>()
                    + (4 << 10),
            )
        })
        .ok_or("CLI capacity overflow")?;
    if orchestration_bytes > verification::CALLER_ORCHESTRATION_BYTES {
        return Err("CLI owners exceed the reserved 32 KiB orchestration allowance".into());
    }
    // A new directory makes failures and partial evidence reviewable, and
    // prevents any existing proof or validation result from being overwritten.
    fs::create_dir(&options.output)?;
    let started = Instant::now();
    let fixture_started = Instant::now();
    let (statement, witness) = ring::fixture(context)?;
    let fixture_ns = fixture_started.elapsed().as_nanos();
    let compilation_started = Instant::now();
    let relation = match ring_circuit::compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        options.capacity,
        REPRESENTATION,
        usize::try_from(options.capacity.limits().required_host_bytes)?,
    ) {
        Ok(relation) => relation,
        Err(failure) => {
            write_report(&paths[0], &failure)?;
            return Err(failure.error.into());
        }
    };
    let compilation_ns = compilation_started.elapsed().as_nanos();
    drop(witness);
    let input = FreshGpuProofInput::new(statement, context, relation)?;
    let proved = match input.prove() {
        Ok(proved) => proved,
        Err(failure) => {
            write_report(&paths[1], &failure)?;
            return Err(failure.into());
        }
    };
    let (statement, descriptor, proof, proving_report) = proved.into_parts();
    let public_hash = proving_report.public_hash;
    let (prover_setup_ns, proving_ns, prover_lifecycle_ns) = (
        proving_report.setup_ns,
        proving_report.proving_ns,
        proving_report.total_proving_lifecycle_ns,
    );
    write_report(&paths[2], &proving_report)?;
    drop(proving_report);

    let codec_started = Instant::now();
    let codec_allowance = WORKER_HOST_BYTES
        .checked_sub(CALLER_HOST_BYTES)
        .ok_or("caller budget overflow")?;
    let encode_bytes = artifact::encoding_required_host_bytes(&proof)?;
    let packet = artifact::encode(
        &statement,
        context,
        REPRESENTATION,
        descriptor,
        &proof,
        codec_allowance,
    )?;
    // The original native proof is not retained through decode or verification.
    drop(proof);
    let artifact_bytes = packet.len();
    let artifact_sha3_256: [u8; 32] = Sha3_256::digest(&packet).into();
    write_new(&paths[3], &packet)?;
    drop(packet);
    let packet = read_packet(&paths[3], codec_allowance)?;
    if packet.len() != artifact_bytes
        || <[u8; 32]>::from(Sha3_256::digest(&packet)) != artifact_sha3_256
    {
        return Err("artifact disk round trip changed the proof bytes".into());
    }
    let decode_bytes = artifact::decoding_required_host_bytes(&packet)?;
    let mut artifact = artifact::Artifact::decode(packet, codec_allowance)?;
    let codec_and_disk_ns = codec_started.elapsed().as_nanos();
    let verification = match verification::verify(
        &mut artifact,
        &statement,
        context,
        options.capacity,
        REPRESENTATION,
    ) {
        Ok(report) => report,
        Err(failure) => {
            write_report(&paths[4], &failure)?;
            return Err(failure.into());
        }
    };
    write_report(&paths[5], &verification)?;
    if Some(public_hash) != verification.public_hash {
        return Err(
            "prover and independent reconstruction used different public hash selections".into(),
        );
    }
    let mut report = WorkflowReport {
        public_hash,
        schema: "lattica-research-direct-ring-complete-gpu-workflow-v1",
        profile: "ring-direct-v1",
        representation: REPRESENTATION.name(),
        research_only: true,
        production_acceptance_changed: false,
        complete_faithful_ringct_workflow: false,
        fresh_relation_proofs: 1,
        recursive_aggregate_proofs: 0,
        independently_verified: verification.verified,
        artifact_roundtrip: true,
        cryptographic_mutation_checks: verification.mutation_checks,
        active_rows: descriptor.active_rows,
        padded_rows: descriptor.padded_rows,
        wires: descriptor.wires,
        caller_reserved_bytes: CALLER_HOST_BYTES,
        artifact_bytes,
        artifact_sha3_256,
        artifact_encode_required_host_bytes: encode_bytes,
        artifact_decode_required_host_bytes: decode_bytes,
        fixture_ns,
        compilation_ns,
        prover_setup_ns,
        proving_ns,
        prover_lifecycle_ns,
        codec_and_disk_ns,
        verifier_reconstruction_ns: verification.reconstruction_ns,
        verifier_setup_ns: verification.gpu_preprocessing_ns,
        cpu_verification_ns: verification.cpu_verification_ns,
        mutation_checks_ns: verification.mutation_checks_ns,
        verifier_lifecycle_ns: verification.total_verification_lifecycle_ns,
        complete_research_workflow_ns: 0,
    };
    drop(verification);
    drop(artifact);
    drop(statement);
    report.complete_research_workflow_ns = started.elapsed().as_nanos();
    write_report(&paths[6], &report)?;
    serde_json::to_writer(io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(
                "research report exceeds its serialized size limit",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_report(path: &Path, report: &impl Serialize) -> Result<(), Box<dyn Error>> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = LimitedWriter {
        inner: file,
        remaining: MAX_REPORT_BYTES,
    };
    serde_json::to_writer(&mut writer, report)?;
    writer.write_all(b"\n")?;
    writer.inner.sync_all()?;
    Ok(())
}

fn read_packet(path: &Path, allowance: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let len = usize::try_from(metadata.len())?;
    if !metadata.is_file() || len > artifact::MAX_ENCODED_BYTES || len > allowance {
        return Err("artifact file exceeds the bounded packet allowance".into());
    }
    // Reserve exactly the admitted input length, rather than read_to_end's
    // unspecified geometric growth; reject any trailing byte or truncation.
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len)?;
    if bytes.capacity() != len {
        return Err("artifact input allocation exceeded its admitted exact capacity".into());
    }
    bytes.resize(len, 0);
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0u8; 1])? != 0 {
        return Err("artifact changed size while being read".into());
    }
    Ok(bytes)
}
