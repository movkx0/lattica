//! CPU-only, bounded component/DAG-slice experiment. Never a full-workflow receipt.
use crate::{component_tree, graph_crypto};
use lattica_prover_p3::block_v2::machine::program::Val;
use sha3::Digest;
use std::{path::PathBuf, sync::Arc, time::Instant};
mod arithmetic;
mod inputs;
mod jobs;
mod scheduler;
mod target;
#[cfg(test)]
mod tests;
type Result<T> = std::result::Result<T, String>;
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Options {
    pub cpu_variant: lattica_prover_p3::block_v2::cpu_commitment::Variant,
    pub cpu_hash_kernel: lattica_prover_p3::block_v2::cpu_commitment::HashKernel,
    pub identity_overlap: bool,
    pub baseline_identity_overlap: bool,
    pub cpu_commitment_path: lattica_prover_p3::block_v2::cpu_commitment::CommitmentPath,
    pub transaction: Option<usize>,
    pub compare_target: bool,
    pub candidate_first: bool,
    pub transactions: usize,
    pub workload: usize,
    pub workers: usize,
    pub threads_per_proof: usize,
    pub retain: bool,
    pub mode: String,
    pub input: PathBuf,
    pub request: usize,
    pub segments: usize,
    pub repetitions: usize,
}
impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<(Self, bool)> {
        let mut options = Self {
            cpu_variant: Default::default(),
            cpu_hash_kernel: Default::default(),
            identity_overlap: false,
            baseline_identity_overlap: false,
            cpu_commitment_path: Default::default(),
            transaction: None,
            compare_target: false,
            candidate_first: false,
            transactions: 3,
            workload: 0,
            workers: 1,
            threads_per_proof: 16,
            retain: false,
            mode: "native".into(),
            input: PathBuf::new(),
            request: 0,
            segments: 2,
            repetitions: 1,
        };
        let mut generate = false;
        let mut seen = std::collections::BTreeSet::new();
        let mut args = args;
        while let Some(key) = args.next() {
            ensure(seen.insert(key.clone()), "repeated option")?;
            let value = args.next().ok_or("every option requires a value")?;
            match key.as_str() {
                "--cpu-variant" => {
                    options.cpu_variant =
                        lattica_prover_p3::block_v2::cpu_commitment::Variant::parse(&value)?
                }
                "--cpu-hash-kernel" => {
                    options.cpu_hash_kernel =
                        lattica_prover_p3::block_v2::cpu_commitment::HashKernel::parse(&value)?
                }
                "--cpu-commitment-path" => {
                    options.cpu_commitment_path =
                        lattica_prover_p3::block_v2::cpu_commitment::CommitmentPath::parse(&value)?;
                }
                "--identity-overlap"
                | "--baseline-identity-overlap"
                | "--compare-target"
                | "--candidate-first" => {
                    ensure(
                        matches!(value.as_str(), "0" | "1"),
                        "boolean option must be 0 or 1",
                    )?;
                    match key.as_str() {
                        "--identity-overlap" => options.identity_overlap = value == "1",
                        "--baseline-identity-overlap" => {
                            options.baseline_identity_overlap = value == "1"
                        }
                        "--compare-target" => options.compare_target = value == "1",
                        _ => options.candidate_first = value == "1",
                    }
                }
                "--transaction" => options.transaction = Some(value.parse().map_err(error)?),
                "--case" => {
                    options.transactions = match value.as_str() {
                        "n3" => 3,
                        "n4" => 4,
                        _ => return Err("case must be n3 or n4".into()),
                    }
                }
                "--workload" => options.workload = value.parse().map_err(error)?,
                "--workers" => options.workers = value.parse().map_err(error)?,
                "--threads-per-proof" => {
                    options.threads_per_proof = value.parse().map_err(error)?
                }
                "--retain" => {
                    options.retain = match value.as_str() {
                        "0" => false,
                        "1" => true,
                        _ => return Err("retain must be 0 or 1".into()),
                    }
                }
                "--mode" => options.mode = value,
                "--input" => options.input = value.into(),
                "--request" => options.request = value.parse().map_err(error)?,
                "--segments" => options.segments = value.parse().map_err(error)?,
                "--repetitions" => options.repetitions = value.parse().map_err(error)?,
                "--generate" => {
                    ensure(value == "1", "generate must be 1")?;
                    generate = true;
                }
                _ => return Err(format!("unknown option {key}")),
            }
        }
        ensure(
            options.workload <= 1
                && (1..=16).contains(&options.workers)
                && (1..=16).contains(&options.threads_per_proof)
                && options.workers * options.threads_per_proof <= 16,
            "CPU worker/thread budget",
        )?;
        ensure(
            (1..=4).contains(&options.segments) && (1..=5).contains(&options.repetitions),
            "slice/repetition limit",
        )?;
        ensure(
            matches!(
                options.mode.as_str(),
                "plan"
                    | "native"
                    | "native-mix"
                    | "paired"
                    | "merge"
                    | "arithmetic"
                    | "graph-leaf"
                    | "graph-parent"
            ),
            "unsupported CPU mode",
        )?;
        ensure(
            options.mode != "native-mix" || (options.request == 0 && options.segments == 1),
            "native-mix requires request 0 and segments 1",
        )?;
        ensure(!options.input.as_os_str().is_empty(), "--input required")?;
        ensure(
            options.transaction.is_none_or(|i| i < options.transactions),
            "transaction outside case",
        )?;
        ensure(
            options.cpu_hash_kernel == Default::default() || options.cpu_variant.tiled(),
            "interleaved hashes require a tiled CPU variant",
        )?;
        ensure(
            options.cpu_commitment_path == Default::default()
                || (options.cpu_variant
                    == lattica_prover_p3::block_v2::cpu_commitment::Variant::Combined
                    && options.cpu_hash_kernel == Default::default()),
            "commitment path requires combined/existing hash",
        )?;
        ensure(
            !options.baseline_identity_overlap || options.compare_target,
            "baseline identity overlap requires target comparison",
        )?;
        ensure(
            !options.candidate_first || options.compare_target,
            "candidate-first requires target comparison",
        )?;
        ensure(
            !options.compare_target
                || (options.transaction.is_some()
                    && options.workers == 1
                    && options.threads_per_proof == 16
                    && options.repetitions == 1
                    && !options.retain
                    && options.segments == 2
                    && matches!(options.mode.as_str(), "paired" | "graph-parent")
                    && options.cpu_variant
                        == lattica_prover_p3::block_v2::cpu_commitment::Variant::Combined),
            "target comparison requires one transaction, combined, 1x16, two children, one repetition and no retention",
        )?;
        Ok((options, generate))
    }
    fn host_bytes(&self) -> u64 {
        (if self.transactions == 3 { 32 } else { 36 }) << 30
    }
    fn host_profile(&self) -> crate::host_memory_profile::HostMemoryProfile {
        use crate::host_memory_profile::HostMemoryProfile;
        if self.transactions == 3 {
            HostMemoryProfile::Standard
        } else {
            HostMemoryProfile::Expanded36
        }
    }
}
pub fn main(args: impl Iterator<Item = String>) -> Result<()> {
    ensure(
        !cfg!(debug_assertions),
        "CPU proof experiments require a release build",
    )?;
    ensure(
        std::env::var("LATTICA_PROVING_POLICY").as_deref() == Ok("cpu-required"),
        "explicit cpu-required policy",
    )?;
    let (options, generate) = Options::parse(args)?;
    ensure(
        std::env::var("LATTICA_RINGCT_HOST_PROFILE").as_deref()
            == Ok(options.host_profile().label()),
        "explicit CPU host profile must match selected case",
    )?;
    if generate {
        return inputs::generate(&options, &options.input);
    }
    let profiling = lattica_prover_p3::block_v2::perf::Profiler::from_env().map_err(error)?;
    let started = Instant::now();
    let (cases, input_digest) = inputs::load(&options)?;
    let preparation_ns = started.elapsed().as_nanos();
    let inventory: Vec<_> = cases.iter().enumerate().flat_map(|(case,c)| c.plan.requests().iter().enumerate()
        .map(move |(index,r)| serde_json::json!({"case":case,"request":index,"operation":r.operation_index(),
            "kind":if matches!(r.descriptor(),graph_crypto::RequestDescriptor::Shake(_)){"shake"}else{"aes"},
            "segments":r.segments().len(),"units":r.units(),"maximum_segment_units":r.maximum_segment_units()}))).collect();
    println!(
        "CPU_PROOF_INVENTORY {}",
        serde_json::json!({"input_sha3_256":input_digest,"requests":inventory,
        "first_case_arithmetic":arithmetic::inventory(&cases[0])?})
    );
    let mut records: Vec<scheduler::Record> = Vec::new();
    if options.mode != "plan" {
        for repetition in 0..options.repetitions {
            let mut graph = jobs::build(&options, &cases)?;
            // Bootstrap weights use the bounded pilot; repeated identical DAGs
            // learn actual per-node costs without retaining a proof or witness.
            if let Some(previous) = records.last() {
                for report in &previous.jobs {
                    graph[report.id].cost = u64::try_from(report.elapsed_ns).map_err(error)?;
                }
            }
            let mut record = scheduler::run(&options, graph, repetition)?;
            for job in &mut record.jobs {
                if matches!(job.kind, "native" | "arithmetic") {
                    // Conservatively charge the entire shared input-loading /
                    // metadata-lowering stage to each native proof. Do not hide
                    // this preparation cost behind an already-loaded fixture.
                    job.cold_input_service_upper_ns = Some(job.service_ns + preparation_ns);
                }
            }
            records.push(record);
        }
    }
    if let Some(profiling) = profiling {
        profiling.report("ringct-cpu-proof");
    }
    println!(
        "CPU_PROOF_PROFILE {}",
        serde_json::json!({"schema":"ringct-cpu-proof-profile-v4",
        "backend":"cpu", "layout":"paired-v1", "options":options,"input_sha3_256":input_digest,
        "preparation_ns":preparation_ns,"records":records,"gpu_contexts":0,"gpu_proof_calls":0,
        "fresh_stark_randomness":true,"complete_workflow":false,"cleanup_complete":true,
        "timing_scope":"service_ns includes per-proof preparation, compilation-to-proof queueing, proving, serialization and verification; excludes negative mutation checks; native cold_input_service_upper_ns additionally charges the entire shared input-loading/lowering stage; target service starts at compilation with verified children available; slice wall includes dependencies and cleanup",
        "memory_admission":"CPU research estimates plus external cgroup; not measured allocation bounds"})
    );
    Ok(())
}
