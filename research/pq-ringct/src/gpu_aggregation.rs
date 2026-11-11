//! Explicit imported-component GPU experiment. Never a fresh-workflow receipt.
use crate::{component_tree, graph_crypto};
use lattica_prover_p3::block_v2::machine::program::Val;
use sha3::{Digest, Sha3_256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
pub(crate) mod architecture;
mod bundle;
mod graph;
mod graph_archive;
mod graph_screen;
mod inputs;
mod kernel_screen;
mod layout;
pub(crate) mod memory;
pub(crate) mod pipeline;
pub(crate) mod policy;
mod resources;
mod selection;
pub(crate) mod telemetry;
#[cfg(test)]
mod tests;
mod typed;
mod typed_graph;
mod weighted;
type Result<T> = std::result::Result<T, String>;
// Reusable registrations retain the conservative 2^18-row ceiling. Consuming
// registrations retire instructions after the trace fence and permit 2^19;
// every proof still requires the same backend phase and allocation checks.
pub(crate) const MAX_RECURSIVE_ROWS: usize = 1 << 18;
pub(crate) const MAX_CONSUMING_ROWS: usize = 1 << 19;
pub(crate) const MAX_ADAPTIVE_ROWS: usize = 1 << 20;
pub(crate) fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Options {
    pub command: String,
    pub transactions: usize,
    pub workload: usize,
    pub input: PathBuf,
    pub bundle: PathBuf,
    pub output: PathBuf,
    pub profile: String,
    pub group_width: usize,
    pub parallel: bool,
    pub seconds: u64,
    pub max_components: usize,
    pub identity: String,
    pub selection: Option<PathBuf>,
    pub request: Option<usize>,
    pub repetitions: usize,
    pub family: String,
    pub first_leaf: usize,
    pub leaves: usize,
    pub gpu_managed_mib: String,
    pub query_gather: String,
    pub memory_qualification: Option<PathBuf>,
    pub compiler_policy: String,
    pub ntt_profile: String,
    pub poseidon_profile: String,
    pub native_source: String,
    pub recursion_backend: String,
    pub preparation_workers: usize,
}
impl Options {
    pub(crate) fn typed_recursion(&self) -> bool {
        self.recursion_backend == "typed"
    }
    pub(crate) fn max_rows(&self) -> usize {
        if matches!(self.profile.as_str(), "grouped-v4" | "grouped-v5") {
            std::env::var("LATTICA_V2_GPU_AGGREGATION_ROWS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(MAX_ADAPTIVE_ROWS)
        } else if self.profile == "grouped-v3" {
            MAX_CONSUMING_ROWS
        } else {
            MAX_RECURSIVE_ROWS
        }
    }
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let command = args
            .next()
            .ok_or("expected prepare-inputs, plan, screen or run")?;
        ensure(
            matches!(
                command.as_str(),
                "prepare-inputs"
                    | "plan"
                    | "screen"
                    | "run"
                    | "qualify-memory"
                    | "kernel-screen"
                    | "preflight-groups"
                    | "architecture-proof"
                    | "architecture-parent"
                    | "architecture-request"
                    | "architecture-graph"
            ),
            "unknown aggregation command",
        )?;
        let mut out = Self {
            command,
            transactions: 3,
            workload: 0,
            input: PathBuf::new(),
            bundle: PathBuf::new(),
            output: PathBuf::new(),
            profile: "grouped-v5".into(),
            group_width: 4,
            parallel: true,
            seconds: 600,
            max_components: usize::MAX,
            identity: "cpu".into(),
            selection: None,
            request: None,
            repetitions: 1,
            family: "shake".into(),
            first_leaf: 0,
            leaves: 8,
            gpu_managed_mib: "auto".into(),
            query_gather: "batch".into(),
            memory_qualification: None,
            compiler_policy: "standard".into(),
            ntt_profile: "smalltile".into(),
            poseidon_profile: "baseline".into(),
            native_source: "current".into(),
            recursion_backend: "typed".into(),
            preparation_workers: 16,
        };
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = args.next() {
            ensure(seen.insert(key.clone()), "repeated option")?;
            let value = args.next().ok_or("every option requires a value")?;
            match key.as_str() {
                "--case" => {
                    out.transactions = match value.as_str() {
                        "n3" => 3,
                        "n4" => 4,
                        _ => return Err("case must be n3 or n4".into()),
                    }
                }
                "--workload" => out.workload = value.parse().map_err(error)?,
                "--input-bundle" => out.bundle = value.into(),
                "--input" => out.input = value.into(),
                "--output" => out.output = value.into(),
                "--profile" => out.profile = value,
                "--group-width" => out.group_width = value.parse().map_err(error)?,
                "--pipeline" => {
                    out.parallel = match value.as_str() {
                        "serial" => false,
                        "lookahead" => true,
                        _ => return Err("invalid pipeline".into()),
                    }
                }
                "--timeout-seconds" => out.seconds = value.parse().map_err(error)?,
                "--max-components" => out.max_components = value.parse().map_err(error)?,
                "--identity" => out.identity = value,
                "--selection" => out.selection = Some(value.into()),
                "--request" => out.request = Some(value.parse().map_err(error)?),
                "--repetitions" => out.repetitions = value.parse().map_err(error)?,
                "--screen-family" => out.family = value,
                "--first-leaf" => out.first_leaf = value.parse().map_err(error)?,
                "--leaves" => out.leaves = value.parse().map_err(error)?,
                "--gpu-managed-mib" => out.gpu_managed_mib = value,
                "--query-gather" => out.query_gather = value,
                "--memory-qualification" => out.memory_qualification = Some(value.into()),
                "--compiler-policy" => out.compiler_policy = value,
                "--ntt-profile" => out.ntt_profile = value,
                "--poseidon-profile" => out.poseidon_profile = value,
                "--native-source" => out.native_source = value,
                "--recursion-backend" => out.recursion_backend = value,
                "--preparation-workers" => {
                    out.preparation_workers = value.parse().map_err(error)?
                }
                _ => return Err(format!("unknown aggregation option {key}")),
            }
        }
        if out.command == "architecture-graph" && !seen.contains("--screen-family") {
            out.family = "graph".into();
        }
        if !seen.contains("--recursion-backend")
            && (out.profile != "grouped-v5"
                || !(matches!(out.command.as_str(), "run" | "plan")
                    || out.command.starts_with("architecture-")))
        {
            out.recursion_backend = "machine".into();
        }
        ensure(
            matches!(out.recursion_backend.as_str(), "typed" | "machine"),
            "invalid recursion backend",
        )?;
        ensure(
            (1..=16).contains(&out.preparation_workers),
            "preparation workers must be 1..16",
        )?;
        ensure(
            !out.command.starts_with("architecture-")
                || out.typed_recursion()
                || out.command == "architecture-graph"
                || (out.command == "architecture-request"
                    && out.family == "aes"
                    && out.group_width == 1),
            "architecture screen requires typed backend",
        )?;
        ensure(
            !out.typed_recursion()
                || (out.profile == "grouped-v5"
                    && (matches!(out.command.as_str(), "run" | "plan")
                        || out.command.starts_with("architecture-"))),
            "typed recursion requires run, plan or typed proof screen",
        )?;
        if out.typed_recursion() && out.transactions == 4 && !seen.contains("--compiler-policy") {
            out.compiler_policy = "typed-batch".into();
        }
        // Historical profiles are explicit comparison modes. Ordinary commands
        // use the consuming four-child pipeline and the measured NTT schedule.
        if out.profile != "grouped-v5" && !seen.contains("--ntt-profile") {
            out.ntt_profile = "baseline".into();
        }
        if matches!(out.profile.as_str(), "legacy" | "grouped-v2" | "grouped-v3")
            && !seen.contains("--group-width")
        {
            out.group_width = 2;
        }
        if matches!(out.profile.as_str(), "legacy" | "grouped-v2") && !seen.contains("--pipeline") {
            out.parallel = false;
        }
        ensure(
            !out.bundle.as_os_str().is_empty()
                && out.workload <= 1
                && matches!(out.group_width, 1 | 2 | 4 | 8 | 16)
                && (1..=600).contains(&out.seconds)
                && out.max_components > 0
                && (1..=4).contains(&out.repetitions)
                && (matches!(
                    out.command.as_str(),
                    "screen"
                        | "qualify-memory"
                        | "architecture-proof"
                        | "architecture-parent"
                        | "architecture-request"
                        | "architecture-graph"
                ) || out.repetitions == 1),
            "invalid aggregation limits",
        )?;
        ensure(
            matches!(
                out.profile.as_str(),
                "legacy" | "grouped-v2" | "grouped-v3" | "grouped-v4" | "grouped-v5"
            ),
            "invalid aggregation profile",
        )?;
        ensure(
            matches!(out.family.as_str(), "shake" | "aes" | "graph")
                && (out.family != "aes" || out.command.starts_with("architecture-"))
                && (1..=8).contains(&out.leaves)
                && (out.family != "graph"
                    || (out.request.is_none()
                        && matches!(
                            out.command.as_str(),
                            "screen"
                                | "prepare-inputs"
                                | "qualify-memory"
                                | "preflight-groups"
                                | "kernel-screen"
                                | "architecture-graph"
                        ))),
            "invalid graph screen selection",
        )?;
        ensure(
            matches!(out.identity.as_str(), "cpu" | "gpu-batched"),
            "invalid identity backend",
        )?;
        ensure(
            out.profile != "legacy"
                || (out.group_width <= 2 && !out.parallel && out.identity == "cpu"),
            "legacy profile cannot select experimental execution",
        )?;
        ensure(
            out.command != "run" || !out.output.as_os_str().is_empty(),
            "run requires a new output artifact",
        )?;
        if out.input.as_os_str().is_empty() {
            out.input = out.bundle.join("inputs.json");
        }
        ensure(
            !matches!(
                out.profile.as_str(),
                "grouped-v3" | "grouped-v4" | "grouped-v5"
            ) || (out.parallel && out.identity == "cpu"),
            "grouped-v3 requires CPU identity and the lookahead pipeline",
        )?;
        if matches!(out.profile.as_str(), "grouped-v4" | "grouped-v5")
            && !seen.contains("--group-width")
        {
            out.group_width = if out.typed_recursion() && out.transactions == 4 {
                16
            } else {
                4
            };
        }
        if !matches!(out.profile.as_str(), "grouped-v4" | "grouped-v5") {
            ensure(
                !seen.contains("--gpu-managed-mib")
                    && !seen.contains("--query-gather")
                    && out.memory_qualification.is_none(),
                "memory/query selection requires grouped-v4",
            )?;
            out.gpu_managed_mib = "8192".into();
            out.query_gather = "scalar".into();
        }
        ensure(
            matches!(out.query_gather.as_str(), "scalar" | "batch"),
            "invalid query gather",
        )?;
        ensure(
            out.gpu_managed_mib == "auto"
                || out
                    .gpu_managed_mib
                    .parse::<u64>()
                    .ok()
                    .is_some_and(|m| (8192..=12288).contains(&m) && m % 256 == 0),
            "invalid managed MiB",
        )?;
        ensure(
            out.command != "qualify-memory"
                || (matches!(out.profile.as_str(), "grouped-v4" | "grouped-v5")
                    && !out.output.as_os_str().is_empty()),
            "memory qualification requires grouped-v4 and a new output path",
        )?;
        policy::Policy::parse(&out.compiler_policy)?;
        ensure(
            out.group_width <= 8 || out.typed_recursion(),
            "sixteen-native batches require the typed architecture backend",
        )?;
        ensure(
            out.compiler_policy != "typed-batch"
                || out.typed_recursion()
                || (out.command == "architecture-request"
                    && out.family == "aes"
                    && out.group_width == 1),
            "typed-batch memory requires typed recursion",
        )?;
        ensure(
            out.native_source == "current"
                || (out.command == "architecture-graph"
                    && out.native_source == "revalidate-archive"
                    && out.family == "graph"
                    && out.request.is_none())
                || (out.native_source == "revalidate-archive"
                    && matches!(
                        out.command.as_str(),
                        "preflight-groups"
                            | "architecture-proof"
                            | "architecture-parent"
                            | "architecture-request"
                            | "architecture-graph"
                    )
                    && matches!(out.family.as_str(), "shake" | "aes")
                    && out.request.is_some()
                    && (out.group_width <= 4 || out.command.starts_with("architecture-"))),
            "archive revalidation requires a bounded AES/SHAKE architecture preflight",
        )?;
        ensure(
            out.command != "architecture-graph"
                || (out.family == "graph"
                    && out.native_source == "revalidate-archive"
                    && out.request.is_none()
                    && out.repetitions <= 3
                    && (out.typed_recursion() || out.group_width <= 4)),
            "graph architecture requires a bounded revalidated archive",
        )?;
        ensure(!matches!(out.command.as_str(), "architecture-proof" | "architecture-parent" | "architecture-request") || (out.native_source == "revalidate-archive"
            && matches!(out.family.as_str(), "shake" | "aes") && out.repetitions <= 3),
            "architecture proof requires a revalidated AES/SHAKE archive and at most three fresh proofs")?;
        ensure(
            matches!(
                out.ntt_profile.as_str(),
                "baseline" | "powers" | "split8" | "smalltile" | "padded" | "local48"
            ),
            "invalid NTT profile",
        )?;
        ensure(
            matches!(
                out.poseidon_profile.as_str(),
                "baseline" | "square" | "square-unroll"
            ),
            "invalid Poseidon profile",
        )?;
        ensure(
            out.profile == "grouped-v5"
                || (out.compiler_policy == "standard"
                    && out.ntt_profile == "baseline"
                    && out.poseidon_profile == "baseline"
                    && !matches!(
                        out.command.as_str(),
                        "kernel-screen"
                            | "preflight-groups"
                            | "architecture-proof"
                            | "architecture-parent"
                            | "architecture-request"
                            | "architecture-graph"
                    )),
            "kernel/compiler experiments require grouped-v5",
        )?;
        ensure(
            out.compiler_policy == "standard" || out.transactions == 4,
            "wide compiler policy requires N4",
        )?;
        Ok(out)
    }
}
pub(crate) struct Deadline {
    start: Instant,
    limit: Duration,
}
impl Deadline {
    fn new(seconds: u64) -> Self {
        Self {
            start: Instant::now(),
            limit: Duration::from_secs(seconds),
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        ensure(
            self.start.elapsed() < self.limit,
            "aggregation deadline exhausted",
        )
    }
    fn seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}
pub(crate) fn construction() -> lattica_prover_p3::block_v2::machine::program::ConstructionLimits {
    crate::component_tree::paired_runtime::source::construction()
}
pub(crate) fn context(options: &Options) -> Result<crate::execution::ProvingContext> {
    let expected = if matches!(options.profile.as_str(), "grouped-v4" | "grouped-v5")
        && options.command != "prepare-inputs"
        && options.query_gather == "batch"
    {
        "events,witness,programs,queries"
    } else if options.profile != "legacy" {
        "events,witness,programs"
    } else {
        ""
    };
    ensure(
        std::env::var("LATTICA_V2_GPU_TUNING").unwrap_or_default() == expected,
        "runner/profile GPU tuning mismatch",
    )?;
    // Native input preparation retains its existing 16 GiB proving partition.
    // Only recursive aggregation uses the consuming backend and worker pool.
    for (key, expected) in [
        ("LATTICA_V2_GPU_NTT_PROFILE", options.ntt_profile.as_str()),
        (
            "LATTICA_V2_GPU_POSEIDON_PROFILE",
            options.poseidon_profile.as_str(),
        ),
    ] {
        ensure(
            std::env::var(key).unwrap_or_else(|_| {
                String::from(if key == "LATTICA_V2_GPU_NTT_PROFILE" {
                    "smalltile"
                } else {
                    "baseline"
                })
            }) == expected,
            "kernel profile differs from guarded selection",
        )?;
    }
    let consuming = matches!(
        options.profile.as_str(),
        "grouped-v3" | "grouped-v4" | "grouped-v5"
    ) && options.command != "prepare-inputs";
    let device_bytes = memory::recheck(options)?;
    let context = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        // Separate CPU compiler/queue reservations fit beside this registered
        // proving allowance in the unchanged 32/36 GiB worker envelope.
        host_bytes: if consuming {
            policy::current().backend_host_bytes
        } else {
            16 << 30
        },
        device_bytes,
        max_rows: options.max_rows(),
    })?;
    if consuming {
        context.configure_consuming_aggregation()?;
    }
    Ok(context)
}
#[cfg(test)]
mod default_tests {
    use super::*;

    #[test]
    fn ordinary_run_uses_measured_pipeline_without_selection_file() {
        let options = Options::parse(
            [
                "run",
                "--case",
                "n4",
                "--input-bundle",
                "/tmp/default-aggregation",
                "--output",
                "/tmp/default-aggregation-output",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        assert_eq!(options.profile, "grouped-v5");
        assert_eq!(options.ntt_profile, "smalltile");
        assert_eq!(options.poseidon_profile, "baseline");
        assert_eq!(options.identity, "cpu");
        assert!(options.parallel);
        assert_eq!(options.group_width, 16);
        assert_eq!(options.query_gather, "batch");
        assert_eq!(options.gpu_managed_mib, "auto");
        assert_eq!(options.compiler_policy, "typed-batch");
        assert!(options.typed_recursion());
        assert!(options.selection.is_none());
        assert_eq!(selection::widths(&options).unwrap(), (16, 8));
    }

    #[test]
    fn historical_comparison_profile_remains_explicit() {
        let options = Options::parse(
            [
                "screen",
                "--case",
                "n3",
                "--input-bundle",
                "/tmp/default-aggregation",
                "--profile",
                "legacy",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        assert_eq!(options.ntt_profile, "baseline");
        assert!(!options.parallel);
        assert_eq!(selection::widths(&options).unwrap(), (2, 1));
    }
    #[test]
    fn machine_compatibility_is_explicit_and_n3_keeps_its_memory_envelope() {
        let parse = |case: &str, backend: &str| {
            Options::parse(
                [
                    "run",
                    "--case",
                    case,
                    "--input-bundle",
                    "/tmp/typed-default",
                    "--output",
                    "/tmp/typed-output",
                    "--recursion-backend",
                    backend,
                ]
                .into_iter()
                .map(String::from),
            )
            .unwrap()
        };
        let old = parse("n4", "machine");
        assert_eq!(old.group_width, 4);
        assert_eq!(old.compiler_policy, "standard");
        let small = parse("n3", "typed");
        assert_eq!(small.group_width, 4);
        assert_eq!(small.compiler_policy, "standard");
        assert!(small.typed_recursion());
    }
}

pub fn run_cli(args: impl Iterator<Item = String>) -> Result<()> {
    let args: Vec<String> = args.collect();
    if args == ["device-inventory"] {
        let (_, _, device) = lattica_prover_p3::gpu_device::select().map_err(error)?;
        println!(
            "GPU_AGGREGATION_DEVICE {}",
            serde_json::json!({"device":device,
            "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint())})
        );
        return Ok(());
    }
    let options = Options::parse(args.into_iter())?;
    policy::install(
        &options.compiler_policy,
        &options.profile,
        options.transactions,
    )?;
    let deadline = Deadline::new(options.seconds);
    ensure(
        cfg!(all(
            not(debug_assertions),
            target_os = "linux",
            target_arch = "x86_64"
        )),
        "GPU aggregation requires release Linux x86_64",
    )?;
    let envelope = resources::Envelope::new(&options)?;
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
        HeightEnvelopeCacheScope, MetadataCpuOptions, MetadataPlanningScope,
    };
    let source = crate::graph_proofs::compiled_source_fingerprint();
    let geometry = HeightEnvelopeCacheScope::begin_with_precomputed(source).map_err(error)?;
    let native = crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(source)
        .map_err(error)?;
    let planning = MetadataPlanningScope::begin(MetadataCpuOptions::workers(2).map_err(error)?)
        .map_err(error)?;
    let mut report = match options.command.as_str() {
        "prepare-inputs" => bundle::prepare(&options, &deadline)?,
        "plan" => graph::plan(&options, &deadline)?,
        "kernel-screen" => kernel_screen::run(&options, &deadline)?,
        "preflight-groups" if options.family == "graph" => {
            graph_screen::screen(&options, &deadline)?
        }
        "preflight-groups" => graph::screen(&options, &deadline)?,
        "architecture-graph" => graph_archive::run(&options, &deadline)?,
        "architecture-proof" | "architecture-parent" | "architecture-request" => {
            architecture::archive_request(&options, &deadline)?
        }
        "screen" | "qualify-memory" if options.family == "graph" => {
            graph_screen::screen(&options, &deadline)?
        }
        "screen" | "qualify-memory" => graph::screen(&options, &deadline)?,
        "run" => graph::run(&options, &deadline)?,
        _ => unreachable!(),
    };
    report["compiler_policy"] = serde_json::to_value(policy::current()).map_err(error)?;
    report["coordinator_metadata"] = serde_json::json!({"native":native.statistics(),"geometry":geometry.statistics(),"planning":planning.statistics()});
    drop((planning, native, geometry));
    report["resources"] = envelope.finish()?;
    if let Some(memory) = memory::selected(&options)? {
        report["memory"] = memory;
    }
    deadline.check()?;
    println!(
        "GPU_AGGREGATION_PROFILE {}",
        serde_json::json!({"schema":"ringct-gpu-aggregation-v1",
        "options":options,"report":report,"controller_wall_seconds":deadline.seconds(),
        "complete_fresh_workflow":false,"performance_qualified":false})
    );
    Ok(())
}
