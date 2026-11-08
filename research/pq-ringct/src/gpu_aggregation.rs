//! Explicit imported-component GPU experiment. Never a fresh-workflow receipt.
use crate::{component_tree, graph_crypto};
use lattica_prover_p3::block_v2::machine::program::Val;
use sha3::{Digest, Sha3_256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
mod bundle;
mod graph;
mod graph_screen;
mod inputs;
mod layout;
pub(crate) mod pipeline;
mod resources;
mod selection;
#[cfg(test)]
mod tests;
type Result<T> = std::result::Result<T, String>;
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
}
impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let command = args
            .next()
            .ok_or("expected prepare-inputs, plan, screen or run")?;
        ensure(
            matches!(
                command.as_str(),
                "prepare-inputs" | "plan" | "screen" | "run"
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
            profile: "legacy".into(),
            group_width: 2,
            parallel: false,
            seconds: 600,
            max_components: usize::MAX,
            identity: "cpu".into(),
            selection: None,
            request: None,
            repetitions: 1,
            family: "shake".into(),
            first_leaf: 0,
            leaves: 8,
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
                _ => return Err(format!("unknown aggregation option {key}")),
            }
        }
        ensure(
            !out.bundle.as_os_str().is_empty()
                && out.workload <= 1
                && matches!(out.group_width, 1 | 2 | 4 | 8)
                && (1..=600).contains(&out.seconds)
                && out.max_components > 0
                && (1..=4).contains(&out.repetitions)
                && (out.command == "screen" || out.repetitions == 1),
            "invalid aggregation limits",
        )?;
        ensure(
            matches!(out.profile.as_str(), "legacy" | "grouped-v2"),
            "invalid aggregation profile",
        )?;
        ensure(
            matches!(out.family.as_str(), "shake" | "graph")
                && (1..=8).contains(&out.leaves)
                && (out.family != "graph"
                    || (out.request.is_none()
                        && matches!(out.command.as_str(), "screen" | "prepare-inputs"))),
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
    let expected = if options.profile == "grouped-v2" {
        "events,witness,programs"
    } else {
        ""
    };
    ensure(
        std::env::var("LATTICA_V2_GPU_TUNING").unwrap_or_default() == expected,
        "runner/profile GPU tuning mismatch",
    )?;
    crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        // Separate CPU compiler/queue reservations fit beside this registered
        // proving allowance in the unchanged 32/36 GiB worker envelope.
        host_bytes: 16 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
}
pub fn run_cli(args: impl Iterator<Item = String>) -> Result<()> {
    let options = Options::parse(args)?;
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
        "screen" if options.family == "graph" => graph_screen::screen(&options, &deadline)?,
        "screen" => graph::screen(&options, &deadline)?,
        "run" => graph::run(&options, &deadline)?,
        _ => unreachable!(),
    };
    report["coordinator_metadata"] = serde_json::json!({"native":native.statistics(),"geometry":geometry.statistics(),"planning":planning.statistics()});
    drop((planning, native, geometry));
    report["resources"] = envelope.finish()?;
    deadline.check()?;
    println!(
        "GPU_AGGREGATION_PROFILE {}",
        serde_json::json!({"schema":"ringct-gpu-aggregation-v1",
        "options":options,"report":report,"controller_wall_seconds":deadline.seconds(),
        "complete_fresh_workflow":false,"performance_qualified":false})
    );
    Ok(())
}
