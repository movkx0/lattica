//! CPU verification and durable replay of the typed execution graph.
//! This diagnostic does not dispatch a prover or apply native chain state.
use super::*;
use lattica_prover_p3::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::Limits,
    job::{ArtifactRef, RegistryPin, VerifiedNode, VerifiedWallet},
    journal::{DurableDag, JournalLimits},
    resources::Resources,
    selection::{PublicInput, Selection},
};
use std::os::unix::fs::DirBuilderExt;

struct Prepared {
    registry: typed_recursive::Registry<12>,
    pin: RegistryPin,
    expected: Expected,
    selection: Selection,
    policies: Vec<(ArtifactRef, Policy)>,
}

fn bytes(path: &Path) -> Result<Vec<u8>, Error> {
    read_bytes(path, profile::MAX_PROOF_BYTES)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn prepare(dir: &Path, pinned: &Path) -> Result<Prepared, Error> {
    prepare_for_backend(dir, pinned, false)
}

fn prepare_for_backend(dir: &Path, pinned: &Path, gpu: bool) -> Result<Prepared, Error> {
    // The parent CPU command dispatcher also rejects active GPU/quotient env.
    if cfg!(any(feature = "gpu", feature = "gpu-metal")) && !gpu {
        return Err("execution diagnostics require a CPU-only unfused probe".into());
    }
    if gpu && !cfg!(any(feature = "gpu", feature = "gpu-metal")) {
        return Err("typed GPU execution requires a GPU build".into());
    }
    if !PAIRED {
        return Err("typed execution requires the paired twelve-key probe".into());
    }
    let expected: Expected = read_json(pinned)?;
    expected.validate()?;
    let body = body(dir)?;
    let baseline = tasks(&body, &expected)?;
    let registered = registry(dir)?;
    let registry = typed_recursive::Registry::<12> {
        height: registered.height,
        caps: registered
            .caps
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "typed execution registry size")?,
    };
    let pin = RegistryPin::new_typed(&registry, expected.profile)?;
    let mut inputs = Vec::new();
    let mut policies = Vec::new();
    for index in 0..expected.count as usize {
        let policy = policy(&body.transactions[index], index, &expected)?;
        let proof = bytes(&dir.join(format!("wallet.{index}")))?;
        let ticket = VerifiedWallet::verify_typed(pin, &registry, expected.chain, policy, &proof)?;
        policies.push((ticket.artifact(), policy));
        inputs.push(PublicInput::new(ticket, proof)?);
    }
    let selection = Selection::new(pin, expected.chain, &inputs)?;
    if selection.root().expected_public() != expected.public()
        || selection.jobs().len() != baseline.len()
    {
        return Err("execution selection differs from independent paired proof plan".into());
    }
    for job in selection.jobs() {
        let target = baseline
            .iter()
            .find(|t| {
                t.level == job.expected().level && t.index == (job.start() as usize >> t.level)
            })
            .ok_or("execution job absent from paired plan")?;
        if target.public() != job.expected_public() {
            return Err("execution job statement differs from paired plan".into());
        }
    }
    Ok(Prepared {
        registry,
        pin,
        expected,
        selection,
        policies,
    })
}

#[path = "execution_budget.rs"]
mod budget;
#[path = "execution_fleet.rs"]
mod fleet;
#[path = "execution_process.rs"]
mod process;
#[path = "execution_prove.rs"]
mod proving;
#[path = "execution_recover.rs"]
mod recovery;
pub(super) use fleet::audit_preseal;
pub(super) use fleet::prove as prove_fleet;
pub(super) use process::{prove as prove_process, serve as serve_process};

pub(super) use recovery::recover;

pub(super) fn prove(
    dir: &Path,
    pinned: &Path,
    out: &Path,
    budget: u64,
    gpu: bool,
    before_shutdown: impl FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    proving::run(
        prepare_for_backend(dir, pinned, gpu)?,
        out,
        budget,
        gpu,
        None,
        before_shutdown,
    )
}

fn describe(prepared: &Prepared) -> serde_json::Value {
    json!({"schema_version":1, "record_type":"typed_execution_plan", "cpu_leaf_verified":true,
           "count":prepared.expected.count, "height":prepared.expected.block_height,
           "registry_keys":12, "profile":hex(&prepared.pin.profile()),
           "root_job":hex(&prepared.selection.root().id().to_bytes()),
           "prover_jobs_started":0, "production_ready":false,
           "jobs":prepared.selection.jobs().map(|job| json!({
               "id":hex(&job.id().to_bytes()), "operation":format!("{:?}",job.operation()),
               "start":job.start(), "level":job.expected().level, "count":job.expected().count,
               "mode":job.expected_public()[programs::MODE].as_canonical_u64(),
               "dependencies":job.dependencies().iter().map(|id|hex(&id.to_bytes())).collect::<Vec<_>>(),
               "wallet_artifacts":job.wallet_inputs().iter().map(|a|json!({"digest":hex(&a.digest_bytes()),"bytes":a.byte_len()})).collect::<Vec<_>>()
           })).collect::<Vec<_>>()})
}

pub(super) fn plan(dir: &Path, pinned: &Path, out: &Path) -> Result<(), Error> {
    let prepared = prepare(dir, pinned)?;
    write_json(out, &describe(&prepared))
}

pub(super) fn audit(
    dir: &Path,
    pinned: &Path,
    nodes: &Path,
    head: &str,
    out: &Path,
) -> Result<(), Error> {
    let started = Instant::now();
    if head.len() != 64 || !head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("independently supplied host head must be 32 hex bytes".into());
    }
    let mut eligibility = [0u8; 32];
    for (i, b) in eligibility.iter_mut().enumerate() {
        *b = u8::from_str_radix(&head[2 * i..2 * i + 2], 16)?;
    }
    let prepared = prepare(dir, pinned)?;
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    write_json(&out.join("plan.json"), &describe(&prepared))?;
    let store_limits = StoreLimits {
        bytes: 128 << 20,
        entries: 512,
    };
    let journal_limits = JournalLimits {
        snapshot_bytes: 1 << 20,
    };
    let limits = Limits {
        jobs: 256,
        candidates: 8,
        attempts: 256,
        artifact_bytes: 128 << 20,
        recovery_window_ms: 3_600_000,
        workers: Resources {
            ram_bytes: 1 << 30,
            vram_bytes: 0,
            scratch_bytes: 0,
            threads: 2,
        },
    };
    let now = || started.elapsed().as_millis() as u64;
    let store = ArtifactStore::create(&out.join("artifacts"), store_limits)?;
    let mut owner = DurableDag::create(
        &out.join("journal"),
        journal_limits,
        store,
        prepared.pin,
        prepared.expected.chain,
        1,
        limits,
    )?;
    let candidate = prepared
        .selection
        .attach(&mut owner, eligibility, now() + 3_600_000, now())?;
    let mut checks = vec![
        "retained typed wallet proofs independently CPU verified",
        "every job matches the paired reference plan",
    ];
    let mut audited = 0;
    for job in prepared.selection.jobs() {
        let name = format!(
            "node.{}.{}",
            job.expected().level,
            job.start() as usize >> job.expected().level
        );
        let proof = bytes(&nodes.join(name))?;
        let ticket = VerifiedNode::verify_typed(job, &prepared.registry, &proof)?;
        // Importing a previously proved node starts no worker and creates no
        // stop receipt. Actual dispatch and worker recovery are separate gates.
        owner.cache_node(ticket, proof, now())?;
        audited += 1;
    }
    checks.push("every retained recursive node independently CPU verified and durably cached");
    owner.seal(candidate, eligibility, now())?;
    let root = owner
        .candidate_result(candidate, eligibility, now())?
        .ok_or("audited root unavailable")?
        .to_vec();
    let mut wrong_head = eligibility;
    wrong_head[0] ^= 1;
    if owner.candidate_result(candidate, wrong_head, now()).is_ok() {
        return Err("typed candidate accepted wrong host eligibility".into());
    }
    checks.push("root export rejects a changed host eligibility token");
    if owner.resource_use()? != Resources::default() {
        return Err("artifact replay reserved worker resources".into());
    }
    drop(owner);
    let store = ArtifactStore::open(&out.join("artifacts"), store_limits)?;
    let recovery = DurableDag::recover_typed(
        &out.join("journal"),
        journal_limits,
        store,
        prepared.pin,
        &prepared.registry,
        prepared.expected.chain,
        2,
        limits,
        |identity| {
            prepared
                .policies
                .iter()
                .find(|(a, _)| *a == identity)
                .map(|(_, p)| *p)
                .ok_or_else(|| "wallet absent from independent host policy".into())
        },
    )?;
    if !recovery.unresolved_attempts().is_empty() {
        return Err("cache-only replay has an unexpected worker attempt".into());
    }
    let mut owner = recovery.resume(
        |_| Err("cache-only replay cannot acknowledge a worker".into()),
        now,
    )?;
    checks.push(
        "journal recovery reverified every wallet and node against independent registry and policy",
    );
    let restored = prepared
        .selection
        .attach(&mut owner, eligibility, now() + 3_600_000, now())?;
    if !owner.ready()?.is_empty() {
        return Err("recovered typed graph lost a verified cached node".into());
    }
    owner.seal(restored, eligibility, now())?;
    if owner.candidate_result(restored, eligibility, now())? != Some(root.as_slice()) {
        return Err("recovered typed root differs from original".into());
    }
    checks.push("fresh-epoch selection reused the complete verified graph and exact root");
    write_json(
        &out.join("summary.json"),
        &json!({"schema_version":1,"record_type":"typed_execution_replay_audit",
        "status":"succeeded","checks":checks,"count":prepared.expected.count,"height":prepared.expected.block_height,
        "cpu_audited_nodes":audited,"prover_jobs_started":0,"native_blocks_applied":0,
        "artifact_replay_only":true,"production_ready":false,"elapsed_seconds":started.elapsed().as_secs_f64()}),
    )
}
