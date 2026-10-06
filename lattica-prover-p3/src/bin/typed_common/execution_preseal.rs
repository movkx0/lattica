//! Complete unsealed subtrees can be reused only after fresh CPU authentication.

use super::*;
use lattica_prover_p3::block_v2::execution::job::{ArtifactKind, Job};

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Node {
    job: [u8; 32],
    level: u8,
    index: u8,
    bytes: usize,
    artifact_digest: [u8; 32],
}

#[derive(serde::Deserialize)]
struct Cache {
    schema_version: u32,
    status: String,
    preseal_only: bool,
    native_host: native::Binding,
    stable_nodes: Vec<Node>,
}

pub(super) fn stable(job: &Job) -> bool {
    let node = job.expected();
    node.level > 0 && node.level < 6 && u16::from(node.count) == 1u16 << node.level
}

pub(super) fn name(job: &Job) -> String {
    format!(
        "node.{}.{}",
        job.expected().level,
        job.start() as usize >> job.expected().level
    )
}

pub(super) fn describe(job: &Job, proof: &[u8]) -> Result<Node, Error> {
    if !stable(job) {
        return Err("only a complete non-root subtree is eligible for pre-seal reuse".into());
    }
    let artifact = ArtifactRef::from_bytes(ArtifactKind::Node, proof)?;
    Ok(Node {
        job: job.id().to_bytes(),
        level: job.expected().level,
        index: (job.start() as usize >> job.expected().level) as u8,
        bytes: proof.len(),
        artifact_digest: artifact.digest_bytes(),
    })
}

pub(super) fn import(
    directories: &[PathBuf],
    binding: Option<&native::Binding>,
    prepared: &Prepared,
    owner: &mut DurableDag,
    out: &Path,
    now: impl Fn() -> u64,
) -> Result<Vec<serde_json::Value>, Error> {
    if directories.is_empty() {
        return Ok(Vec::new());
    }
    if directories.len() > 64 {
        return Err("pre-seal cache directory limit exceeded".into());
    }
    let binding = binding.ok_or("pre-seal reuse requires an independently bound native head")?;
    let jobs: BTreeMap<_, _> = prepared
        .selection
        .jobs()
        .map(|j| (j.id().to_bytes(), j))
        .collect();
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for directory in directories {
        let cache: Cache = read_json(&directory.join("result.json"))?;
        if cache.schema_version != 1
            || cache.status != "preseal_verified"
            || !cache.preseal_only
            || cache.stable_nodes.len() > 62
        {
            return Err("invalid bounded pre-seal cache manifest".into());
        }
        cache.native_host.check_cache_session(binding)?;
        for node in cache.stable_nodes {
            let Some(job) = jobs.get(&node.job) else {
                continue;
            };
            if !stable(job)
                || node.level != job.expected().level
                || node.index as usize != job.start() as usize >> job.expected().level
                || node.bytes == 0
                || node.bytes > profile::MAX_PROOF_BYTES
            {
                return Err("pre-seal cache geometry differs from the current semantic job".into());
            }
            if seen.contains(&node.job) {
                continue;
            }
            let path = directory.join(name(job));
            let proof = bytes(&path)?;
            let artifact = ArtifactRef::from_bytes(ArtifactKind::Node, &proof)?;
            if proof.len() != node.bytes || artifact.digest_bytes() != node.artifact_digest {
                return Err("pre-seal cache artifact bytes changed".into());
            }
            let ticket = VerifiedNode::verify_typed(job, &prepared.registry, &proof)?;
            owner.cache_node(ticket, proof.clone(), now())?;
            write_bytes(&out.join(name(job)), &proof, profile::MAX_PROOF_BYTES)?;
            seen.insert(node.job);
            records.push(
                json!({"job":hex(&node.job),"source":path,"level":node.level,
                "index":node.index,"bytes":node.bytes,"cpu_reverified":true}),
            );
        }
    }
    Ok(records)
}

pub(super) fn audit(dir: &Path, pinned: &Path, nodes: &Path, out: &Path) -> Result<(), Error> {
    let prepared = prepare(dir, pinned)?;
    let mut verified = Vec::new();
    for job in prepared.selection.jobs().filter(|job| stable(job)) {
        let proof = bytes(&nodes.join(name(job)))?;
        let _ticket = VerifiedNode::verify_typed(job, &prepared.registry, &proof)?;
        verified.push(describe(job, &proof)?);
    }
    if verified.is_empty() || nodes.join("node.6.0").exists() {
        return Err("prefix audit requires complete subtrees and no candidate root".into());
    }
    write_json(
        out,
        &json!({"schema_version":1,"record_type":"typed_preseal_audit",
        "status":"passed","cpu_prefix_audited":true,"cpu_audited_roots":0,
        "count":prepared.expected.count,"nodes":verified,"production_ready":false}),
    )
}
