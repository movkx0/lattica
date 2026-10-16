//! Complete unsealed subtrees can be reused only after fresh CPU authentication.

use super::*;
use lattica_prover_p3::block_v2::execution::job::{ArtifactKind, Job};

#[cfg(all(test, not(any(feature = "gpu", feature = "gpu-metal"))))]
#[path = "execution_preseal_diagnostic.rs"]
mod diagnostic;

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
    #[serde(default)]
    pool_workflow: Option<pool_timing::Workflow>,
}

pub(super) fn pool_output_storage_bytes() -> usize {
    std::mem::size_of::<Vec<Node>>() + (profile::MAX_TRANSACTIONS - 2) * std::mem::size_of::<Node>()
}

pub(super) fn pool_output(prefix: bool, jobs: usize) -> Result<Vec<Node>, Error> {
    if !prefix {
        return Ok(Vec::new());
    }
    if !(1..=profile::MAX_TRANSACTIONS - 2).contains(&jobs) {
        return Err("pool prefix output cardinality".into());
    }
    input::exact(jobs)
}

fn check_workflow(cache: &Cache, workflow: Option<&pool_timing::Workflow>) -> Result<(), Error> {
    if let Some(workflow) = workflow {
        if cache.pool_workflow.as_ref() != Some(workflow) {
            return Err("bounded prefix cache changed its original workflow".into());
        }
        workflow.validate_live()?;
    }
    Ok(())
}

pub(super) fn stable(job: &Job) -> bool {
    job.is_complete_non_root_subtree()
}

pub(super) fn name(job: &Job) -> String {
    format!(
        "node.{}.{}",
        job.expected().level,
        job.start() as usize >> job.expected().level
    )
}

pub(super) fn describe(job: &Job, proof: &[u8]) -> Result<Node, Error> {
    describe_artifact(job, ArtifactRef::from_bytes(ArtifactKind::Node, proof)?)
}

fn describe_artifact(job: &Job, artifact: ArtifactRef) -> Result<Node, Error> {
    if !stable(job) {
        return Err("only a complete non-root subtree is eligible for pre-seal reuse".into());
    }
    if artifact.kind() != ArtifactKind::Node {
        return Err("pre-seal descriptor is not a node artifact".into());
    }
    Ok(Node {
        job: job.id().to_bytes(),
        level: job.expected().level,
        index: (job.start() as usize >> job.expected().level) as u8,
        bytes: artifact.byte_len() as usize,
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
    workflow: Option<&pool_timing::Workflow>,
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
    let registry = TypedRegistryContext::new(&prepared.registry, prepared.pin.profile())?;
    for directory in directories {
        let cache: Cache = read_json(&directory.join("result.json"))?;
        if cache.schema_version != 1
            || cache.status != "preseal_verified"
            || !cache.preseal_only
            || cache.stable_nodes.len() > profile::MAX_TRANSACTIONS - 2
        {
            return Err("invalid bounded pre-seal cache manifest".into());
        }
        cache.native_host.check_cache_session(binding)?;
        check_workflow(&cache, workflow)?;
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
            if proof.len() != node.bytes {
                return Err("pre-seal cache artifact bytes changed".into());
            }
            let payload = registry.verify_node_owned(job, proof)?;
            if payload.ticket().artifact().digest_bytes() != node.artifact_digest {
                return Err("pre-seal cache artifact bytes changed".into());
            }
            owner.cache_verified_node(payload, now())?;
            let retained = owner
                .verified_node_bytes(job.id())?
                .ok_or("imported pre-seal node was not retained")?;
            write_bytes(&out.join(name(job)), retained, profile::MAX_PROOF_BYTES)?;
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
    let registry = TypedRegistryContext::new(&prepared.registry, prepared.pin.profile())?;
    let mut verified = Vec::new();
    for job in prepared.selection.jobs().filter(|job| stable(job)) {
        let proof = bytes(&nodes.join(name(job)))?;
        let ticket = registry.verify_node(job, &proof)?;
        verified.push(describe_artifact(job, ticket.artifact())?);
    }
    if verified.is_empty() || nodes.join(profile::ROOT_FILE).exists() {
        return Err("prefix audit requires complete subtrees and no candidate root".into());
    }
    write_json(
        out,
        &json!({"schema_version":1,"record_type":"typed_preseal_audit",
        "status":"passed","cpu_prefix_audited":true,"cpu_audited_roots":0,
        "count":prepared.expected.count,"nodes":verified,"production_ready":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_manifest_backing_is_bounded_before_allocation() {
        for count in 1..=profile::MAX_TRANSACTIONS - 2 {
            let nodes = pool_output(true, count).unwrap();
            assert_eq!(nodes.capacity(), count);
            assert!(
                std::mem::size_of_val(&nodes) + nodes.capacity() * std::mem::size_of::<Node>()
                    <= pool_output_storage_bytes()
            );
        }
        for count in [0, profile::MAX_TRANSACTIONS - 1, usize::MAX] {
            assert!(pool_output(true, count).is_err());
        }
        assert_eq!(
            pool_output(false, profile::MAX_DAG_NODES)
                .unwrap()
                .capacity(),
            0
        );
    }

    #[test]
    fn bounded_import_requires_original_workflow_and_rejects_unbound_or_rebooted_cache() {
        let workflow = pool_timing::Workflow {
            schema_version: 1,
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
                .to_owned(),
            started_monotonic_ms: 0,
            deadline_monotonic_ms: pool_timing::CANDIDATE_MS,
        };
        let binding = json!({"schema_version":1,"scope":"prefix","head_token":vec![1u8;32],"generation":0,
            "configuration_sha256":vec![2u8;32],"complete_body_sha256":vec![3u8;32],
            "preparation_sha256":vec![4u8;32],"expected":{"schema_version":1,
            "profile":vec![5u8;32],"chain":vec![6u8;32],"root":[7,7,7,7],"count":4,
            "block_height":10,"authorized_issuance":{"3":7}}});
        let mut cache: Cache =
            serde_json::from_value(json!({"schema_version":1,"status":"preseal_verified",
            "preseal_only":true,"native_host":binding,"stable_nodes":[]}))
            .unwrap();
        assert!(check_workflow(&cache, Some(&workflow)).is_err());
        cache.pool_workflow = Some(workflow.clone());
        let mut changed = workflow.clone();
        changed.started_monotonic_ms += 1;
        changed.deadline_monotonic_ms += 1;
        assert!(check_workflow(&cache, Some(&changed)).is_err());
        changed.boot_id = "00000000-0000-0000-0000-000000000000".into();
        cache.pool_workflow = Some(changed.clone());
        assert!(check_workflow(&cache, Some(&changed)).is_err());
        check_workflow(&cache, None).unwrap();
    }
}
