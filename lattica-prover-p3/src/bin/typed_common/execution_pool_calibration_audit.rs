//! Independent CPU audit of complete calibration proof bytes. No result or
//! timing receipt is proof authority, and this command never approves timings.
use super::*;

#[derive(serde::Serialize)]
struct Record {
    source: &'static str,
    index: usize,
    job: String,
    artifact_digest: String,
    proof_bytes: usize,
    mode: u64,
    level: u8,
    count: u8,
}

fn verify(
    registry: &typed_recursive::Registry<12>,
    job: &Job,
    path: &Path,
    source: &'static str,
    index: usize,
) -> Result<Record, Error> {
    // Read a bounded regular nonsymlink file through EOF, then decode and
    // verify the whole proof against the independently reconstructed job.
    let proof = bytes(path)?;
    let ticket = VerifiedNode::verify_typed(job, registry, &proof)?;
    Ok(Record {
        source,
        index,
        job: hex(&job.id().to_bytes()),
        artifact_digest: hex(&ticket.artifact().digest_bytes()),
        proof_bytes: proof.len(),
        mode: job.expected_public()[programs::MODE].as_canonical_u64(),
        level: job.expected().level,
        count: job.expected().count,
    })
}

pub(in super::super) fn run(
    dir: &Path,
    pinned: &Path,
    request_path: &Path,
    nodes: &Path,
    out: &Path,
) -> Result<(), Error> {
    if !PAIRED || cfg!(any(feature = "gpu", feature = "gpu-metal")) {
        return Err("calibration proof audit requires the CPU-only paired CLI".into());
    }
    let input = read_bytes(request_path, JSON_LIMIT)?;
    let request: Request = serde_json::from_slice(&input)?;
    let request_digest = configuration_digest(&input)?;
    drop(input);
    request.validate()?;
    let metadata = fs::symlink_metadata(nodes)?;
    if !nodes.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("calibration audit proof directory must be absolute and nonsymlink".into());
    }
    let prepared = prepare(dir, pinned)?;
    let jobs = request.ordered(prepared.selection.jobs())?;
    let mut records = input::exact(request.seeds.len() + jobs.len())?;
    for (index, seed) in request.seeds.iter().enumerate() {
        let job = prepared
            .selection
            .jobs()
            .find(|job| job.id().to_bytes() == seed.job)
            .ok_or("calibration audit seed is outside the independent selection")?;
        records.push(verify(&prepared.registry, job, &seed.path, "seed", index)?);
    }
    for (index, job) in jobs.iter().enumerate() {
        let path = nodes.join(format!(
            "node.{}.{}",
            job.expected().level,
            job.start() as usize >> job.expected().level
        ));
        records.push(verify(&prepared.registry, job, &path, "requested", index)?);
    }
    // No success artifact exists until every seed and requested node passes.
    // The original failed trial, clock and timing identity remain untouched.
    write_json(
        out,
        &json!({
            "schema_version":1, "record_type":"typed_pool_calibration_proof_audit", "status":"passed",
            "auditor_executable":image_fingerprint(&std::env::current_exe()?)?,
            "request_digest":hex(&request_digest), "request_identity":request.identity,
            "registry_profile":prepared.expected.profile, "chain":prepared.expected.chain,
            "candidate_root_job":hex(&prepared.selection.root().id().to_bytes()),
            "candidate_count":prepared.expected.count, "cpu_verified_wallets":prepared.expected.count,
            "requested_proofs":jobs.len(), "seed_proofs":request.seeds.len(), "proofs":records,
            "independent_selection":true, "complete_proof_bytes_verified":true,
            "complete_candidate_dag":false, "cpu_audited_roots":0, "gpu_workers_started":0,
            "timing_approved":false, "native_applied":false, "production_ready":false,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_complete_inventory_receipt_fits_without_proof_payloads() {
        let record = || Record {
            source: "requested",
            index: MAX_SEEDS + MAX_JOBS,
            job: "f".repeat(64),
            artifact_digest: "f".repeat(64),
            proof_bytes: profile::MAX_PROOF_BYTES,
            mode: 12,
            level: 6,
            count: 64,
        };
        let records: Vec<_> = (0..MAX_SEEDS + MAX_JOBS).map(|_| record()).collect();
        // Keep separate room for the fixed receipt fields and five identity
        // fingerprints. Proof bytes are streamed one at a time, never retained.
        assert!(serde_json::to_vec_pretty(&records).unwrap().len() + 8192 < JSON_LIMIT);
    }

    #[test]
    fn gpu_or_other_registry_auditor_rejects_before_reading_any_input() {
        if !PAIRED || cfg!(any(feature = "gpu", feature = "gpu-metal")) {
            let absent = Path::new("/nonexistent/calibration-audit-input");
            let error = run(absent, absent, absent, absent, absent).unwrap_err();
            assert_eq!(
                error.to_string(),
                "calibration proof audit requires the CPU-only paired CLI"
            );
        }
    }
}
