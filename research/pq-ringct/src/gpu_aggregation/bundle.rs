//! Disk artifacts are inputs, never verification or execution authority.
use super::*;
use crate::{graph_auxiliary, graph_proofs, graph_sources};
use std::io::{Read, Write};
const ENTRY_LIMIT: u64 = 64 << 20;
const BUNDLE_LIMIT: u64 = 2 << 30;
#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    path: String,
    bytes: u64,
    sha3: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    schema: String,
    input_sha3: String,
    source_sha3: String,
    transactions: usize,
    workload: usize,
    complete: bool,
    component_instances: usize,
    files: Vec<Entry>,
}
pub(crate) struct Caches {
    pub sources: graph_sources::SourceCache,
    pub algebra: graph_proofs::ProofCache,
    pub crypto: graph_crypto::ProofCache,
    pub auxiliary: graph_auxiliary::AuxiliaryCache,
}
impl Caches {
    pub fn new(root: &Path, create: bool) -> Result<Self> {
        if !create {
            for family in ["sources", "algebra", "crypto", "auxiliary"] {
                ensure(
                    std::fs::symlink_metadata(root.join(family))
                        .map_err(error)?
                        .is_dir(),
                    "missing or linked component family directory",
                )?;
            }
        }
        Ok(Self {
            sources: graph_sources::SourceCache::new(root.join("sources"), ENTRY_LIMIT)
                .map_err(error)?,
            algebra: graph_proofs::ProofCache::new(root.join("algebra"), ENTRY_LIMIT)
                .map_err(error)?,
            crypto: graph_crypto::ProofCache::new(root.join("crypto"), ENTRY_LIMIT)
                .map_err(error)?,
            auxiliary: graph_auxiliary::AuxiliaryCache::new(root.join("auxiliary"), ENTRY_LIMIT)
                .map_err(error)?,
        })
    }
}
fn file_digest(path: &Path, limit: u64) -> Result<(u64, String)> {
    let metadata = std::fs::symlink_metadata(path).map_err(error)?;
    ensure(
        metadata.is_file() && metadata.len() <= limit,
        "invalid component file type/size",
    )?;
    let mut file = std::fs::File::open(path).map_err(error)?;
    let mut hash = Sha3_256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(error)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or("file size overflow")?;
        ensure(count <= limit, "component file grew beyond limit")?;
        hash.update(&buffer[..n]);
    }
    ensure(
        count == metadata.len(),
        "component file changed while reading",
    )?;
    Ok((count, hex(&hash.finalize())))
}
fn relative(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 2
        && matches!(parts[0], "sources" | "algebra" | "crypto" | "auxiliary")
        && parts[1].len() == 69
        && parts[1].is_ascii()
        && parts[1].ends_with(".json")
        && parts[1][..64].bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn validate(options: &Options, complete: bool) -> Result<()> {
    let path = options.bundle.join("manifest.json");
    file_digest(&path, 4 << 20)?;
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(path).map_err(error)?).map_err(error)?;
    ensure(
        manifest.schema == "ringct-native-component-bundle-v1"
            && manifest.transactions == options.transactions
            && manifest.workload == options.workload
            && (!complete || manifest.complete)
            && manifest.files.len() <= 16384
            && manifest.source_sha3 == hex(&crate::graph_proofs::compiled_source_fingerprint()),
        "component bundle identity/completeness mismatch",
    )?;
    ensure(
        file_digest(&options.input, 8 << 20)?.1 == manifest.input_sha3,
        "component bundle input digest mismatch",
    )?;
    for family in ["sources", "algebra", "crypto", "auxiliary"] {
        ensure(
            std::fs::symlink_metadata(options.bundle.join(family))
                .map_err(error)?
                .is_dir(),
            "invalid component family directory",
        )?;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut bytes = 0u64;
    for entry in manifest.files {
        ensure(
            relative(&entry.path) && seen.insert(entry.path.clone()),
            "invalid/duplicate component path",
        )?;
        let actual = file_digest(&options.bundle.join(&entry.path), ENTRY_LIMIT)?;
        ensure(
            actual == (entry.bytes, entry.sha3),
            "component bundle file integrity mismatch",
        )?;
        bytes = bytes.checked_add(entry.bytes).ok_or("bundle overflow")?;
        ensure(bytes <= BUNDLE_LIMIT, "component bundle exceeds 2 GiB")?;
    }
    Ok(())
}
fn publish(options: &Options, input_sha3: String, complete: bool, instances: usize) -> Result<()> {
    let mut files = Vec::new();
    let mut bytes = 0u64;
    for family in ["sources", "algebra", "crypto", "auxiliary"] {
        for file in std::fs::read_dir(options.bundle.join(family)).map_err(error)? {
            let file = file.map_err(error)?;
            let path = format!("{family}/{}", file.file_name().to_string_lossy());
            if path.split('/').nth(1).is_some_and(|n| n.starts_with('.')) {
                continue;
            }
            ensure(relative(&path), "unexpected component file")?;
            let (size, sha3) = file_digest(&file.path(), ENTRY_LIMIT)?;
            bytes = bytes.checked_add(size).ok_or("bundle overflow")?;
            ensure(
                bytes <= BUNDLE_LIMIT && files.len() < 16384,
                "component bundle capacity exceeded",
            )?;
            files.push(Entry {
                path,
                bytes: size,
                sha3,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        schema: "ringct-native-component-bundle-v1".into(),
        input_sha3,
        source_sha3: hex(&crate::graph_proofs::compiled_source_fingerprint()),
        transactions: options.transactions,
        workload: options.workload,
        complete,
        component_instances: instances,
        files,
    };
    let tmp = options
        .bundle
        .join(format!("manifest-{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(error)?;
    serde_json::to_writer(&mut file, &manifest).map_err(error)?;
    file.flush().map_err(error)?;
    file.sync_all().map_err(error)?;
    std::fs::rename(tmp, options.bundle.join("manifest.json")).map_err(error)?;
    Ok(())
}
pub(crate) fn prepare(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    std::fs::create_dir_all(&options.bundle).map_err(error)?;
    if !options.input.exists() {
        inputs::generate(options, &options.input)?;
    }
    let (cases, digest) = inputs::load(options)?;
    if options.bundle.join("manifest.json").exists() {
        validate(options, false)?;
    }
    ensure(
        options
            .request
            .is_none_or(|i| i < cases[0].plan.requests().len()),
        "request outside case",
    )?;
    let caches = Caches::new(&options.bundle, true)?;
    let execution = context(options)?;
    let mut generated = 0usize;
    let mut instances = 0usize;
    let mut complete = true;
    let outcome: Result<()> = (|| {
        if options.family == "graph" {
            complete = false;
            instances = super::graph_screen::prepare(
                &cases[0],
                options,
                &caches,
                &execution,
                deadline,
                &mut generated,
            )?;
            return Ok(());
        }
        'cases: for (case_index, case) in cases.iter().enumerate() {
            if options.request.is_some() && case_index > 0 {
                complete = false;
                break;
            }
            let sources = graph_sources::SourceFactory::new(
                &case.tree,
                &case.graph,
                &case.context,
                &case.statement,
                &case.private_proof,
                24 << 30,
            )
            .map_err(error)?;
            // Crypto first gives resumable representative inputs for the grouping screen.
            for (request_index, request) in case.plan.requests().iter().enumerate() {
                if options.request.is_some_and(|i| i != request_index) {
                    continue;
                }
                for index in 0..request.segments().len() {
                    deadline.check()?;
                    instances += 1;
                    if caches.crypto.load(request, index).map_err(error)?.is_none() {
                        if generated == options.max_components {
                            complete = false;
                            break 'cases;
                        }
                        let proof = request
                            .prove_segment_with_context(index, Some(&execution))
                            .map_err(error)?;
                        caches.crypto.store(request, index, &proof).map_err(error)?;
                        generated += 1;
                        eprintln!(
                            "gpu_aggregation_component_generated family=crypto count={generated}"
                        );
                    }
                }
            }
            if options.request.is_some() {
                complete = false;
                break;
            }
            deadline.check()?;
            instances += 1;
            if sources
                .load_statement(&caches.sources)
                .map_err(error)?
                .is_none()
            {
                if generated == options.max_components {
                    complete = false;
                    break;
                }
                let proof = sources
                    .prove_statement_with_context(Some(&execution))
                    .map_err(error)?;
                sources
                    .store_statement(&caches.sources, &proof)
                    .map_err(error)?;
                generated += 1;
            }
            deadline.check()?;
            instances += 1;
            if sources
                .load_private(&caches.sources)
                .map_err(error)?
                .is_none()
            {
                if generated == options.max_components {
                    complete = false;
                    break;
                }
                let proof = sources
                    .prove_private_with_context(Some(&execution))
                    .map_err(error)?;
                sources
                    .store_private(&caches.sources, &proof)
                    .map_err(error)?;
                generated += 1;
            }
            let algebra = case.algebra()?;
            for (index, batch) in algebra.batches().iter().enumerate() {
                if batch.resource_estimate().is_none() {
                    continue;
                }
                deadline.check()?;
                instances += 1;
                if caches
                    .algebra
                    .load(&algebra, index)
                    .map_err(error)?
                    .is_none()
                {
                    if generated == options.max_components {
                        complete = false;
                        break 'cases;
                    }
                    let proof = algebra
                        .prove_batch_with_context(index, Some(&execution))
                        .map_err(error)?;
                    caches
                        .algebra
                        .store(&algebra, index, &proof)
                        .map_err(error)?;
                    generated += 1;
                }
            }
            let aux = graph_auxiliary::AuxiliaryFactory::new(
                &case.tree,
                &case.graph,
                &case.context,
                24 << 30,
            )
            .map_err(error)?;
            for request in aux.requests() {
                deadline.check()?;
                instances += 1;
                if caches.auxiliary.load(request).map_err(error)?.is_none() {
                    if generated == options.max_components {
                        complete = false;
                        break 'cases;
                    }
                    let proof = request
                        .prove_with_context(Some(&execution))
                        .map_err(error)?;
                    caches.auxiliary.store(request, &proof).map_err(error)?;
                    generated += 1;
                }
            }
        }
        Ok(())
    })();
    let cleanup = execution.close_without_completion()?;
    // Persist completed verified children even after a cooperative deadline.
    publish(options, digest, complete && outcome.is_ok(), instances)?;
    outcome?;
    Ok(
        serde_json::json!({"scope":"native-component-preparation","complete":complete,"generated":generated,
        "component_instances":instances,"session_closed":cleanup["session_closed"],"aggregation_timed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_reject_mutation_incomplete_manifest_wrong_inputs_and_links() {
        let directory =
            std::env::temp_dir().join(format!("ringct-aggregation-bundle-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let options = Options::parse(
            ["plan", "--input-bundle", directory.to_str().unwrap()]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        let _ = Caches::new(&directory, true).unwrap();
        std::fs::write(&options.input, b"public fixture").unwrap();
        let path = directory
            .join("crypto")
            .join(format!("{}.json", "ab".repeat(32)));
        std::fs::write(&path, b"native component").unwrap();
        let digest = file_digest(&options.input, 1 << 20).unwrap().1;
        publish(&options, digest.clone(), false, 1).unwrap();
        assert!(validate(&options, false).is_ok());
        assert!(validate(&options, true).is_err());
        publish(&options, digest, true, 1).unwrap();
        assert!(validate(&options, true).is_ok());
        std::fs::write(&path, b"changed component").unwrap();
        assert!(validate(&options, true).is_err());
        std::fs::write(&path, b"native component").unwrap();
        std::fs::write(&options.input, b"wrong fixture").unwrap();
        assert!(validate(&options, true).is_err());
        std::fs::write(&options.input, b"public fixture").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&options.input, &path).unwrap();
        assert!(validate(&options, true).is_err());
        assert!(!relative("../inputs.json"));
        assert!(!relative(&format!("crypto/{}.json", "é".repeat(32))));
    }
}
