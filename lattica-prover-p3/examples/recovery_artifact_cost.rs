//! Measure the unchanged public artifact digest on bounded retained proof files.
//! This never proves, verifies, applies, or mutates a journal or artifact.
use lattica_prover_p3::block_v2::{
    execution::job::{ArtifactKind, ArtifactRef},
    profile::MAX_PROOF_BYTES,
};
use std::{hint::black_box, io::Read, path::Path, time::Instant};

fn measure(kind: ArtifactKind, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PROOF_BYTES as u64
    {
        return Err("digest benchmark requires a bounded regular public proof".into());
    }
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file).take(MAX_PROOF_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("digest benchmark input length changed".into());
    }
    let expected = ArtifactRef::from_bytes(kind, &bytes)?;
    let mut samples = Vec::with_capacity(10);
    for _ in 0..10 {
        let started = Instant::now();
        let observed = ArtifactRef::from_bytes(kind, black_box(bytes.as_slice()))?;
        samples.push(started.elapsed().as_nanos());
        if black_box(observed) != expected {
            return Err("digest benchmark changed an artifact identity".into());
        }
    }
    println!("{}", serde_json::json!({
        "kind":if kind == ArtifactKind::Wallet {"wallet"} else {"node"},
        "bytes":bytes.len(),"samples_ns":samples,"artifact_digest":expected.digest_bytes(),
        "fresh_proofs":0,"native_blocks_applied":0,"journal_mutated":false
    }));
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("usage: recovery_artifact_cost WALLET_PROOF NODE_PROOF".into());
    }
    measure(ArtifactKind::Wallet, Path::new(&arguments[0]))?;
    measure(ArtifactKind::Node, Path::new(&arguments[1]))
}
