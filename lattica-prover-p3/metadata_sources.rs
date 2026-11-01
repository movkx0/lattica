//! Build-time invalidation for qualified numeric planning tables. Only the
//! generated rows and unrelated execution sources are excluded.
#[path = "src/block_v2/machine/numeric_sources.rs"]
mod numeric_sources;
use sha3::{Digest, Sha3_256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const GENERATED: &str = "src/block_v2/machine/verifier/batch/shape/precomputed/data.rs";
fn sources(root: &Path, path: &Path, files: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", path.display());
    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("metadata source directory")
        .map(|e| e.expect("metadata source entry").path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            sources(root, &entry, files);
        } else if entry.strip_prefix(root).unwrap() != Path::new(GENERATED) {
            files.push(entry);
        }
    }
}
pub fn write_digest() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = Vec::new();
    // Include every local arithmetic/protocol dependency, even if a particular
    // feature does not use it. Registry sources are pinned by Cargo.lock.
    sources(&root, &root.join("src"), &mut files);
    sources(&root, &root.join("vendor"), &mut files);
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "metadata_sources.rs",
    ] {
        files.push(root.join(name));
    }
    // Both supported build roots must stay pinned. A downstream dependency
    // build uses the research lock rather than this library's own Cargo.lock.
    // A standalone crate without the research lock gets a different digest.
    let research_lock = root.join("../research/pq-ringct/Cargo.lock");
    println!("cargo:rerun-if-changed={}", research_lock.display());
    if research_lock.is_file() {
        files.push(research_lock);
    }
    files.sort();
    files.dedup();
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/qualified-numeric-planning-sources/v2\0");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .as_bytes();
        let label = if name == b"../research/pq-ringct/Cargo.lock" {
            "research/pq-ringct/Cargo.lock".to_string()
        } else {
            format!("lattica-prover-p3/{}", std::str::from_utf8(name).unwrap())
        };
        if !numeric_sources::selected(&label, false) {
            continue;
        }
        let contents = fs::read(&path).expect("metadata source contents");
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        hash.update((contents.len() as u64).to_le_bytes());
        hash.update(contents);
    }
    let rustc = Command::new(env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .expect("metadata rustc version");
    assert!(rustc.status.success());
    let identity = format!(
        "{};target={};opt={};debug={}",
        String::from_utf8(rustc.stdout).unwrap().trim(),
        env::var("TARGET").unwrap(),
        env::var("OPT_LEVEL").unwrap(),
        env::var("DEBUG").unwrap()
    );
    hash.update((identity.len() as u64).to_le_bytes());
    hash.update(identity.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let text = format!("const COMPILED_SOURCE_DIGEST: [u8; 32] = {digest:?};\n");
    let destination = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("metadata-source.rs");
    if fs::read_to_string(&destination).ok().as_deref() != Some(&text) {
        fs::write(destination, text).expect("metadata digest output");
    }
}
