//! Build-time inputs for persistent research proof-cache invalidation.
#[path = "../../lattica-prover-p3/src/block_v2/machine/numeric_sources.rs"]
mod numeric_sources;
use sha3::{Digest, Sha3_256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn rust_sources(path: &Path, files: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", path.display());
    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("read proof source directory")
        .map(|entry| entry.expect("proof source entry").path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            rust_sources(&entry, files);
        } else if entry.extension().is_some_and(|extension| {
            matches!(
                extension.to_str(),
                Some("rs" | "cl" | "cu" | "metal" | "c" | "h" | "inc")
            )
        }) {
            files.push(entry);
        }
    }
}
pub fn write_manifest() {
    let crate_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = crate_dir.parent().unwrap().parent().unwrap();
    let mut files = Vec::new();
    for path in [
        "research/pq-ringct/src",
        "research/pq-ringct/native",
        "research/pq-ringct/vendor/matrict-plus",
        "lattica-prover-p3/src",
        "lattica-prover-p3/vendor/p3-field/src",
        "lattica-prover-p3/vendor/p3-lookup/src",
        "lattica-prover-p3/vendor/p3-symmetric/src",
    ] {
        rust_sources(&root.join(path), &mut files);
    }
    for path in [
        "research/pq-ringct/Cargo.toml",
        "research/pq-ringct/Cargo.lock",
        "research/pq-ringct/build.rs",
        "research/pq-ringct/graph_proof_sources.rs",
        "lattica-prover-p3/Cargo.toml",
        "lattica-prover-p3/build.rs",
        "lattica-prover-p3/metadata_sources.rs",
        "lattica-prover-p3/vendor/p3-field/Cargo.toml",
        "lattica-prover-p3/vendor/p3-lookup/Cargo.toml",
        "lattica-prover-p3/vendor/p3-symmetric/Cargo.toml",
    ] {
        let path = root.join(path);
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files.dedup();
    let compiler = Command::new(env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .expect("rustc version");
    assert!(compiler.status.success(), "read rustc version");
    let identity = format!(
        "{};target={};opt={};debug={}",
        String::from_utf8(compiler.stdout).unwrap().trim(),
        env::var("TARGET").unwrap(),
        env::var("OPT_LEVEL").unwrap(),
        env::var("DEBUG").unwrap()
    );
    // Preserve the runtime v1 framing, but hash it once when building. Runtime
    // callers no longer embed or scan the complete compiler source tree.
    let mut workflow = Sha3_256::new();
    workflow.update(b"lattica/matrict/compiled-proof-sources/v1");
    workflow.update(identity.as_bytes());
    let features = [
        u8::from(env::var_os("CARGO_FEATURE_RECURSIVE_WIDE").is_some()),
        u8::from(env::var_os("CARGO_FEATURE_NATIVE_MATRICT").is_some()),
    ];
    workflow.update(features);
    let mut numeric = Sha3_256::new();
    numeric.update(b"ringct/native-numeric-sources/v2\0");
    numeric.update(identity.as_bytes());
    numeric.update(features);
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let label = path.strip_prefix(root).unwrap().to_str().unwrap();
        let contents = fs::read(&path).expect("read proof source");
        let feed = |hash: &mut Sha3_256| {
            hash.update((label.len() as u64).to_le_bytes());
            hash.update(label.as_bytes());
            hash.update((contents.len() as u64).to_le_bytes());
            hash.update(&contents);
        };
        feed(&mut workflow);
        if numeric_sources::selected(label, true) {
            feed(&mut numeric);
        }
    }
    let fingerprint: [u8; 32] = workflow.finalize().into();
    let native: [u8; 32] = numeric.finalize().into();
    let source = format!(
        "const SOURCE_FINGERPRINT: [u8; 32] = {fingerprint:?};\n\
        pub(crate) const NATIVE_NUMERIC_SOURCE: [u8; 32] = {native:?};\n"
    );
    let destination = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("graph-proof-sources.rs");
    if fs::read_to_string(&destination).ok().as_deref() != Some(&source) {
        fs::write(destination, source).expect("write proof source manifest");
    }
}
