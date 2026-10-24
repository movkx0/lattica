//! Build-time inputs for persistent research proof-cache invalidation.
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
            matches!(extension.to_str(), Some("rs" | "cl" | "cu" | "metal"))
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
    let mut source = String::from("const SOURCES: &[(&str, &[u8])] = &[\n");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let label = path.strip_prefix(root).unwrap().to_str().unwrap();
        source.push_str(&format!(
            "({label:?}, include_bytes!({:?})),\n",
            path.to_str().unwrap()
        ));
    }
    source.push_str("];\n");
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
    source.push_str(&format!("const BUILD_IDENTITY: &str = {identity:?};\n"));
    let destination = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("graph-proof-sources.rs");
    if fs::read_to_string(&destination).ok().as_deref() != Some(&source) {
        fs::write(destination, source).expect("write proof source manifest");
    }
}
