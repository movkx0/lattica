use std::{env, path::PathBuf, process::Command};
mod graph_proof_sources;

fn run(command: &mut Command) {
    let status = command.status().expect("launch native research compiler");
    assert!(
        status.success(),
        "native research build failed: {command:?}"
    );
}

fn main() {
    if env::var_os("CARGO_FEATURE_RECURSIVE").is_some() {
        graph_proof_sources::write_manifest();
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-changed=vendor/matrict-plus");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var_os("CARGO_FEATURE_NATIVE_MATRICT").is_none() {
        return;
    }
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        "x86_64",
        "MatRiCT+ reference backend currently requires x86_64"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        "linux",
        "MatRiCT+ reference backend currently requires Linux"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let source = PathBuf::from("vendor/matrict-plus/n10");
    let names = [
        "fastrandombytes",
        "gaussian_avx",
        "hash",
        "keygen",
        "mint",
        "poly_mult",
        "poly_q",
        "sammat",
        "sampleb",
        "setup",
        "spend",
        "verify",
    ];
    let oracle = env::var_os("CARGO_FEATURE_NATIVE_SPEND_ORACLE").is_some();
    let mut objects = Vec::new();
    for (name, path) in names
        .iter()
        .map(|name| (name.to_string(), source.join(format!("{name}.c"))))
        .chain(std::iter::once((
            "lattica_adapter".to_owned(),
            PathBuf::from("native/matrict.c"),
        )))
    {
        let object = out.join(format!("{name}.o"));
        let mut compiler = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()));
        if oracle {
            compiler.arg("-DLATTICA_NATIVE_SPEND_ORACLE=1");
        }
        run(compiler
            .args([
                "-std=gnu11",
                "-O2",
                "-fPIC",
                "-mavx2",
                "-maes",
                "-mfma",
                "-fwrapv",
                "-Wall",
                "-Wextra",
            ])
            .arg("-I")
            .arg(&source)
            .args(["-I", "native/include", "-I", "native"])
            .arg("-c")
            .arg(path)
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    let archive = out.join("liblattica_matrict.a");
    run(
        Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
            .arg("crs")
            .arg(&archive)
            .args(&objects),
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=lattica_matrict");
    println!("cargo:rustc-link-lib=m");
}
